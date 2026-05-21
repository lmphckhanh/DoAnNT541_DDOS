import time
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, ipv4
from ddos_engine import DdosEngine


class DdosController(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(DdosController, self).__init__(*args, **kwargs)
        self.engine = DdosEngine()
        self.mac_to_port = {}
        self.datapaths = {}

        self.logger.info("=== DDOS CONTROLLER v3.0 - FLOW BASED BLOCK ===")
        self.logger.info("Detect theo cap src_ip -> dst_ip, chi block dung flow tan cong")

    def add_flow(self, datapath, priority, match, actions, timeout=0):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]

        mod = parser.OFPFlowMod(
            datapath=datapath,
            priority=priority,
            match=match,
            instructions=inst,
            idle_timeout=timeout,
            hard_timeout=timeout
        )

        datapath.send_msg(mod)

    def delete_flow_on_all_switches(self, attacker_ip, victim_ip):
        """
        Xoa cac forwarding flow cu cua dung cap attacker -> victim
        de rule DROP priority cao co tac dung ngay.
        """
        for dp_id, datapath in list(self.datapaths.items()):
            parser = datapath.ofproto_parser
            ofproto = datapath.ofproto

            match = parser.OFPMatch(
                eth_type=0x0800,
                ipv4_src=attacker_ip,
                ipv4_dst=victim_ip
            )

            mod = parser.OFPFlowMod(
                datapath=datapath,
                command=ofproto.OFPFC_DELETE,
                out_port=ofproto.OFPP_ANY,
                out_group=ofproto.OFPG_ANY,
                match=match
            )

            datapath.send_msg(mod)

    def block_flow_on_all_switches(self, attacker_ip, victim_ip, timeout=60):
        """
        Chi block dung flow tan cong:
        attacker_ip -> victim_ip

        Vi du:
        10.0.0.3 -> 10.0.0.1 bi chan
        10.0.0.3 -> 10.0.0.2 van co the hoat dong
        """
        self.delete_flow_on_all_switches(attacker_ip, victim_ip)

        for dp_id, datapath in list(self.datapaths.items()):
            parser = datapath.ofproto_parser

            match_block = parser.OFPMatch(
                eth_type=0x0800,
                ipv4_src=attacker_ip,
                ipv4_dst=victim_ip
            )

            self.add_flow(
                datapath=datapath,
                priority=65535,
                match=match_block,
                actions=[],
                timeout=timeout
            )

            self.logger.error(
                "!!! [FLOW BLOCK] %s -> %s blocked on switch dpid=%s timeout=%ss priority=65535",
                attacker_ip,
                victim_ip,
                dp_id,
                timeout
            )

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        self.datapaths[datapath.id] = datapath
        self.mac_to_port.setdefault(datapath.id, {})

        self.logger.info("[SWITCH CONNECTED] dpid=%s", datapath.id)

        actions_to_controller = [
            parser.OFPActionOutput(
                ofproto.OFPP_CONTROLLER,
                ofproto.OFPCML_NO_BUFFER
            )
        ]

        # Monitor HTTP traffic port 80.
        # Kich ban web-3 ddos web-1 nen dung:
        # web-3 -> 10.0.0.1:80
        match_http = parser.OFPMatch(
            eth_type=0x0800,
            ip_proto=6,
            tcp_dst=80
        )
        self.add_flow(
            datapath=datapath,
            priority=100,
            match=match_http,
            actions=actions_to_controller
        )

        # Table-miss: goi chua match flow nao se gui ve controller
        match_any = parser.OFPMatch()
        self.add_flow(
            datapath=datapath,
            priority=0,
            match=match_any,
            actions=actions_to_controller
        )

        self.logger.info("[FLOW INIT] Installed monitor flow and table-miss on dpid=%s", datapath.id)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        in_port = msg.match["in_port"]

        pkt = packet.Packet(msg.data)
        eth_list = pkt.get_protocols(ethernet.ethernet)

        if not eth_list:
            return

        eth = eth_list[0]

        # Bo qua LLDP
        if eth.ethertype == 0x88cc:
            return

        ip_pkt = pkt.get_protocol(ipv4.ipv4)

        # Neu khong phai IPv4 thi forward L2 binh thuong
        if not ip_pkt:
            self._forward_packet(msg, eth, in_port)
            return

        src_ip = ip_pkt.src
        dst_ip = ip_pkt.dst

        # Cap nhat engine va lay ket qua phan tich
        result = self.engine.update_and_analyze(src_ip, dst_ip, eth.src)

        status = result["status"]
        pps = result["pps"]
        packet_count = result["packet_count"]
        window = result["window"]

        self.logger.info(
            "[MONITOR] %s -> %s | status=%s | pps=%.2f | packets=%s | window=%.2fs",
            src_ip,
            dst_ip,
            status,
            pps,
            packet_count,
            window
        )

        if status == "ATTACK":
            self.logger.error(
                "[DDOS DETECTED] attacker=%s victim=%s pps=%.2f",
                src_ip,
                dst_ip,
                pps
            )

            self.block_flow_on_all_switches(src_ip, dst_ip, timeout=60)
            self.engine.mark_blocked(src_ip, dst_ip)

            return

        if status == "BLOCK":
            # Flow nay da bi danh dau block trong engine.
            # Packet neu van len controller thi drop luon.
            self.logger.warning("[DROP PACKET] blocked flow %s -> %s", src_ip, dst_ip)
            return

        self._forward_packet(msg, eth, in_port, ip_pkt)

    def _forward_packet(self, msg, eth, in_port, ip_pkt=None):
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})
        self.mac_to_port[dpid][eth.src] = in_port

        out_port = self.mac_to_port[dpid].get(eth.dst, ofproto.OFPP_FLOOD)
        actions = [parser.OFPActionOutput(out_port)]

        if out_port != ofproto.OFPP_FLOOD:
            if ip_pkt:
                match = parser.OFPMatch(
                    eth_type=0x0800,
                    ipv4_src=ip_pkt.src,
                    ipv4_dst=ip_pkt.dst
                )
            else:
                match = parser.OFPMatch(
                    eth_src=eth.src,
                    eth_dst=eth.dst
                )

            # Priority 10 thap hon monitor flow 100 va block flow 65535
            self.add_flow(
                datapath=datapath,
                priority=10,
                match=match,
                actions=actions,
                timeout=20
            )

        data = msg.data if msg.buffer_id == ofproto.OFP_NO_BUFFER else None

        out = parser.OFPPacketOut(
            datapath=datapath,
            buffer_id=msg.buffer_id,
            in_port=in_port,
            actions=actions,
            data=data
        )

        datapath.send_msg(out)