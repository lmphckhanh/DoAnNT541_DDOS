import time
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, ipv4, tcp
from ddos_engine import DdosEngine

class DdosController(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(DdosController, self).__init__(*args, **kwargs)
        self.engine = DdosEngine()
        self.mac_to_port = {}
        self.datapaths = {}
        self.logger.info("=== DDOS CONTROLLER v2.2 - FIXED PRIORITY ===")

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

    def block_attacker_on_all_switches(self, attacker_ip, timeout=60):
        for dp_id, datapath in list(self.datapaths.items()):
            parser = datapath.ofproto_parser
            ofproto = datapath.ofproto

            # Xóa sạch các flow Forwarding cũ để ép traffic phải đi qua luật Block
            match_del = parser.OFPMatch(eth_type=0x0800, ipv4_src=attacker_ip)
            mod_del = parser.OFPFlowMod(
                datapath=datapath, command=ofproto.OFPFC_DELETE,
                out_port=ofproto.OFPP_ANY, out_group=ofproto.OFPG_ANY,
                match=match_del
            )
            datapath.send_msg(mod_del)

            # Block với Priority cao nhất tuyệt đối
            self.add_flow(datapath, 65535, match_del, [], timeout=timeout)
            self.logger.error(f"!!! [HARD BLOCK] {attacker_ip} blocked (Priority 65535)")

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        self.datapaths[datapath.id] = datapath
        self.mac_to_port.setdefault(datapath.id, {})

        # Quan trọng: Priority của Monitor (100) phải cao hơn Priority của Forward (10)
        match_http = parser.OFPMatch(eth_type=0x0800, ip_proto=6, tcp_dst=80)
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 100, match_http, actions) # Nâng lên 100
        
        match_any = parser.OFPMatch()
        self.add_flow(datapath, 0, match_any, actions)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        in_port = msg.match["in_port"]
        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]

        if eth.ethertype == 0x88cc: return

        ip_pkt = pkt.get_protocol(ipv4.ipv4)
        if not ip_pkt:
            self._forward_packet(msg, eth, in_port)
            return

        src_ip = ip_pkt.src
        dst_ip = ip_pkt.dst
        
        # Monitor mọi traffic IPv4 để không bỏ lỡ kiểu DDoS nào
        status = self.engine.update_and_analyze(src_ip, dst_ip, eth.src)
        if status == "ATTACK":
            self.block_attacker_on_all_switches(src_ip)
            return 

        self._forward_packet(msg, eth, in_port, ip_pkt)

    def _forward_packet(self, msg, eth, in_port, ip_pkt=None):
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        
        self.mac_to_port[datapath.id][eth.src] = in_port
        out_port = self.mac_to_port[datapath.id].get(eth.dst, ofproto.OFPP_FLOOD)
        actions = [parser.OFPActionOutput(out_port)]

        if out_port != ofproto.OFPP_FLOOD:
            # Luật Forward chỉ để priority 10
            match = parser.OFPMatch(eth_type=0x0800, ipv4_src=ip_pkt.src, ipv4_dst=ip_pkt.dst) if ip_pkt else \
                    parser.OFPMatch(eth_src=eth.src, eth_dst=eth.dst)
            self.add_flow(datapath, 10, match, actions, timeout=20)

        data = msg.data if msg.buffer_id == ofproto.OFP_NO_BUFFER else None
        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)