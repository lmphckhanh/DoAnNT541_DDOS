# ddos_controller.py

import time
from dataclasses import dataclass, field

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, ipv4, icmp


@dataclass
class FlowSecurityState:
    src_ip: str
    dst_ip: str
    src_mac: str
    packet_count: int = 0
    start_time: float = field(default_factory=time.time)
    status: str = "NORMAL"


class DdosEngine:
    def __init__(self):
        # Key theo cap (src_ip, dst_ip), khong key moi theo src_ip nua.
        # Nhu vay h2 -> h1 bi ATTACK thi chi cap do bi chan,
        # h2 -> h3 van duoc di binh thuong.
        self.flows = {}

        # Threshold test. Khi demo on dinh co the tang len 20 / 100.
        self.THRESHOLD_SUSPICIOUS = 5
        self.THRESHOLD_ATTACK = 20

    def update_and_analyze(self, src_ip, dst_ip, src_mac):
        key = (src_ip, dst_ip)

        if key not in self.flows:
            self.flows[key] = FlowSecurityState(
                src_ip=src_ip,
                dst_ip=dst_ip,
                src_mac=src_mac
            )

        flow = self.flows[key]
        flow.packet_count += 1

        current_time = time.time()
        elapsed = current_time - flow.start_time

        if elapsed >= 1.0:
            pps = flow.packet_count / elapsed
            print(
                f"[MONITOR] FLOW {src_ip} -> {dst_ip} MAC {src_mac} dang dat {pps:.2f} PPS"
            )

            if pps > self.THRESHOLD_ATTACK:
                flow.status = "ATTACK"
            elif pps > self.THRESHOLD_SUSPICIOUS:
                flow.status = "SUSPICIOUS"
            else:
                flow.status = "NORMAL"

            flow.packet_count = 0
            flow.start_time = current_time

        return flow.status

    def reset_flow(self, src_ip, dst_ip):
        key = (src_ip, dst_ip)
        if key in self.flows:
            del self.flows[key]


class DdosController(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(DdosController, self).__init__(*args, **kwargs)

        self.engine = DdosEngine()

        # Luu bang MAC cho learning switch
        self.mac_to_port = {}

        # Luu tat ca switch ket noi vao controller
        self.datapaths = {}

        self.logger.info("=== DDOS CONTROLLER STARTED ===")

    def add_flow(self, datapath, priority, match, actions, timeout=0):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [
            parser.OFPInstructionActions(
                ofproto.OFPIT_APPLY_ACTIONS,
                actions
            )
        ]

        mod = parser.OFPFlowMod(
            datapath=datapath,
            priority=priority,
            match=match,
            instructions=inst,
            idle_timeout=timeout,
            hard_timeout=timeout
        )

        datapath.send_msg(mod)

    def block_pair_on_all_switches(self, attacker_ip, victim_ip, timeout=20):
        """
        Chi drop dung cap attacker -> victim.
        Vi du: 10.0.0.2 -> 10.0.0.1 DROP.

        Khong drop toan bo ipv4_src=10.0.0.2, nen:
        - 10.0.0.2 -> 10.0.0.3 van OK
        - 10.0.0.1 -> 10.0.0.3 van OK
        - 10.0.0.3 -> 10.0.0.1 van OK
        """
        for dp_id, datapath in self.datapaths.items():
            parser = datapath.ofproto_parser

            match = parser.OFPMatch(
                eth_type=0x0800,
                ipv4_src=attacker_ip,
                ipv4_dst=victim_ip
            )

            # actions = [] nghia la DROP
            self.add_flow(
                datapath=datapath,
                priority=200,
                match=match,
                actions=[],
                timeout=timeout
            )

            self.logger.warning(
                "[BLOCK] Installed DROP rule for pair %s -> %s on switch %s",
                attacker_ip,
                victim_ip,
                dp_id
            )

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        self.datapaths[datapath.id] = datapath
        self.mac_to_port.setdefault(datapath.id, {})

        # Table-miss: gui packet chua match len controller
        match = parser.OFPMatch()
        actions = [
            parser.OFPActionOutput(
                ofproto.OFPP_CONTROLLER,
                ofproto.OFPCML_NO_BUFFER
            )
        ]

        self.add_flow(
            datapath=datapath,
            priority=0,
            match=match,
            actions=actions,
            timeout=0
        )

        self.logger.info("[CONNECTED] Switch %s connected", datapath.id)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        dpid = datapath.id

        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        in_port = msg.match["in_port"]

        pkt = packet.Packet(msg.data)
        eth_list = pkt.get_protocols(ethernet.ethernet)

        if not eth_list:
            return

        eth = eth_list[0]

        # Bo qua LLDP
        if eth.ethertype == 0x88cc:
            return

        dst = eth.dst
        src = eth.src

        self.mac_to_port.setdefault(dpid, {})
        self.mac_to_port[dpid][src] = in_port

        # ===== DDOS DETECTION =====
        ip_pkt = pkt.get_protocol(ipv4.ipv4)

        if ip_pkt:
            src_ip = ip_pkt.src
            dst_ip = ip_pkt.dst

            # Them tin hieu de biet controller co nhan goi IP/ICMP.
            # Khi ping binh thuong se thay log ICMP nay.
            icmp_pkt = pkt.get_protocol(icmp.icmp)
            if icmp_pkt:
                self.logger.info(
                    "[PING/ICMP] switch=%s in_port=%s %s -> %s icmp_type=%s",
                    dpid,
                    in_port,
                    src_ip,
                    dst_ip,
                    icmp_pkt.type
                )
            else:
                self.logger.info(
                    "[IP] switch=%s in_port=%s %s -> %s",
                    dpid,
                    in_port,
                    src_ip,
                    dst_ip
                )

            status = self.engine.update_and_analyze(src_ip, dst_ip, src)

            if status == "SUSPICIOUS":
                self.logger.warning(
                    "[SUSPICIOUS] FLOW %s -> %s MAC %s on switch %s",
                    src_ip,
                    dst_ip,
                    src,
                    dpid
                )

            elif status == "ATTACK":
                self.logger.error(
                    "[ATTACK] DDOS detected on flow %s -> %s MAC %s",
                    src_ip,
                    dst_ip,
                    src
                )

                self.block_pair_on_all_switches(src_ip, dst_ip, timeout=20)
                return

        # ===== LEARNING SWITCH FORWARDING =====
        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD

        actions = [parser.OFPActionOutput(out_port)]

        # De timeout ngan de controller van thay packet va dem PPS.
        # Match them eth_type/ipv4_src/ipv4_dst cho IP de tranh flow layer-2
        # qua mat controller qua lau khi test ping/DDOS.
        if out_port != ofproto.OFPP_FLOOD:
            if ip_pkt:
                match = parser.OFPMatch(
                    in_port=in_port,
                    eth_type=0x0800,
                    ipv4_src=ip_pkt.src,
                    ipv4_dst=ip_pkt.dst
                )
            else:
                match = parser.OFPMatch(
                    in_port=in_port,
                    eth_src=src,
                    eth_dst=dst
                )

            self.add_flow(
                datapath=datapath,
                priority=1,
                match=match,
                actions=actions,
                timeout=1
            )

        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = parser.OFPPacketOut(
            datapath=datapath,
            buffer_id=msg.buffer_id,
            in_port=in_port,
            actions=actions,
            data=data
        )

        datapath.send_msg(out)
