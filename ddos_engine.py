import time
from dataclasses import dataclass, field


@dataclass
class FlowSecurityState:
    src_ip: str
    dst_ip: str
    src_mac: str

    packet_count: int = 0
    start_time: float = field(default_factory=time.time)

    status: str = "NORMAL"
    last_pps: float = 0.0
    last_log_time: float = field(default_factory=time.time)

    blocked_until: float = 0.0


class DdosEngine:
    def __init__(self):
        # Key theo cap (src_ip, dst_ip)
        # Vi du: 10.0.0.3 -> 10.0.0.1
        self.flows = {}

        # Cua so thoi gian de tinh PPS
        self.WINDOW_SECONDS = 0.5

        # Threshold thap de demo lab
        # Co the tang len sau khi demo on dinh
        self.THRESHOLD_SUSPICIOUS = 10
        self.THRESHOLD_ATTACK = 30

        # Thoi gian block logic trong engine
        self.BLOCK_SECONDS = 60

    def update_and_analyze(self, src_ip, dst_ip, src_mac):
        key = (src_ip, dst_ip)
        now = time.time()

        if key not in self.flows:
            self.flows[key] = FlowSecurityState(
                src_ip=src_ip,
                dst_ip=dst_ip,
                src_mac=src_mac
            )

        flow = self.flows[key]

        # Neu flow dang trong thoi gian block thi tra ve BLOCK
        if flow.blocked_until > now:
            return {
                "status": "BLOCK",
                "pps": flow.last_pps,
                "packet_count": flow.packet_count,
                "window": max(now - flow.start_time, 0.0)
            }

        # Het thoi gian block thi reset ve NORMAL
        if flow.status == "BLOCK" and flow.blocked_until <= now:
            flow.status = "NORMAL"
            flow.packet_count = 0
            flow.start_time = now
            flow.last_pps = 0.0

        flow.src_mac = src_mac
        flow.packet_count += 1

        elapsed = now - flow.start_time

        # Chua du window thi giu trang thai hien tai
        if elapsed < self.WINDOW_SECONDS:
            return {
                "status": flow.status,
                "pps": flow.last_pps,
                "packet_count": flow.packet_count,
                "window": elapsed
            }

        pps = flow.packet_count / elapsed
        flow.last_pps = pps

        if pps >= self.THRESHOLD_ATTACK:
            flow.status = "ATTACK"
        elif pps >= self.THRESHOLD_SUSPICIOUS:
            flow.status = "SUSPICIOUS"
        else:
            flow.status = "NORMAL"

        result = {
            "status": flow.status,
            "pps": pps,
            "packet_count": flow.packet_count,
            "window": elapsed
        }

        # Reset counter cho window tiep theo
        flow.packet_count = 0
        flow.start_time = now

        return result

    def mark_blocked(self, src_ip, dst_ip):
        key = (src_ip, dst_ip)
        now = time.time()

        if key not in self.flows:
            self.flows[key] = FlowSecurityState(
                src_ip=src_ip,
                dst_ip=dst_ip,
                src_mac="unknown"
            )

        flow = self.flows[key]
        flow.status = "BLOCK"
        flow.blocked_until = now + self.BLOCK_SECONDS

    def reset_flow(self, src_ip, dst_ip):
        key = (src_ip, dst_ip)

        if key in self.flows:
            del self.flows[key]

    def reset_all(self):
        self.flows.clear()