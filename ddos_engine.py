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


class DdosEngine:
    def __init__(self):
        # Key theo cặp (src_ip, dst_ip) → chỉ block chính xác flow bị tấn công
        self.flows = {}

        # Threshold thấp để test kịch bản dễ dàng (bạn có thể tăng lên sau)
        self.THRESHOLD_SUSPICIOUS = 10
        self.THRESHOLD_ATTACK = 30

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

        if elapsed >= 0.5:
            pps = flow.packet_count / elapsed
            print(
                f"[MONITOR] FLOW {src_ip} -> {dst_ip} MAC {src_mac} đang đạt {pps:.2f} PPS"
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