
@dataclass
class SIPMessage:
    """Represents a parsed SIP message from trace log."""
    timestamp: str
    direction: str  # 'IN' or 'OUT'
    src_ip: str
    src_port: int
    dst_ip: str
    dst_port: int
    transport: str  # 'TCP', 'UDP', etc.
    message: str  # Full SIP message
    
    def __str__(self):
        return (f"[{self.timestamp}] SIP {self.direction}: "
                f"{self.src_ip}:{self.src_port} -> {self.dst_ip}:{self.dst_port} "
                f"({self.transport})")