from typing import Dict, Tuple

from src.config import Config
from src.models import ClientContext


class ConnectManager:
    free_udp_ports = []
    clients: Dict[str, ClientContext] = {}

    def __init__(self, config: Config):
        self.free_udp_ports = [(i, i + 1) for i in range(config.rtp_rtcp_port_ranges[0], config.rtp_rtcp_port_ranges[1], 2)]

    def get_free_ports(self) -> Tuple[int, int]:
        return self.free_udp_ports.pop()

    def set_free_ports(self, ports) -> None:
        self.free_udp_ports.append(ports)

    def add_client(self, ip: str, port: str, context: ClientContext):
        self.clients[f'{ip}:{port}'] = context
