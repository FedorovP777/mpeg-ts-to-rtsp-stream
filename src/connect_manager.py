import dataclasses
import datetime
import enum
from enum import Enum
from typing import Dict, Tuple
from uuid import uuid4

from src.config import Config
from src.sdp import SDPSession


@enum.unique
class PlayStatus(Enum):
    NEW = 1
    PLAY = 2
    PAUSE = 3
    DONE = 4


@dataclasses.dataclass
class ClientContext:
    sequence_number: int = 0
    timestamp: int = 0
    uuid: str = dataclasses.field(default_factory=uuid4)
    ip: str = ''
    port: str = ''
    play_status: PlayStatus = PlayStatus.NEW
    sdp_session: SDPSession = dataclasses.field(default_factory=SDPSession)
    client_udp_ports: list = dataclasses.field(default_factory=list)
    server_rtp = None
    server_rtcp = None
    latest_activity: datetime.datetime = dataclasses.field(default_factory=datetime.datetime.now)

    def __del__(self):
        print(f"Call ClientContext dtor {self}")


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

    def rtp_disconnect(self, client_id: str):
        self.clients[client_id].server_rtp.shutdown()
        self.clients[client_id].server_rtp.close()

    def rtpcp_disconnect(self, client_id: str):
        self.clients[client_id].server_rtcp.shutdown()
        self.clients[client_id].server_rtcp.close()

    def remove_client(self, client_id: str) -> None:
        del self.clients[client_id]
