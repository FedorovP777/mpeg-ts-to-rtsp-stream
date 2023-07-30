import dataclasses
import datetime

from enum import Enum
from typing import Optional, List, Tuple
from uuid import uuid4

from src.utils import byte_struct


class RTPControlProtocolPacketType(Enum):
    SEND_REPORT = 200
    RECEIVE_REPORT = 200
    SOURCE_DESCRIPTION = 202
    BYE = 203
    APP = 204


@dataclasses.dataclass
class RTSPPacket:
    """https://datatracker.ietf.org/doc/html/rfc2326"""
    method: str = None
    version: str = None
    url: str = None
    status_code: Optional[int] = None
    headers: dict = dataclasses.field(default_factory=dict)
    body_string: Optional[int] = None


class RTSPPlayStatus(Enum):
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
    status: RTSPPlayStatus = dataclasses.field(default_factory=lambda: RTSPPlayStatus.NEW)
    sdp: str = ""
    client_udp_ports: list = dataclasses.field(default_factory=list)
    server_rtp = None
    server_rtcp = None
    latest_activity: datetime.datetime = dataclasses.field(default_factory=datetime.datetime.now)

    def __del__(self):
        print(f"Call ClientContext dtor {self}")


class BaseMethod:
    url: str
    version: str


class DescribeMethod:
    pass


class OptionsMethod:
    pass


class SetupMethod:
    pass


class PlayMethod:
    pass


class TearDownMethod:
    pass


class GetParameterMethod:
    pass


@byte_struct
@dataclasses.dataclass
class RTPPacketHeader:
    """
     https://datatracker.ietf.org/doc/html/rfc3550#section-5.1
     0                   1                   2                   3
     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |V=2|P|X|  CC   |M|     PT      |       sequence number         |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                           timestamp                           |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |           synchronization source (SSRC) identifier            |
    +=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+
    """
    version: int
    padding: int
    extension: int
    CRCC: int
    marker: int
    payload_type: int
    sequence_number: int
    timestamp: int
    SSRC: int

    def repr_bytes(self):
        return [
            (self.version, 2),
            (self.padding, 1),
            (self.extension, 1),
            (self.CRCC, 4),
            (self.marker, 1),
            (self.payload_type, 7),
            (self.sequence_number, 16),
            (self.timestamp, 32),
            (self.SSRC, 32),
        ]


@byte_struct
@dataclasses.dataclass
class RTPControlProtocolPacketHeader:
    """
     0                   1                   2                   3
     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |V=2|P|    RC   |   PT=SR=200   |             length            |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                         SSRC of sender                        |
    +=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+
    """
    version: int  # 2 bite
    padding: int  # 1 byte
    reception_report_count: int  # 5 bit
    packet_type: int  # 8 bit
    length: int  # 16 bit
    SSRC: int  # 32 bit

    def repr_bytes(self):
        return [
            (self.version, 2),
            (self.padding, 1),
            (self.reception_report_count, 5),
            (self.packet_type, 8),
            (self.length, 16),
            (self.SSRC, 32),
        ]


@byte_struct
@dataclasses.dataclass
class RTPControlProtocolSendReport:
    msw: int  # 32
    lsw: int  # 32
    rtp_timestamp: int  # 32
    senders_packet_count: int  # 32
    senders_octet_count: int  # 32

    def repr_bytes(self):
        return [
            (self.msw, 32),
            (self.lsw, 32),
            (self.rtp_timestamp, 32),
            (self.senders_packet_count, 32),
            (self.senders_octet_count, 32),
        ]


ResultParseMethod = tuple[Optional[str], Optional[str], Optional[str]]
