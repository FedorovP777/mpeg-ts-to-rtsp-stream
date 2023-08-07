import asyncio
import dataclasses
import datetime
import socket
import socketserver
import sys
import threading
from enum import Enum

from functools import singledispatch
from typing import Tuple, Dict, Optional

import av

from src.config import Config
from src.connect_manager import ConnectManager, ClientContext, PlayStatus
from src.sdp import sdp_create
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

rtsp_response_codes = {
    100: "Continue",
    200: "OK",
    201: "Created",
    250: "Low on Storage Space",
    300: "Multiple Choices",
    301: "Moved Permanently",
    302: "Moved Temporarily",
    303: "See Other",
    305: "Use Proxy",
    400: "Bad Request",
    401: "Unauthorized",
    402: "Payment Required",
    403: "Forbidden",
    404: "Not Found",
    405: "Method Not Allowed",
    406: "Not Acceptable",
    407: "Proxy Authentication Required",
    408: "Request Timeout",
    410: "Gone",
    411: "Length Required",
    412: "Precondition Failed",
    413: "Request Entity Too Large",
    414: "Request-URI Too Long",
    415: "Unsupported Media Type",
    451: "Invalid parameter",
    452: "Illegal Conference Identifier",
    453: "Not Enough Bandwidth",
    454: "Session Not Found",
    455: "Method Not Valid In This State",
    456: "Header Field Not Valid",
    457: "Invalid Range",
    458: "Parameter Is Read-Only",
    459: "Aggregate Operation Not Allowed",
    460: "Only Aggregate Operation Allowed",
    461: "Unsupported Transport",
    462: "Destination Unreachable",
    500: "Internal Server Error",
    501: "Not Implemented",
    502: "Bad Gateway",
    503: "Service Unavailable",
    504: "Gateway Timeout",
    505: "RTSP Version Not Supported",
    551: "Option not support"
}


class RTSPResponseCreator:
    def set_status(self, packet: RTSPPacket, status_code: int) -> None:
        assert status_code in rtsp_response_codes
        packet.status_code = status_code

    def set_url(self, packet: RTSPPacket, url):
        packet.url = url

    def set_version(self, packet: RTSPPacket, version):
        packet.version = version

    def set_header(self, packet: RTSPPacket, name: str, value: str):
        packet.headers[name] = value

    def set_body_string(self, packet: RTSPPacket, body: str) -> None:
        packet.body_string = body

    def compile_packet(self, packet: RTSPPacket) -> str:
        result = [
            f'RTSP/{packet.version} {packet.status_code} {rtsp_response_codes[packet.status_code]}',
        ]

        if 'CSeq' in packet.headers:
            cseq = packet.headers['CSeq']
            result.append(f'CSeq: {cseq}')
            del packet.headers['CSeq']

        result += [f'{k}: {v}' for k, v in packet.headers.items()]
        headers = "\r\n".join(result) + "\r\n\r\n"

        if packet.body_string:
            return headers + packet.body_string

        return headers


@singledispatch
def handle_request(method, rtsp_message: RTSPPacket, context: ClientContext, socket: socket.socket, connect_manager: ConnectManager):
    pass


@handle_request.register
def _(method: SetupMethod, rtsp_message: RTSPPacket, context: ClientContext, socket: socket.socket, connect_manager: ConnectManager):
    from src.socket_handlers import TCPHandler, RTPCPHandler, RTPHandler
    str_port = 'client_port='
    pos = rtsp_message.headers['Transport'].find(str_port)
    ports = rtsp_message.headers['Transport'][pos + len(str_port):]
    port1, port2 = ports.split("-")
    context.client_udp_ports = [port1, port2]
    transport = rtsp_message.headers['Transport']
    rtp_server_port, rtpcp_server_port = connect_manager.get_free_ports()
    server_rtp = socketserver.UDPServer((Config.host, rtp_server_port), RTPHandler)
    server_rtcp = socketserver.UDPServer((Config.host, rtpcp_server_port), RTPCPHandler)

    server_rtp.context = context
    server_rtcp.context = context
    server_rtcp.config = Config

    context.server_rtp = server_rtp
    context.server_rtcp = server_rtcp
    context.latest_activity = datetime.datetime.now()
    threading.Thread(target=server_rtp.handle_request).start()
    threading.Thread(target=server_rtcp.handle_request).start()
    RTSP_response_creator = RTSPResponseCreator()
    packet = RTSPPacket()
    RTSP_response_creator.set_version(packet, Config.rtsp_protocol_version)
    RTSP_response_creator.set_status(packet, 200)
    RTSP_response_creator.set_header(packet, 'CSeq', rtsp_message.headers['CSeq'])
    RTSP_response_creator.set_header(packet, 'Session', context.uuid)
    RTSP_response_creator.set_header(packet, 'User-Agent', Config.user_agent)
    RTSP_response_creator.set_header(packet, 'Transport', f'{transport};server_port={rtp_server_port}-{rtpcp_server_port}')

    socket.sendall(str.encode(RTSP_response_creator.compile_packet(packet)))


@handle_request.register
def _(method: PlayMethod, rtsp_message: RTSPPacket, context: ClientContext, socket: socket.socket, connect_manager: ConnectManager):
    CSeq = rtsp_message.headers['CSeq']
    packet_maker = RTSPResponseCreator()
    packet = RTSPPacket()
    packet_maker.set_version(packet, '1.0')
    packet_maker.set_status(packet, 200)
    packet_maker.set_header(packet, 'CSeq', CSeq)
    packet_maker.set_header(packet, 'Session', context.uuid)
    packet_maker.set_header(packet, 'User-Agent', Config.user_agent)
    context.play_status = PlayStatus.PLAY
    context.latest_activity = datetime.datetime.now()
    socket.sendall(str.encode(packet_maker.compile_packet(packet)))


@handle_request.register
def _(method: DescribeMethod, rtsp_message: RTSPPacket, context: ClientContext, socket: socket.socket, connect_manager: ConnectManager):
    CSeq = rtsp_message.headers.get('CSeq', None)
    packet_maker = RTSPResponseCreator()
    packet = RTSPPacket()
    sdp = sdp_create(context.sdp_session, av.open(sys.argv[1]).streams)
    packet_maker.set_version(packet, Config.rtsp_protocol_version)
    packet_maker.set_status(packet, 200)
    packet_maker.set_header(packet, 'CSeq', CSeq)
    packet_maker.set_header(packet, 'Session', context.uuid)
    packet_maker.set_header(packet, 'User-Agent', Config.user_agent)
    packet_maker.set_header(packet, 'Content-Type', 'application/sdp')
    packet_maker.set_header(packet, 'Content-Length', str(len(sdp)))
    packet_maker.set_body_string(packet, sdp)
    context.latest_activity = datetime.datetime.now()
    socket.sendall(str.encode(packet_maker.compile_packet(packet)))


@handle_request.register
def _(method: OptionsMethod, rtsp_message: RTSPPacket, context: ClientContext, socket: socket.socket, connect_manager: ConnectManager):
    CSeq = rtsp_message.headers.get('CSeq', None)

    packet_maker = RTSPResponseCreator()
    packet = RTSPPacket()
    packet_maker.set_version(packet, Config.rtsp_protocol_version)
    packet_maker.set_status(packet, 200)
    packet_maker.set_header(packet, 'CSeq', CSeq)
    packet_maker.set_header(packet, 'Options:', 'OPTIONS, DESCRIBE, SETUP, PLAY, PAUSE, GET_PARAMETER, TEARDOWN, SET_PARAMETER')
    packet_maker.set_header(packet, 'User-Agent', Config.user_agent)
    context.latest_activity = datetime.datetime.now()

    socket.sendall(str.encode(packet_maker.compile_packet(packet)))


@handle_request.register
def _(method: TearDownMethod, rtsp_message: RTSPPacket, context: ClientContext, socket: socket.socket, connect_manager: ConnectManager):
    CSeq = rtsp_message.headers['CSeq']

    packet_maker = RTSPResponseCreator()
    packet = RTSPPacket()
    packet_maker.set_version(packet, Config.rtsp_protocol_version)
    packet_maker.set_status(packet, 200)
    packet_maker.set_header(packet, 'CSeq', CSeq)
    packet_maker.set_header(packet, 'Session', context.uuid)
    packet_maker.set_header(packet, 'User-Agent', Config.user_agent)
    context.latest_activity = datetime.datetime.now()
    context.play_status = PlayStatus.DONE
    socket.sendall(str.encode(packet_maker.compile_packet(packet)))
