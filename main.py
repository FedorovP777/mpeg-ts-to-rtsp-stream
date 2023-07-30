import asyncio
import dataclasses
import datetime
import fractions
import socket
import socketserver
import sys
import threading
import time
from dataclasses import _set_new_attribute
from enum import Enum
from functools import singledispatch
from typing import Tuple, Optional, List, Dict
from uuid import uuid4
import av

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


class GetParameterMethod:
    pass


class Config:
    rtsp_protocol_version = '1.0'
    user_agent = 'Streamer 23.02'
    rtp_rtcp_port_ranges = (160, 560)  # must start from even number. Even - rtp, odd - rtcp
    client_timeout = 1000  # seconds


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
    sdp: str = open('example-mpeg-ts/example_1.sdp').read()
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


class TearDownMethod:
    pass


type
ResultParseMethod = tuple[Optional[str], Optional[str], Optional[str]]


@dataclasses.dataclass
class RTSPPacket:
    """https://datatracker.ietf.org/doc/html/rfc2326"""
    method: str = None
    version: str = None
    url: str = None
    status_code: Optional[int] = None
    headers: dict = dataclasses.field(default_factory=dict)
    body_string: Optional[int] = None


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
def handle_request(method, rtsp_message: RTSPPacket, context: ClientContext, socket: socket.socket):
    pass


@handle_request.register
def _(method: SetupMethod, rtsp_message: RTSPPacket, context: ClientContext, socket: socket.socket):
    str_port = 'client_port='
    pos = rtsp_message.headers['Transport'].find(str_port)
    ports = rtsp_message.headers['Transport'][pos + len(str_port):]
    port1, port2 = ports.split("-")
    context.client_udp_ports = [port1, port2]
    transport = rtsp_message.headers['Transport']
    rtp_server_port, rtpcp_server_port = connect_manager.get_free_ports()
    server_rtp = socketserver.UDPServer((HOST, rtp_server_port), RTPHandler)
    server_rtcp = socketserver.UDPServer((HOST, rtpcp_server_port), RTPCPHandler)

    server_rtp.context = context
    server_rtcp.context = context

    context.server_rtp = server_rtp
    context.server_rtcp = server_rtcp
    context.latest_activity = datetime.datetime.now()
    threading.Thread(target=server_rtp.handle_request).start()
    threading.Thread(target=server_rtcp.handle_request).start()
    packet_maker = RTSPResponseCreator()
    packet = RTSPPacket()
    packet_maker.set_version(packet, Config.rtsp_protocol_version)
    packet_maker.set_status(packet, 200)
    packet_maker.set_header(packet, 'CSeq', rtsp_message.headers['CSeq'])
    packet_maker.set_header(packet, 'Session', context.uuid)
    packet_maker.set_header(packet, 'User-Agent', Config.user_agent)
    packet_maker.set_header(packet, 'Transport', f'{transport};server_port={rtp_server_port}-{rtpcp_server_port}')

    socket.sendall(str.encode(packet_maker.compile_packet(packet)))


@handle_request.register
def _(method: PlayMethod, rtsp_message: RTSPPacket, context: ClientContext, socket: socket.socket):
    CSeq = rtsp_message.headers['CSeq']
    packet_maker = RTSPResponseCreator()
    packet = RTSPPacket()
    packet_maker.set_version(packet, '1.0')
    packet_maker.set_status(packet, 200)
    packet_maker.set_header(packet, 'CSeq', CSeq)
    packet_maker.set_header(packet, 'Session', context.uuid)
    packet_maker.set_header(packet, 'User-Agent', Config.user_agent)
    context.status = RTSPPlayStatus.PLAY
    context.latest_activity = datetime.datetime.now()
    socket.sendall(str.encode(packet_maker.compile_packet(packet)))


@handle_request.register
def _(method: DescribeMethod, rtsp_message: RTSPPacket, context: ClientContext, socket: socket.socket):
    CSeq = rtsp_message.headers.get('CSeq', None)
    packet_maker = RTSPResponseCreator()
    packet = RTSPPacket()
    packet_maker.set_version(packet, Config.rtsp_protocol_version)
    packet_maker.set_status(packet, 200)
    packet_maker.set_header(packet, 'CSeq', CSeq)
    packet_maker.set_header(packet, 'Session', context.uuid)
    packet_maker.set_header(packet, 'User-Agent', Config.user_agent)
    packet_maker.set_header(packet, 'Content-Type', 'application/sdp')
    packet_maker.set_header(packet, 'Content-Length', str(len(context.sdp)))
    packet_maker.set_body_string(packet, context.sdp)
    context.latest_activity = datetime.datetime.now()
    socket.sendall(str.encode(packet_maker.compile_packet(packet)))


@handle_request.register
def _(method: OptionsMethod, rtsp_message: RTSPPacket, context: ClientContext, socket: socket.socket):
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
def _(method: TearDownMethod, rtsp_message: RTSPPacket, context: ClientContext, socket: socket.socket):
    CSeq = rtsp_message.headers['CSeq']

    packet_maker = RTSPResponseCreator()
    packet = RTSPPacket()
    packet_maker.set_version(packet, Config.rtsp_protocol_version)
    packet_maker.set_status(packet, 200)
    packet_maker.set_header(packet, 'CSeq', CSeq)
    packet_maker.set_header(packet, 'Session', context.uuid)
    packet_maker.set_header(packet, 'User-Agent', Config.user_agent)
    context.latest_activity = datetime.datetime.now()
    context.status = RTSPPlayStatus.DONE
    socket.sendall(str.encode(packet_maker.compile_packet(packet)))


TCP_BUFF_SIZE = 20048


class RTSPPacketParser:
    def get_packet(self, body: str) -> Optional[RTSPPacket]:
        body = body.rstrip("\r\n").split("\r\n")
        body_rows = [i for i in body if i]

        if len(body_rows) < 1 or len(body_rows[0].split(" ")) != 3:
            return None

        rtsp_method, url, version = self._parse_protocol_parameters(body_rows[0])
        print(rtsp_method, url, version)
        if not rtsp_method:
            return None

        headers = self._parse_headers(body_rows)

        return RTSPPacket(method=rtsp_method, url=url, version=version, headers=headers, status_code=None)

    def _parse_headers(self, body_rows: List[str]) -> Dict[str, str]:
        headers = []

        for body_row in body_rows[1:]:
            headers.append(body_row.split(":", 1))

        headers = dict(headers)

        for k, v in headers.items():
            headers[k] = v.strip()

        return headers

    def _parse_protocol_parameters(self, protocol_row) -> ResultParseMethod:
        method_str, url, version = None, None, None
        method = None

        if len(protocol_row.split(" ")) == 3:
            method_str, url, version = protocol_row.split(" ")

        if method_str == 'PLAY':
            method = PlayMethod()
        if method_str == 'DESCRIBE':
            method = DescribeMethod()
        if method_str == 'GET_PARAMETER':
            method = GetParameterMethod()
        if method_str == 'OPTIONS':
            method = OptionsMethod()
        if method_str == 'SETUP':
            method = SetupMethod()
        if method_str == 'TEARDOWN':
            method = TearDownMethod()

        return method, url, version


connect_manager = ConnectManager(config=Config())


class TCPHandler(socketserver.ThreadingMixIn, socketserver.BaseRequestHandler):
    """
    The request handler class for our server.

    It is instantiated once per connection to the server, and must
    override the handle() method to implement communication to the
    client.
    """

    def handle(self):
        ip, port = self.request.getpeername()
        context = ClientContext(ip=ip, port=port)
        connect_manager.add_client(ip, port, ClientContext(ip=ip, port=port))
        print(self.request)
        while True:
            body = self.request.recv(TCP_BUFF_SIZE)
            global remote_addr
            remote_addr = self.request.getpeername()[0]

            try:
                request_body = bytes.decode(body, 'utf-8')
                rtsp_packet = RTSPPacketParser().get_packet(request_body)

                if not rtsp_packet:
                    continue

                handle_request(rtsp_packet.method, rtsp_packet, context, self.request)

            except Exception as e:
                # context.status = RTSPPlayStatus.DONE
                raise Exception from e

    # return


class RTPHandler(socketserver.BaseRequestHandler):
    def handle(self):
        # for k, v in connect_manager.clients.items():
        #     if v.client_udp_ports
        context = self.server.context
        with av.open(sys.argv[1]) as container:
            time_int = 12345
            stream = container.streams.video[0]

            for packet in container.demux(stream):
                time_int = time_int + 4000
                context.timestamp = time_int
                packet.time_base = fractions.Fraction(numerator=1, denominator=90000)
                packet.pts = time_int
                packet.dts = time_int

                packet = make_rtp_packet(context, packet.to_bytes())
                self.request[1].sendto(
                    packet,
                    self.client_address)
                time.sleep(0.04)


class RTPCPHandler(socketserver.BaseRequestHandler):

    def setup(self):
        # the socket is called request in the request handler
        self.request[1].settimeout(1.0)

    def handle(self):
        body = self.request[1].recv(TCP_BUFF_SIZE)
        print("RTPCPHandler!!!!!!!!!!!!!!!!!!!!!!!", body)

        report = make_rtcp_sender_report()
        print("send report", report)
        print(self.request[1])
        self.request[1].sendto(
            report,
            self.client_address)
        while True:
            try:
                data = self.request[1].recv(TCP_BUFF_SIZE)
                print("receive report", data)

                if not data:
                    break  # connection is closed
                else:
                    pass  # do your thing
            except socket.timeout:
                pass  # handle timeout


def size_byte_struct(iter: List[Tuple[int, int]]) -> int:
    return sum([size for value, size in iter])


def integers_to_bytes(iter: List[Tuple[int, int]]) -> bytes:
    """Convert integers array to bytes."""
    result = 0
    for value, size in iter:
        result = value ^ (result << size)

    return result.to_bytes(size_byte_struct(iter) // 8, byteorder='big', signed=False)


def byte_struct(cls):
    def wrap(cls):
        _set_new_attribute(cls,
                           '__bytes__',
                           lambda self: integers_to_bytes(self.repr_bytes())
                           )

        _set_new_attribute(cls,
                           '__len__',
                           lambda self: size_byte_struct(self.repr_bytes())
                           )
        return cls

    if cls is None:
        # We're called with parens.
        return wrap

    return wrap(cls)


class RTPControlProtocolPacketType(Enum):
    SEND_REPORT = 200
    RECEIVE_REPORT = 200
    SOURCE_DESCRIPTION = 202
    BYE = 203
    APP = 204


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


def make_rtcp_sender_report():
    current_time = datetime.datetime.now()
    msw, lsw = utc_time_to_ntp(current_time)
    rtp_timestamp = 0
    senders_packet_count = 0
    senders_octet_count = 0
    header = RTPControlProtocolPacketHeader(version=2, padding=0, reception_report_count=0, packet_type=0, length=6, SSRC=1)
    body = RTPControlProtocolSendReport(
        msw=msw,
        lsw=lsw,
        rtp_timestamp=rtp_timestamp,
        senders_packet_count=senders_packet_count,
        senders_octet_count=senders_octet_count
    )
    return make_rtcp_packet(header, body)


def make_rtp_packet(context: ClientContext, body: bytes) -> bytes:
    context.sequence_number += 1
    header = RTPPacketHeader(version=2,
                             padding=0,
                             extension=0,
                             CRCC=0,
                             marker=0,
                             payload_type=96,
                             sequence_number=context.sequence_number,
                             timestamp=context.timestamp,
                             SSRC=1)

    return bytes(header) + body


def make_rtcp_packet(header, body):
    return bytes(header) + bytes(body)


def utc_time_to_ntp(time_: datetime.datetime) -> Tuple[int, int]:
    """
    Convert utc time to ntp time
    Args:
        time_: datetime.datetime

    Returns: msw and lsw

    """
    lsw = time_.microsecond / 1000000 * 0xffffffff
    msw = time_.timestamp()
    ntp_begin = datetime.datetime(1900, 1, 1)
    utc_begin = datetime.datetime(1970, 1, 1)
    diff = (utc_begin - ntp_begin).total_seconds()
    return int(msw + diff), int(lsw)


assert utc_time_to_ntp(datetime.datetime(2023, 7, 23, 7, 12, 17, 145999, tzinfo=datetime.timezone.utc)) == (3899085137, 627060930)
#
context = ClientContext()
header = RTPPacketHeader(version=2,
                         padding=0,
                         extension=0,
                         CRCC=0,
                         marker=0,
                         payload_type=96,
                         sequence_number=context.sequence_number,
                         timestamp=context.timestamp,
                         SSRC=1)


async def RTSPClientCheker():
    while True:
        await asyncio.sleep(10)
        delete_keys = set()

        for key, client_context in connect_manager.clients.items():
            print(client_context, (datetime.datetime.now() - client_context.latest_activity).total_seconds())
            if (datetime.datetime.now() - client_context.latest_activity).total_seconds() > Config.client_timeout:
                delete_keys.add(key)

            if client_context.status == RTSPPlayStatus.DONE:
                delete_keys.add(key)
        print(delete_keys)
        for key in delete_keys:
            if key in connect_manager.clients:
                if connect_manager.clients[key].server_rtp:
                    connect_manager.clients[key].server_rtp.shutdown()
                    connect_manager.clients[key].server_rtp.close()
                if connect_manager.clients[key].server_rtcp:
                    connect_manager.clients[key].server_rtcp.shutdown()
                    connect_manager.clients[key].server_rtcp.close()
                del connect_manager.clients[key]


if __name__ == "__main__":
    HOST, PORT = "0.0.0.0", 554

    # Create the server, binding to HOST on port PORT
    with socketserver.TCPServer((HOST, PORT), TCPHandler) as server:
        # Activate the server; this will keep running until you
        # interrupt the program with Ctrl-C
        # with socketserver.UDPServer((HOST, 160), RTPHandler) as server_rtp:
        #     with socketserver.UDPServer((HOST, 161), RTPCPHandler) as server_rtcp:
        #         threading.Thread(target=server_rtp.handle_request).start()
        #         threading.Thread(target=server_rtcp.handle_request).start()
        threading.Thread(target=server.serve_forever).start()
        # server.serve_forever()

        asyncio.run(RTSPClientCheker())
