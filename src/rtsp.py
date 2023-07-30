import asyncio
import datetime
import socket
import socketserver
import sys
import threading

from functools import singledispatch
from typing import Tuple, Dict

import av

from src.config import Config
from src.connect_manager import ConnectManager
from src.models import PlayMethod, DescribeMethod, OptionsMethod, SetupMethod, RTSPPacket, RTSPPlayStatus, \
    ClientContext, TearDownMethod
from src.sdp import sdp_create

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
def _(method: PlayMethod, rtsp_message: RTSPPacket, context: ClientContext, socket: socket.socket, connect_manager: ConnectManager):
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
def _(method: DescribeMethod, rtsp_message: RTSPPacket, context: ClientContext, socket: socket.socket, connect_manager: ConnectManager):
    CSeq = rtsp_message.headers.get('CSeq', None)
    packet_maker = RTSPResponseCreator()
    packet = RTSPPacket()
    sdp = sdp_create(context.sdp, av.open(sys.argv[1]).streams)
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
    context.status = RTSPPlayStatus.DONE
    socket.sendall(str.encode(packet_maker.compile_packet(packet)))
