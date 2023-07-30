import datetime
import fractions
import socket
import socketserver
import sys
import time
from typing import Optional, List, Dict

import av

from src.config import Config
from src.models import ClientContext, RTPControlProtocolPacketHeader, RTPControlProtocolSendReport, RTPPacketHeader, ResultParseMethod, \
    PlayMethod, DescribeMethod, GetParameterMethod, OptionsMethod, SetupMethod, TearDownMethod, RTSPPacket
from src.rtsp import handle_request
from src.sdp import SDPSession
from src.utils import utc_time_to_ntp


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
        sdp_session = SDPSession(sdp_version=0,
                                 id='0',
                                 version='0',
                                 start_time=0,
                                 end_time=0,
                                 ttl=0,
                                 user='',
                                 src_addr='192.168.0.102',
                                 src_type='IP4',
                                 dst_addr='0.0.0.0',
                                 dst_type='IP4',
                                 name='No Name')
        context.sdp = sdp_session
        self.server.connect_manager.add_client(ip, port, ClientContext(ip=ip, port=port))
        config: Config = self.server.config
        print(self.request)
        while True:
            body = self.request.recv(config.tcp_buff_size)
            global remote_addr
            remote_addr = self.request.getpeername()[0]

            try:
                request_body = bytes.decode(body, 'utf-8')
                rtsp_packet = RTSPPacketParser().get_packet(request_body)

                if not rtsp_packet:
                    continue

                handle_request(rtsp_packet.method, rtsp_packet, context, self.request, self.server.connect_manager)

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
        config: Config = self.server.config
        body = self.request[1].recv(config.tcp_buff_size)
        print("RTPCPHandler!!!!!!!!!!!!!!!!!!!!!!!", body)

        report = make_rtcp_sender_report()
        print("send report", report)
        print(self.request[1])
        self.request[1].sendto(
            report,
            self.client_address)
        while True:
            try:
                data = self.request[1].recv(config.tcp_buff_size)
                print("receive report", data)

                if not data:
                    break  # connection is closed
                else:
                    pass  # do your thing
            except socket.timeout:
                pass  # handle timeout
