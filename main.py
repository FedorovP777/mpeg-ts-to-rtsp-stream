import asyncio
import datetime
import socketserver
import sys
import threading

from typing import Tuple, Dict

import av
from av.logging import Capture

from src.config import Config
from src.connect_manager import ConnectManager
from src.models import RTSPPlayStatus, \
    ClientContext
from src.sdp import SDPSession, sdp_version, ident, session_name, connection_info, time_activity, attribute_tool, stream_type, \
    attribute_stream_id, bitrate, attribute_rtpmap_h264, attribute_fmtp_h264

connect_manager = ConnectManager(config=Config())



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
    from src.socket_handlers import TCPHandler, RTPCPHandler, RTPHandler

    with socketserver.TCPServer((HOST, PORT), TCPHandler) as server:
        server.connect_manager = connect_manager
        server.config = Config
        threading.Thread(target=server.serve_forever).start()
        asyncio.run(RTSPClientCheker())
