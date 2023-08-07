import asyncio
import datetime
import socketserver
import sys
import threading

from src.rtsp_client_cheker import RTSPClientCheker
from src.config import Config
from src.connect_manager import ConnectManager, PlayStatus

if __name__ == "__main__":
    connect_manager = ConnectManager(config=Config())

    HOST, PORT = "0.0.0.0", 554
    from src.socket_handlers import TCPHandler

    with socketserver.TCPServer((HOST, PORT), TCPHandler) as server:
        server.connect_manager = connect_manager
        server.config = Config
        threading.Thread(target=server.serve_forever).start()
        asyncio.run(RTSPClientCheker(connect_manager))
