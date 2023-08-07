import asyncio
import socketserver
import threading

from src.config import Config
from src.connect_manager import ConnectManager
from src.rtsp_client_monitor import RTSPClientMonitor
from src.socket_handlers import TCPHandler

if __name__ == "__main__":
    config = Config()
    connect_manager = ConnectManager(config=config)

    with socketserver.TCPServer((config.host, config.rtsp_port), TCPHandler) as server:
        server.connect_manager = connect_manager
        server.config = config
        threading.Thread(target=server.serve_forever).start()
        asyncio.run(RTSPClientMonitor(connect_manager))
