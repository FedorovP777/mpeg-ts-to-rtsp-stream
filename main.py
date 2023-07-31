import asyncio
import datetime
import socketserver
import sys
import threading

from src.config import Config
from src.connect_manager import ConnectManager, PlayStatus

connect_manager = ConnectManager(config=Config())


async def RTSPClientCheker():
    while True:
        await asyncio.sleep(10)
        delete_keys = set()

        for key, client_context in connect_manager.clients.items():
            print(client_context.play_status)
            if (datetime.datetime.now() - client_context.latest_activity).total_seconds() > Config.client_timeout:
                delete_keys.add(key)

            if client_context.play_status == PlayStatus.DONE.value:
                delete_keys.add(key)
        print(delete_keys)
        for key in delete_keys:
            if key not in connect_manager.clients:
                continue

            if connect_manager.clients[key].server_rtp:
                connect_manager.clients[key].server_rtp.shutdown()
                connect_manager.clients[key].server_rtp.close()
            if connect_manager.clients[key].server_rtcp:
                connect_manager.clients[key].server_rtcp.shutdown()
                connect_manager.clients[key].server_rtcp.close()
            del connect_manager.clients[key]


if __name__ == "__main__":
    HOST, PORT = "0.0.0.0", 554
    from src.socket_handlers import TCPHandler

    with socketserver.TCPServer((HOST, PORT), TCPHandler) as server:
        server.connect_manager = connect_manager
        server.config = Config
        threading.Thread(target=server.serve_forever).start()
        asyncio.run(RTSPClientCheker())
