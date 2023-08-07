import asyncio
import datetime

from src.config import Config
from src.connect_manager import ConnectManager, PlayStatus


# noinspection PyPep8Naming
async def RTSPClientMonitor(connect_manager: ConnectManager):
    while True:
        await asyncio.sleep(10)
        delete_keys = set()

        for key, client_context in connect_manager.clients.items():
            if (datetime.datetime.now() - client_context.latest_activity).total_seconds() > Config.client_timeout:
                delete_keys.add(key)

            if client_context.play_status == PlayStatus.DONE.value:
                delete_keys.add(key)
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