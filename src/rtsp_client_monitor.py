import asyncio
import datetime

from src.config import Config
from src.connect_manager import ConnectManager, PlayStatus


# noinspection PyPep8Naming
async def RTSPClientMonitor(connect_manager: ConnectManager) -> None:
    while True:
        await asyncio.sleep(Config.interval_client_state_seconds)
        delete_keys = set()

        for key, client_context in connect_manager.clients.items():
            if (datetime.datetime.now() - client_context.latest_activity).total_seconds() >= Config.client_timeout:
                client_context.play_status = PlayStatus.DONE

            if client_context.play_status == PlayStatus.DONE:
                delete_keys.add(key)

        for key in delete_keys:
            if key not in connect_manager.clients:
                continue

            if connect_manager.clients[key].server_rtp:
                connect_manager.rtp_disconnect(key)

            if connect_manager.clients[key].server_rtcp:
                connect_manager.rtpcp_disconnect(key)

            connect_manager.remove_client(key)
