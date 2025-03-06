import sys
import uvloop
import asyncio

from sslmask.server import Server

if __name__ == "__main__":
    server = Server(users={"admin": "password"})
    if sys.version_info >= (3, 11):
        with asyncio.Runner(loop_factory=uvloop.new_event_loop) as runner:
            runner.run(server.start_server())
    else:
        uvloop.install()
        asyncio.run(server.start_server())
    asyncio.run(server.start_server())
