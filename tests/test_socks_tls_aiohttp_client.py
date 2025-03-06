import asyncio
import aiohttp

from aiohttp_socks import ProxyConnector


async def amain():
    async with aiohttp.ClientSession(
        connector=ProxyConnector.from_url("socks5://192.168.31.45:61080")
    ) as sess:
        async with sess.get("https://autotest.dnslog.fun", ssl=False) as resp:
            print(await resp.text())


if __name__ == "__main__":
    asyncio.run(amain())
