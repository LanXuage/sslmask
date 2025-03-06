import asyncio

from sslmask.io_async import TLS


async def amain():
    async with TLS(b"autotest.dnslog.fun", 443) as tls:
        print("test async with %s", tls)


if __name__ == "__main__":
    asyncio.run(amain())
