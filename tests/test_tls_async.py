import asyncio

from sslmask.io_async import TLS


async def amain():
    tls = TLS(host="autotest.dnslog.fun")
    await tls.connect()
    await tls.close()


if __name__ == "__main__":
    asyncio.run(amain())
