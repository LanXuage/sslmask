import asyncio
import aiohttp


async def amain():
    async with aiohttp.ClientSession() as sess:
        async with sess.get("https://192.168.31.45:61080", ssl=False) as resp:
            print(await resp.content.read())


if __name__ == "__main__":
    asyncio.run(amain())
