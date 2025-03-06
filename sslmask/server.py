import struct
import asyncio

from .log import logger
from .io_async import TLS, TLSServer
from .funcs import gen_self_signed_certificate
from typing import Dict, Union, Optional, List
from cryptography.hazmat.backends.openssl import backend
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509 import load_pem_x509_certificates, Certificate
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from .constants import (
    SOCKS4,
    SOCKS5,
    SOCKS5_AUTH,
    SOCKS5_NOAUTH,
    SOCKS5_AUTH_SUCCESS,
    SOCKS5_AUTH_FAILED,
    REP_SUCCESS,
    REP_FIALED,
    HANDSHAKE_CLIENT_HELLO,
)


class Server:
    def __init__(
        self,
        host: str = "0.0.0.0",
        port: int = 1080,
        users: Dict[str, str] = {},
        bufsize: int = 4096,
        enable_auth: bool = False,
        key: Optional[str] = None,
        key_pass: Optional[str] = None,
        cert: Optional[str] = None,
    ):
        self.host = host
        self.port = port
        self.users = users
        self.bufsize = bufsize
        self.enable_auth = enable_auth
        self.certs = None
        if isinstance(key, str):
            with open(key, "rb") as f:
                self.key = load_pem_private_key(f.read(), key_pass, backend=backend)
        else:
            self.key: ec.EllipticCurvePrivateKey = ec.generate_private_key(
                ec.SECP256R1(), backend=backend
            )
            self.certs: List[Certificate] = [gen_self_signed_certificate(self.key)]
        if self.certs is None or len(self.certs) == 0:
            if isinstance(cert, str):
                with open(cert, "rb") as f:
                    self.certs = load_pem_x509_certificates(f.read())
            else:
                self.certs: List[Certificate] = [gen_self_signed_certificate(self.key)]

    async def process_socks5(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ):
        nmethods = struct.unpack("!B", await reader.read(1))[0]
        methods = struct.unpack("!" + "B" * nmethods, await reader.read(nmethods))
        logger.info("methods %s", methods)
        if SOCKS5_AUTH in methods:
            writer.write(struct.pack("!BB", SOCKS5, SOCKS5_AUTH))
            await writer.drain()
            sub_ver, ulen = struct.unpack("!BB", await reader.read(2))
            logger.info("sub_ver %s, ulen %s", sub_ver, ulen)
            username = await reader.read(ulen)
            logger.info("username %s", username)
            plen = struct.unpack("!B", await reader.read(1))[0]
            logger.info("sub_ver %s, plen %s", sub_ver, plen)
            password = await reader.read(plen)
            logger.info("password %s", password)
            if self.users.get(username.decode()) == password.decode():
                writer.write(struct.pack("!BB", sub_ver, SOCKS5_AUTH_SUCCESS))
            else:
                writer.write(struct.pack("!BB", sub_ver, SOCKS5_AUTH_FAILED))
                await writer.drain()
                return
            await writer.drain()
        else:
            writer.write(struct.pack("!BB", SOCKS5, SOCKS5_NOAUTH))
            await writer.drain()
        _, cmd, rsv, atyp = struct.unpack("!BBBB", await reader.read(4))
        logger.info("cmd %s, rsv, %s, atyp, %s", cmd, rsv, atyp)
        if atyp == 0x1:
            addr = ".".join(
                [str(x) for x in struct.unpack("!BBBB", await reader.read(4))]
            )
        elif atyp == 0x3:
            addr_len = struct.unpack("!B", await reader.read(1))[0]
            addr = await reader.read(addr_len)
        elif atyp == 0x4:
            # todo
            addr = await reader.read(16)
        port = struct.unpack("!H", await reader.read(2))[0]
        logger.info("addr %s, port %s", addr, port)
        local_ip = b"\x7f\x00\x00\x01"
        local_port = 23451
        try:
            writer.write(struct.pack("!BBBB", SOCKS5, REP_SUCCESS, 0, 1))
            writer.write(local_ip)
            writer.write(struct.pack("!H", local_port))
            await writer.drain()
            tls_header = b""
            try:
                tls_header = await asyncio.wait_for(reader.read(6), timeout=1)
            except asyncio.TimeoutError:
                pass
            else:
                logger.info("tls_header %s", tls_header.hex())
                if (
                    tls_header.startswith(b"\x16\x03")
                    and tls_header[2] > 0
                    and tls_header[2] < 5
                    and tls_header[5] == HANDSHAKE_CLIENT_HELLO
                ):
                    async with TLSServer(
                        reader, writer, tls_header, self.key, self.certs
                    ) as tls_server:
                        logger.info("server %s", tls_server)
                        logger.info("client %s:%s", addr, port)
                        async with TLS(addr, port) as tls_client:
                            logger.info("client %s", tls_client)
                            asyncio.create_task(
                                self.process_tls_pipe(tls_server, tls_client)
                            )
                            await self.process_tls_pipe(tls_client, tls_server)
                    return
            t_reader, t_writer = await asyncio.open_connection(addr, port)
            local_ip, local_port = t_writer.get_extra_info("sockname")
            logger.info("local_ip %s, local_port %s", local_ip, local_port)
            if isinstance(local_ip, str):
                local_ip = local_ip.encode()
            else:
                logger.warning("local_ip %s", local_ip)
            if tls_header != b"":
                t_writer.write(tls_header)
                await t_writer.drain()
            asyncio.create_task(self.process_tcp_pipe(reader, t_writer))
            await self.process_tcp_pipe(t_reader, writer)
        finally:
            try:
                writer.write(
                    struct.pack("!BBBBB", SOCKS5, REP_FIALED, 0, 1, len(local_ip))
                )
                writer.write(local_ip.encode())
                writer.write(struct.pack("!H", local_port))
                await writer.drain()
            except:
                pass
            try:
                writer.close()
                t_writer.close()
                await writer.wait_closed()
                await t_writer.wait_closed()
            except:
                pass

    async def process_tls_pipe(
        self, src: Union[TLSServer, TLS], tgt: Union[TLSServer, TLS]
    ):
        while src.is_connected():
            await tgt.send(await src.read())

    async def process_tcp_pipe(
        self,
        reader: asyncio.StreamReader,
        t_writer: asyncio.StreamWriter,
    ):
        while not reader.at_eof():
            t_writer.write(await reader.read(self.bufsize))
            await t_writer.drain()

    async def process_socks4(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ):
        pass

    async def handle_connection(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ):
        ver = struct.unpack("!B", await reader.read(1))[0]
        logger.info("ver %s", ver)
        if ver == SOCKS5:
            await self.process_socks5(reader, writer)
        elif ver == SOCKS4:
            await self.process_socks4(reader, writer)

    async def start_server(self):
        async with await asyncio.start_server(
            self.handle_connection, self.host, self.port
        ) as server:
            logger.info("Listening on %s:%s", self.host, self.port)
            await server.serve_forever()
