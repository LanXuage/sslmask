import os
import io
import struct
import asyncio

from .log import logger
from .tls import TLSBase, TLS_STATE
from hashlib import sha256, sha384
from typing import Optional, List, Union
from .schema import (
    ClientHello,
    ServerHello,
    Extension,
    KeyShareEntry,
    UnknowExtension,
    TLSHandshake,
    SupportedVersion,
    TLSRecordLayer,
    MultiExtension,
)
from .constants import (
    VERSION_TLS_1,
    HANDSHAKE_NEW_SESSION_TICKET,
    VERSION_TLS_1_2,
    VERSION_TLS_1_3,
    HANDSHAKE_CERTIFICATE_VERIFY,
    RECORD_TYPE_APPLICATION_DATA,
    RECORD_TYPE_CHANGE_CIPHER_SPEC,
    RECORD_TYPE_HANDSHAKE,
    HANDSHAKE_CLIENT_HELLO,
    HANDSHAKE_SERVER_HELLO,
    HANDSHAKE_ENCRYPTED_EXTENSIONS,
    HANDSHAKE_CERTIFICATE,
    HANDSHAKE_FINISHED,
    SUPPORTED_VERSIONS,
    KEY_SHARE,
    KEY_SHARE_GROUP_X25519,
    KEY_SHARE_GROUP_X25519MLKEM768,
    TLS_AES_128_GCM_SHA256,
    TLS_AES_256_GCM_SHA384,
    TLS_CHACHA20_POLY1305_SHA256,
    TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
    HANDSHAKE_CERTIFICATE,
)
from cryptography.x509 import Certificate
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends.openssl import backend
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from .funcs import hkdf_expand, hkdf_extract, get_hkdflabel, gen_self_signed_certificate


class TLSServer:
    def __init__(
        self,
        reader: Optional[asyncio.StreamReader] = None,
        writer: Optional[asyncio.StreamWriter] = None,
        preloaded_data: bytes = b"",
        prikey: Union[ec.EllipticCurvePrivateKey, rsa.RSAPrivateKey, None] = None,
        certs: List[Certificate] = None,
    ):
        self.reader = reader
        self.writer = writer
        self.preloaded_data = preloaded_data
        self.state = TLS_STATE.INITIAL
        self.tls_version = VERSION_TLS_1
        self.buffer = io.BytesIO()
        self.private_key = x25519.X25519PrivateKey.generate()
        self.public_key = self.private_key.public_key()
        self.c_public_key = None
        self.cipher_suite = None
        self.zero_bytes = b"\x00" * 64
        self.seq = 0
        self.s_seq = 0
        self.certs = certs
        if prikey is None:
            self.prikey = ec.generate_private_key(ec.SECP256R1(), backend)
        else:
            self.prikey = prikey
            self.certs = [gen_self_signed_certificate(self.prikey)]
        if self.certs is None or len(self.certs) == 0:
            self.certs = [gen_self_signed_certificate(self.prikey)]

    async def __aenter__(self):
        await self.connect()
        return self

    async def __aexit__(self, *args):
        await self.close()

    async def close(self):
        if self.writer is not None:
            self.writer.close()
            await self.writer.wait_closed()

    def is_connected(self) -> bool:
        return self.state == TLS_STATE.CONNECTED

    async def _read(self, n: int) -> bytes:
        ret = b""
        preloaded_data_len = len(self.preloaded_data)
        if preloaded_data_len > 0:
            if preloaded_data_len >= n:
                ret = self.preloaded_data[:n]
                self.preloaded_data = self.preloaded_data[n:]
            else:
                ret = self.preloaded_data
                self.preloaded_data = b""
        for _ in range(1000):
            if len(ret) >= n:
                break
            await asyncio.sleep(0.01)
            ret += await self.reader.read(n - len(ret))
        return ret

    async def _read_tls_header(self) -> bytes:
        return await self._read(5)

    def _process_application_data(
        self, en_content: bytes, tls_header: bytes
    ) -> List[bytes]:
        content = self._decrypt_application_data(en_content, tls_header)
        if self.state == TLS_STATE.HANDSHAKE:
            return self._process_handshake(content)
        return []

    def _process_client_hello(self, content: bytes) -> List[bytes]:
        logger.info("process_client_hello %s", content.hex())
        ret = []
        client_hello = ClientHello.unpack(content)
        for ext in client_hello.extensions:
            logger.info("ext %s", ext.extension_type)
            if ext.extension_type == KEY_SHARE:
                for entry in ext.data.items:
                    if isinstance(entry, KeyShareEntry):
                        if entry.group == KEY_SHARE_GROUP_X25519:
                            self.c_public_key = (
                                x25519.X25519PublicKey.from_public_bytes(
                                    entry.key_exchange
                                )
                            )
                            break
                        elif entry.group == KEY_SHARE_GROUP_X25519MLKEM768:
                            logger.info(
                                "unsupported %s", KEY_SHARE_GROUP_X25519MLKEM768
                            )
            elif ext.extension_type == SUPPORTED_VERSIONS:
                logger.info("sversion %s", ext.data)
                for ver in ext.data.items:
                    if isinstance(ver, SupportedVersion):
                        if VERSION_TLS_1_3 == ver.version:
                            self.tls_version = VERSION_TLS_1_3
        if self.tls_version != VERSION_TLS_1_3:
            logger.warning("data %s", content.hex())
            raise ValueError("unsupport tls version")
        if self.c_public_key is None:
            logger.warning("data %s", content.hex())
            raise ValueError("error ext key share not x25519 group")
        supported_cipher_suites = [TLS_AES_128_GCM_SHA256, TLS_AES_256_GCM_SHA384]
        for cipher_suite in client_hello.cipher_suites:
            if cipher_suite in supported_cipher_suites:
                self.cipher_suite = cipher_suite
                break
        handshake = TLSHandshake(
            HANDSHAKE_SERVER_HELLO,
            ServerHello(
                VERSION_TLS_1_2,
                os.urandom(32),
                client_hello.session_id,
                self.cipher_suite,
                0,
                [
                    Extension(
                        SUPPORTED_VERSIONS,
                        UnknowExtension(struct.pack("!H", VERSION_TLS_1_3)),
                    ),
                    Extension(
                        KEY_SHARE,
                        UnknowExtension(
                            struct.pack("!HH", KEY_SHARE_GROUP_X25519, 32)
                            + self.public_key.public_bytes_raw()
                        ),
                    ),
                ],
            ),
        )
        self.server_hello_bytes = handshake.pack()
        tls_record = TLSRecordLayer(
            RECORD_TYPE_HANDSHAKE, VERSION_TLS_1, self.server_hello_bytes
        )
        self.state = TLS_STATE.HANDSHAKE
        change_cipher_spec_data = b"\x01"

        pms = self.private_key.exchange(self.c_public_key)
        logger.info("priKey: %s", self.private_key.private_bytes_raw().hex())
        logger.info("pubKey: %s", self.public_key.public_bytes_raw().hex())
        logger.info("pubKey: %s", self.c_public_key.public_bytes_raw().hex())
        logger.info("cbytes: %s", self.client_hello_bytes.hex())
        logger.info("sbytes: %s", self.server_hello_bytes.hex())
        logger.info("pms: %s", pms.hex())
        self.ivlen = 12
        if self.cipher_suite == TLS_AES_128_GCM_SHA256:
            # self.algorithm = aead.AESGCM
            self.algorithm = algorithms.AES128
            self.cipher_mode_mod = modes.GCM
            self.cert_hash_algo = 4
            self.digestmod = sha256
            self.digestlen = 32
            self.keylen = 16
        elif self.cipher_suite == TLS_CHACHA20_POLY1305_SHA256:
            self.algorithm = algorithms.ChaCha20
            # self.algorithm = aead.ChaCha20Poly1305
            self.cipher_mode_mod = modes.GCM
            self.cert_hash_algo = 4
            self.digestmod = sha256
            self.digestlen = 32
            self.keylen = 32
        elif self.cipher_suite == TLS_AES_256_GCM_SHA384:
            # self.algorithm = aead.AESGCM
            self.algorithm = algorithms.AES256
            self.cipher_mode_mod = modes.GCM
            self.cert_hash_algo = 4
            self.digestmod = sha384
            self.digestlen = 48
            self.keylen = 32
        elif self.cipher_suite == TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256:
            self.algorithm = algorithms.AES128
            self.cipher_mode_mod = modes.GCM
            self.cert_hash_algo = 4
            self.digestmod = sha256
            self.digestlen = 32
            self.keylen = 16
        else:
            logger.error("Unsupport cipher suite: %s", self.cipher_suite)
            raise ValueError("Unsupport cipher suite")
        prk = hkdf_extract(
            self.zero_bytes[: self.digestlen],
            self.zero_bytes[: self.digestlen],
            self.digestmod,
        )
        logger.info("early_secret: %s", prk.hex())
        empty_hash = self.digestmod(b"").digest()
        logger.info("empty_hash: %s", empty_hash.hex())
        info = get_hkdflabel(b"derived", empty_hash, self.digestlen)
        logger.info("derived: %s", info.hex())
        okm = hkdf_expand(prk, info, self.digestmod, self.digestlen, self.digestlen)
        logger.info("okm: %s", okm.hex())
        handshake_secret = hkdf_extract(okm, pms, self.digestmod)
        logger.info("handshake secret: %s", handshake_secret.hex())
        okm = hkdf_expand(
            handshake_secret, info, self.digestmod, self.digestlen, self.digestlen
        )
        self.master_secret = hkdf_extract(
            okm, self.zero_bytes[: self.digestlen], self.digestmod
        )
        logger.info("master_secret: %s", self.master_secret.hex())
        handshake_hash = self.digestmod(
            self.client_hello_bytes + self.server_hello_bytes
        ).digest()
        logger.info("hash: %s", handshake_hash.hex())
        info = get_hkdflabel(b"s hs traffic", handshake_hash, self.digestlen)
        s_hs_traffic_secret = hkdf_expand(
            handshake_secret, info, self.digestmod, self.digestlen, self.digestlen
        )
        logger.info("s hs traffic: %s", s_hs_traffic_secret.hex())
        info = get_hkdflabel(b"key", b"", self.keylen)
        self.key = hkdf_expand(
            s_hs_traffic_secret, info, self.digestmod, self.digestlen, self.keylen
        )
        logger.info("key: %s", self.key.hex())

        info = get_hkdflabel(b"iv", b"", self.ivlen)
        self.iv = hkdf_expand(
            s_hs_traffic_secret, info, self.digestmod, self.digestlen, self.ivlen
        )
        logger.info("iv: %s", self.iv.hex())

        info = get_hkdflabel(b"finished", b"", self.digestlen)
        self.finished = hkdf_expand(
            s_hs_traffic_secret, info, self.digestmod, self.digestlen, self.digestlen
        )
        logger.info("finished: %s", self.finished.hex())

        info = get_hkdflabel(b"c hs traffic", handshake_hash, self.digestlen)
        c_hs_traffic_secret = hkdf_expand(
            handshake_secret, info, self.digestmod, self.digestlen, self.digestlen
        )
        logger.info("c hs traffic: %s", c_hs_traffic_secret.hex())

        info = get_hkdflabel(b"key", b"", self.keylen)
        self.s_key = hkdf_expand(
            c_hs_traffic_secret, info, self.digestmod, self.digestlen, self.keylen
        )
        logger.info("s key: %s", self.s_key.hex())

        info = get_hkdflabel(b"iv", b"", self.ivlen)
        self.s_iv = hkdf_expand(
            c_hs_traffic_secret, info, self.digestmod, self.digestlen, self.ivlen
        )
        logger.info("s iv: %s", self.s_iv.hex())

        info = get_hkdflabel(b"finished", b"", self.digestlen)
        self.s_finished = hkdf_expand(
            c_hs_traffic_secret, info, self.digestmod, self.digestlen, self.digestlen
        )
        logger.info("s finished: %s", self.s_finished.hex())
        self.taglen = 16
        handshake = TLSHandshake(
            HANDSHAKE_ENCRYPTED_EXTENSIONS, MultiExtension().pack()
        )
        self.encrypted_extensions_bytes = handshake.pack()
        logger.info("self.encrypted %s", self.encrypted_extensions_bytes.hex())

        data = b""

        for cert in self.certs:
            cert_bytes = cert.public_bytes(Encoding.DER)
            data += struct.pack("!I", len(cert_bytes))[1:] + cert_bytes + b"\x00\x00"
        handshake = TLSHandshake(
            HANDSHAKE_CERTIFICATE, b"\x00" + struct.pack("!I", len(data))[1:] + data
        )
        self.certificate_bytes = handshake.pack()

        transcript_hash = self.digestmod(
            self.client_hello_bytes
            + self.server_hello_bytes
            + self.encrypted_extensions_bytes
            + self.certificate_bytes
        ).digest()
        signed_data = self.prikey.sign(
            b" " * 64 + b"TLS 1.3, server CertificateVerify\x00" + transcript_hash,
            ec.ECDSA(hashes.SHA256() if self.cert_hash_algo == 4 else hashes.SHA384()),
        )
        logger.info("signed_data len %s", len(signed_data))
        handshake = TLSHandshake(
            HANDSHAKE_CERTIFICATE_VERIFY,
            struct.pack("!BBH", self.cert_hash_algo, 3, len(signed_data)) + signed_data,
        )
        self.certificate_verify_bytes = handshake.pack()
        logger.info("cert verify %s", self.certificate_verify_bytes.hex())
        transcript_hash = self.digestmod(
            self.client_hello_bytes
            + self.server_hello_bytes
            + self.encrypted_extensions_bytes
            + self.certificate_bytes
            + self.certificate_verify_bytes
        ).digest()
        s_verify_data = hkdf_extract(self.finished, transcript_hash, self.digestmod)
        handshake = TLSHandshake(HANDSHAKE_FINISHED, s_verify_data)
        self.finished_bytes = handshake.pack()
        ret.append(
            tls_record.pack()
            + struct.pack(
                "!BHH",
                RECORD_TYPE_CHANGE_CIPHER_SPEC,
                VERSION_TLS_1_2,
                len(change_cipher_spec_data),
            )
            + change_cipher_spec_data
            + self._gen_application_data(self.encrypted_extensions_bytes)
            + self._gen_application_data(self.certificate_bytes)
            + self._gen_application_data(self.certificate_verify_bytes)
            + self._gen_application_data(self.finished_bytes)
        )
        return ret

    def _gen_application_data(self, content: bytes, suffix: bytes = b"\x16") -> bytes:
        disposable_iv = (int.from_bytes(self.iv) ^ self.seq).to_bytes(self.ivlen)
        logger.info("iv: %s", disposable_iv.hex())
        self.seq += 1
        cipher = Cipher(
            self.algorithm(self.key),  # Unsupported ChaCha20
            (self.cipher_mode_mod(disposable_iv)),
            backend,
        )
        er = cipher.encryptor()
        tls_header = struct.pack(
            "!BHH",
            RECORD_TYPE_APPLICATION_DATA,
            VERSION_TLS_1_2,
            len(content) + self.taglen + len(suffix),
        )
        logger.info("tls_header: %s", tls_header.hex())
        er.authenticate_additional_data(tls_header)
        en_content = er.update(content + suffix) + er.finalize()
        logger.info("en_content: %s", en_content.hex())
        logger.info("tag: %s", er.tag.hex())
        return tls_header + en_content + er.tag

    def _decrypt_application_data(self, en_content: bytes, add: bytes) -> bytes:
        tag = en_content[-self.taglen :]
        logger.info("algorithm: %s", self.algorithm)
        logger.info("add: %s", add.hex())
        disposable_iv = (int.from_bytes(self.s_iv) ^ self.s_seq).to_bytes(self.ivlen)
        logger.info("iv: %s", disposable_iv.hex())
        self.s_seq += 1
        cipher = Cipher(
            self.algorithm(self.s_key),  # Unsupported ChaCha20
            (self.cipher_mode_mod(disposable_iv, tag)),
            backend,
        )
        der = cipher.decryptor()
        der.authenticate_additional_data(add)
        content = der.update(en_content[: -self.taglen]) + der.finalize()
        logger.warning("data: %s", content.hex())
        return content

    def _process_handshake(self, content: bytes) -> List[bytes]:
        handshake_type = struct.unpack("!B", content[0:1])[0]
        handshake_len = struct.unpack("!I", b"\x00" + content[1:4])[0]
        logger.info("handshake bytes: %s", content[: 4 + handshake_len].hex())
        logger.info("handshake type: %s", handshake_type)
        if handshake_type == HANDSHAKE_CLIENT_HELLO:
            self.client_hello_bytes = content[: 4 + handshake_len]
            return self._process_client_hello(content[4 : 4 + handshake_len])
        elif handshake_type == HANDSHAKE_FINISHED:
            # self.finished_bytes = content[: 4 + handshake_len]
            return self._process_finished(content[4 : 4 + handshake_len])
        else:
            logger.warning("Unsupport handshake type: %s", handshake_type)
        return []

    def _process_change_cipher_spec(self, content: bytes) -> List[bytes]:
        logger.warning("not implemented %s", content.hex())
        return []

    def _process_finished(self, content: bytes) -> List[bytes]:
        logger.info("finished: %s", content.hex())
        ret = []
        s_transcript_hash = self.digestmod(
            self.client_hello_bytes
            + self.server_hello_bytes
            + self.encrypted_extensions_bytes
            + self.certificate_bytes
            + self.certificate_verify_bytes
            + self.finished_bytes
        ).digest()
        logger.info("s_transcript_hash: %s", s_transcript_hash.hex())
        c_verify_data = hkdf_extract(self.s_finished, s_transcript_hash, self.digestmod)
        logger.info("c_verify_data: %s", c_verify_data.hex())
        self.seq = 0
        self.s_seq = 0
        info = get_hkdflabel(b"s ap traffic", s_transcript_hash, self.digestlen)
        s_ap_traffic_secret = hkdf_expand(
            self.master_secret, info, self.digestmod, self.digestlen, self.digestlen
        )
        logger.info("s ap traffic: %s", s_ap_traffic_secret.hex())
        info = get_hkdflabel(b"key", b"", self.keylen)
        self.key = hkdf_expand(
            s_ap_traffic_secret, info, self.digestmod, self.digestlen, self.keylen
        )
        logger.info("key: %s", self.key.hex())

        info = get_hkdflabel(b"iv", b"", self.ivlen)
        self.iv = hkdf_expand(
            s_ap_traffic_secret, info, self.digestmod, self.digestlen, self.ivlen
        )
        logger.info("iv: %s", self.iv.hex())
        info = get_hkdflabel(b"c ap traffic", s_transcript_hash, self.digestlen)
        c_ap_traffic_secret = hkdf_expand(
            self.master_secret, info, self.digestmod, self.digestlen, self.digestlen
        )
        logger.info("c ap traffic: %s", c_ap_traffic_secret.hex())
        info = get_hkdflabel(b"key", b"", self.keylen)
        self.s_key = hkdf_expand(
            c_ap_traffic_secret, info, self.digestmod, self.digestlen, self.keylen
        )
        logger.info("s key: %s", self.s_key.hex())

        info = get_hkdflabel(b"iv", b"", self.ivlen)
        self.s_iv = hkdf_expand(
            c_ap_traffic_secret, info, self.digestmod, self.digestlen, self.ivlen
        )
        logger.info("s iv: %s", self.s_iv.hex())
        self.state = TLS_STATE.CONNECTED
        return ret

    def _process_msg(
        self, tls_header: bytes, content_type: int, content: bytes
    ) -> List[bytes]:
        logger.info(
            "process msg %s, %s, %s", tls_header.hex(), content_type, self.tls_version
        )
        if self.tls_version == VERSION_TLS_1_3 or self.tls_version == VERSION_TLS_1_2:
            if content_type == RECORD_TYPE_CHANGE_CIPHER_SPEC:
                return self._process_change_cipher_spec(content)
            elif content_type == RECORD_TYPE_HANDSHAKE:
                return self._process_handshake(content)
            elif content_type == RECORD_TYPE_APPLICATION_DATA:
                logger.info("edata: %s", content.hex())
                return self._process_application_data(content, tls_header)
            else:
                logger.warning("Unsupport content type: %s", content_type)
        elif content_type == RECORD_TYPE_HANDSHAKE:
            logger.warning("Unsupport tls version: %s", content_type)
            return self._process_handshake(content)
        return []

    async def connect(self):
        while self.state != TLS_STATE.CLOSED and self.state != TLS_STATE.CONNECTED:
            tls_header = await self._read_tls_header()
            logger.info("tls_header: %s", tls_header.hex())
            content_type, tls_version, content_length = struct.unpack(
                "!BHH", tls_header
            )
            logger.info("tls version %s, %s", self.tls_version, tls_version)
            if self.tls_version == VERSION_TLS_1:
                self.tls_version = tls_version
            content = await self._read(content_length)
            logger.info("tls_content: %s", content.hex())
            data = self._process_msg(tls_header, content_type, content)
            for content in data:
                await self._send(content)

    async def _send(self, content: bytes):
        logger.info("send: %s", content.hex())
        if self.writer is not None and self.reader is not None:
            self.writer.write(content)
            await self.writer.drain()
        else:
            logger.warning("not connect")

    async def send(self, content: bytes):
        if isinstance(content, str):
            content = content.encode()
        en_content = self._gen_application_data(content, suffix=b"\x17")
        await self._send(en_content)

    async def readuntil(self, end: bytes) -> bytes:
        if isinstance(end, str):
            end = end.encode()
        content = io.BytesIO()
        end_len = len(end)
        end_index = 0
        while end_index >= end_len:
            b = await self.read(1)
            if end[end_index] == b:
                end_index += 1
            else:
                end_index = 0
            content.write(b)
        content.seek(0)
        return content.getvalue()

    async def read(self, size: int = -1) -> bytes:
        logger.warning(
            "buffer %s, %s", self.buffer.getbuffer().nbytes, self.buffer.tell()
        )
        t = self.buffer.tell()
        while (
            self.buffer.getbuffer().nbytes - t < size
            or self.buffer.getbuffer().nbytes == t
        ):
            tls_header = await self._read_tls_header()
            _, _, content_len = struct.unpack("!BHH", tls_header)
            content = await self._read(content_len)
            content = self._decrypt_application_data(content, tls_header)
            if content[0] == HANDSHAKE_NEW_SESSION_TICKET:
                continue
            if content == b"\x02\x14\x15":
                break
            self.buffer.write(content[:-1])
        self.buffer.seek(t)
        if size == -1:
            size = self.buffer.getbuffer().nbytes
        ret = self.buffer.read(size)
        if (
            self.buffer.getbuffer().nbytes > 4096
            and self.buffer.getbuffer().nbytes == self.buffer.tell()
        ):
            logger.warning("- %s", self.buffer.getbuffer().nbytes)
            self.buffer.truncate(0)
            self.buffer.seek(0)
        return ret


class TLS(TLSBase):
    def __init__(
        self,
        host: Union[str, bytes, None] = None,
        port: int = 443,
        session_id: bytes = os.urandom(32),
        reader: Optional[asyncio.StreamReader] = None,
        writer: Optional[asyncio.StreamWriter] = None,
        preloaded_data: bytes = b"",
    ):
        self.preloaded_data = preloaded_data
        self.reader = reader
        self.writer = writer
        super().__init__(session_id, host, port)

    async def __aenter__(self):
        await self.connect()
        return self

    async def __aexit__(self, *args):
        await self.close()

    async def close(self):
        if self.writer is not None:
            self.writer.close()
            await self.writer.wait_closed()

    async def _read_tls_header(self) -> bytes:
        return await self._read(5)

    async def _read(self, n: int) -> bytes:
        ret = b""
        preloaded_data_len = len(self.preloaded_data)
        if preloaded_data_len > 0:
            if preloaded_data_len >= n:
                ret = self.preloaded_data[:n]
                self.preloaded_data = self.preloaded_data[n:]
            else:
                ret = self.preloaded_data
                self.preloaded_data = b""
        for _ in range(1000):
            if len(ret) >= n:
                break
            await asyncio.sleep(0.1)
            ret += await self.reader.read(n - len(ret))
        return ret

    def is_connected(self) -> bool:
        return self.state == TLS_STATE.CONNECTED

    async def connect(self):
        await self._send(self.gen_client_hello())
        while self.state != TLS_STATE.CLOSED and self.state != TLS_STATE.CONNECTED:
            tls_header = await self._read_tls_header()
            logger.info("tls_header: %s", tls_header.hex())
            content_type, tls_version, content_length = struct.unpack(
                "!BHH", tls_header
            )
            if self.tls_version == VERSION_TLS_1:
                self.tls_version = tls_version
            content = await self._read(content_length)
            logger.info("tls_content: %s", content.hex())
            data = self._process_msg(tls_header, content_type, content)
            for content in data:
                await self._send(content)

    async def _send(self, content: bytes):
        logger.info("send: %s", content.hex())
        if self.writer is not None and self.reader is not None:
            self.writer.write(content)
            await self.writer.drain()
        elif self.host is not None:
            self.reader, self.writer = await asyncio.open_connection(
                self.host, self.port
            )
            self.writer.write(content)
            await self.writer.drain()
        else:
            logger.warning("not connect")

    async def send(self, content: bytes):
        if isinstance(content, str):
            content = content.encode()
        en_content = self._gen_application_data(content, suffix=b"\x17")
        await self._send(en_content)

    async def readuntil(self, end: bytes, maxsize: int = 4096) -> bytes:
        if isinstance(end, str):
            end = end.encode()
        content = io.BytesIO()
        end_len = len(end)
        end_index = 0
        while end_index < end_len:
            b = await self.read(1)
            if len(b) < 1:
                break
            elif end[end_index] == b[0]:
                end_index += 1
            else:
                end_index = 0
            if content.getbuffer().nbytes > maxsize:
                break
            content.write(b)
        content.seek(0)
        return content.getvalue()

    async def read(self, size: int = -1) -> bytes:
        logger.warning(
            "buffer %s, %s", self.buffer.getbuffer().nbytes, self.buffer.tell()
        )
        t = self.buffer.tell()
        while (
            self.buffer.getbuffer().nbytes - t < size
            or self.buffer.getbuffer().nbytes == t
        ):
            tls_header = await self._read_tls_header()
            _, _, content_len = struct.unpack("!BHH", tls_header)
            content = await self._read(content_len)
            content = self._decrypt_application_data(content, tls_header)
            if content[0] == HANDSHAKE_NEW_SESSION_TICKET:
                continue
            if content == b"\x02\x14\x15":
                break
            self.buffer.write(content[:-1])
        self.buffer.seek(t)
        if size == -1:
            size = self.buffer.getbuffer().nbytes
        ret = self.buffer.read(size)
        if (
            self.buffer.getbuffer().nbytes > 4096
            and self.buffer.getbuffer().nbytes == self.buffer.tell()
        ):
            logger.warning("- %s", self.buffer.getbuffer().nbytes)
            self.buffer.truncate(0)
            self.buffer.seek(0)
        return ret
