import os
import io
import socket
import struct


from . import clients
from enum import Enum
from .log import logger
from typing import List, Union
from hashlib import sha256, sha384
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends.openssl import backend
from cryptography.hazmat.primitives.asymmetric import ec
from .funcs import hkdf_expand, hkdf_extract, get_hkdflabel
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.x509 import load_der_x509_certificate, Certificate
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from .schema import (
    Extension,
    ServerHello,
    TLSHandshake,
    TLSRecordLayer,
)
from .constants import (
    VERSION_TLS_1,
    VERSION_TLS_1_2,
    VERSION_TLS_1_3,
    RECORD_TYPE_APPLICATION_DATA,
    RECORD_TYPE_CHANGE_CIPHER_SPEC,
    RECORD_TYPE_HANDSHAKE,
    HANDSHAKE_CERTIFICATE,
    HANDSHAKE_CERTIFICATE_VERIFY,
    HANDSHAKE_CLIENT_HELLO,
    HANDSHAKE_ENCRYPTED_EXTENSIONS,
    HANDSHAKE_FINISHED,
    HANDSHAKE_NEW_SESSION_TICKET,
    HANDSHAKE_SERVER_HELLO,
    HANDSHAKE_SERVER_HELLO_DONE,
    HANDSHAKE_SERVER_KEY_EXCHANGE,
    KEY_SHARE,
    KEY_SHARE_GROUP_X25519,
    KEY_SHARE_GROUP_X25519MLKEM768,
    SUPPORTED_VERSIONS,
    TLS_AES_128_GCM_SHA256,
    TLS_AES_256_GCM_SHA384,
    TLS_CHACHA20_POLY1305_SHA256,
    TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
)


class TLS_STATE(Enum):
    INITIAL = 0
    HANDSHAKE = 1
    CONNECTED = 2
    CLOSED = 3


class TLSBase:
    def __init__(
        self,
        session_id: bytes = os.urandom(32),
        host: Union[str, bytes, None] = None,
        port: int = 443,
    ):
        self.private_key = x25519.X25519PrivateKey.generate()
        self.public_key = self.private_key.public_key()
        self.s_public_key = None
        self.random = os.urandom(32)
        self.session_id = session_id
        self.zero_bytes = b"\x00" * 64
        self.seq = 0
        self.s_seq = 0
        self.host = host.decode() if isinstance(host, bytes) else host
        self.port = port
        self.state = TLS_STATE.INITIAL
        self.buffer = io.BytesIO()
        self.tls_version = VERSION_TLS_1
        self.certs: List[Certificate] = []

    def _process_msg(
        self, tls_header: bytes, content_type: int, content: bytes
    ) -> List[bytes]:
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
        else:
            logger.warning("Unsupport tls version: %s", content_type)
            return self._process_handshake(content)
        return []

    def _decrypt_application_data(self, en_content: bytes, add: bytes) -> bytes:
        tag = en_content[-self.taglen :]
        logger.info("algorithm: %s", self.algorithm)
        logger.info("add: %s", add.hex())
        disposable_iv = (int.from_bytes(self.iv) ^ self.seq).to_bytes(self.ivlen)
        logger.info("iv: %s", disposable_iv.hex())
        self.seq += 1
        cipher = Cipher(
            self.algorithm(self.key),  # Unsupported ChaCha20
            (self.cipher_mode_mod(disposable_iv, tag)),
            backend,
        )
        der = cipher.decryptor()
        der.authenticate_additional_data(add)
        content = der.update(en_content[: -self.taglen]) + der.finalize()
        logger.info("data: %s", content.hex())
        return content

    def _process_application_data(
        self, en_content: bytes, tls_header: bytes
    ) -> List[bytes]:
        content = self._decrypt_application_data(en_content, tls_header)
        if self.state == TLS_STATE.HANDSHAKE:
            return self._process_handshake(content)
        return []

    def _process_handshake(self, content: bytes) -> List[bytes]:
        handshake_type = struct.unpack("!B", content[0:1])[0]
        handshake_len = struct.unpack("!I", b"\x00" + content[1:4])[0]
        logger.info("handshake bytes: %s", content[: 4 + handshake_len].hex())
        logger.info("handshake type: %s", handshake_type)
        if handshake_type == HANDSHAKE_SERVER_HELLO:
            self.server_hello_bytes = content[: 4 + handshake_len]
            return self._process_server_hello(content[4 : 4 + handshake_len])
        elif handshake_type == HANDSHAKE_SERVER_HELLO_DONE:
            return self._process_server_hello_done(content[4 : 4 + handshake_len])
        elif handshake_type == HANDSHAKE_SERVER_KEY_EXCHANGE:
            return self._process_server_key_exchange(content[4 : 4 + handshake_len])
        elif handshake_type == HANDSHAKE_ENCRYPTED_EXTENSIONS:
            self.encrypted_extensions_bytes = content[: 4 + handshake_len]
            return self._process_encrypted_extensions(content[4 : 4 + handshake_len])
        elif handshake_type == HANDSHAKE_CERTIFICATE:
            self.certificate_bytes = content[: 4 + handshake_len]
            return self._process_certificate(content[4 : 4 + handshake_len])
        elif handshake_type == HANDSHAKE_CERTIFICATE_VERIFY:
            self.certificate_verify_bytes = content[: 4 + handshake_len]
            return self._process_certificate_verify(content[4 : 4 + handshake_len])
        elif handshake_type == HANDSHAKE_FINISHED:
            self.finished_bytes = content[: 4 + handshake_len]
            return self._process_finished(content[4 : 4 + handshake_len])
        elif handshake_type == HANDSHAKE_NEW_SESSION_TICKET:
            return self._process_new_session_ticket(content[4 : 4 + handshake_len])
        else:
            logger.warning("Unsupport handshake type: %s", handshake_type)
        return []

    def _process_new_session_ticket(self, content: bytes) -> List[bytes]:
        return []

    def _process_server_hello_done(self, content: bytes) -> List[bytes]:
        return []

    def _process_server_key_exchange(self, content: bytes) -> List[bytes]:
        return []

    def _process_certificate_verify(self, content: bytes) -> List[bytes]:
        logger.info("data %s", content.hex())
        hash_algo, sign_algo, signed_len = struct.unpack("!BBH", content[:4])
        logger.info(
            "hash_algo %s, sign_algo %s, signed_len %s",
            hash_algo,
            sign_algo,
            signed_len,
        )
        if hash_algo == 4:
            hash_algo_method = hashes.SHA256()
        elif hash_algo == 5:
            hash_algo_method = hashes.SHA384()
        else:
            logger.warning("unknow hash_algo %s", hash_algo)
            return []
        if sign_algo == 3:
            transcript_hash = self.digestmod(
                self.client_hello_bytes
                + self.server_hello_bytes
                + self.encrypted_extensions_bytes
                + self.certificate_bytes
            ).digest()
            self.certs[0].public_key().verify(
                content[4 : 4 + signed_len],
                b" " * 64 + b"TLS 1.3, server CertificateVerify\x00" + transcript_hash,
                ec.ECDSA(hash_algo_method),
            )
            logger.info(
                "signed_len %s, data %s", signed_len, content[4 : 4 + signed_len].hex()
            )
        return []

    def _process_finished(self, content: bytes) -> List[bytes]:
        logger.info("finished: %s", content.hex())
        ret = []
        transcript_hash = self.digestmod(
            self.client_hello_bytes
            + self.server_hello_bytes
            + self.encrypted_extensions_bytes
            + self.certificate_bytes
            + self.certificate_verify_bytes
        ).digest()
        s_transcript_hash = self.digestmod(
            self.client_hello_bytes
            + self.server_hello_bytes
            + self.encrypted_extensions_bytes
            + self.certificate_bytes
            + self.certificate_verify_bytes
            + self.finished_bytes
        ).digest()
        logger.info("transcript_hash: %s", transcript_hash.hex())
        logger.info("s_transcript_hash: %s", s_transcript_hash.hex())
        s_verify_data = hkdf_extract(self.finished, transcript_hash, self.digestmod)
        c_verify_data = hkdf_extract(self.s_finished, s_transcript_hash, self.digestmod)
        logger.info("s_verify_data: %s", s_verify_data.hex())
        logger.info("c_verify_data: %s", c_verify_data.hex())
        c_verify_data_len = struct.pack("!I", len(c_verify_data))
        send_content = (
            struct.pack("!B3s", HANDSHAKE_FINISHED, c_verify_data_len[1:])
            + c_verify_data
        )
        change_cipher_spec_data = b"\x01"
        ret.append(
            struct.pack(
                "!BHH",
                RECORD_TYPE_CHANGE_CIPHER_SPEC,
                VERSION_TLS_1_2,
                len(change_cipher_spec_data),
            )
            + change_cipher_spec_data
            + self._gen_application_data(send_content)
        )
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

    def _gen_application_data(self, content: bytes, suffix: bytes = b"\x16") -> bytes:
        disposable_iv = (int.from_bytes(self.s_iv) ^ self.s_seq).to_bytes(self.ivlen)
        logger.info("iv: %s", disposable_iv.hex())
        self.s_seq += 1
        cipher = Cipher(
            self.algorithm(self.s_key),  # Unsupported ChaCha20
            (self.cipher_mode_mod(disposable_iv)),
            backend,
        )
        er = cipher.encryptor()
        tls_header = struct.pack(
            "!BHH",
            RECORD_TYPE_APPLICATION_DATA,
            VERSION_TLS_1_2,
            len(content) + self.taglen + 1,
        )
        logger.info("tls_header: %s", tls_header.hex())
        er.authenticate_additional_data(tls_header)
        en_content = er.update(content + suffix) + er.finalize()
        logger.info("en_content: %s", en_content.hex())
        logger.info("tag: %s", er.tag.hex())
        return tls_header + en_content + er.tag

    def _process_certificate(self, content: bytes) -> List[bytes]:
        logger.info("tls_version %s", self.tls_version)
        data = content
        if self.tls_version == VERSION_TLS_1_3:
            if data[0] != 0:
                logger.warning("context is not zero. ")
            data = data[1:]
        certs_len = struct.unpack("!I", b"\x00" + data[:3])[0]
        logger.info("certs_len: %s", certs_len)
        data = data[3:]
        if len(data) != certs_len:
            logger.warning("data len mismatch")
        while data:
            cert_len = struct.unpack("!I", b"\x00" + data[:3])[0]
            logger.info("cert_len: %s", cert_len)
            cert_bytes = data[3 : 3 + cert_len]
            logger.info("certs %s", cert_bytes.hex())
            self.certs.append(load_der_x509_certificate(cert_bytes))
            data = data[3 + cert_len :]
            # tls 1.3 only
            if self.tls_version == VERSION_TLS_1_3:
                extensions_len = struct.unpack("!H", data[:2])[0]
                extensions_bytes = data[2 : 2 + extensions_len]
                logger.info(
                    "len %s, extensions_bytes %s",
                    extensions_len,
                    extensions_bytes.hex(),
                )
                data = data[2 + extensions_len :]
        return []

    def _process_encrypted_extensions(self, content: bytes) -> List[bytes]:
        logger.info("encrypted_extensions: %s", content.hex())
        extensions = Extension.unpack(content)
        for ext in extensions:
            logger.info("ext: %s", ext.data)
        return []

    def _process_change_cipher_spec(self, content: bytes) -> List[bytes]:
        logger.warning("not implemented %s", content.hex())
        return []

    def _process_server_hello(self, content: bytes) -> List[bytes]:
        logger.info("aaaaaaaaaaa")
        server_hello = ServerHello.unpack(content)
        logger.info("aaaaaaaaaaa")
        for ext in server_hello.extensions:
            logger.info("ext %s, %s", ext.extension_type, ext.data)
            if ext.extension_type == KEY_SHARE:
                for entry in ext.data.items:
                    logger.info("entry %s", entry)
                    if entry.group == KEY_SHARE_GROUP_X25519:
                        self.s_public_key = x25519.X25519PublicKey.from_public_bytes(
                            entry.key_exchange
                        )
                    elif entry.group == KEY_SHARE_GROUP_X25519MLKEM768:
                        logger.info("unsupported %s", KEY_SHARE_GROUP_X25519)
            elif ext.extension_type == SUPPORTED_VERSIONS:
                logger.info("sversion %s", ext.data.items)
                if ext.data.items[0].version == VERSION_TLS_1_3:
                    self.tls_version = VERSION_TLS_1_3
        pms = self.private_key.exchange(self.s_public_key)
        logger.info("priKey: %s", self.private_key.private_bytes_raw().hex())
        logger.info("spubKey: %s", self.s_public_key.public_bytes_raw().hex())
        logger.info("cbytes: %s", self.client_hello_bytes.hex())
        logger.info("sbytes: %s", self.server_hello_bytes.hex())
        logger.info("pms: %s", pms.hex())
        self.ivlen = 12
        if server_hello.cipher_suite == TLS_AES_128_GCM_SHA256:
            # self.algorithm = aead.AESGCM
            self.algorithm = algorithms.AES128
            self.cipher_mode_mod = modes.GCM
            self.digestmod = sha256
            self.digestlen = 32
            self.keylen = 16
        elif server_hello.cipher_suite == TLS_CHACHA20_POLY1305_SHA256:
            self.algorithm = algorithms.ChaCha20
            # self.algorithm = aead.ChaCha20Poly1305
            self.cipher_mode_mod = modes.GCM
            self.digestmod = sha256
            self.digestlen = 32
            self.keylen = 32
        elif server_hello.cipher_suite == TLS_AES_256_GCM_SHA384:
            # self.algorithm = aead.AESGCM
            self.algorithm = algorithms.AES256
            self.cipher_mode_mod = modes.GCM
            self.digestmod = sha384
            self.digestlen = 48
            self.keylen = 32
        elif server_hello.cipher_suite == TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256:
            self.algorithm = algorithms.AES128
            self.cipher_mode_mod = modes.GCM
            self.digestmod = sha256
            self.digestlen = 32
            self.keylen = 16
        else:
            logger.error("Unsupport cipher suite: %s", server_hello.cipher_suite)
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
        return []

    def gen_client_hello(self) -> bytes:
        handshake = TLSHandshake(
            HANDSHAKE_CLIENT_HELLO,
            clients.MSEdge133(self.host, self.random, self.session_id, self.public_key),
        )
        self.client_hello_bytes = handshake.pack()
        tls_record = TLSRecordLayer(
            RECORD_TYPE_HANDSHAKE, VERSION_TLS_1, self.client_hello_bytes
        )
        self.state = TLS_STATE.HANDSHAKE
        return tls_record.pack()


class TLS(TLSBase):

    def __init__(
        self,
        host=None,
        port=443,
        session_id=os.urandom(32),
        socket=None,
    ):
        self.socket = socket
        super().__init__(session_id, host, port)

    def __enter__(self):
        self.connect()
        return self

    def __exit__(self, *args):
        self.close()

    def close(self):
        if self.socket is not None:
            self.socket.close()

    def _read_tls_header(self) -> bytes:
        return self._read(5)

    def _read(self, bufsize: int) -> bytes:
        logger.info("socket %s", self.socket)
        return self.socket.recv(bufsize)

    def connect(self):
        self._send(self.gen_client_hello())
        while self.state != TLS_STATE.CLOSED and self.state != TLS_STATE.CONNECTED:
            tls_header = self._read_tls_header()
            logger.info("tls_header: %s", tls_header.hex())
            content_type, tls_version, content_length = struct.unpack(
                "!BHH", tls_header
            )
            logger.info("vvvvvvvvvvvv %s", tls_version)
            if self.tls_version == VERSION_TLS_1:
                self.tls_version = tls_version
            content = self._read(content_length)
            logger.info("tls_content: %s", content.hex())
            data = self._process_msg(tls_header, content_type, content)
            for content in data:
                self._send(content)

    def _send(self, content: bytes):
        logger.info("send: %s", content.hex())
        if self.socket is not None:
            self.socket.send(content)
        elif self.host is not None:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.connect((self.host, self.port))
            self.socket.send(content)

    def send(self, content: bytes):
        if isinstance(content, str):
            content = content.encode()
        en_content = self._gen_application_data(content, suffix=b"\x17")
        self._send(en_content)

    def readuntil(self, end: Union[str, bytes], maxsize: int = 4096) -> bytes:
        if isinstance(end, str):
            end = end.encode()
        content = io.BytesIO()
        end_len = len(end)
        end_index = 0
        while end_index < end_len:
            b = self.read(1)
            if len(b) < 1:
                break
            elif end[end_index] == b[0]:
                end_index += 1
            else:
                end_index = 0
            content.write(b)
            if content.getbuffer().nbytes > maxsize:
                break
        content.seek(0)
        return content.getvalue()

    def read(self, size: int = -1) -> bytes:
        while self.buffer.getbuffer().nbytes - self.buffer.tell() <= size or size == -1:
            tls_header = self._read_tls_header()
            logger.info("tls_header: %s, %s", tls_header.hex(), len(tls_header))
            if len(tls_header) == 0:
                break
            _, tls_version, content_length = struct.unpack("!BHH", tls_header)
            if self.tls_version == VERSION_TLS_1:
                self.tls_version = tls_version
            content = self._read(content_length)
            logger.info("tls_content: %s", content)
            content = self._decrypt_application_data(content, tls_header)
            if content[0] == HANDSHAKE_NEW_SESSION_TICKET:
                continue
            elif content == b"\x02\x14\x15":
                return b""
            tell = self.buffer.tell()
            self.buffer.write(content)
            self.buffer.seek(tell)
            logger.info("size: %s", self.buffer.getbuffer().nbytes - self.buffer.tell())
        return self.buffer.read(size)
