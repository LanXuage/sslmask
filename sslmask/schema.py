import struct

from .log import logger
from abc import ABC, abstractmethod
from typing import List, Union, Type
from .constants import (
    SERVER_NAME,
    KEY_SHARE,
    SUPPORTED_VERSIONS,
    EC_POINT_FORMATS,
)


class Parcelable(ABC):
    @abstractmethod
    def pack(self):
        pass


class UnknowExtension(Parcelable):
    def __init__(self, data: bytes = b""):
        self.data = data

    def pack(self):
        return self.data

    @classmethod
    def unpack(cls, data):
        return cls(data)


class ExtensionItem(Parcelable):
    @classmethod
    @abstractmethod
    def unpack(cls, data: bytes) -> List["ExtensionItem"]:
        pass


class KeyShareEntry(ExtensionItem):
    def __init__(self, group: int, key_exchange: bytes):
        self.group = group
        self.key_exchange = key_exchange

    def pack(self):
        return (
            struct.pack("!HH", self.group, len(self.key_exchange)) + self.key_exchange
        )

    @classmethod
    def unpack(cls, data: bytes) -> List["KeyShareEntry"]:
        items = []
        if len(data) > 1:
            items_len = struct.unpack("!H", data[:2])[0]
            if items_len == len(data) - 2:
                data = data[2:]
            while data:
                group, key_exchange_len = struct.unpack("!HH", data[:4])
                key_exchange = data[4 : 4 + key_exchange_len]
                items.append(cls(group, key_exchange))
                data = data[4 + key_exchange_len :]
        return items


class ALPN(ExtensionItem):
    def __init__(self, protocol: Union[str, bytes]):
        self.alpn = protocol.encode() if isinstance(protocol, str) else protocol

    def pack(self):
        return struct.pack("!B", len(self.alpn)) + self.alpn

    @classmethod
    def unpack(cls, data: bytes) -> List["ALPN"]:
        items = []
        if len(data) > 1:
            items_len = struct.unpack("!H", data[:2])[0]
            if items_len == len(data) - 2:
                data = data[2:]
            while data:
                l = data[0]
                item = data[1 : l + 1]
                items.append(cls(item))
                data = data[l + 1 :]
        return items


class ServerName(ExtensionItem):
    def __init__(self, name_type: int, name: Union[str, bytes]):
        self.name_type = name_type
        self.name = name.encode() if isinstance(name, str) else name

    def pack(self):
        return struct.pack("!BH", self.name_type, len(self.name)) + self.name

    @classmethod
    def unpack(cls, data: bytes) -> List["ServerName"]:
        items = []
        if len(data) > 1:
            items_len = struct.unpack("!H", data[:2])[0]
            if items_len == len(data) - 2:
                data = data[2:]
            while data:
                name_type, name_len = struct.unpack("!BH", data[:3])
                name = data[3 : 3 + name_len]
                items.append(cls(name_type, name))
                data = data[3 + name_len :]
        return items


class MultiExtension:
    def __init__(self, items: List[ExtensionItem] = [], len_placeholder: str = "!H"):
        self.items = items
        self.len_placeholder = len_placeholder

    def pack(self, is_multi: bool = False):
        data = b"".join(x.pack() for x in self.items)
        if is_multi:
            return data
        return struct.pack(self.len_placeholder, len(data)) + data

    @classmethod
    def unpack(
        cls, data: bytes, item_cls: Type[ExtensionItem], len_placeholder: str = "!H"
    ) -> "MultiExtension":
        return cls(item_cls.unpack(data), len_placeholder)


class ECPointFormat(ExtensionItem):
    def __init__(self, ec_point_format: int):
        self.ec_point_format = ec_point_format

    def pack(self):
        return struct.pack("!B", self.ec_point_format)

    @classmethod
    def unpack(cls, data: bytes) -> List["ECPointFormat"]:
        items = []
        if len(data) > 0:
            items_len = struct.unpack("!B", data[:1])[0]
            if items_len == len(data) - 1:
                data = data[1:]
            for i in data:
                items.append(cls(i))
        return items


class SupportedVersion(ExtensionItem):
    def __init__(self, version: int):
        self.version = version

    def pack(self):
        return struct.pack("!H", self.version)

    @classmethod
    def unpack(cls, data: bytes) -> List["SupportedVersion"]:
        items = []
        if len(data) > 0:
            items_len = struct.unpack("!B", data[:1])[0]
            if items_len == len(data) - 1:
                data = data[1:]
            while data:
                version = struct.unpack("!H", data[:2])[0]
                items.append(cls(version))
                data = data[2:]
        return items


class Extension(ExtensionItem):
    def __init__(
        self,
        extension_type: int,
        data: Union[UnknowExtension, MultiExtension],
    ):
        self.extension_type = extension_type
        self.data = data

    def pack(self):
        payload = self.data.pack()
        return struct.pack("!HH", self.extension_type, len(payload)) + payload

    @classmethod
    def unpack(cls, data: bytes) -> List["Extension"]:
        items = []
        if len(data) > 1:
            items_len = struct.unpack("!H", data[:2])[0]
            if items_len == len(data) - 2:
                data = data[2:]
            while data:
                extension_type, length = struct.unpack("!HH", data[:4])
                extension_data = data[4 : 4 + length]
                logger.info(
                    "type: %s, length: %s, data: %s",
                    extension_type,
                    length,
                    extension_data.hex(),
                )
                if extension_type == SERVER_NAME:
                    item = MultiExtension.unpack(extension_data, ServerName)
                elif extension_type == KEY_SHARE:
                    item = MultiExtension.unpack(extension_data, KeyShareEntry)
                elif extension_type == SUPPORTED_VERSIONS:
                    item = MultiExtension.unpack(extension_data, SupportedVersion, "!B")
                elif extension_type == EC_POINT_FORMATS:
                    item = MultiExtension.unpack(extension_data, ECPointFormat, "!B")
                else:
                    item = UnknowExtension.unpack(extension_data)
                items.append(cls(extension_type, item))
                data = data[4 + length :]
        return items


class Hello:
    def __init__(
        self,
        version: int,
        random: bytes,
        session_id: bytes,
        extensions: List[Extension],
    ):
        self.version = version
        self.random = random
        self.session_id = session_id
        self.extensions = extensions

    def pack(self, diff: bytes):
        data = (
            struct.pack("!H32sB", self.version, self.random, len(self.session_id))
            + self.session_id
        )
        data += diff
        extensions_bytes = b"".join(x.pack() for x in self.extensions)
        data += struct.pack("!H", len(extensions_bytes)) + extensions_bytes
        return data


class ClientHello(Hello):
    def __init__(
        self,
        version: int,
        random: bytes,
        session_id: bytes,
        cipher_suites: List[int],
        compression_methods: List[int],
        extensions: List[Extension],
    ):
        super().__init__(version, random, session_id, extensions)
        self.cipher_suites = cipher_suites
        self.compression_methods = compression_methods

    def pack(self):
        cipher_suites_bytes = b"".join(struct.pack("!H", x) for x in self.cipher_suites)
        compression_methods_bytes = b"".join(
            struct.pack("!B", x) for x in self.compression_methods
        )
        diff = (
            struct.pack("!H", len(cipher_suites_bytes))
            + cipher_suites_bytes
            + struct.pack("!B", len(compression_methods_bytes))
            + compression_methods_bytes
        )
        return super().pack(diff)

    @classmethod
    def unpack(cls, content: bytes):
        logger.info("content %s", content.hex())
        version, random, session_id_len = struct.unpack(
            "!H32sB", content[0 : 2 + 32 + 1]
        )
        start = 2 + 32 + 1
        session_id = content[start : start + session_id_len]
        logger.info("session_id_len %s", session_id_len)
        start += session_id_len
        cipher_suites_len = struct.unpack("!H", content[start : start + 2])[0]
        logger.info("cipher_suites_len %s", cipher_suites_len)
        start += 2
        cipher_suites = struct.unpack(
            "!" + "H" * (cipher_suites_len // 2),
            content[start : start + cipher_suites_len],
        )
        start += cipher_suites_len
        compression_methods_len = struct.unpack("!B", content[start : start + 1])[0]
        start += 1
        compression_methods = struct.unpack(
            "!" + "B" * compression_methods_len,
            content[start : start + compression_methods_len],
        )
        start += compression_methods_len
        extensions_len = struct.unpack("!H", content[start : start + 2])[0]
        start += 2
        extensions_bytes = content[start : start + extensions_len]
        logger.info("extensions %s", extensions_bytes.hex())
        extensions = Extension.unpack(extensions_bytes)
        return cls(
            version, random, session_id, cipher_suites, compression_methods, extensions
        )


class ServerHello(Hello):
    def __init__(
        self,
        version,
        random,
        session_id,
        cipher_suite: int,
        compression_method: int,
        extensions,
    ):
        super().__init__(version, random, session_id, extensions)
        self.cipher_suite = cipher_suite
        self.compression_method = compression_method

    def pack(self):
        cipher_suites_compression_method_bytes = struct.pack(
            "!HB", self.cipher_suite, self.compression_method
        )
        return super().pack(cipher_suites_compression_method_bytes)

    @classmethod
    def unpack(cls, content: bytes):
        version, random, session_id_length = struct.unpack(
            "!H32sB", content[0 : 2 + 32 + 1]
        )
        start = 2 + 32 + 1
        session_id = content[start : start + session_id_length]
        start += session_id_length
        cipher_suite, compression_method = struct.unpack(
            "!HB", content[start : start + 3]
        )
        start += 3
        extensions_length = struct.unpack("!H", content[start : start + 2])[0]
        start += 2
        extensions_bytes = content[start : start + extensions_length]
        logger.info("extensions %s", extensions_bytes.hex())
        extensions = Extension.unpack(extensions_bytes)
        return cls(
            version, random, session_id, cipher_suite, compression_method, extensions
        )


class TLSHandshake:
    def __init__(
        self, handshake_type: int, content: Union[ClientHello, ServerHello, bytes]
    ):
        self.handshake_type = handshake_type
        self.content = content

    def pack(self) -> bytes:
        handshake_content = (
            self.content if isinstance(self.content, bytes) else self.content.pack()
        )
        handshake_type = struct.pack("!B", self.handshake_type)
        handshake_length = struct.pack("!I", len(handshake_content))[1:]
        return handshake_type + handshake_length + handshake_content


class TLSRecordLayer:
    def __init__(self, conetent_type: int, version: int, content: bytes):
        self.conetent_type = conetent_type
        self.version = version
        self.content = content

    def pack(self):
        return (
            struct.pack("!BHH", self.conetent_type, self.version, len(self.content))
            + self.content
        )

    @classmethod
    def unpack(cls, data: bytes) -> List["TLSRecordLayer"]:
        records = []
        while data:
            conetent_type, version, length = struct.unpack("!BHH", data[:5])
            records.append(cls(conetent_type, version, data[5 : 5 + length]))
            data = data[5 + length :]
        return records
