import random
import struct

from .funcs import is_valid_ip
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PublicKey
from .constants import (
    GREASE,
    KEY_SHARE,
    SERVER_NAME,
    VERSION_TLS_1_2,
    VERSION_TLS_1_3,
    TLS_AES_128_GCM_SHA256,
    TLS_AES_256_GCM_SHA384,
    TLS_CHACHA20_POLY1305_SHA256,
    TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
    TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
    TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
    TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
    TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
    TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
    TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
    TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
    TLS_RSA_WITH_AES_128_GCM_SHA256,
    TLS_RSA_WITH_AES_256_GCM_SHA384,
    TLS_RSA_WITH_AES_128_CBC_SHA,
    TLS_RSA_WITH_AES_256_CBC_SHA,
    STATUS_REQUEST,
    PSK_KEY_EXCHANGE_MODES,
    EC_POINT_FORMATS,
    SUPPORTED_GROUPS,
    SUPPORTED_VERSIONS,
    ENCRYPTED_CLIENT_HELLO,
    EXTENDED_MASTER_SECRET,
    SESSION_TICKET,
    APPLICATION_LAYER_PROTOCOL_NEGOTIATION,
    RENEGOTIATION_INFO,
    SIGNATURE_ALGORITHMS,
    SIGNED_CERTIFICATE_TIMESTAMP,
    APPLICATION_SETTINGS,
    COMPRESS_CERTIFICATE,
)
from .schema import (
    UnknowExtension,
    MultiExtension,
    ServerName,
    KeyShareEntry,
    ClientHello,
    ALPN,
    Extension,
)


class MSEdge133(ClientHello):
    def __init__(
        self,
        host: str,
        rand: bytes,
        session_id: bytes,
        public_key: X25519PublicKey,
        h2: bool = False,
        version: int = VERSION_TLS_1_2,
    ):
        extensions = [
            Extension(STATUS_REQUEST, UnknowExtension(bytes.fromhex("0100000000"))),
            Extension(SESSION_TICKET, UnknowExtension()),
            Extension(EC_POINT_FORMATS, UnknowExtension(b"\x01\x00")),
            Extension(EXTENDED_MASTER_SECRET, UnknowExtension(b"")),
        ]
        if host is not None and not is_valid_ip(host):
            extensions.append(
                Extension(
                    SERVER_NAME,
                    MultiExtension([ServerName(0, host)]),
                )
            )
        extensions.append(
            Extension(
                APPLICATION_LAYER_PROTOCOL_NEGOTIATION,
                MultiExtension(
                    [ALPN("h2"), ALPN("http/1.1")] if h2 else [ALPN("http/1.1")]
                ),
            )
        )
        extensions.append(
            Extension(
                SIGNATURE_ALGORITHMS,
                UnknowExtension(bytes.fromhex("001004030804040105030805050108060601")),
            )
        )
        extensions.append(
            Extension(
                SUPPORTED_VERSIONS,
                UnknowExtension(
                    struct.pack(
                        "!BHHH",
                        6,
                        random.choice(GREASE),
                        VERSION_TLS_1_3,
                        VERSION_TLS_1_2,
                    )
                ),
            )
        )
        if h2:
            extensions.append(
                Exception(
                    APPLICATION_SETTINGS,
                    UnknowExtension(bytes.fromhex("0003026832")),
                )
            )
        extensions.append(
            Extension(
                ENCRYPTED_CLIENT_HELLO,
                UnknowExtension(
                    bytes.fromhex(
                        "00000100016600204a3bcdfb34534f3bbc0aa61768ffc20c911f54316a57156a45e0d95dd448410800f0b1452ff290bca8f39c02d25f880a713c9afd6fa1fad3f728023819ec39b60d5529782cd620cd9c6da9dca34fcfef1f797d597157aeb9d5ece69bfc4f2a78c1284b9b29e18a175ccd07a3bc9973ca509e46d4fe47c97d3b55b4c66604b088ec578f9cb7c4a15e155618626bec1f13291d54b0f0f8418ab77a8144b6d1d219e74e5e03ad96b7afd7d7e7a160729f42626707a867f15d3adc4833b543f9d5c622be4190fb8b0381980ce00d9caf7644609c9819dc41889af32537c27d13a80d4880c481d9f6dc699b8659b8a5147f16e07010a1032c46a6fdb00638943651347cf1eee57e6abe2fdf339bea299fb6011df1"
                    )
                ),
            )
        )
        extensions.append(
            Extension(COMPRESS_CERTIFICATE, UnknowExtension(bytes.fromhex("020002"))),
        )
        grease_group = random.choice(GREASE)
        extensions.append(
            Extension(
                SUPPORTED_GROUPS,
                UnknowExtension(
                    struct.pack(
                        "!HHHHHH",
                        0xA,
                        grease_group,
                        0x11EC,
                        0x001D,
                        0x0017,
                        0x0018,
                    )
                ),
            )
        )
        extensions.append(
            Extension(
                KEY_SHARE,
                MultiExtension(
                    [
                        KeyShareEntry(grease_group, b"\x00"),
                        KeyShareEntry(
                            0x11EC,
                            bytes.fromhex(
                                "c151337cb53f4b515b3a4c8520f91d7c688d24672e6c27b44837b864775ba6255f07d3487042b1352b69ea2895636c14bc6bb59ea281ae380042246501f7397fb8733b1a78dd94ae3bf32694e300b5551491b314403ccdd76835a9129471ba0a8547c8daca9d8f388fa13ca4f6dc3142eb96c590457094451d3a52c44273e7563fe95ccd3eac4405f082ea0b59e6e6a6d215becffb3af516be9d991e64116352882d3ba77289e567ee45adbc6297e8c27937e4121bb2894ab18f262706e1f5a8c8e28e43fa79dd15ab2c7965cf67c814c3457cc7a3846120a704696f0b96dd01920ad416e63b514123744908479d8c8608982e0138c9d510517889b56a0cbce4c19b0f6460cb5839d07660ea31326bfbad796c7bdf3c45be0738a01c6b56a6822bc74ad9496eb9e333bc12948a769c4a1948ca6c6d3cf6bd756a84261760ade66177026eb0e66908d770e395b723ec1c7dc90731842d3c073f9b70721bd76884d8262e097a5e43b69e4acd2d168180e08cee197ca53c8e53204a29d066fbd2817de97f12318ae953ba1fa446b3670f2340a833c13271028117f98f561c70b5769e5acb60a1dac6565861db43c38aa9633cc60c9aa3799a306861641a628319ff2a14c7f5125071aa5df593ed9a22825b4d5dcc28fbe61c5febb362bbb281f40bdd2c3bef63413e291d3582962fa25d364784c8f646128b92a1160fd0772729017cda04ae9edaa9b1a0c740b46f831c659ef269bdf94e826340b55342ef14c218739eaee37f12a41e6e7164c5e467b8c39044569ce7e46983bb2d69bbabd9924d0d959a433c5fe5611c6ee6b4984a652177531a547bcdd63c82c29f3884881016169e592d5b77cfb52546f20247595cc1d532b52648227a361ba7ab6af7373fd11b942c71125f607452e944b4d88cc488caacc08bdc16c8a5304f74992b9313250f707de9234b1b626310f96cb6110c106485d46007b77b4330d939a086b6f77443acb078f8db15e79008bcc25bfdd811e8f28f59d124a856bc6ce1c6bf77b2305050d487493812570378b7d22c46625005109703c4fc0a3249242d6b88e31c2702809626ba1d23d7b97b956be2d483099914762c5da882c9241976d4624e78e7b0c38c6b367cb9e4570711ec3ea677089f709e7da977e8d1b93207256016ca90db6a96cb0a2a707cc2917c9f91a84a02a2bcfc194972a92313597f5631953458152610e848041d25b907dcbdbf8474052c9329703c782c3860eaaf7a37a3775861bb5393bb0c7b096a5d086c520fc78b32e6ce57708e445bc3b34057966330664b7d5cd3263d20108842693df57529047b19775d188b89ad62acdcc70b76e143c7f4300ad61ad4e6ce9a524d32a6553783ad6bc74af4889da088799d164c9f808b2e7286fc128a3c118caca26ec17839b6d07a3e82ab7bb600650a8e0fda652fbabec99b89fa432e470b75c6c4cc4ed3569b9c5ba353036fc5acce8b7886c12eee0738f571484a9277d20b44c0915a14e04875318adaa49723f2922de8be82929ee1a2a47f3b03fdbb28e48b78e9962fee231c1a72bf086c71cfe683abba9c2e7c19c24cbaffe48373f00e901648095614130384af8890ef140604986d13f071a6c9ee273cce5486b6617620352ce4191b6283b7424cf2a825a36f895a2fb8e8f4596ab5a398e691d991de460744c279fd4e9316197c6e0f412115f80dffbf36"
                            ),
                        ),
                        KeyShareEntry(0x1D, public_key.public_bytes_raw()),
                    ]
                ),
            )
        )
        extensions.append(Extension(SIGNED_CERTIFICATE_TIMESTAMP, UnknowExtension()))
        extensions.append(
            Extension(PSK_KEY_EXCHANGE_MODES, UnknowExtension(b"\x01\x01"))
        )
        extensions.append(Extension(RENEGOTIATION_INFO, UnknowExtension(b"\x00")))
        random.shuffle(extensions)
        extensions.insert(0, Extension(random.choice(GREASE), UnknowExtension()))
        extensions.append(Extension(random.choice(GREASE), UnknowExtension(b"\x00")))
        super().__init__(
            version,
            rand,
            session_id,
            [
                random.choice(GREASE),
                TLS_AES_128_GCM_SHA256,
                TLS_AES_256_GCM_SHA384,
                TLS_CHACHA20_POLY1305_SHA256,
                TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
                TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
                TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
                TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
                TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
                TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
                TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
                TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
                TLS_RSA_WITH_AES_128_GCM_SHA256,
                TLS_RSA_WITH_AES_256_GCM_SHA384,
                TLS_RSA_WITH_AES_128_CBC_SHA,
                TLS_RSA_WITH_AES_256_CBC_SHA,
            ],
            [0],
            extensions,
        )
