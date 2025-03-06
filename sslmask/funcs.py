import re
import hmac
import math
import struct

from cryptography import x509
from typing import Callable, Union
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from datetime import datetime, timedelta, timezone
from cryptography.hazmat.backends.openssl import backend
from cryptography.hazmat.primitives.asymmetric import ec, rsa

IPV4_PATTERN = r"^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$"
IPV6_PATTERN = r"^(([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:))$"
IP_RE = re.compile(IPV4_PATTERN + "|" + IPV6_PATTERN)


def is_valid_ip(ip_str: Union[str, bytes]):
    if isinstance(ip_str, bytes):
        ip_str = ip_str.decode()
    return True if IP_RE.match(ip_str) is not None else False


def hkdf_extract(salt: bytes, ikm: bytes, hmac_method: Callable) -> bytes:
    return hmac.new(salt, ikm, hmac_method).digest()


def get_hkdflabel(label: bytes, data: bytes, outlen) -> bytes:
    prefix = b"tls13 "
    prefix_label = prefix + label
    hkdflabel = (
        struct.pack("!H", outlen)
        + struct.pack("!B", len(prefix_label))
        + prefix_label
        + struct.pack("!B", len(data))
        + data
    )
    return hkdflabel


def hkdf_expand(
    prk: bytes, info: bytes, digestmod: Callable, digestlen: int, outlen: int
) -> bytes:
    n = math.ceil(outlen / digestlen)
    m: hmac.HMAC = hmac.new(key=prk, digestmod=digestmod)
    okm = b""
    prev = b""
    for i in range(1, n + 1):
        if i > 1:
            m = hmac.new(key=b"", digestmod=digestmod)
            m.update(prev)
        m.update(info)
        m.update(struct.pack("!B", i))
        prev = m.digest()
        okm += prev
    return okm[:outlen]


def gen_self_signed_certificate(
    private_key: Union[ec.EllipticCurvePrivateKey, rsa.RSAPrivateKey],
):
    subject = issuer = x509.Name(
        [
            x509.NameAttribute(NameOID.COUNTRY_NAME, "CN"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "SomeState"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, "SomeCity"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "ExampleOrg"),
            x509.NameAttribute(NameOID.COMMON_NAME, "example.com"),
        ]
    )
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(timezone.utc))
        .not_valid_after(datetime.now(timezone.utc) + timedelta(days=365))
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName("localhost")]),
            critical=False,
        )
        .sign(private_key, hashes.SHA256(), backend)
    )
    return cert
