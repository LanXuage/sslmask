
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.backends.openssl import backend
from cryptography.hazmat.primitives.serialization import Encoding, load_pem_private_key

a = bytes.fromhex('20202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020544c5320312e332c2073657276657220436572746966696361746556657269667900477610958abfa525e1f3f67208ba3fdc19b0b67f0ddd055df8e6da2f7ef69135f2e5ad36d00633297d4bd6fb4d49cecb')

with open("server.key", 'rb') as f:
    prikey = load_pem_private_key(f.read(), None, backend)
    sign = prikey.sign(a, ec.ECDSA(hashes.SHA256()))
    print(len(sign))

    print(sign.hex())

