# SPDX-FileCopyrightText: 2025 Salvatore Mesoraca <s.mesoraca16@gmail.com>
# SPDX-License-Identifier: Apache-2.0

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import utils


def generate_key(password=None, size=2048):
    if password is None:
        enc = serialization.NoEncryption()
    else:
        enc = serialization.BestAvailableEncryption(password.encode('latin-1'))
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=size)
    private_pem = private_key.private_bytes(encoding=serialization.Encoding.DER,
                                            format=serialization.PrivateFormat.PKCS8,
                                            encryption_algorithm=enc)
    public_key = private_key.public_key()
    public_pem = public_key.public_bytes(encoding=serialization.Encoding.DER,
                                  format=serialization.PublicFormat.SubjectPublicKeyInfo)
    return private_pem, public_pem


def sign(data, key_path, key_password=None):
        with open(key_path, "rb") as fd:
            private_key = serialization.load_der_private_key(fd.read(),
                                password=key_password.encode('latin-1') if key_password else None)
        sha256 = hashes.SHA256()
        h = hashes.Hash(sha256)
        h.update(data)
        digest = h.finalize()
        return private_key.sign(digest,
                                padding.PSS(mgf=padding.MGF1(sha256),
                                            salt_length=padding.PSS.MAX_LENGTH),
                                utils.Prehashed(sha256))


def key_requires_password(key_path):
    try:
        with open(key_path, "rb") as fd:
            serialization.load_der_private_key(fd.read(), password=None)
    except TypeError:
        return True
    return False
