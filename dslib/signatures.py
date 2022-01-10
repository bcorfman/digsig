from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.exceptions import InvalidSignature


def generate_keys():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()
    return private_key, public_key


def sign(message: bytes, private_key: rsa.RSAPrivateKey):
    signature = private_key.sign(message,
                                 padding.PSS(mgf=padding.MGF1(hashes.SHA256()),
                                             salt_length=padding.PSS.MAX_LENGTH),
                                 hashes.SHA256())
    return signature


def verify(message: bytes, signature, public_key: rsa.RSAPublicKey):
    verified = False
    try:
        public_key.verify(signature, message,
                          padding.PSS(mgf=padding.MGF1(hashes.SHA256()),
                                      salt_length=padding.PSS.MAX_LENGTH),
                          hashes.SHA256())
        verified = True
    except InvalidSignature:
        pass
    return verified
