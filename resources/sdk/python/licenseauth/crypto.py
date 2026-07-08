import base64
import hashlib
import os
import uuid

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


class CryptoError(Exception):
    pass


def base64UrlEncode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def base64UrlDecode(value: str) -> bytes:
    paddingText = "=" * ((4 - len(value) % 4) % 4)
    return base64.urlsafe_b64decode(value + paddingText)


def sha256Hex(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()

def algorithmConfig(name: str) -> dict:
    if name == "rsa_oaep_aes_256_gcm":
        return {"keyBytes": 32, "padding": "oaep"}
    if name == "rsa_oaep_aes_128_gcm":
        return {"keyBytes": 16, "padding": "oaep"}
    if name == "rsa_pkcs1_aes_256_gcm":
        return {"keyBytes": 32, "padding": "pkcs1"}
    raise CryptoError(f"unsupported client crypto algorithm: {name}")


def aesGcmEncrypt(plaintext: bytes, key: bytes, aad: bytes) -> dict:
    nonce = os.urandom(12)
    encrypted = AESGCM(key).encrypt(nonce, plaintext, aad)
    return {
        "iv": base64UrlEncode(nonce),
        "ciphertext": base64UrlEncode(encrypted[:-16]),
        "tag": base64UrlEncode(encrypted[-16:]),
    }


def aesGcmDecrypt(envelope: dict, key: bytes, aad: bytes) -> bytes:
    nonce = base64UrlDecode(envelope["iv"])
    ciphertext = base64UrlDecode(envelope["ciphertext"])
    tag = base64UrlDecode(envelope["tag"])
    return AESGCM(key).decrypt(nonce, ciphertext + tag, aad)


def rsaEncrypt(publicKeyPem: str, payload: bytes, algorithm: str) -> bytes:
    publicKey = serialization.load_pem_public_key(publicKeyPem.encode("utf-8"))
    return publicKey.encrypt(payload, rsaPadding(algorithm))


def rsaPadding(algorithm: str):
    config = algorithmConfig(algorithm)
    if config["padding"] == "oaep":
        return padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA1()),
            algorithm=hashes.SHA1(),
            label=None,
        )
    return padding.PKCS1v15()


def generateInstallId() -> str:
    return uuid.uuid4().hex


def generateDeviceKeyPair() -> dict[str, str]:
    privateKey = ec.generate_private_key(ec.SECP256R1())
    privatePem = privateKey.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode("utf-8")
    publicPem = privateKey.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("utf-8")
    return {"device_private_key": privatePem, "device_public_key": publicPem}


def signDeviceMessage(privateKeyPem: str, message: str) -> str:
    privateKey = serialization.load_pem_private_key(privateKeyPem.encode("utf-8"), password=None)
    signature = privateKey.sign(message.encode("utf-8"), ec.ECDSA(hashes.SHA256()))
    return base64UrlEncode(signature)
