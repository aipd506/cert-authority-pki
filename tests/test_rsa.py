"""Tests for pure stdlib Miller-Rabin RSA keypair generator and PKCS#1 v1.5 signer."""

import pytest

from enterpriseca.rsa import (
    RSAError,
    RSAPrivateKey,
    RSAPublicKey,
    generate_keypair,
    is_probable_prime,
)


def test_is_probable_prime():
    assert is_probable_prime(2) is True
    assert is_probable_prime(3) is True
    assert is_probable_prime(17) is True
    assert is_probable_prime(65537) is True
    assert is_probable_prime(4) is False
    assert is_probable_prime(15) is False
    assert is_probable_prime(100) is False


def test_rsa_key_generation_and_signing():
    # 512-bit key for fast testing
    keypair = generate_keypair(bits=512)
    assert keypair.key_size >= 512
    pub = keypair.public_key

    message = b"Cryptographic certificate signing payload"
    signature = keypair.sign_pkcs1v15(message)
    assert len(signature) == keypair.byte_size

    # Verify signature succeeds
    assert pub.verify_pkcs1v15(message, signature) is True

    # Tampered message fails verification
    assert pub.verify_pkcs1v15(b"Tampered payload", signature) is False

    # Tampered signature fails verification
    bad_sig = bytearray(signature)
    bad_sig[10] ^= 0x01
    assert pub.verify_pkcs1v15(message, bytes(bad_sig)) is False


def test_rsa_serialization_pkcs1_and_spki():
    keypair = generate_keypair(bits=512)

    # Private key PEM round-trip
    priv_pem = keypair.to_pem()
    assert "BEGIN RSA PRIVATE KEY" in priv_pem
    restored_priv = RSAPrivateKey.from_pem(priv_pem)
    assert restored_priv.n == keypair.n
    assert restored_priv.d == keypair.d

    # Public key PEM round-trip
    pub_pem = keypair.public_key.to_pem()
    assert "BEGIN PUBLIC KEY" in pub_pem
    restored_pub = RSAPublicKey.from_pem(pub_pem)
    assert restored_pub.n == keypair.public_key.n
    assert restored_pub.e == keypair.public_key.e


def test_rsa_small_key_rejected():
    with pytest.raises(RSAError):
        generate_keypair(bits=256)
