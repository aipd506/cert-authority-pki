"""Pure Python standard library Miller-Rabin RSA keypair generator and PKCS#1 v1.5 SHA-256 signer."""

from __future__ import annotations

import dataclasses
import hashlib
import math
import secrets
from typing import Any

from enterpriseca.asn1 import (
    ASN1Error,
    ASN1Node,
    OID_RSA_ENCRYPTION,
    TAG_SEQUENCE,
    decode_der,
    decode_integer,
    der_to_pem,
    encode_bit_string,
    encode_integer,
    encode_null,
    encode_oid,
    encode_sequence,
    pem_to_der,
)

# Standard PKCS#1 v1.5 DigestInfo prefix for SHA-256 (RFC 3447 Section 9.2)
# SEQUENCE { SEQUENCE { OID sha256 (2.16.840.1.101.3.4.2.1), NULL }, OCTET STRING (32 bytes) }
SHA256_DIGEST_INFO_PREFIX = bytes.fromhex(
    "3031300d060960864801650304020105000420"
)


class RSAError(Exception):
    """Raised on RSA cryptographic errors."""
    pass


def is_probable_prime(n: int, rounds: int = 20) -> bool:
    """Miller-Rabin probabilistic primality test."""
    if n < 2:
        return False
    if n in (2, 3):
        return True
    if n % 2 == 0:
        return False

    r, s = 0, n - 1
    while s % 2 == 0:
        r += 1
        s //= 2

    for _ in range(rounds):
        a = secrets.randbelow(n - 3) + 2
        x = pow(a, s, n)
        if x == 1 or x == n - 1:
            continue
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True


def generate_prime(bits: int) -> int:
    """Generate a random prime of given bit length."""
    while True:
        # Ensure highest two bits and lowest bit are set
        candidate = secrets.randbits(bits) | (1 << (bits - 1)) | (1 << (bits - 2)) | 1
        if is_probable_prime(candidate):
            return candidate


@dataclasses.dataclass(frozen=True)
class RSAPublicKey:
    n: int  # Modulus
    e: int  # Public exponent

    @property
    def key_size(self) -> int:
        return self.n.bit_length()

    @property
    def byte_size(self) -> int:
        return (self.n.bit_length() + 7) // 8

    def verify_pkcs1v15(self, message: bytes, signature: bytes) -> bool:
        """Verify PKCS#1 v1.5 SHA-256 digital signature."""
        k = self.byte_size
        if len(signature) != k:
            return False

        s = int.from_bytes(signature, "big")
        if s < 0 or s >= self.n:
            return False

        # m = s^e mod n
        m = pow(s, self.e, self.n)
        em = m.to_bytes(k, "big")

        # Verify PKCS#1 v1.5 padding: 0x00 || 0x01 || PS (all 0xFF) || 0x00 || DigestInfo || H
        if em[0] != 0x00 or em[1] != 0x01:
            return False

        # Find 0x00 separator after padding bytes
        sep_idx = em.find(b"\x00", 2)
        if sep_idx < 10:  # Minimum 8 bytes of 0xFF padding
            return False

        # Verify that all bytes in PS are 0xFF
        ps = em[2:sep_idx]
        if any(b != 0xFF for b in ps):
            return False

        expected_digest_block = SHA256_DIGEST_INFO_PREFIX + hashlib.sha256(message).digest()
        actual_digest_block = em[sep_idx + 1 :]

        return actual_digest_block == expected_digest_block

    def to_pkcs1_der(self) -> bytes:
        """RSAPublicKey ::= SEQUENCE { modulus INTEGER, publicExponent INTEGER }"""
        return encode_sequence([encode_integer(self.n), encode_integer(self.e)])

    def to_spki_der(self) -> bytes:
        """SubjectPublicKeyInfo ::= SEQUENCE { algorithm AlgorithmIdentifier, subjectPublicKey BIT STRING }"""
        alg_id = encode_sequence([encode_oid(OID_RSA_ENCRYPTION), encode_null()])
        pkcs1 = self.to_pkcs1_der()
        bit_str = encode_bit_string(pkcs1)
        return encode_sequence([alg_id, bit_str])

    def to_pem(self) -> str:
        return der_to_pem(self.to_spki_der(), "PUBLIC KEY")

    @classmethod
    def from_spki_der(cls, data: bytes) -> RSAPublicKey:
        node = decode_der(data)
        if len(node.children) < 2:
            raise RSAError("Invalid SubjectPublicKeyInfo DER structure")
        # Second child is BIT STRING containing RSAPublicKey sequence
        bit_str_node = node.children[1]
        raw_key_bytes = bit_str_node.value[1:]  # skip unused bits byte
        pkcs1_node = decode_der(raw_key_bytes)
        n = decode_integer(pkcs1_node.children[0].value)
        e = decode_integer(pkcs1_node.children[1].value)
        return cls(n=n, e=e)

    @classmethod
    def from_pem(cls, pem_str: str) -> RSAPublicKey:
        der = pem_to_der(pem_str)
        try:
            return cls.from_spki_der(der)
        except Exception:
            # Try direct PKCS#1 DER
            node = decode_der(der)
            n = decode_integer(node.children[0].value)
            e = decode_integer(node.children[1].value)
            return cls(n=n, e=e)


@dataclasses.dataclass(frozen=True)
class RSAPrivateKey:
    n: int
    e: int
    d: int
    p: int
    q: int
    dp: int
    dq: int
    qinv: int

    @property
    def key_size(self) -> int:
        return self.n.bit_length()

    @property
    def byte_size(self) -> int:
        return (self.n.bit_length() + 7) // 8

    @property
    def public_key(self) -> RSAPublicKey:
        return RSAPublicKey(n=self.n, e=self.e)

    def sign_pkcs1v15(self, message: bytes) -> bytes:
        """Sign message using PKCS#1 v1.5 with SHA-256."""
        k = self.byte_size
        h = hashlib.sha256(message).digest()
        t = SHA256_DIGEST_INFO_PREFIX + h
        t_len = len(t)

        if k < t_len + 11:
            raise RSAError(f"Key size {self.key_size} bits is too short to sign with SHA-256")

        ps_len = k - t_len - 3
        ps = b"\xff" * ps_len
        em = b"\x00\x01" + ps + b"\x00" + t

        m = int.from_bytes(em, "big")
        # Compute signature using Chinese Remainder Theorem (CRT) for 4x speedup
        # s1 = m^dp mod p, s2 = m^dq mod q
        s1 = pow(m, self.dp, self.p)
        s2 = pow(m, self.dq, self.q)
        h_crt = ((s1 - s2) * self.qinv) % self.p
        s = (s2 + h_crt * self.q) % self.n

        return s.to_bytes(k, "big")

    def to_pkcs1_der(self) -> bytes:
        """RSAPrivateKey ::= SEQUENCE { version INTEGER (0), modulus, publicExponent, privateExponent, prime1, prime2, exponent1, exponent2, coefficient }"""
        return encode_sequence([
            encode_integer(0),
            encode_integer(self.n),
            encode_integer(self.e),
            encode_integer(self.d),
            encode_integer(self.p),
            encode_integer(self.q),
            encode_integer(self.dp),
            encode_integer(self.dq),
            encode_integer(self.qinv),
        ])

    def to_pem(self) -> str:
        return der_to_pem(self.to_pkcs1_der(), "RSA PRIVATE KEY")

    @classmethod
    def from_pkcs1_der(cls, data: bytes) -> RSAPrivateKey:
        node = decode_der(data)
        if len(node.children) < 9:
            raise RSAError("Invalid RSAPrivateKey DER sequence")
        return cls(
            n=decode_integer(node.children[1].value),
            e=decode_integer(node.children[2].value),
            d=decode_integer(node.children[3].value),
            p=decode_integer(node.children[4].value),
            q=decode_integer(node.children[5].value),
            dp=decode_integer(node.children[6].value),
            dq=decode_integer(node.children[7].value),
            qinv=decode_integer(node.children[8].value),
        )

    @classmethod
    def from_pem(cls, pem_str: str) -> RSAPrivateKey:
        der = pem_to_der(pem_str, header="RSA PRIVATE KEY")
        return cls.from_pkcs1_der(der)


def generate_keypair(bits: int = 2048, e: int = 65537) -> RSAPrivateKey:
    """Generate a new RSA keypair of requested bit length (e.g. 512, 1024, 2048)."""
    if bits < 512:
        raise RSAError(f"RSA bit size {bits} is too small. Minimum supported is 512 bits.")

    half_bits = bits // 2
    while True:
        p = generate_prime(half_bits)
        if (p - 1) % e != 0:
            break

    while True:
        q = generate_prime(bits - half_bits)
        if q != p and (q - 1) % e != 0:
            break

    # Ensure p > q for consistency in CRT
    if p < q:
        p, q = q, p

    n = p * q
    phi = (p - 1) * (q - 1)
    d = pow(e, -1, phi)
    dp = d % (p - 1)
    dq = d % (q - 1)
    qinv = pow(q, -1, p)

    return RSAPrivateKey(
        n=n,
        e=e,
        d=d,
        p=p,
        q=q,
        dp=dp,
        dq=dq,
        qinv=qinv,
    )
