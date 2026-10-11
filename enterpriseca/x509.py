"""Root, Intermediate, and End-Entity X.509 v3 certificate hierarchy builder and SAN profile generator."""

from __future__ import annotations

import dataclasses
import datetime
import hashlib
import ipaddress
import secrets
from typing import Any, Sequence

from enterpriseca.asn1 import (
    ASN1Error,
    ASN1Node,
    OID_AUTHORITY_KEY_IDENTIFIER,
    OID_BASIC_CONSTRAINTS,
    OID_CLIENT_AUTH,
    OID_CODE_SIGNING,
    OID_COMMON_NAME,
    OID_COUNTRY_NAME,
    OID_EXT_KEY_USAGE,
    OID_KEY_USAGE,
    OID_ORGANIZATION_NAME,
    OID_ORGANIZATIONAL_UNIT_NAME,
    OID_SERVER_AUTH,
    OID_SHA256_WITH_RSA,
    OID_SUBJECT_ALT_NAME,
    OID_SUBJECT_KEY_IDENTIFIER,
    decode_der,
    decode_integer,
    decode_oid,
    decode_utc_time,
    der_to_pem,
    encode_bit_string,
    encode_boolean,
    encode_context_explicit,
    encode_context_implicit,
    encode_ia5_string,
    encode_integer,
    encode_null,
    encode_octet_string,
    encode_oid,
    encode_printable_string,
    encode_sequence,
    encode_set,
    encode_utc_time,
    encode_utf8_string,
    pem_to_der,
)
from enterpriseca.rsa import RSAPrivateKey, RSAPublicKey


class X509Error(Exception):
    """Raised on X.509 certificate errors."""
    pass


@dataclasses.dataclass
class DistinguishedName:
    common_name: str
    organization: str = "Enterprise Suite"
    country: str = "US"
    organizational_unit: str | None = None

    def to_der(self) -> bytes:
        """Encode to ASN.1 Name (SEQUENCE OF SET OF AttributeTypeAndValue)."""
        rdns: list[bytes] = []

        # Country (PrintableString)
        if self.country:
            c_tv = encode_sequence([encode_oid(OID_COUNTRY_NAME), encode_printable_string(self.country)])
            rdns.append(encode_set([c_tv]))

        # Organization (UTF8String)
        if self.organization:
            o_tv = encode_sequence([encode_oid(OID_ORGANIZATION_NAME), encode_utf8_string(self.organization)])
            rdns.append(encode_set([o_tv]))

        # Organizational Unit (UTF8String)
        if self.organizational_unit:
            ou_tv = encode_sequence([encode_oid(OID_ORGANIZATIONAL_UNIT_NAME), encode_utf8_string(self.organizational_unit)])
            rdns.append(encode_set([ou_tv]))

        # Common Name (UTF8String)
        if self.common_name:
            cn_tv = encode_sequence([encode_oid(OID_COMMON_NAME), encode_utf8_string(self.common_name)])
            rdns.append(encode_set([cn_tv]))

        return encode_sequence(rdns)

    @classmethod
    def from_der_node(cls, node: ASN1Node) -> DistinguishedName:
        cn = ""
        o = ""
        c = ""
        ou = None

        for rdn_set in node.children:
            for atv in rdn_set.children:
                if len(atv.children) >= 2:
                    oid_val = decode_oid(atv.children[0].value)
                    str_val = atv.children[1].value.decode("utf-8", errors="replace")
                    if oid_val == OID_COMMON_NAME:
                        cn = str_val
                    elif oid_val == OID_ORGANIZATION_NAME:
                        o = str_val
                    elif oid_val == OID_COUNTRY_NAME:
                        c = str_val
                    elif oid_val == OID_ORGANIZATIONAL_UNIT_NAME:
                        ou = str_val

        return cls(common_name=cn, organization=o, country=c, organizational_unit=ou)


@dataclasses.dataclass
class SANProfile:
    dns_names: list[str] = dataclasses.field(default_factory=list)
    ip_addresses: list[str] = dataclasses.field(default_factory=list)

    def to_der_extension_value(self) -> bytes:
        """GeneralNames ::= SEQUENCE OF GeneralName."""
        names: list[bytes] = []
        for dns in self.dns_names:
            # dNSName [2] IA5String
            names.append(encode_context_implicit(2, dns.encode("ascii")))
        for ip_str in self.ip_addresses:
            # iPAddress [7] OCTET STRING
            ip_obj = ipaddress.ip_address(ip_str.strip())
            names.append(encode_context_implicit(7, ip_obj.packed))
        return encode_sequence(names)

    @classmethod
    def from_der(cls, data: bytes) -> SANProfile:
        node = decode_der(data)
        dns_list = []
        ip_list = []
        for item in node.children:
            tag_num = item.tag & 0x1F
            if tag_num == 2:
                dns_list.append(item.value.decode("ascii", errors="replace"))
            elif tag_num == 7:
                try:
                    ip_list.append(str(ipaddress.ip_address(item.value)))
                except ValueError:
                    pass
        return cls(dns_names=dns_list, ip_addresses=ip_list)


@dataclasses.dataclass
class X509Certificate:
    serial_number: int
    subject: DistinguishedName
    issuer: DistinguishedName
    not_before: datetime.datetime
    not_after: datetime.datetime
    public_key: RSAPublicKey
    is_ca: bool
    san: SANProfile | None
    signature: bytes
    tbs_der: bytes
    raw_der: bytes

    def to_pem(self) -> str:
        return der_to_pem(self.raw_der, "CERTIFICATE")

    def verify_signature(self, issuer_key_or_cert: RSAPublicKey | X509Certificate) -> bool:
        """Verify certificate signature using issuer public key."""
        pubkey = issuer_key_or_cert.public_key if isinstance(issuer_key_or_cert, X509Certificate) else issuer_key_or_cert
        return pubkey.verify_pkcs1v15(self.tbs_der, self.signature)

    def is_valid_at(self, dt: datetime.datetime | None = None) -> bool:
        """Check if certificate is within notBefore and notAfter bounds."""
        target = dt or datetime.datetime.now(datetime.timezone.utc)
        if target.tzinfo is None:
            target = target.replace(tzinfo=datetime.timezone.utc)
        return self.not_before <= target <= self.not_after

    def matches_hostname(self, hostname: str) -> bool:
        """Verify if certificate is valid for a given hostname or IP address."""
        clean_host = hostname.strip().lower()
        if self.san:
            if clean_host in [d.lower() for d in self.san.dns_names]:
                return True
            if clean_host in self.san.ip_addresses:
                return True
        return self.subject.common_name.lower() == clean_host


def build_tbs_certificate(
    serial_number: int,
    subject: DistinguishedName,
    issuer: DistinguishedName,
    not_before: datetime.datetime,
    not_after: datetime.datetime,
    public_key: RSAPublicKey,
    is_ca: bool = False,
    path_length: int | None = None,
    san: SANProfile | None = None,
    key_usage: list[str] | None = None,
    ext_key_usage: list[str] | None = None,
    issuer_public_key: RSAPublicKey | None = None,
) -> bytes:
    """Build the DER-encoded TBSCertificate structure."""
    # 1. Version [0] EXPLICIT INTEGER (2 for v3)
    version_der = encode_context_explicit(0, encode_integer(2))

    # 2. Serial Number
    serial_der = encode_integer(serial_number)

    # 3. Signature AlgorithmIdentifier (sha256WithRSAEncryption)
    sig_alg_der = encode_sequence([encode_oid(OID_SHA256_WITH_RSA), encode_null()])

    # 4. Issuer Name
    issuer_der = issuer.to_der()

    # 5. Validity: SEQUENCE { notBefore Time, notAfter Time }
    validity_der = encode_sequence([encode_utc_time(not_before), encode_utc_time(not_after)])

    # 6. Subject Name
    subject_der = subject.to_der()

    # 7. SubjectPublicKeyInfo
    spki_der = public_key.to_spki_der()

    # 8. Extensions [3] EXPLICIT Extensions
    exts: list[bytes] = []

    # Basic Constraints (critical)
    bc_items = [encode_boolean(is_ca)]
    if is_ca and path_length is not None:
        bc_items.append(encode_integer(path_length))
    bc_val = encode_sequence(bc_items)
    exts.append(encode_sequence([encode_oid(OID_BASIC_CONSTRAINTS), encode_boolean(True), encode_octet_string(bc_val)]))

    # Key Usage (critical)
    if key_usage:
        usage_bits = 0
        usage_map = {
            "digitalSignature": 0,
            "nonRepudiation": 1,
            "keyEncipherment": 2,
            "dataEncipherment": 3,
            "keyAgreement": 4,
            "keyCertSign": 5,
            "cRLSign": 6,
        }
        for u in key_usage:
            bit_idx = usage_map.get(u)
            if bit_idx is not None:
                usage_bits |= 1 << (7 - (bit_idx % 8))
        ku_bytes = bytes([usage_bits])
        ku_val = encode_bit_string(ku_bytes, unused_bits=0)
        exts.append(encode_sequence([encode_oid(OID_KEY_USAGE), encode_boolean(True), encode_octet_string(ku_val)]))

    # Extended Key Usage
    if ext_key_usage:
        eku_oids = []
        for eku in ext_key_usage:
            if eku == "serverAuth":
                eku_oids.append(encode_oid(OID_SERVER_AUTH))
            elif eku == "clientAuth":
                eku_oids.append(encode_oid(OID_CLIENT_AUTH))
            elif eku == "codeSigning":
                eku_oids.append(encode_oid(OID_CODE_SIGNING))
        if eku_oids:
            eku_val = encode_sequence(eku_oids)
            exts.append(encode_sequence([encode_oid(OID_EXT_KEY_USAGE), encode_octet_string(eku_val)]))

    # Subject Key Identifier
    pub_key_hash = hashlib.sha256(public_key.to_spki_der()).digest()[:20]
    ski_val = encode_octet_string(pub_key_hash)
    exts.append(encode_sequence([encode_oid(OID_SUBJECT_KEY_IDENTIFIER), encode_octet_string(ski_val)]))

    # Authority Key Identifier
    iss_pub = issuer_public_key or public_key
    iss_key_hash = hashlib.sha256(iss_pub.to_spki_der()).digest()[:20]
    aki_val = encode_sequence([encode_context_implicit(0, iss_key_hash)])
    exts.append(encode_sequence([encode_oid(OID_AUTHORITY_KEY_IDENTIFIER), encode_octet_string(aki_val)]))

    # Subject Alternative Name
    if san and (san.dns_names or san.ip_addresses):
        san_val = san.to_der_extension_value()
        exts.append(encode_sequence([encode_oid(OID_SUBJECT_ALT_NAME), encode_octet_string(san_val)]))

    extensions_der = encode_context_explicit(3, encode_sequence(exts))

    return encode_sequence([
        version_der,
        serial_der,
        sig_alg_der,
        issuer_der,
        validity_der,
        subject_der,
        spki_der,
        extensions_der,
    ])


def issue_certificate(
    subject: DistinguishedName,
    public_key: RSAPublicKey,
    issuer_private_key: RSAPrivateKey,
    issuer: DistinguishedName | None = None,
    issuer_public_key: RSAPublicKey | None = None,
    serial_number: int | None = None,
    days: int = 365,
    is_ca: bool = False,
    path_length: int | None = None,
    san: SANProfile | None = None,
    profile: str = "server",
) -> X509Certificate:
    """Issue a signed X.509 v3 certificate (Root CA, Intermediate CA, or Leaf)."""
    now = datetime.datetime.now(datetime.timezone.utc)
    # Set not_before 5 minutes in the past to avoid slight clock skew issues
    not_before = now - datetime.timedelta(minutes=5)
    not_after = not_before + datetime.timedelta(days=days)

    serial = serial_number or secrets.randbits(128)
    actual_issuer = issuer or subject  # Self-signed if issuer is None

    # Determine KeyUsage and ExtKeyUsage based on CA status or profile
    if is_ca:
        key_usage = ["keyCertSign", "cRLSign", "digitalSignature"]
        ext_key_usage = None
    else:
        key_usage = ["digitalSignature", "keyEncipherment"]
        if profile == "server":
            ext_key_usage = ["serverAuth"]
        elif profile == "client":
            ext_key_usage = ["clientAuth"]
        elif profile == "code-signing":
            ext_key_usage = ["codeSigning"]
        else:
            ext_key_usage = ["serverAuth", "clientAuth"]

    tbs_der = build_tbs_certificate(
        serial_number=serial,
        subject=subject,
        issuer=actual_issuer,
        not_before=not_before,
        not_after=not_after,
        public_key=public_key,
        is_ca=is_ca,
        path_length=path_length,
        san=san,
        key_usage=key_usage,
        ext_key_usage=ext_key_usage,
        issuer_public_key=issuer_public_key or issuer_private_key.public_key,
    )

    # Sign TBS bytes using issuer private key
    sig_bytes = issuer_private_key.sign_pkcs1v15(tbs_der)

    # Certificate ::= SEQUENCE { tbsCertificate, signatureAlgorithm, signatureValue BIT STRING }
    sig_alg_der = encode_sequence([encode_oid(OID_SHA256_WITH_RSA), encode_null()])
    sig_bit_str = encode_bit_string(sig_bytes)

    cert_der = encode_sequence([tbs_der, sig_alg_der, sig_bit_str])

    return X509Certificate(
        serial_number=serial,
        subject=subject,
        issuer=actual_issuer,
        not_before=not_before,
        not_after=not_after,
        public_key=public_key,
        is_ca=is_ca,
        san=san,
        signature=sig_bytes,
        tbs_der=tbs_der,
        raw_der=cert_der,
    )


def parse_certificate(data: bytes | str) -> X509Certificate:
    """Parse X.509 certificate from binary DER or PEM string."""
    der_bytes = pem_to_der(data) if isinstance(data, str) else data
    root = decode_der(der_bytes)

    if len(root.children) < 3:
        raise X509Error("Invalid Certificate structure")

    tbs_node = root.children[0]
    sig_node = root.children[2]
    # Signature value is BIT STRING; skip unused bits byte
    sig_bytes = sig_node.value[1:]

    # Parse TBS fields
    # Children of TBS: version [0], serial, sig_alg, issuer, validity, subject, spki, [extensions [3]]
    tbs_children = tbs_node.children

    # Version might be missing in v1, but present in v3
    offset = 0
    if tbs_children[0].tag == 0xA0:
        offset = 1

    serial = decode_integer(tbs_children[offset].value)
    issuer = DistinguishedName.from_der_node(tbs_children[offset + 2])
    validity_node = tbs_children[offset + 3]
    not_before = decode_utc_time(validity_node.children[0].value)
    not_after = decode_utc_time(validity_node.children[1].value)
    subject = DistinguishedName.from_der_node(tbs_children[offset + 4])
    spki_node = tbs_children[offset + 5]
    public_key = RSAPublicKey.from_spki_der(spki_node.to_der())

    is_ca = False
    san = None

    # Check for extensions [3]
    if len(tbs_children) > offset + 6:
        ext_wrapper = tbs_children[offset + 6]
        if ext_wrapper.tag == 0xA3 and ext_wrapper.children:
            ext_seq = ext_wrapper.children[0]
            for ext in ext_seq.children:
                if len(ext.children) >= 2:
                    oid_str = decode_oid(ext.children[0].value)
                    ext_val_node = ext.children[-1]
                    raw_ext_val = ext_val_node.value

                    if oid_str == OID_BASIC_CONSTRAINTS:
                        bc_inner = decode_der(raw_ext_val)
                        if bc_inner.children and bc_inner.children[0].tag == 0x01:
                            is_ca = bool(bc_inner.children[0].value != b"\x00")
                    elif oid_str == OID_SUBJECT_ALT_NAME:
                        san = SANProfile.from_der(raw_ext_val)

    return X509Certificate(
        serial_number=serial,
        subject=subject,
        issuer=issuer,
        not_before=not_before,
        not_after=not_after,
        public_key=public_key,
        is_ca=is_ca,
        san=san,
        signature=sig_bytes,
        tbs_der=tbs_node.to_der(),
        raw_der=der_bytes,
    )
