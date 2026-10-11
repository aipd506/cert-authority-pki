"""X.509 v2 Certificate Revocation List (CRL) issuer and parser."""

from __future__ import annotations

import dataclasses
import datetime
import enum
from typing import Sequence

from enterpriseca.asn1 import (
    ASN1Error,
    ASN1Node,
    OID_CRL_NUMBER,
    OID_CRL_REASON,
    OID_SHA256_WITH_RSA,
    decode_der,
    decode_integer,
    decode_oid,
    decode_utc_time,
    der_to_pem,
    encode_bit_string,
    encode_context_explicit,
    encode_integer,
    encode_null,
    encode_octet_string,
    encode_oid,
    encode_sequence,
    encode_utc_time,
    pem_to_der,
)
from enterpriseca.rsa import RSAPrivateKey, RSAPublicKey
from enterpriseca.x509 import DistinguishedName, X509Certificate


class RevocationReason(int, enum.Enum):
    UNSPECIFIED = 0
    KEY_COMPROMISE = 1
    CA_COMPROMISE = 2
    AFFILIATION_CHANGED = 3
    SUPERSEDED = 4
    CESSATION_OF_OPERATION = 5
    CERTIFICATE_HOLD = 6


@dataclasses.dataclass
class RevocationEntry:
    serial_number: int
    revocation_date: datetime.datetime
    reason: RevocationReason = RevocationReason.UNSPECIFIED

    def to_der(self) -> bytes:
        """RevokedCertificate ::= SEQUENCE { userCertificate INTEGER, revocationDate Time, crlEntryExtensions Extensions OPTIONAL }"""
        user_cert = encode_integer(self.serial_number)
        rev_time = encode_utc_time(self.revocation_date)

        # reasonCode extension (2.5.29.21)
        # CRLReason ::= ENUMERATED (encoded as INTEGER in DER)
        reason_der = encode_integer(self.reason.value)
        ext = encode_sequence([encode_oid(OID_CRL_REASON), encode_octet_string(reason_der)])
        crl_entry_exts = encode_sequence([ext])

        return encode_sequence([user_cert, rev_time, crl_entry_exts])


@dataclasses.dataclass
class X509CRL:
    issuer: DistinguishedName
    this_update: datetime.datetime
    next_update: datetime.datetime
    revoked_entries: list[RevocationEntry]
    signature: bytes
    tbs_der: bytes
    raw_der: bytes

    def to_pem(self) -> str:
        return der_to_pem(self.raw_der, "X509 CRL")

    def is_revoked(self, serial_number: int) -> tuple[bool, RevocationEntry | None]:
        """Check if a serial number is contained in the revocation list."""
        for entry in self.revoked_entries:
            if entry.serial_number == serial_number:
                return True, entry
        return False, None

    def verify_signature(self, issuer_key_or_cert: RSAPublicKey | X509Certificate) -> bool:
        """Verify the cryptographic signature of the CRL against issuer public key."""
        pubkey = issuer_key_or_cert.public_key if isinstance(issuer_key_or_cert, X509Certificate) else issuer_key_or_cert
        return pubkey.verify_pkcs1v15(self.tbs_der, self.signature)


def issue_crl(
    issuer: DistinguishedName,
    issuer_private_key: RSAPrivateKey,
    revoked_entries: Sequence[RevocationEntry],
    days: int = 30,
    crl_number: int = 1,
) -> X509CRL:
    """Issue a signed X.509 v2 CRL."""
    now = datetime.datetime.now(datetime.timezone.utc)
    this_update = now
    next_update = now + datetime.timedelta(days=days)

    # TBSCertList ::= SEQUENCE {
    #   version INTEGER OPTIONAL (1 for v2),
    #   signature AlgorithmIdentifier,
    #   issuer Name,
    #   thisUpdate Time,
    #   nextUpdate Time,
    #   revokedCertificates SEQUENCE OF RevokedCertificate OPTIONAL,
    #   crlExtensions [0] EXPLICIT Extensions OPTIONAL
    # }
    version_der = encode_integer(1)  # v2
    sig_alg_der = encode_sequence([encode_oid(OID_SHA256_WITH_RSA), encode_null()])
    issuer_der = issuer.to_der()
    this_update_der = encode_utc_time(this_update)
    next_update_der = encode_utc_time(next_update)

    tbs_parts = [
        version_der,
        sig_alg_der,
        issuer_der,
        this_update_der,
        next_update_der,
    ]

    # Revoked certificates sequence
    if revoked_entries:
        rev_items = [entry.to_der() for entry in revoked_entries]
        tbs_parts.append(encode_sequence(rev_items))

    # CRL extensions: crlNumber (2.5.29.20)
    crl_num_ext = encode_sequence([encode_oid(OID_CRL_NUMBER), encode_octet_string(encode_integer(crl_number))])
    crl_exts = encode_context_explicit(0, encode_sequence([crl_num_ext]))
    tbs_parts.append(crl_exts)

    tbs_der = encode_sequence(tbs_parts)

    # Sign TBS
    sig_bytes = issuer_private_key.sign_pkcs1v15(tbs_der)
    sig_bit_str = encode_bit_string(sig_bytes)

    raw_crl = encode_sequence([tbs_der, sig_alg_der, sig_bit_str])

    return X509CRL(
        issuer=issuer,
        this_update=this_update,
        next_update=next_update,
        revoked_entries=list(revoked_entries),
        signature=sig_bytes,
        tbs_der=tbs_der,
        raw_der=raw_crl,
    )


def parse_crl(data: bytes | str) -> X509CRL:
    """Parse X.509 CRL from binary DER or PEM string."""
    der_bytes = pem_to_der(data) if isinstance(data, str) else data
    root = decode_der(der_bytes)

    if len(root.children) < 3:
        raise ASN1Error("Invalid CRL DER sequence")

    tbs_node = root.children[0]
    sig_node = root.children[2]
    sig_bytes = sig_node.value[1:]  # skip unused bits byte

    tbs_children = tbs_node.children
    offset = 0
    if tbs_children[0].tag == 0x02:  # version
        offset = 1

    issuer = DistinguishedName.from_der_node(tbs_children[offset + 1])
    this_update = decode_utc_time(tbs_children[offset + 2].value)
    next_update = decode_utc_time(tbs_children[offset + 3].value)

    revoked_list: list[RevocationEntry] = []
    if len(tbs_children) > offset + 4 and tbs_children[offset + 4].tag == 0x30:
        rev_seq = tbs_children[offset + 4]
        for item in rev_seq.children:
            if len(item.children) >= 2:
                serial = decode_integer(item.children[0].value)
                r_date = decode_utc_time(item.children[1].value)
                reason = RevocationReason.UNSPECIFIED

                # check for entry extensions
                if len(item.children) >= 3 and item.children[2].children:
                    for ext in item.children[2].children:
                        if ext.children and decode_oid(ext.children[0].value) == OID_CRL_REASON:
                            r_val = decode_integer(decode_der(ext.children[1].value).value)
                            try:
                                reason = RevocationReason(r_val)
                            except ValueError:
                                pass

                revoked_list.append(RevocationEntry(serial_number=serial, revocation_date=r_date, reason=reason))

    return X509CRL(
        issuer=issuer,
        this_update=this_update,
        next_update=next_update,
        revoked_entries=revoked_list,
        signature=sig_bytes,
        tbs_der=tbs_node.to_der(),
        raw_der=der_bytes,
    )
