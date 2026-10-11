"""OCSP request validator and signed response generator (RFC 6960)."""

from __future__ import annotations

import dataclasses
import datetime
import enum
import hashlib
from typing import Any

from enterpriseca.asn1 import (
    ASN1Error,
    ASN1Node,
    OID_OCSP_BASIC,
    OID_SHA256_WITH_RSA,
    decode_der,
    decode_generalized_time,
    decode_integer,
    decode_oid,
    der_to_pem,
    encode_bit_string,
    encode_context_explicit,
    encode_context_implicit,
    encode_generalized_time,
    encode_integer,
    encode_null,
    encode_octet_string,
    encode_oid,
    encode_sequence,
    pem_to_der,
)
from enterpriseca.crl import RevocationReason
from enterpriseca.rsa import RSAPrivateKey, RSAPublicKey
from enterpriseca.x509 import DistinguishedName, X509Certificate

# OID id-sha256 (2.16.840.1.101.3.4.2.1)
OID_SHA256 = "2.16.840.1.101.3.4.2.1"


class OCSPCertStatus(int, enum.Enum):
    GOOD = 0
    REVOKED = 1
    UNKNOWN = 2


@dataclasses.dataclass
class SingleResponse:
    serial_number: int
    cert_status: OCSPCertStatus
    this_update: datetime.datetime
    next_update: datetime.datetime
    revocation_time: datetime.datetime | None = None
    revocation_reason: RevocationReason | None = None

    def to_der(self, issuer_name_hash: bytes, issuer_key_hash: bytes) -> bytes:
        """SingleResponse ::= SEQUENCE {
            certID CertID,
            certStatus CertStatus,
            thisUpdate GeneralizedTime,
            nextUpdate [0] EXPLICIT GeneralizedTime OPTIONAL
        }
        """
        # CertID ::= SEQUENCE {
        #   hashAlgorithm AlgorithmIdentifier,
        #   issuerNameHash OCTET STRING,
        #   issuerKeyHash OCTET STRING,
        #   serialNumber CertificateSerialNumber
        # }
        hash_alg = encode_sequence([encode_oid(OID_SHA256), encode_null()])
        cert_id = encode_sequence([
            hash_alg,
            encode_octet_string(issuer_name_hash),
            encode_octet_string(issuer_key_hash),
            encode_integer(self.serial_number),
        ])

        # CertStatus ::= CHOICE {
        #   good [0] IMPLICIT NULL,
        #   revoked [1] IMPLICIT RevokedInfo,
        #   unknown [2] IMPLICIT NULL
        # }
        if self.cert_status == OCSPCertStatus.GOOD:
            status_der = encode_context_implicit(0, b"")
        elif self.cert_status == OCSPCertStatus.REVOKED:
            rev_time = self.revocation_time or datetime.datetime.now(datetime.timezone.utc)
            rev_parts = [encode_generalized_time(rev_time)]
            if self.revocation_reason is not None:
                reason_val = encode_context_explicit(0, encode_integer(self.revocation_reason.value))
                rev_parts.append(reason_val)
            status_der = encode_context_implicit(1, b"".join(rev_parts))
        else:
            status_der = encode_context_implicit(2, b"")

        this_up = encode_generalized_time(self.this_update)
        next_up = encode_context_explicit(0, encode_generalized_time(self.next_update))

        return encode_sequence([cert_id, status_der, this_up, next_up])


@dataclasses.dataclass
class OCSPResponse:
    status: OCSPCertStatus
    serial_number: int
    produced_at: datetime.datetime
    this_update: datetime.datetime
    next_update: datetime.datetime
    signature: bytes
    raw_der: bytes
    revocation_time: datetime.datetime | None = None
    revocation_reason: RevocationReason | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "status": self.status.name,
            "status_code": self.status.value,
            "serial_number": hex(self.serial_number),
            "produced_at": self.produced_at.isoformat(),
            "this_update": self.this_update.isoformat(),
            "next_update": self.next_update.isoformat(),
            "revocation_time": self.revocation_time.isoformat() if self.revocation_time else None,
            "revocation_reason": self.revocation_reason.name if self.revocation_reason else None,
        }


def create_ocsp_response(
    serial_number: int,
    status: OCSPCertStatus,
    issuer_cert: X509Certificate,
    issuer_private_key: RSAPrivateKey,
    revocation_time: datetime.datetime | None = None,
    revocation_reason: RevocationReason | None = None,
    valid_hours: int = 24,
) -> bytes:
    """Create a signed RFC 6960 OCSP Response in DER format."""
    now = datetime.datetime.now(datetime.timezone.utc)
    next_up = now + datetime.timedelta(hours=valid_hours)

    issuer_name_hash = hashlib.sha256(issuer_cert.subject.to_der()).digest()
    issuer_key_hash = hashlib.sha256(issuer_cert.public_key.to_spki_der()).digest()

    single_resp = SingleResponse(
        serial_number=serial_number,
        cert_status=status,
        this_update=now,
        next_update=next_up,
        revocation_time=revocation_time,
        revocation_reason=revocation_reason,
    )

    responses_seq = encode_sequence([single_resp.to_der(issuer_name_hash, issuer_key_hash)])

    # ResponseData ::= SEQUENCE {
    #   version [0] EXPLICIT Version (v1 is 0),
    #   responderID ResponderID,
    #   producedAt GeneralizedTime,
    #   responses SEQUENCE OF SingleResponse
    # }
    responder_id = encode_context_explicit(1, issuer_cert.subject.to_der())
    produced_at = encode_generalized_time(now)

    response_data_der = encode_sequence([responder_id, produced_at, responses_seq])

    # Sign ResponseData
    sig_bytes = issuer_private_key.sign_pkcs1v15(response_data_der)
    sig_alg_der = encode_sequence([encode_oid(OID_SHA256_WITH_RSA), encode_null()])
    sig_bit_str = encode_bit_string(sig_bytes)

    # BasicOCSPResponse ::= SEQUENCE {
    #   tbsResponseData ResponseData,
    #   signatureAlgorithm AlgorithmIdentifier,
    #   signature BIT STRING
    # }
    basic_ocsp_der = encode_sequence([response_data_der, sig_alg_der, sig_bit_str])

    # ResponseBytes ::= SEQUENCE {
    #   responseType OID id-pkix-ocsp-basic,
    #   response OCTET STRING
    # }
    resp_bytes_der = encode_sequence([encode_oid(OID_OCSP_BASIC), encode_octet_string(basic_ocsp_der)])

    # OCSPResponse ::= SEQUENCE {
    #   responseStatus ENUMERATED (successful 0),
    #   responseBytes [0] EXPLICIT ResponseBytes OPTIONAL
    # }
    resp_status_der = encode_integer(0)  # successful
    resp_bytes_opt = encode_context_explicit(0, resp_bytes_der)

    return encode_sequence([resp_status_der, resp_bytes_opt])


def verify_ocsp_response(
    response_der: bytes,
    issuer_key_or_cert: RSAPublicKey | X509Certificate,
) -> tuple[bool, OCSPResponse]:
    """Verify cryptographic signature and parse OCSP status response."""
    root = decode_der(response_der)
    if len(root.children) < 2:
        raise ASN1Error("Invalid OCSPResponse structure")

    status_code = decode_integer(root.children[0].value)
    if status_code != 0:
        raise ASN1Error(f"OCSP responder error status code: {status_code}")

    resp_bytes_wrapper = root.children[1]  # [0] EXPLICIT
    resp_bytes_seq = resp_bytes_wrapper.children[0]
    basic_raw_octet = resp_bytes_seq.children[1].value

    basic_node = decode_der(basic_raw_octet)
    tbs_resp_data = basic_node.children[0]
    sig_node = basic_node.children[2]
    sig_bytes = sig_node.value[1:]

    # Verify signature
    pubkey = issuer_key_or_cert.public_key if isinstance(issuer_key_or_cert, X509Certificate) else issuer_key_or_cert
    sig_valid = pubkey.verify_pkcs1v15(tbs_resp_data.to_der(), sig_bytes)

    # Parse response fields
    # ResponseData children: responderID, producedAt, responses
    tbs_children = tbs_resp_data.children
    produced_at = decode_generalized_time(tbs_children[1].value)
    responses_seq = tbs_children[2]
    first_single = responses_seq.children[0]

    # SingleResponse: certID, certStatus, thisUpdate, [nextUpdate]
    cert_id_node = first_single.children[0]
    serial_num = decode_integer(cert_id_node.children[3].value)

    status_tag = first_single.children[1].tag & 0x1F
    if status_tag == 0:
        cert_status = OCSPCertStatus.GOOD
    elif status_tag == 1:
        cert_status = OCSPCertStatus.REVOKED
    else:
        cert_status = OCSPCertStatus.UNKNOWN

    this_up = decode_generalized_time(first_single.children[2].value)
    next_up = this_up
    if len(first_single.children) > 3:
        next_up_node = first_single.children[3]
        if next_up_node.children:
            next_up = decode_generalized_time(next_up_node.children[0].value)

    ocsp_obj = OCSPResponse(
        status=cert_status,
        serial_number=serial_num,
        produced_at=produced_at,
        this_update=this_up,
        next_update=next_up,
        signature=sig_bytes,
        raw_der=response_der,
    )

    return sig_valid, ocsp_obj
