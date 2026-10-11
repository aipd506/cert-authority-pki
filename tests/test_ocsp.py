"""Tests for RFC 6960 OCSP signed response generation and verification."""

import pytest

from enterpriseca.crl import RevocationReason
from enterpriseca.ocsp import (
    OCSPCertStatus,
    create_ocsp_response,
    verify_ocsp_response,
)
from enterpriseca.rsa import generate_keypair
from enterpriseca.x509 import DistinguishedName, issue_certificate


def test_ocsp_good_and_revoked():
    ca_key = generate_keypair(bits=512)
    ca_dn = DistinguishedName(common_name="OCSP Issuing CA")
    ca_cert = issue_certificate(subject=ca_dn, public_key=ca_key.public_key, issuer_private_key=ca_key, is_ca=True)

    # 1. Good status response
    serial_good = 0x55AA1122
    resp_good_der = create_ocsp_response(
        serial_number=serial_good,
        status=OCSPCertStatus.GOOD,
        issuer_cert=ca_cert,
        issuer_private_key=ca_key,
    )

    sig_ok, ocsp_good = verify_ocsp_response(resp_good_der, ca_cert)
    assert sig_ok is True
    assert ocsp_good.status == OCSPCertStatus.GOOD
    assert ocsp_good.serial_number == serial_good

    # 2. Revoked status response
    serial_revoked = 0x99887766
    resp_rev_der = create_ocsp_response(
        serial_number=serial_revoked,
        status=OCSPCertStatus.REVOKED,
        issuer_cert=ca_cert,
        issuer_private_key=ca_key,
        revocation_reason=RevocationReason.KEY_COMPROMISE,
    )

    sig_ok2, ocsp_rev = verify_ocsp_response(resp_rev_der, ca_cert)
    assert sig_ok2 is True
    assert ocsp_rev.status == OCSPCertStatus.REVOKED
    assert ocsp_rev.serial_number == serial_revoked
