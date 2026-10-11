"""Tests for X.509 v2 CRL generation and parsing."""

import datetime
import pytest

from enterpriseca.crl import (
    RevocationEntry,
    RevocationReason,
    issue_crl,
    parse_crl,
)
from enterpriseca.rsa import generate_keypair
from enterpriseca.x509 import DistinguishedName, issue_certificate


def test_crl_generation_and_lookup():
    ca_key = generate_keypair(bits=512)
    ca_dn = DistinguishedName(common_name="CRL Test CA")

    rev_date = datetime.datetime.now(datetime.timezone.utc)
    entries = [
        RevocationEntry(serial_number=1001, revocation_date=rev_date, reason=RevocationReason.KEY_COMPROMISE),
        RevocationEntry(serial_number=1002, revocation_date=rev_date, reason=RevocationReason.SUPERSEDED),
    ]

    crl = issue_crl(issuer=ca_dn, issuer_private_key=ca_key, revoked_entries=entries, days=30)
    assert crl.verify_signature(ca_key.public_key) is True

    # Serialize to PEM and re-parse
    pem = crl.to_pem()
    assert "-----BEGIN X509 CRL-----" in pem
    parsed = parse_crl(pem)

    assert parsed.verify_signature(ca_key.public_key) is True

    # Verify is_revoked status
    is_rev, r_entry = parsed.is_revoked(1001)
    assert is_rev is True
    assert r_entry.reason == RevocationReason.KEY_COMPROMISE

    is_rev2, r_entry2 = parsed.is_revoked(1002)
    assert is_rev2 is True
    assert r_entry2.reason == RevocationReason.SUPERSEDED

    # Non-revoked serial returns False
    is_rev3, r_entry3 = parsed.is_revoked(9999)
    assert is_rev3 is False
    assert r_entry3 is None
