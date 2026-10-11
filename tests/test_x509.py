"""Tests for X.509 v3 certificate hierarchy builder, SAN generator, and parser."""

import datetime
import pytest

from enterpriseca.rsa import generate_keypair
from enterpriseca.x509 import (
    DistinguishedName,
    SANProfile,
    issue_certificate,
    parse_certificate,
)


def test_root_and_leaf_issuance_and_verification():
    # 512-bit keys for fast test execution
    root_key = generate_keypair(bits=512)
    root_dn = DistinguishedName(common_name="Enterprise Root CA", organization="SecOps Inc", country="US")

    # Issue self-signed Root CA
    root_cert = issue_certificate(
        subject=root_dn,
        public_key=root_key.public_key,
        issuer_private_key=root_key,
        days=3650,
        is_ca=True,
    )
    assert root_cert.is_ca is True
    assert root_cert.verify_signature(root_key.public_key) is True
    assert root_cert.is_valid_at() is True

    # Issue Leaf certificate signed by Root CA
    leaf_key = generate_keypair(bits=512)
    leaf_dn = DistinguishedName(common_name="api.corp.local", organization="SecOps Inc", country="US")
    san = SANProfile(dns_names=["api.corp.local", "api-backup.corp.local"], ip_addresses=["10.0.0.1", "127.0.0.1"])

    leaf_cert = issue_certificate(
        subject=leaf_dn,
        public_key=leaf_key.public_key,
        issuer_private_key=root_key,
        issuer=root_cert.subject,
        issuer_public_key=root_key.public_key,
        days=90,
        is_ca=False,
        san=san,
        profile="server",
    )

    assert leaf_cert.is_ca is False
    # Verify leaf signature against Root CA
    assert leaf_cert.verify_signature(root_cert) is True
    # Verify leaf does not match leaf_key signature
    assert leaf_cert.verify_signature(leaf_key.public_key) is False

    # Hostname matching
    assert leaf_cert.matches_hostname("api.corp.local") is True
    assert leaf_cert.matches_hostname("api-backup.corp.local") is True
    assert leaf_cert.matches_hostname("10.0.0.1") is True
    assert leaf_cert.matches_hostname("evil.attacker.com") is False


def test_certificate_pem_serialization():
    ca_key = generate_keypair(bits=512)
    ca_dn = DistinguishedName(common_name="Test CA", organization="Test", country="US")
    cert = issue_certificate(
        subject=ca_dn,
        public_key=ca_key.public_key,
        issuer_private_key=ca_key,
        days=30,
        is_ca=True,
    )

    pem_str = cert.to_pem()
    assert "-----BEGIN CERTIFICATE-----" in pem_str
    assert "-----END CERTIFICATE-----" in pem_str

    parsed = parse_certificate(pem_str)
    assert parsed.serial_number == cert.serial_number
    assert parsed.subject.common_name == "Test CA"
    assert parsed.is_ca is True
    assert parsed.verify_signature(ca_key.public_key) is True


def test_intermediate_ca_hierarchy():
    root_key = generate_keypair(bits=512)
    root_dn = DistinguishedName(common_name="Enterprise Root CA")
    root_cert = issue_certificate(subject=root_dn, public_key=root_key.public_key, issuer_private_key=root_key, is_ca=True)

    inter_key = generate_keypair(bits=512)
    inter_dn = DistinguishedName(common_name="Enterprise Intermediate CA")
    inter_cert = issue_certificate(
        subject=inter_dn,
        public_key=inter_key.public_key,
        issuer_private_key=root_key,
        issuer=root_dn,
        issuer_public_key=root_key.public_key,
        is_ca=True,
        path_length=0,
    )

    leaf_key = generate_keypair(bits=512)
    leaf_dn = DistinguishedName(common_name="mail.enterprise.com")
    leaf_cert = issue_certificate(
        subject=leaf_dn,
        public_key=leaf_key.public_key,
        issuer_private_key=inter_key,
        issuer=inter_dn,
        issuer_public_key=inter_key.public_key,
        is_ca=False,
    )

    # Chain of trust verification
    assert root_cert.verify_signature(root_cert) is True
    assert inter_cert.verify_signature(root_cert) is True
    assert leaf_cert.verify_signature(inter_cert) is True
