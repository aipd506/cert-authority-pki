"""Tests for enterpriseca CLI subcommands and exit codes."""

import json
from io import StringIO
import pytest
from unittest.mock import patch

from enterpriseca.cli import main
from enterpriseca.x509 import parse_certificate


def test_cli_help_and_version():
    with pytest.raises(SystemExit) as exc:
        main(["--help"])
    assert exc.value.code == 0

    with pytest.raises(SystemExit) as exc:
        main(["--version"])
    assert exc.value.code == 0

    assert main([]) == 2


def test_cli_full_pki_lifecycle(tmp_path):
    ca_cert = tmp_path / "ca_cert.pem"
    ca_key = tmp_path / "ca_key.pem"
    db_file = tmp_path / "test_ca.db"

    # 1. Init Root CA
    rc = main([
        "init-ca",
        "--cn", "Test Root CA",
        "--bits", "512",
        "--out-cert", str(ca_cert),
        "--out-key", str(ca_key),
        "--db", str(db_file),
    ])
    assert rc == 0
    assert ca_cert.exists()
    assert ca_key.exists()

    # 2. Issue Leaf Certificate
    leaf_cert = tmp_path / "leaf_cert.pem"
    leaf_key = tmp_path / "leaf_key.pem"
    rc = main([
        "issue",
        "--ca-cert", str(ca_cert),
        "--ca-key", str(ca_key),
        "--cn", "vpn.corp.internal",
        "--san", "vpn.corp.internal,vpn2.corp.internal",
        "--san-ip", "10.0.0.50",
        "--bits", "512",
        "--out-cert", str(leaf_cert),
        "--out-key", str(leaf_key),
        "--db", str(db_file),
    ])
    assert rc == 0
    assert leaf_cert.exists()

    # Read serial from leaf certificate
    with open(leaf_cert, "r", encoding="utf-8") as f:
        cert_obj = parse_certificate(f.read())
    serial_str = str(cert_obj.serial_number)

    # 3. OCSP Check: Initially GOOD -> returns 0
    with patch("sys.stdout", new_callable=StringIO) as fake_out:
        rc = main([
            "ocsp-check",
            "--cert", str(leaf_cert),
            "--issuer", str(ca_cert),
            "--db", str(db_file),
        ])
        assert rc == 0
        res = json.loads(fake_out.getvalue())
        assert res["status"] == "GOOD"

    # 4. Revoke Certificate
    rc = main([
        "revoke",
        "--serial", serial_str,
        "--reason", "keyCompromise",
        "--db", str(db_file),
    ])
    assert rc == 0

    # 5. OCSP Check after Revocation -> returns 1
    with patch("sys.stdout", new_callable=StringIO) as fake_out:
        rc = main([
            "ocsp-check",
            "--cert", str(leaf_cert),
            "--issuer", str(ca_cert),
            "--db", str(db_file),
        ])
        assert rc == 1
        res = json.loads(fake_out.getvalue())
        assert res["status"] == "REVOKED"
        assert res["revocation_reason"] == "keyCompromise"

    # 6. Generate CRL
    crl_file = tmp_path / "crl.pem"
    rc = main([
        "crl",
        "--ca-cert", str(ca_cert),
        "--ca-key", str(ca_key),
        "--out", str(crl_file),
        "--db", str(db_file),
    ])
    assert rc == 0
    assert crl_file.exists()


def test_cli_intermediate_ca(tmp_path):
    root_cert = tmp_path / "root_cert.pem"
    root_key = tmp_path / "root_key.pem"
    inter_cert = tmp_path / "inter_cert.pem"
    inter_key = tmp_path / "inter_key.pem"
    db_file = tmp_path / "inter_ca.db"

    # Root CA
    main([
        "init-ca",
        "--cn", "Root CA",
        "--bits", "512",
        "--out-cert", str(root_cert),
        "--out-key", str(root_key),
        "--db", str(db_file),
    ])

    # Intermediate CA
    rc = main([
        "init-ca",
        "--cn", "Intermediate CA",
        "--ca-type", "intermediate",
        "--bits", "512",
        "--signer-cert", str(root_cert),
        "--signer-key", str(root_key),
        "--out-cert", str(inter_cert),
        "--out-key", str(inter_key),
        "--db", str(db_file),
    ])
    assert rc == 0
    assert inter_cert.exists()
