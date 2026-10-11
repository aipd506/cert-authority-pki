"""Command-line interface for cert-authority-pki (enterpriseca)."""

from __future__ import annotations

import argparse
import datetime
import json
import os
import sqlite3
import sys
from typing import Sequence

from enterpriseca.asn1 import der_to_pem, pem_to_der
from enterpriseca.crl import (
    RevocationEntry,
    RevocationReason,
    X509CRL,
    issue_crl,
    parse_crl,
)
from enterpriseca.ocsp import (
    OCSPCertStatus,
    create_ocsp_response,
    verify_ocsp_response,
)
from enterpriseca.rsa import RSAPrivateKey, RSAPublicKey, generate_keypair
from enterpriseca.x509 import (
    DistinguishedName,
    SANProfile,
    X509Certificate,
    issue_certificate,
    parse_certificate,
)


def init_db(db_path: str) -> None:
    """Initialize SQLite database for CA certificates and revocation tracking."""
    with sqlite3.connect(db_path) as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS certificates (
                serial_number TEXT PRIMARY KEY,
                common_name TEXT NOT NULL,
                subject_dn TEXT NOT NULL,
                issued_at TEXT NOT NULL,
                expires_at TEXT NOT NULL,
                is_ca INTEGER NOT NULL,
                revoked INTEGER NOT NULL DEFAULT 0,
                revoked_at TEXT,
                revocation_reason TEXT,
                cert_pem TEXT NOT NULL
            )
            """
        )
        conn.commit()


def record_cert(db_path: str, cert: X509Certificate, pem_str: str) -> None:
    init_db(db_path)
    with sqlite3.connect(db_path) as conn:
        conn.execute(
            """
            INSERT OR REPLACE INTO certificates (serial_number, common_name, subject_dn, issued_at, expires_at, is_ca, cert_pem)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                str(cert.serial_number),
                cert.subject.common_name,
                cert.subject.common_name,
                cert.not_before.isoformat(),
                cert.not_after.isoformat(),
                1 if cert.is_ca else 0,
                pem_str,
            ),
        )
        conn.commit()


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="enterpriseca",
        description="Hierarchical X.509 v3 Certificate Authority, CRL issuer, and OCSP validator.",
    )
    parser.add_argument("--version", action="version", version="enterpriseca 0.1.0")

    subparsers = parser.add_subparsers(dest="subcommand", help="Subcommand to execute")

    # init-ca
    p_init = subparsers.add_parser("init-ca", help="Initialize a Root or Intermediate Certificate Authority")
    p_init.add_argument("--cn", required=True, help="Common Name for the Certificate Authority")
    p_init.add_argument("--ca-type", choices=["root", "intermediate"], default="root", help="CA hierarchy level")
    p_init.add_argument("--bits", type=int, default=2048, help="RSA key modulus size (512, 1024, 2048, 4096)")
    p_init.add_argument("--days", type=int, default=3650, help="Validity period in days (default: 3650)")
    p_init.add_argument("--org", default="Enterprise Suite", help="Organization name")
    p_init.add_argument("--country", default="US", help="Country code (2 characters)")
    p_init.add_argument("--out-cert", default="ca_cert.pem", help="Destination path for CA certificate PEM")
    p_init.add_argument("--out-key", default="ca_key.pem", help="Destination path for CA private key PEM")
    p_init.add_argument("--signer-cert", help="Issuer CA certificate path (required for intermediate)")
    p_init.add_argument("--signer-key", help="Issuer CA private key path (required for intermediate)")
    p_init.add_argument("--db", default="ca.db", help="Path to CA certificate database")

    # issue
    p_issue = subparsers.add_parser("issue", help="Issue an End-Entity certificate signed by the CA")
    p_issue.add_argument("--ca-cert", required=True, help="Signing CA certificate PEM path")
    p_issue.add_argument("--ca-key", required=True, help="Signing CA private key PEM path")
    p_issue.add_argument("--cn", required=True, help="Common Name for the leaf certificate")
    p_issue.add_argument("--san", "--san-dns", dest="san_dns", help="Comma-separated Subject Alternative DNS names")
    p_issue.add_argument("--san-ip", help="Comma-separated Subject Alternative IP addresses")
    p_issue.add_argument("--profile", choices=["server", "client", "code-signing"], default="server", help="Profile")
    p_issue.add_argument("--bits", type=int, default=2048, help="RSA key modulus size (default: 2048)")
    p_issue.add_argument("--days", type=int, default=365, help="Validity period in days (default: 365)")
    p_issue.add_argument("--out-cert", default="cert.pem", help="Destination path for issued certificate PEM")
    p_issue.add_argument("--out-key", default="key.pem", help="Destination path for leaf private key PEM")
    p_issue.add_argument("--db", default="ca.db", help="Path to CA certificate database")

    # revoke
    p_revoke = subparsers.add_parser("revoke", help="Revoke an issued certificate by serial number")
    p_revoke.add_argument("--serial", required=True, help="Certificate serial number (decimal or 0x hex)")
    p_revoke.add_argument(
        "--reason",
        choices=["unspecified", "keyCompromise", "caCompromise", "affiliationChanged", "superseded", "cessationOfOperation"],
        default="unspecified",
        help="Revocation reason code",
    )
    p_revoke.add_argument("--ca-key", help="Optional CA key path")
    p_revoke.add_argument("--ca-cert", help="Optional CA cert path")
    p_revoke.add_argument("--db", default="ca.db", help="Path to CA certificate database")

    # crl
    p_crl = subparsers.add_parser("crl", help="Generate a signed X.509 v2 Certificate Revocation List (CRL)")
    p_crl.add_argument("--ca-cert", required=True, help="Issuer CA certificate PEM path")
    p_crl.add_argument("--ca-key", required=True, help="Issuer CA private key PEM path")
    p_crl.add_argument("--out", "--out-crl", dest="out_crl", default="crl.pem", help="Destination path for CRL")
    p_crl.add_argument("--format", choices=["pem", "der"], default="pem", help="Output format (default: pem)")
    p_crl.add_argument("--days", type=int, default=30, help="CRL validity window in days (default: 30)")
    p_crl.add_argument("--db", default="ca.db", help="Path to CA certificate database")

    # ocsp-check
    p_ocsp = subparsers.add_parser("ocsp-check", help="Check certificate revocation status via OCSP / DB / CRL")
    p_ocsp.add_argument("--cert", required=True, help="Target certificate path to verify")
    p_ocsp.add_argument("--issuer", "--ca-cert", dest="ca_cert", required=True, help="Issuing CA certificate path")
    p_ocsp.add_argument("--crl", help="Optional CRL file path to check against")
    p_ocsp.add_argument("--url", help="Optional OCSP responder endpoint URL")
    p_ocsp.add_argument("--db", default="ca.db", help="Path to CA certificate database")
    p_ocsp.add_argument("-j", "--json", action="store_true", default=True, help="Output in JSON format")

    return parser


def handle_init_ca(args: argparse.Namespace) -> int:
    try:
        # Generate CA RSA keypair
        keypair = generate_keypair(bits=args.bits)
        ca_dn = DistinguishedName(common_name=args.cn, organization=args.org, country=args.country)

        if args.ca_type == "root":
            # Self-signed Root CA
            cert = issue_certificate(
                subject=ca_dn,
                public_key=keypair.public_key,
                issuer_private_key=keypair,
                days=args.days,
                is_ca=True,
                path_length=None,
            )
        else:
            # Intermediate CA signed by Root CA
            if not args.signer_cert or not args.signer_key:
                sys.stderr.write("Error: --signer-cert and --signer-key are required for intermediate CA.\n")
                return 2
            with open(args.signer_cert, "r", encoding="utf-8") as f:
                root_cert = parse_certificate(f.read())
            with open(args.signer_key, "r", encoding="utf-8") as f:
                root_key = RSAPrivateKey.from_pem(f.read())

            cert = issue_certificate(
                subject=ca_dn,
                public_key=keypair.public_key,
                issuer_private_key=root_key,
                issuer=root_cert.subject,
                issuer_public_key=root_cert.public_key,
                days=args.days,
                is_ca=True,
                path_length=0,
            )

        cert_pem = cert.to_pem()
        key_pem = keypair.to_pem()

        with open(args.out_cert, "w", encoding="utf-8") as f:
            f.write(cert_pem)
        with open(args.out_key, "w", encoding="utf-8") as f:
            f.write(key_pem)

        record_cert(args.db, cert, cert_pem)
        print(f"Successfully initialized {args.ca_type.upper()} CA: {args.cn} (Serial: {hex(cert.serial_number)})")
        return 0
    except Exception as err:
        sys.stderr.write(f"Cryptographic / CA initialization error: {err}\n")
        return 3


def handle_issue(args: argparse.Namespace) -> int:
    try:
        if not os.path.isfile(args.ca_cert) or not os.path.isfile(args.ca_key):
            sys.stderr.write("Error: CA certificate or private key file not found.\n")
            return 3

        with open(args.ca_cert, "r", encoding="utf-8") as f:
            ca_cert = parse_certificate(f.read())
        with open(args.ca_key, "r", encoding="utf-8") as f:
            ca_key = RSAPrivateKey.from_pem(f.read())

        # Generate leaf RSA keypair
        leaf_key = generate_keypair(bits=args.bits)
        leaf_dn = DistinguishedName(common_name=args.cn, organization=ca_cert.subject.organization, country=ca_cert.subject.country)

        # Build SAN profile if provided
        dns_names = [d.strip() for d in args.san_dns.split(",")] if args.san_dns else []
        ip_addrs = [ip.strip() for ip in args.san_ip.split(",")] if args.san_ip else []
        san = SANProfile(dns_names=dns_names, ip_addresses=ip_addrs) if (dns_names or ip_addrs) else None

        leaf_cert = issue_certificate(
            subject=leaf_dn,
            public_key=leaf_key.public_key,
            issuer_private_key=ca_key,
            issuer=ca_cert.subject,
            issuer_public_key=ca_cert.public_key,
            days=args.days,
            is_ca=False,
            san=san,
            profile=args.profile,
        )

        cert_pem = leaf_cert.to_pem()
        key_pem = leaf_key.to_pem()

        with open(args.out_cert, "w", encoding="utf-8") as f:
            f.write(cert_pem)
        with open(args.out_key, "w", encoding="utf-8") as f:
            f.write(key_pem)

        record_cert(args.db, leaf_cert, cert_pem)
        print(f"Successfully issued certificate: {args.cn} (Serial: {hex(leaf_cert.serial_number)})")
        return 0
    except Exception as err:
        sys.stderr.write(f"Certificate issuance error: {err}\n")
        return 3


def handle_revoke(args: argparse.Namespace) -> int:
    try:
        raw_serial = args.serial.strip()
        serial_int = int(raw_serial, 16) if raw_serial.startswith("0x") else int(raw_serial)
    except ValueError:
        sys.stderr.write(f"Error: Invalid serial number format: '{args.serial}'\n")
        return 2

    init_db(args.db)
    now_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()
    with sqlite3.connect(args.db) as conn:
        cursor = conn.execute(
            """
            UPDATE certificates
            SET revoked = 1, revoked_at = ?, revocation_reason = ?
            WHERE serial_number = ?
            """,
            (now_iso, args.reason, str(serial_int)),
        )
        if cursor.rowcount == 0:
            # Insert record if not present
            conn.execute(
                """
                INSERT INTO certificates (serial_number, common_name, subject_dn, issued_at, expires_at, is_ca, revoked, revoked_at, revocation_reason, cert_pem)
                VALUES (?, 'unknown', 'unknown', ?, ?, 0, 1, ?, ?, '')
                """,
                (str(serial_int), now_iso, now_iso, now_iso, args.reason),
            )
        conn.commit()

    print(f"Successfully revoked certificate {args.serial} (Reason: {args.reason})")
    return 0


def handle_crl(args: argparse.Namespace) -> int:
    try:
        if not os.path.isfile(args.ca_cert) or not os.path.isfile(args.ca_key):
            sys.stderr.write("Error: CA certificate or key not found.\n")
            return 3

        with open(args.ca_cert, "r", encoding="utf-8") as f:
            ca_cert = parse_certificate(f.read())
        with open(args.ca_key, "r", encoding="utf-8") as f:
            ca_key = RSAPrivateKey.from_pem(f.read())

        # Fetch revoked certificates from DB
        revoked_entries: list[RevocationEntry] = []
        if os.path.isfile(args.db):
            init_db(args.db)
            with sqlite3.connect(args.db) as conn:
                cursor = conn.execute("SELECT serial_number, revoked_at, revocation_reason FROM certificates WHERE revoked = 1")
                for row in cursor.fetchall():
                    s_int = int(row[0])
                    r_date = datetime.datetime.fromisoformat(row[1]) if row[1] else datetime.datetime.now(datetime.timezone.utc)
                    reason_name = row[2] or "unspecified"
                    reason_map = {
                        "keyCompromise": RevocationReason.KEY_COMPROMISE,
                        "caCompromise": RevocationReason.CA_COMPROMISE,
                        "affiliationChanged": RevocationReason.AFFILIATION_CHANGED,
                        "superseded": RevocationReason.SUPERSEDED,
                        "cessationOfOperation": RevocationReason.CESSATION_OF_OPERATION,
                    }
                    reason_enum = reason_map.get(reason_name, RevocationReason.UNSPECIFIED)
                    revoked_entries.append(RevocationEntry(serial_number=s_int, revocation_date=r_date, reason=reason_enum))

        crl = issue_crl(issuer=ca_cert.subject, issuer_private_key=ca_key, revoked_entries=revoked_entries, days=args.days)

        if args.format == "der":
            with open(args.out_crl, "wb") as f:
                f.write(crl.raw_der)
        else:
            with open(args.out_crl, "w", encoding="utf-8") as f:
                f.write(crl.to_pem())

        print(f"Successfully issued CRL to {args.out_crl} with {len(revoked_entries)} revoked certificates.")
        return 0
    except Exception as err:
        sys.stderr.write(f"CRL generation error: {err}\n")
        return 3


def handle_ocsp_check(args: argparse.Namespace) -> int:
    try:
        if not os.path.isfile(args.cert) or not os.path.isfile(args.ca_cert):
            sys.stderr.write("Error: Certificate or CA certificate file not found.\n")
            return 3

        with open(args.cert, "r", encoding="utf-8") as f:
            target_cert = parse_certificate(f.read())
        with open(args.ca_cert, "r", encoding="utf-8") as f:
            ca_cert = parse_certificate(f.read())

        # Check signature validity first
        if not target_cert.verify_signature(ca_cert.public_key):
            sys.stderr.write("Certificate signature verification failed.\n")
            return 1

        is_revoked = False
        rev_reason = None
        rev_time = None

        # Check CRL file if provided
        if args.crl and os.path.isfile(args.crl):
            with open(args.crl, "r", encoding="utf-8") as f:
                crl_obj = parse_crl(f.read())
            revoked, entry = crl_obj.is_revoked(target_cert.serial_number)
            if revoked and entry:
                is_revoked = True
                rev_reason = entry.reason.name
                rev_time = entry.revocation_date.isoformat()

        # Check DB if not already flagged revoked
        if not is_revoked and os.path.isfile(args.db):
            init_db(args.db)
            with sqlite3.connect(args.db) as conn:
                cursor = conn.execute(
                    "SELECT revoked, revoked_at, revocation_reason FROM certificates WHERE serial_number = ?",
                    (str(target_cert.serial_number),),
                )
                row = cursor.fetchone()
                if row and row[0] == 1:
                    is_revoked = True
                    rev_time = row[1]
                    rev_reason = row[2]

        status = OCSPCertStatus.REVOKED if is_revoked else OCSPCertStatus.GOOD
        result = {
            "common_name": target_cert.subject.common_name,
            "serial_number": hex(target_cert.serial_number),
            "status": status.name,
            "valid_dates": target_cert.is_valid_at(),
            "revoked_at": rev_time,
            "revocation_reason": rev_reason,
            "issuer": ca_cert.subject.common_name,
        }

        if args.json:
            print(json.dumps(result, indent=2))
        else:
            print(f"Status for {target_cert.subject.common_name}: {status.name}")

        return 1 if status == OCSPCertStatus.REVOKED else 0
    except Exception as err:
        sys.stderr.write(f"OCSP verification error: {err}\n")
        return 3


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if not args.subcommand:
        parser.print_help()
        return 2

    if args.subcommand == "init-ca":
        return handle_init_ca(args)
    elif args.subcommand == "issue":
        return handle_issue(args)
    elif args.subcommand == "revoke":
        return handle_revoke(args)
    elif args.subcommand == "crl":
        return handle_crl(args)
    elif args.subcommand == "ocsp-check":
        return handle_ocsp_check(args)

    return 2


if __name__ == "__main__":
    sys.exit(main())
