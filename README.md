# cert-authority-pki (`enterpriseca`)

Hierarchical X.509 v3 public key infrastructure (Root & Intermediate CAs), pure Python standard library ASN.1 DER parser/encoder, RSA PKCS#1 v1.5 signer, Certificate Revocation List (CRL) issuer, and OCSP validator.

## Features

- **Pure Stdlib ASN.1 DER Engine**: Universal TLV encoder and recursive parser for integers, booleans, bit strings, octet strings, OIDs, UTCTime/GeneralizedTime, Sequences, Sets, and context tags.
- **Pure Stdlib RSA Cryptography**: Miller-Rabin primality testing, RSA keypair generation (512, 1024, 2048, 4096-bit), and PKCS#1 v1.5 SHA-256 digital signing/verification.
- **Hierarchical X.509 v3 PKI**: Builder for self-signed Root CAs, intermediate CAs, and end-entity leaf certificates with BasicConstraints, KeyUsage, ExtKeyUsage, Subject Key Identifier, and Authority Key Identifier.
- **Subject Alternative Name (SAN) Profiles**: Full support for DNS hostnames and IPv4/IPv6 addresses.
- **X.509 v2 CRL Issuer**: Complete CRL generation and parsing with standard revocation reason codes.
- **OCSP Status Engine**: Online Certificate Status Protocol response generator and validator (RFC 6960).
- **Dedicated CLI Binary**: Fully featured `enterpriseca` CLI with POSIX exit codes.

## Installation

```bash
pip install -e .
```

## CLI Usage

### 1. Initialize Root or Intermediate CA
```bash
# Initialize Root CA
enterpriseca init-ca --cn "Corp Root CA" --bits 2048 --days 3650 --out-cert ca_cert.pem --out-key ca_key.pem

# Initialize Intermediate CA
enterpriseca init-ca --cn "Corp Intermediate CA" --ca-type intermediate --signer-cert ca_cert.pem --signer-key ca_key.pem
```

### 2. Issue End-Entity Certificate
```bash
enterpriseca issue --ca-cert ca_cert.pem --ca-key ca_key.pem --cn "api.corp.local" --san "api.corp.local,api-backup.corp.local" --san-ip "10.0.0.1" --profile server
```

### 3. Revoke Certificate
```bash
enterpriseca revoke --serial 0x1a2b3c --reason keyCompromise
```

### 4. Issue CRL
```bash
enterpriseca crl --ca-cert ca_cert.pem --ca-key ca_key.pem --out crl.pem
```

### 5. Check OCSP / Revocation Status
```bash
enterpriseca ocsp-check --cert cert.pem --issuer ca_cert.pem
```

## Exit Codes

- `0`: Operation succeeded (certificate issued, CA initialized, cert status GOOD).
- `1`: Revoked certificate status or signature verification failure.
- `2`: Invalid CLI arguments or syntax error.
- `3`: Cryptographic, ASN.1 parsing, or file I/O error.

## License

MIT License. Copyright (c) 2026 aipd506.
