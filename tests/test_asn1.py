"""Tests for pure stdlib ASN.1 DER parser and serializer."""

import datetime
import pytest

from enterpriseca.asn1 import (
    ASN1Error,
    decode_der,
    decode_integer,
    decode_length,
    decode_oid,
    decode_utc_time,
    der_to_pem,
    encode_bit_string,
    encode_boolean,
    encode_integer,
    encode_length,
    encode_null,
    encode_octet_string,
    encode_oid,
    encode_sequence,
    encode_set,
    encode_utc_time,
    pem_to_der,
)


def test_encode_decode_integer():
    assert encode_integer(0) == b"\x02\x01\x00"
    assert decode_integer(b"\x00") == 0

    assert encode_integer(127) == b"\x02\x01\x7f"
    assert decode_integer(b"\x7f") == 127

    # Positive integer with MSB set requires 0x00 prefix in DER
    assert encode_integer(128) == b"\x02\x02\x00\x80"
    assert decode_integer(b"\x00\x80") == 128

    large_num = 0x123456789ABCDEF0
    enc = encode_integer(large_num)
    node = decode_der(enc)
    assert decode_integer(node.value) == large_num


def test_encode_decode_oid():
    # sha256WithRSAEncryption: 1.2.840.113549.1.1.11
    oid_str = "1.2.840.113549.1.1.11"
    enc = encode_oid(oid_str)
    node = decode_der(enc)
    assert decode_oid(node.value) == oid_str

    # commonName: 2.5.4.3
    cn_oid = "2.5.4.3"
    enc_cn = encode_oid(cn_oid)
    node_cn = decode_der(enc_cn)
    assert decode_oid(node_cn.value) == cn_oid


def test_encode_decode_boolean_and_null():
    b_true = encode_boolean(True)
    assert b_true == b"\x01\x01\xff"
    node_t = decode_der(b_true)
    assert node_t.value == b"\xff"

    b_false = encode_boolean(False)
    assert b_false == b"\x01\x01\x00"

    null_der = encode_null()
    assert null_der == b"\x05\x00"


def test_encode_decode_length():
    # Short form (< 128)
    assert encode_length(42) == bytes([42])
    length, offset = decode_length(bytes([42]), 0)
    assert length == 42
    assert offset == 1

    # Long form (>= 128)
    assert encode_length(256) == b"\x82\x01\x00"
    length2, offset2 = decode_length(b"\x82\x01\x00", 0)
    assert length2 == 256
    assert offset2 == 3


def test_encode_decode_time():
    dt = datetime.datetime(2026, 10, 11, 14, 30, 0, tzinfo=datetime.timezone.utc)
    enc = encode_utc_time(dt)
    node = decode_der(enc)
    assert decode_utc_time(node.value) == dt


def test_sequence_tree_parsing():
    seq = encode_sequence([
        encode_integer(100),
        encode_octet_string(b"secret-bytes"),
        encode_null(),
    ])
    tree = decode_der(seq)
    assert tree.tag == 0x30
    assert len(tree.children) == 3
    assert decode_integer(tree.children[0].value) == 100
    assert tree.children[1].value == b"secret-bytes"


def test_pem_der_conversions():
    data = b"\x01\x02\x03\x04\x05"
    pem = der_to_pem(data, "TEST BLOCK")
    assert "-----BEGIN TEST BLOCK-----" in pem
    assert "-----END TEST BLOCK-----" in pem
    recovered = pem_to_der(pem, "TEST BLOCK")
    assert recovered == data
