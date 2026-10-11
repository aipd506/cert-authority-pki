"""Pure Python standard library ASN.1 DER parser and serializer (TLV encoder/decoder)."""

from __future__ import annotations

import base64
import dataclasses
import datetime
import re
from typing import Sequence


class ASN1Error(Exception):
    """Base exception for ASN.1 DER encoding and decoding."""
    pass


# Universal ASN.1 Tags
TAG_BOOLEAN = 0x01
TAG_INTEGER = 0x02
TAG_BIT_STRING = 0x03
TAG_OCTET_STRING = 0x04
TAG_NULL = 0x05
TAG_OBJECT_IDENTIFIER = 0x06
TAG_UTF8_STRING = 0x0C
TAG_PRINTABLE_STRING = 0x13
TAG_IA5_STRING = 0x16
TAG_UTC_TIME = 0x17
TAG_GENERALIZED_TIME = 0x18
TAG_SEQUENCE = 0x30
TAG_SET = 0x31

# Standard Cryptographic OIDs
OID_RSA_ENCRYPTION = "1.2.840.113549.1.1.1"
OID_SHA256_WITH_RSA = "1.2.840.113549.1.1.11"
OID_COMMON_NAME = "2.5.4.3"
OID_COUNTRY_NAME = "2.5.4.6"
OID_ORGANIZATION_NAME = "2.5.4.10"
OID_ORGANIZATIONAL_UNIT_NAME = "2.5.4.11"
OID_BASIC_CONSTRAINTS = "2.5.29.19"
OID_KEY_USAGE = "2.5.29.15"
OID_EXT_KEY_USAGE = "2.5.29.37"
OID_SUBJECT_ALT_NAME = "2.5.29.17"
OID_SUBJECT_KEY_IDENTIFIER = "2.5.29.14"
OID_AUTHORITY_KEY_IDENTIFIER = "2.5.29.35"
OID_CRL_NUMBER = "2.5.29.20"
OID_CRL_REASON = "2.5.29.21"
OID_SERVER_AUTH = "1.3.6.1.5.5.7.3.1"
OID_CLIENT_AUTH = "1.3.6.1.5.5.7.3.2"
OID_CODE_SIGNING = "1.3.6.1.5.5.7.3.3"
OID_OCSP_BASIC = "1.3.6.1.5.5.7.48.1.1"


def encode_length(length: int) -> bytes:
    """Encode length according to DER rules."""
    if length < 128:
        return bytes([length])
    num_bytes = (length.bit_length() + 7) // 8
    return bytes([0x80 | num_bytes]) + length.to_bytes(num_bytes, "big")


def decode_length(data: bytes, offset: int = 0) -> tuple[int, int]:
    """Decode DER length at offset. Returns (length, new_offset)."""
    if offset >= len(data):
        raise ASN1Error("Unexpected EOF while decoding length")
    first = data[offset]
    offset += 1
    if first < 128:
        return first, offset
    num_bytes = first & 0x7F
    if num_bytes == 0:
        raise ASN1Error("Indefinite length not permitted in DER")
    if offset + num_bytes > len(data):
        raise ASN1Error("Unexpected EOF reading multi-byte length")
    length = int.from_bytes(data[offset : offset + num_bytes], "big")
    return length, offset + num_bytes


def encode_tlv(tag: int, value: bytes) -> bytes:
    """Encode tag, length, and value into DER bytes."""
    return bytes([tag]) + encode_length(len(value)) + value


def encode_boolean(val: bool) -> bytes:
    return encode_tlv(TAG_BOOLEAN, b"\xff" if val else b"\x00")


def encode_integer(val: int) -> bytes:
    """Encode an integer in signed two's complement DER format."""
    if val == 0:
        return encode_tlv(TAG_INTEGER, b"\x00")

    if val > 0:
        length = (val.bit_length() + 7) // 8
        b = val.to_bytes(length, "big")
        # If the most significant bit is set, prepend a 0x00 byte to keep it positive
        if b[0] & 0x80:
            b = b"\x00" + b
        return encode_tlv(TAG_INTEGER, b)
    else:
        # Negative integer representation
        length = (val.bit_length() + 8) // 8
        b = val.to_bytes(length, "big", signed=True)
        return encode_tlv(TAG_INTEGER, b)


def decode_integer(data: bytes) -> int:
    """Decode DER INTEGER value bytes to Python int."""
    if not data:
        raise ASN1Error("Empty integer value bytes")
    return int.from_bytes(data, "big", signed=bool(data[0] & 0x80))


def encode_bit_string(data: bytes, unused_bits: int = 0) -> bytes:
    return encode_tlv(TAG_BIT_STRING, bytes([unused_bits]) + data)


def encode_octet_string(data: bytes) -> bytes:
    return encode_tlv(TAG_OCTET_STRING, data)


def encode_null() -> bytes:
    return b"\x05\x00"


def encode_oid(oid_str: str) -> bytes:
    """Encode dot-delimited OID string to DER bytes."""
    arcs = [int(p) for p in oid_str.split(".")]
    if len(arcs) < 2 or arcs[0] > 2 or (arcs[0] < 2 and arcs[1] >= 40):
        raise ASN1Error(f"Invalid OID: {oid_str}")

    encoded = bytearray()
    # First byte is 40 * X + Y
    encoded.append(40 * arcs[0] + arcs[1])

    # Subsequent arcs are variable-length base-128
    for arc in arcs[2:]:
        if arc == 0:
            encoded.append(0)
            continue
        octets = []
        val = arc
        while val > 0:
            octets.append(val & 0x7F)
            val >>= 7
        octets.reverse()
        for i in range(len(octets) - 1):
            octets[i] |= 0x80
        encoded.extend(octets)

    return encode_tlv(TAG_OBJECT_IDENTIFIER, bytes(encoded))


def decode_oid(data: bytes) -> str:
    """Decode DER OID value bytes to dot-delimited string."""
    if not data:
        raise ASN1Error("Empty OID bytes")
    first = data[0]
    arc0 = first // 40
    arc1 = first % 40
    arcs = [arc0, arc1]

    val = 0
    for b in data[1:]:
        val = (val << 7) | (b & 0x7F)
        if not (b & 0x80):
            arcs.append(val)
            val = 0
    return ".".join(str(a) for a in arcs)


def encode_utf8_string(s: str) -> bytes:
    return encode_tlv(TAG_UTF8_STRING, s.encode("utf-8"))


def encode_printable_string(s: str) -> bytes:
    return encode_tlv(TAG_PRINTABLE_STRING, s.encode("ascii"))


def encode_ia5_string(s: str) -> bytes:
    return encode_tlv(TAG_IA5_STRING, s.encode("ascii"))


def encode_utc_time(dt: datetime.datetime) -> bytes:
    """Format YYMMDDHHMMSSZ."""
    dt_utc = dt.astimezone(datetime.timezone.utc)
    s = dt_utc.strftime("%y%m%d%H%M%SZ")
    return encode_tlv(TAG_UTC_TIME, s.encode("ascii"))


def decode_utc_time(data: bytes) -> datetime.datetime:
    s = data.decode("ascii")
    # YYMMDDHHMMSSZ
    return datetime.datetime.strptime(s, "%y%m%d%H%M%SZ").replace(tzinfo=datetime.timezone.utc)


def encode_generalized_time(dt: datetime.datetime) -> bytes:
    """Format YYYYMMDDHHMMSSZ."""
    dt_utc = dt.astimezone(datetime.timezone.utc)
    s = dt_utc.strftime("%Y%m%d%H%M%SZ")
    return encode_tlv(TAG_GENERALIZED_TIME, s.encode("ascii"))


def decode_generalized_time(data: bytes) -> datetime.datetime:
    s = data.decode("ascii")
    return datetime.datetime.strptime(s, "%Y%m%d%H%M%SZ").replace(tzinfo=datetime.timezone.utc)


def encode_sequence(items: Sequence[bytes]) -> bytes:
    return encode_tlv(TAG_SEQUENCE, b"".join(items))


def encode_set(items: Sequence[bytes]) -> bytes:
    return encode_tlv(TAG_SET, b"".join(items))


def encode_context_explicit(tag_number: int, content: bytes) -> bytes:
    """Constructed context-specific tag [tag_number]: 0xA0 | tag_number."""
    return encode_tlv(0xA0 | tag_number, content)


def encode_context_implicit(tag_number: int, content: bytes) -> bytes:
    """Primitive context-specific tag [tag_number]: 0x80 | tag_number."""
    return encode_tlv(0x80 | tag_number, content)


@dataclasses.dataclass
class ASN1Node:
    tag: int
    value: bytes
    children: list[ASN1Node] = dataclasses.field(default_factory=list)

    @property
    def is_constructed(self) -> bool:
        return bool(self.tag & 0x20)

    def to_der(self) -> bytes:
        if self.children and self.is_constructed:
            content = b"".join(c.to_der() for c in self.children)
            return encode_tlv(self.tag, content)
        return encode_tlv(self.tag, self.value)


def decode_der_node(data: bytes, offset: int = 0) -> tuple[ASN1Node, int]:
    """Parse one TLV element from data starting at offset."""
    if offset >= len(data):
        raise ASN1Error("Offset exceeds data length")
    tag = data[offset]
    offset += 1
    length, offset = decode_length(data, offset)
    if offset + length > len(data):
        raise ASN1Error(f"TLV length {length} exceeds buffer size at offset {offset}")

    val_bytes = data[offset : offset + length]
    new_offset = offset + length

    # Check if constructed (0x20 bit set) or Sequence/Set
    is_constructed = bool(tag & 0x20) or tag in (TAG_SEQUENCE, TAG_SET)
    children: list[ASN1Node] = []

    if is_constructed:
        sub_offset = 0
        while sub_offset < len(val_bytes):
            try:
                child_node, sub_offset = decode_der_node(val_bytes, sub_offset)
                children.append(child_node)
            except ASN1Error:
                break

    return ASN1Node(tag=tag, value=val_bytes, children=children), new_offset


def decode_der(data: bytes) -> ASN1Node:
    """Parse root ASN.1 DER tree."""
    node, _ = decode_der_node(data, 0)
    return node


def der_to_pem(der_bytes: bytes, header: str = "CERTIFICATE") -> str:
    """Convert binary DER bytes to standard PEM formatted text."""
    b64 = base64.b64encode(der_bytes).decode("ascii")
    lines = [b64[i : i + 64] for i in range(0, len(b64), 64)]
    return f"-----BEGIN {header}-----\n" + "\n".join(lines) + f"\n-----END {header}-----\n"


def pem_to_der(pem_str: str, header: str | None = None) -> bytes:
    """Extract binary DER bytes from PEM formatted text."""
    lines = pem_str.strip().splitlines()
    body_lines = []
    in_block = False

    for line in lines:
        line_clean = line.strip()
        if line_clean.startswith("-----BEGIN"):
            if header is None or header in line_clean:
                in_block = True
            continue
        elif line_clean.startswith("-----END"):
            if in_block:
                break
        elif in_block:
            body_lines.append(line_clean)

    if not body_lines:
        # Fallback if raw base64 string
        try:
            return base64.b64decode(pem_str.strip())
        except Exception as err:
            raise ASN1Error(f"Failed to extract PEM payload: {err}") from err

    b64_str = "".join(body_lines)
    return base64.b64decode(b64_str)
