"""Standard-library DER/X.509 certificate reader."""

from __future__ import annotations

from collections.abc import Callable
from datetime import datetime, timezone
import re
from typing import Any, Optional

from sot_validator.discovery._fingerprint_common import _DER_MAX_INPUT
from sot_validator.discovery._fingerprint_models import TlsCertificate


def _der_tlv(data: bytes, offset: int, end: int) -> tuple[int, int, int]:
    """Read one DER TLV header; return ``(tag, value_start, value_end)``."""
    if offset + 2 > end:
        raise ValueError("truncated DER element")
    tag = data[offset]
    if tag & 0x1F == 0x1F:
        raise ValueError("high-tag-number DER form is not supported")
    first_len = data[offset + 1]
    pos = offset + 2
    if first_len < 0x80:
        length = first_len
    else:
        num_bytes = first_len & 0x7F
        if num_bytes == 0 or num_bytes > 3 or pos + num_bytes > end:
            raise ValueError("unsupported DER length")
        length = int.from_bytes(data[pos : pos + num_bytes], "big")
        pos += num_bytes
    if pos + length > end:
        raise ValueError("DER length exceeds input")
    return tag, pos, pos + length


def _der_children(data: bytes, start: int, end: int) -> list[tuple[int, int, int]]:
    children: list[tuple[int, int, int]] = []
    offset = start
    while offset < end:
        tlv = _der_tlv(data, offset, end)
        children.append(tlv)
        offset = tlv[2]
    return children


def _der_expect(tlv: tuple[int, int, int], tag: int) -> tuple[int, int, int]:
    if tlv[0] != tag:
        raise ValueError(f"unexpected DER tag 0x{tlv[0]:02x}")
    return tlv


_DER_SEQUENCE = 0x30
_DER_SET = 0x31
_DER_INTEGER = 0x02
_DER_BIT_STRING = 0x03
_DER_OID = 0x06
_DER_OCTET_STRING = 0x04
_DER_UTC_TIME = 0x17
_DER_GENERALIZED_TIME = 0x18
_DER_EXTENSIONS = 0xA3
_DER_SAN_DNS_NAME = 0x82
_OID_COMMON_NAME = b"\x55\x04\x03"
_OID_SUBJECT_ALT_NAME = b"\x55\x1d\x11"
_DER_STRING_CODECS: dict[int, str] = {
    0x0C: "utf-8",
    0x13: "latin-1",
    0x14: "latin-1",
    0x16: "latin-1",
    0x1C: "utf-32-be",
    0x1E: "utf-16-be",
}
_DN_SHORT_NAMES: dict[str, str] = {
    "2.5.4.3": "CN",
    "2.5.4.6": "C",
    "2.5.4.7": "L",
    "2.5.4.8": "ST",
    "2.5.4.9": "STREET",
    "2.5.4.10": "O",
    "2.5.4.11": "OU",
    "0.9.2342.19200300.100.1.25": "DC",
    "0.9.2342.19200300.100.1.1": "UID",
}
_DN_SPECIAL_CHARS = frozenset(',+"\\<>;')
_SIGNATURE_ALGORITHM_NAMES: dict[str, str] = {
    "1.2.840.113549.1.1.5": "sha1WithRSAEncryption",
    "1.2.840.113549.1.1.11": "sha256WithRSAEncryption",
    "1.2.840.113549.1.1.12": "sha384WithRSAEncryption",
    "1.2.840.113549.1.1.13": "sha512WithRSAEncryption",
    "1.2.840.10045.4.1": "ecdsa-with-SHA1",
    "1.2.840.10045.4.3.2": "ecdsa-with-SHA256",
    "1.2.840.10045.4.3.3": "ecdsa-with-SHA384",
    "1.2.840.10045.4.3.4": "ecdsa-with-SHA512",
}
_OID_RSA_ENCRYPTION = "1.2.840.113549.1.1.1"
_OID_EC_PUBLIC_KEY = "1.2.840.10045.2.1"
_EC_CURVE_BITS: dict[str, int] = {
    "1.2.840.10045.3.1.7": 256,
    "1.3.132.0.34": 384,
    "1.3.132.0.35": 521,
}
_KEY_TYPE_NAMES: dict[str, str] = {
    "1.3.101.112": "Ed25519",
    "1.3.101.113": "Ed448",
    "1.2.840.10040.4.1": "DSA",
}
_UTC_TIME_RE = re.compile(r"([0-9]{2})([0-9]{2})([0-9]{2})([0-9]{2})([0-9]{2})([0-9]{2})Z")
_GENERALIZED_TIME_RE = re.compile(
    r"([0-9]{4})([0-9]{2})([0-9]{2})([0-9]{2})([0-9]{2})([0-9]{2})Z"
)


def _decode_oid(body: bytes) -> str:
    """Decode a DER OBJECT IDENTIFIER body into its dotted string form."""
    if not body or body[-1] & 0x80:
        raise ValueError("truncated OID")
    arcs: list[int] = []
    value = 0
    for byte in body:
        value = (value << 7) | (byte & 0x7F)
        if not byte & 0x80:
            arcs.append(value)
            value = 0
    first = arcs[0]
    if first < 40:
        head = [0, first]
    elif first < 80:
        head = [1, first - 40]
    else:
        head = [2, first - 80]
    return ".".join(str(arc) for arc in [*head, *arcs[1:]])


def _der_oid(data: bytes, tlv: tuple[int, int, int]) -> str:
    oid = _der_expect(tlv, _DER_OID)
    return _decode_oid(data[oid[1] : oid[2]])


def _escape_dn_value(value: str) -> str:
    """Escape one attribute value for an RFC 4514 DN string."""
    chars = ["\\" + ch if ch in _DN_SPECIAL_CHARS else ch for ch in value]
    if chars and chars[0] in ("#", " "):
        chars[0] = "\\" + chars[0]
    if len(chars) > 1 and chars[-1] == " ":
        chars[-1] = "\\ "
    return "".join(chars)


def _render_dn(data: bytes, name_tlv: tuple[int, int, int]) -> str:
    """Render an X.509 Name as an RFC 4514 string (RDNs in reverse DER order)."""
    name = _der_expect(name_tlv, _DER_SEQUENCE)
    rdns: list[str] = []
    for rdn in _der_children(data, name[1], name[2]):
        _der_expect(rdn, _DER_SET)
        attributes: list[str] = []
        for atv in _der_children(data, rdn[1], rdn[2]):
            _der_expect(atv, _DER_SEQUENCE)
            parts = _der_children(data, atv[1], atv[2])
            if len(parts) != 2:
                raise ValueError("malformed AttributeTypeAndValue")
            dotted = _der_oid(data, parts[0])
            label = _DN_SHORT_NAMES.get(dotted, dotted)
            codec = _DER_STRING_CODECS.get(parts[1][0])
            if codec is None:
                # The value TLV starts where the attribute type OID ends
                value = "#" + data[parts[0][2] : parts[1][2]].hex()
            else:
                value = _escape_dn_value(data[parts[1][1] : parts[1][2]].decode(codec))
            attributes.append(f"{label}={value}")
        rdns.append("+".join(attributes))
    return ",".join(reversed(rdns))


def _parse_der_time(data: bytes, tlv: tuple[int, int, int]) -> datetime:
    """Parse a UTCTime or GeneralizedTime ``...Z`` value into an aware UTC datetime."""
    text = data[tlv[1] : tlv[2]].decode("ascii")
    if tlv[0] == _DER_UTC_TIME:
        match = _UTC_TIME_RE.fullmatch(text)
        if match is None:
            raise ValueError("malformed UTCTime")
        year = int(match.group(1))
        year += 1900 if year >= 50 else 2000
    elif tlv[0] == _DER_GENERALIZED_TIME:
        match = _GENERALIZED_TIME_RE.fullmatch(text)
        if match is None:
            raise ValueError("malformed GeneralizedTime")
        year = int(match.group(1))
    else:
        raise ValueError("unsupported validity time type")
    month, day, hour, minute, second = (int(match.group(i)) for i in range(2, 7))
    return datetime(year, month, day, hour, minute, second, tzinfo=timezone.utc)


def _validity_time(
    data: bytes, validity_tlv: tuple[int, int, int], index: int
) -> datetime:
    validity = _der_expect(validity_tlv, _DER_SEQUENCE)
    times = _der_children(data, validity[1], validity[2])
    if len(times) != 2:
        raise ValueError("malformed Validity")
    return _parse_der_time(data, times[index])


def _signature_algorithm(data: bytes, algorithm_tlv: tuple[int, int, int]) -> str:
    algorithm = _der_expect(algorithm_tlv, _DER_SEQUENCE)
    parts = _der_children(data, algorithm[1], algorithm[2])
    dotted = _der_oid(data, parts[0])
    return _SIGNATURE_ALGORITHM_NAMES.get(dotted, dotted)


def _public_key(
    data: bytes, spki_tlv: tuple[int, int, int]
) -> tuple[str, Optional[int]]:
    """Return ``(key_type, key_bits)`` from a subjectPublicKeyInfo."""
    spki = _der_expect(spki_tlv, _DER_SEQUENCE)
    parts = _der_children(data, spki[1], spki[2])
    if len(parts) != 2:
        raise ValueError("malformed SubjectPublicKeyInfo")
    algorithm = _der_expect(parts[0], _DER_SEQUENCE)
    algorithm_parts = _der_children(data, algorithm[1], algorithm[2])
    dotted = _der_oid(data, algorithm_parts[0])
    bit_string = _der_expect(parts[1], _DER_BIT_STRING)
    if bit_string[1] >= bit_string[2] or data[bit_string[1]] != 0:
        raise ValueError("malformed public key BIT STRING")
    if dotted == _OID_RSA_ENCRYPTION:
        rsa_key = _der_expect(
            _der_tlv(data, bit_string[1] + 1, bit_string[2]), _DER_SEQUENCE
        )
        if rsa_key[2] != bit_string[2]:
            raise ValueError("trailing data after RSAPublicKey")
        rsa_parts = _der_children(data, rsa_key[1], rsa_key[2])
        if len(rsa_parts) != 2:
            raise ValueError("malformed RSAPublicKey")
        modulus = _der_expect(rsa_parts[0], _DER_INTEGER)
        # Unsigned read: a leading 0x00 sign byte adds no bits
        bits = int.from_bytes(data[modulus[1] : modulus[2]], "big").bit_length()
        if bits == 0:
            raise ValueError("empty RSA modulus")
        return "RSA", bits
    if dotted == _OID_EC_PUBLIC_KEY:
        curve_bits: Optional[int] = None
        if len(algorithm_parts) == 2 and algorithm_parts[1][0] == _DER_OID:
            curve_bits = _EC_CURVE_BITS.get(_der_oid(data, algorithm_parts[1]))
        return "EC", curve_bits
    return _KEY_TYPE_NAMES.get(dotted, dotted), None


def _guarded_read(reader: Callable[..., Any], *args: Any) -> Any:
    """Run one optional field reader; any malformed-DER error leaves the field unset."""
    try:
        return reader(*args)
    except (ValueError, IndexError):
        # UnicodeDecodeError is a ValueError subclass
        return None


def _read_certificate(data: bytes) -> dict[str, Any]:
    """Walk a DER X.509 certificate without recursion and return its fields.

    The CN/SAN walk is structural and raises on malformed input; every other
    field is read in its own guarded step and is ``None`` when it can't be read.
    """
    cert = _der_expect(_der_tlv(data, 0, len(data)), _DER_SEQUENCE)
    if cert[2] != len(data):
        raise ValueError("trailing data after certificate")
    cert_children = _der_children(data, cert[1], cert[2])
    if not cert_children:
        raise ValueError("empty certificate")
    tbs = _der_expect(cert_children[0], _DER_SEQUENCE)
    fields = _der_children(data, tbs[1], tbs[2])
    idx = 1 if fields and fields[0][0] == 0xA0 else 0
    # serialNumber, signature, issuer, validity, subject, subjectPublicKeyInfo
    if len(fields) < idx + 6:
        raise ValueError("truncated tbsCertificate")
    subject = _der_expect(fields[idx + 4], _DER_SEQUENCE)

    common_name: Optional[str] = None
    for rdn in _der_children(data, subject[1], subject[2]):
        _der_expect(rdn, _DER_SET)
        for atv in _der_children(data, rdn[1], rdn[2]):
            _der_expect(atv, _DER_SEQUENCE)
            parts = _der_children(data, atv[1], atv[2])
            if len(parts) != 2:
                raise ValueError("malformed AttributeTypeAndValue")
            oid = _der_expect(parts[0], _DER_OID)
            if common_name is None and data[oid[1] : oid[2]] == _OID_COMMON_NAME:
                codec = _DER_STRING_CODECS.get(parts[1][0])
                if codec is None:
                    raise ValueError("unsupported CN string type")
                common_name = data[parts[1][1] : parts[1][2]].decode(codec)

    san_names: list[str] = []
    for extra in fields[idx + 6 :]:
        if extra[0] != _DER_EXTENSIONS:
            continue
        ext_children = _der_children(data, extra[1], extra[2])
        if len(ext_children) != 1:
            raise ValueError("malformed extensions")
        ext_seq = _der_expect(ext_children[0], _DER_SEQUENCE)
        for ext in _der_children(data, ext_seq[1], ext_seq[2]):
            _der_expect(ext, _DER_SEQUENCE)
            ext_parts = _der_children(data, ext[1], ext[2])
            if len(ext_parts) < 2:
                raise ValueError("malformed Extension")
            oid = _der_expect(ext_parts[0], _DER_OID)
            if data[oid[1] : oid[2]] != _OID_SUBJECT_ALT_NAME:
                continue
            value = _der_expect(ext_parts[-1], _DER_OCTET_STRING)
            general_names = _der_children(data, value[1], value[2])
            if len(general_names) != 1:
                raise ValueError("malformed GeneralNames")
            names_seq = _der_expect(general_names[0], _DER_SEQUENCE)
            for gn in _der_children(data, names_seq[1], names_seq[2]):
                if gn[0] == _DER_SAN_DNS_NAME:
                    dns_name = data[gn[1] : gn[2]].decode("ascii")
                    if dns_name not in san_names:
                        san_names.append(dns_name)

    key = _guarded_read(_public_key, data, fields[idx + 5]) or (None, None)
    return {
        "subject_cn": common_name,
        "san_dns_names": san_names,
        "subject_dn": _guarded_read(_render_dn, data, fields[idx + 4]),
        "issuer_dn": _guarded_read(_render_dn, data, fields[idx + 2]),
        "not_before": _guarded_read(_validity_time, data, fields[idx + 3], 0),
        "not_after": _guarded_read(_validity_time, data, fields[idx + 3], 1),
        "signature_algorithm": _guarded_read(
            _signature_algorithm, data, cert_children[1]
        ),
        "key_type": key[0],
        "key_bits": key[1],
    }


def _read_certificate_bytes(der: Any) -> Optional[dict[str, Any]]:
    if not isinstance(der, (bytes, bytearray)) or not der or len(der) > _DER_MAX_INPUT:
        return None
    try:
        return _read_certificate(bytes(der))
    except (ValueError, IndexError):
        # UnicodeDecodeError is a ValueError subclass
        return None


def parse_tls_certificate(der: Any, ip: str, port: int) -> Optional[TlsCertificate]:
    """Read the leaf certificate details from DER bytes seen on ``ip:port``.

    Returns ``None`` for oversized or structurally malformed input; fields that
    can't be read individually are left as ``None``.
    """
    fields = _read_certificate_bytes(der)
    if fields is None:
        return None
    return TlsCertificate(ip=ip, port=port, **fields)


def _parse_der_certificate(der: Any) -> tuple[Optional[str], list[str]]:
    """Extract the subject CN and SAN dNSNames from a DER X.509 certificate.

    The reader walks the fixed X.509 structure without recursion and returns
    ``(None, [])`` for oversized or malformed input.
    """
    fields = _read_certificate_bytes(der)
    if fields is None:
        return None, []
    return fields["subject_cn"], fields["san_dns_names"]
