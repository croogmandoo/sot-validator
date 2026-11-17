"""Tests for full TLS certificate capture and the lifecycle conversion helper.

The DER fixtures in `tests/fixtures/certs/` are built by the stdlib-only DER builder
below, with dummy keys and signatures. Regenerate them with
`UPDATE_CERT_FIXTURES=1 python3 -m pytest tests/test_certificate_capture.py`.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
import hashlib
import os
from pathlib import Path
import random
import socket
import ssl
from typing import Optional

import pytest

from sot_validator.discovery import (
    RawServiceBanner,
    ServiceBannerFingerprinter,
    TlsCertificate,
    parse_tls_certificate,
)
from sot_validator.lifecycle import CertificateInventory, certificate_records_from_tls

FIXTURE_DIR = Path(__file__).parent / "fixtures" / "certs"
UPDATE_ENV = "UPDATE_CERT_FIXTURES"
NOW = datetime(2026, 1, 1, 12, 0, tzinfo=timezone.utc)
IP = "10.42.1.10"

# The OpenSSL-made self-signed EC P-256 certificate also pinned in test_fingerprinter.py
TEST_CERT_PEM = """-----BEGIN CERTIFICATE-----
MIIB4jCCAYigAwIBAgIUCbsAauLZnCqieRjHG0OtnLQdOf0wCgYIKoZIzj0EAwIw
OTEbMBkGA1UECgwSU29UIFZhbGlkYXRvciBUZXN0MRowGAYDVQQDDBFwdmUwMS5s
YWIuZXhhbXBsZTAgFw0yNjExMTIxNTI2MzlaGA8yMTI2MTAxOTE1MjYzOVowOTEb
MBkGA1UECgwSU29UIFZhbGlkYXRvciBUZXN0MRowGAYDVQQDDBFwdmUwMS5sYWIu
ZXhhbXBsZTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABBnxVjbO80uFrhajQCe7
qeUBMKRhnYQjbQZphL/m+cTe09sq3Yh/tbaexEdgu/g8Nwhe/kEVkIShwHj9YoAv
34ejbDBqMB0GA1UdDgQWBBT73zhShYMT9XdAGOMl3H5MHh76fTAPBgNVHRMBAf8E
BTADAQH/MDgGA1UdEQQxMC+CEXB2ZTAxLmxhYi5leGFtcGxlggVwdmUwMYcECioB
CoINKi5sYWIuZXhhbXBsZTAKBggqhkjOPQQDAgNIADBFAiBDT7J2U2YtksahIkVD
IFEeHZpM1/bk23eo9o/Sluvh1QIhAOWylQFH947SuhnHFfAYp8f9XxIz9zYs7QoB
8PBoAPtB
-----END CERTIFICATE-----
"""


@pytest.fixture(autouse=True)
def no_outbound_connect(monkeypatch: pytest.MonkeyPatch):
    """Fail any test that attempts a real outbound socket connect."""
    attempts: list[tuple] = []

    def _blocked(self: socket.socket, *args, **kwargs):
        attempts.append(args)
        raise OSError("outbound connect blocked in certificate capture tests")

    monkeypatch.setattr(socket.socket, "connect", _blocked)
    monkeypatch.setattr(socket.socket, "connect_ex", _blocked)
    yield attempts
    assert attempts == [], f"unexpected outbound connect attempts: {attempts!r}"


# --- Stdlib DER builder ------------------------------------------------------

OID_CN = "2.5.4.3"
OID_O = "2.5.4.10"
OID_SAN = "2.5.29.17"
OID_RSA = "1.2.840.113549.1.1.1"
OID_EC = "1.2.840.10045.2.1"
OID_P384 = "1.3.132.0.34"
OID_SHA1_RSA = "1.2.840.113549.1.1.5"
OID_SHA256_RSA = "1.2.840.113549.1.1.11"
OID_ECDSA_SHA384 = "1.2.840.10045.4.3.3"

# P-384 base point G (SEC 2), uncompressed
P384_G = bytes.fromhex(
    "04"
    "aa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e082542a38"
    "5502f25dbf55296c3a545e3872760ab7"
    "3617de4a96262c6f5d9e98bf9292dc29f8f41dbd289a147ce9da3113b5f0b8c0"
    "0a60b1ce1d7e819d7a431d7c90ea0e5f"
)


def der_tlv(tag: int, body: bytes) -> bytes:
    n = len(body)
    if n < 0x80:
        length = bytes([n])
    else:
        raw = n.to_bytes((n.bit_length() + 7) // 8, "big")
        length = bytes([0x80 | len(raw)]) + raw
    return bytes([tag]) + length + body


def der_seq(*items: bytes) -> bytes:
    return der_tlv(0x30, b"".join(items))


def der_set(*items: bytes) -> bytes:
    return der_tlv(0x31, b"".join(items))


def der_oid(dotted: str) -> bytes:
    arcs = [int(a) for a in dotted.split(".")]
    body = bytearray()
    for arc in [arcs[0] * 40 + arcs[1], *arcs[2:]]:
        chunk = [arc & 0x7F]
        arc >>= 7
        while arc:
            chunk.append(0x80 | (arc & 0x7F))
            arc >>= 7
        body.extend(reversed(chunk))
    return der_tlv(0x06, bytes(body))


def der_int(value: int) -> bytes:
    body = value.to_bytes(value.bit_length() // 8 + 1, "big")
    return der_tlv(0x02, body)


def der_utf8(text: str) -> bytes:
    return der_tlv(0x0C, text.encode("utf-8"))


def der_utc_time(dt: datetime) -> bytes:
    return der_tlv(0x17, dt.strftime("%y%m%d%H%M%SZ").encode("ascii"))


def der_generalized_time(dt: datetime) -> bytes:
    return der_tlv(0x18, dt.strftime("%Y%m%d%H%M%SZ").encode("ascii"))


def der_name(rdns: Sequence[Sequence[tuple[str, bytes]]]) -> bytes:
    """Build a Name from RDNs in DER order; each attribute is ``(oid, value_tlv)``."""
    return der_seq(
        *(der_set(*(der_seq(der_oid(oid), value) for oid, value in rdn)) for rdn in rdns)
    )


def simple_name(cn: str, org: str = "SoT Validator Test") -> bytes:
    return der_name([[(OID_O, der_utf8(org))], [(OID_CN, der_utf8(cn))]])


def fake_modulus(bits: int, seed: str) -> int:
    """Deterministic odd integer of exactly ``bits`` bits (not a real RSA modulus)."""
    stream = b""
    counter = 0
    while len(stream) * 8 < bits:
        stream += hashlib.sha256(f"{seed}:{counter}".encode()).digest()
        counter += 1
    value = int.from_bytes(stream, "big") >> (len(stream) * 8 - bits)
    return value | (1 << (bits - 1)) | 1


def rsa_spki(bits: int, seed: str) -> bytes:
    rsa_key = der_seq(der_int(fake_modulus(bits, seed)), der_int(65537))
    return der_seq(
        der_seq(der_oid(OID_RSA), der_tlv(0x05, b"")),
        der_tlv(0x03, b"\x00" + rsa_key),
    )


def ec_spki(curve_param: bytes, point: bytes = P384_G) -> bytes:
    return der_seq(der_seq(der_oid(OID_EC), curve_param), der_tlv(0x03, b"\x00" + point))


def sig_alg(oid: str) -> bytes:
    if oid.startswith("1.2.840.10045."):
        return der_seq(der_oid(oid))
    return der_seq(der_oid(oid), der_tlv(0x05, b""))


def san_extension(dns_names: Sequence[str]) -> bytes:
    names = der_seq(*(der_tlv(0x82, n.encode("ascii")) for n in dns_names))
    return der_tlv(
        0xA3, der_seq(der_seq(der_oid(OID_SAN), der_tlv(0x04, names)))
    )


def build_certificate(
    *,
    serial: int,
    subject: bytes,
    issuer: bytes,
    not_before: bytes,
    not_after: bytes,
    spki: bytes,
    signature_oid: str = OID_SHA256_RSA,
    sans: Sequence[str] = (),
) -> bytes:
    algorithm = sig_alg(signature_oid)
    tbs = der_seq(
        der_tlv(0xA0, der_int(2)),
        der_int(serial),
        algorithm,
        issuer,
        der_seq(not_before, not_after),
        subject,
        spki,
        san_extension(sans),
    )
    dummy_signature = der_tlv(0x03, b"\x00" + hashlib.sha256(tbs).digest())
    return der_seq(tbs, algorithm, dummy_signature)


# --- Fixture definitions -----------------------------------------------------

ISSUER_DN = "CN=Fixture Issuing CA,O=SoT Validator Test"
DEFAULT_NOT_BEFORE = datetime(2025, 1, 1, tzinfo=timezone.utc)
DEFAULT_NOT_AFTER = datetime(2028, 1, 1, tzinfo=timezone.utc)


@dataclass
class FixtureCert:
    name: str
    cn: str
    sans: list[str]
    subject: bytes
    subject_dn: str
    issuer: bytes
    issuer_dn: str
    not_before: datetime
    not_after: datetime
    signature_algorithm: str
    key_type: str
    key_bits: int
    issues: list[str]
    spki: bytes = b""
    signature_oid: str = OID_SHA256_RSA
    generalized_not_after: bool = False
    extra: dict = field(default_factory=dict)

    def der(self) -> bytes:
        return build_certificate(
            serial=int.from_bytes(hashlib.sha256(self.name.encode()).digest()[:8], "big"),
            subject=self.subject,
            issuer=self.issuer,
            not_before=der_utc_time(self.not_before),
            not_after=(
                der_generalized_time(self.not_after)
                if self.generalized_not_after
                else der_utc_time(self.not_after)
            ),
            spki=self.spki or rsa_spki(self.key_bits, self.name),
            signature_oid=self.signature_oid,
            sans=self.sans,
        )


def _fixture(
    name: str,
    issues: list[str],
    *,
    self_signed: bool = False,
    not_after: datetime = DEFAULT_NOT_AFTER,
    key_bits: int = 2048,
    signature_oid: str = OID_SHA256_RSA,
    signature_algorithm: str = "sha256WithRSAEncryption",
) -> FixtureCert:
    cn = f"{name.replace('_', '-')}.fixture.example"
    subject = simple_name(cn)
    subject_dn = f"CN={cn},O=SoT Validator Test"
    return FixtureCert(
        name=name,
        cn=cn,
        sans=[cn, name.replace("_", "-")],
        subject=subject,
        subject_dn=subject_dn,
        issuer=subject if self_signed else simple_name("Fixture Issuing CA"),
        issuer_dn=subject_dn if self_signed else ISSUER_DN,
        not_before=DEFAULT_NOT_BEFORE,
        not_after=not_after,
        signature_algorithm=signature_algorithm,
        key_type="RSA",
        key_bits=key_bits,
        issues=issues,
        signature_oid=signature_oid,
    )


def _escaped_dn_fixture() -> FixtureCert:
    subject = simple_name("Foo, Inc", org="R+D Lab")
    dn = "CN=Foo\\, Inc,O=R\\+D Lab"
    return FixtureCert(
        name="escaped_dn",
        cn="Foo, Inc",
        sans=["foo.fixture.example"],
        subject=subject,
        subject_dn=dn,
        issuer=subject,
        issuer_dn=dn,
        not_before=DEFAULT_NOT_BEFORE,
        not_after=DEFAULT_NOT_AFTER,
        signature_algorithm="sha256WithRSAEncryption",
        key_type="RSA",
        key_bits=2048,
        issues=["self_signed"],
    )


def _ec_p384_fixture() -> FixtureCert:
    cert = _fixture("ec_p384", [])
    cert.not_after = datetime(2060, 1, 1, tzinfo=timezone.utc)
    cert.generalized_not_after = True
    cert.spki = ec_spki(der_oid(OID_P384))
    cert.signature_oid = OID_ECDSA_SHA384
    cert.signature_algorithm = "ecdsa-with-SHA384"
    cert.key_type = "EC"
    cert.key_bits = 384
    return cert


FIXTURES: dict[str, FixtureCert] = {
    cert.name: cert
    for cert in (
        _fixture("expired", ["expired"], not_after=datetime(2025, 12, 1, tzinfo=timezone.utc)),
        _fixture("near_expiry", ["expiring_30d"], not_after=NOW + timedelta(days=10)),
        _fixture("self_signed", ["self_signed"], self_signed=True),
        _fixture("rsa1024", ["rsa_key_lt_2048"], key_bits=1024),
        _fixture(
            "sha1",
            ["sha1_signature"],
            signature_oid=OID_SHA1_RSA,
            signature_algorithm="sha1WithRSAEncryption",
        ),
        _ec_p384_fixture(),
        _escaped_dn_fixture(),
    )
}


def _load(name: str) -> bytes:
    return (FIXTURE_DIR / f"{name}.der").read_bytes()


def test_fixture_files_match_builder() -> None:
    if os.environ.get(UPDATE_ENV) == "1":
        FIXTURE_DIR.mkdir(parents=True, exist_ok=True)
        for name, cert in FIXTURES.items():
            (FIXTURE_DIR / f"{name}.der").write_bytes(cert.der())
    assert sorted(p.stem for p in FIXTURE_DIR.glob("*.der")) == sorted(FIXTURES)
    for name, cert in FIXTURES.items():
        assert _load(name) == cert.der(), f"{name}.der differs from the builder output"


@pytest.mark.parametrize("name", sorted(FIXTURES))
def test_fixture_fields(name: str) -> None:
    expected = FIXTURES[name]
    cert = parse_tls_certificate(_load(name), IP, 443)
    assert cert is not None
    assert cert.ip == IP and cert.port == 443
    assert cert.subject_cn == expected.cn
    assert cert.subject_dn == expected.subject_dn
    assert cert.issuer_dn == expected.issuer_dn
    assert cert.san_dns_names == expected.sans
    assert cert.not_before == expected.not_before
    assert cert.not_after == expected.not_after
    assert cert.signature_algorithm == expected.signature_algorithm
    assert cert.key_type == expected.key_type
    assert cert.key_bits == expected.key_bits


def test_pem_reference_certificate_fields() -> None:
    cert = parse_tls_certificate(ssl.PEM_cert_to_DER_cert(TEST_CERT_PEM), IP, 8006)
    assert cert is not None
    assert cert.subject_dn == cert.issuer_dn == "CN=pve01.lab.example,O=SoT Validator Test"
    assert cert.subject_cn == "pve01.lab.example"
    assert cert.san_dns_names == ["pve01.lab.example", "pve01", "*.lab.example"]
    # notBefore is a UTCTime, notAfter a GeneralizedTime
    assert cert.not_before == datetime(2026, 11, 12, 15, 26, 39, tzinfo=timezone.utc)
    assert cert.not_after == datetime(2126, 10, 19, 15, 26, 39, tzinfo=timezone.utc)
    assert cert.signature_algorithm == "ecdsa-with-SHA256"
    assert cert.key_type == "EC"
    assert cert.key_bits == 256


# --- Independent cross-check against OpenSSL's decoder -----------------------

_OPENSSL_SHORT = {"commonName": "CN", "organizationName": "O"}


def _openssl_dn(rdns) -> str:
    def esc(value: str) -> str:
        out = "".join("\\" + c if c in ',+"\\<>;' else c for c in value)
        if out.startswith(("#", " ")):
            out = "\\" + out
        return out

    return ",".join(
        "+".join(f"{_OPENSSL_SHORT[k]}={esc(v)}" for k, v in rdn) for rdn in reversed(rdns)
    )


def _openssl_time(text: str) -> datetime:
    return datetime.strptime(" ".join(text.split()), "%b %d %H:%M:%S %Y %Z").replace(
        tzinfo=timezone.utc
    )


@pytest.mark.parametrize("name", [*sorted(FIXTURES), "pem"])
def test_cross_check_with_openssl_decoder(name: str, tmp_path: Path) -> None:
    decode = getattr(getattr(ssl, "_ssl", None), "_test_decode_cert", None)
    if decode is None:
        pytest.skip("ssl._ssl._test_decode_cert is not available")
    der = ssl.PEM_cert_to_DER_cert(TEST_CERT_PEM) if name == "pem" else _load(name)
    pem_path = tmp_path / "cert.pem"
    pem_path.write_text(ssl.DER_cert_to_PEM_cert(der), encoding="ascii")
    reference = decode(str(pem_path))
    cert = parse_tls_certificate(der, IP, 443)
    assert cert is not None
    assert cert.not_before == _openssl_time(reference["notBefore"])
    assert cert.not_after == _openssl_time(reference["notAfter"])
    assert cert.subject_dn == _openssl_dn(reference["subject"])
    assert cert.issuer_dn == _openssl_dn(reference["issuer"])
    assert cert.san_dns_names == [v for k, v in reference["subjectAltName"] if k == "DNS"]


# --- Conversion and evaluation ----------------------------------------------


@pytest.mark.parametrize("name", sorted(FIXTURES))
def test_fixture_evaluation_flags(name: str) -> None:
    cert = parse_tls_certificate(_load(name), IP, 443)
    records = certificate_records_from_tls([cert], site_id="S1")
    assert len(records) == 1
    record = records[0]
    assert (record.site_id, record.ip, record.port) == ("S1", IP, 443)
    assert record.issuer == cert.issuer_dn
    assert record.key_bits == cert.key_bits
    findings = CertificateInventory().evaluate(records, now=NOW)
    expected = FIXTURES[name].issues
    if expected:
        assert [f.issues for f in findings] == [expected]
    else:
        assert findings == []


def test_hostname_mismatch_from_sot_hostname() -> None:
    cert = parse_tls_certificate(_load("ec_p384"), IP, 443)
    mismatch = certificate_records_from_tls([cert], "S1", sot_hostname="other.example")
    findings = CertificateInventory().evaluate(mismatch, now=NOW)
    assert [f.issues for f in findings] == [["hostname_mismatch"]]
    match = certificate_records_from_tls(
        [cert], "S1", sot_hostname="ec-p384.fixture.example"
    )
    assert CertificateInventory().evaluate(match, now=NOW) == []


def test_conversion_keeps_order_and_validates_input() -> None:
    certs = [
        parse_tls_certificate(_load("sha1"), IP, 9443),
        parse_tls_certificate(_load("expired"), IP, 443),
    ]
    records = certificate_records_from_tls(iter(certs), "S1", sot_hostname="x")
    assert [r.port for r in records] == [9443, 443]
    assert all(r.sot_hostname == "x" for r in records)
    assert records[0].not_before == certs[0].not_before
    assert records[0].signature_algorithm == "sha1WithRSAEncryption"
    with pytest.raises(ValueError):
        certificate_records_from_tls([certs[0].to_dict()], "S1")
    with pytest.raises(ValueError):
        certificate_records_from_tls(certs, "  ")
    assert certificate_records_from_tls([], "S1") == []


# --- Partial failure ---------------------------------------------------------


def _variant(**overrides) -> bytes:
    values = dict(
        serial=7,
        subject=simple_name("variant.fixture.example"),
        issuer=simple_name("Fixture Issuing CA"),
        not_before=der_utc_time(DEFAULT_NOT_BEFORE),
        not_after=der_utc_time(DEFAULT_NOT_AFTER),
        spki=rsa_spki(2048, "variant"),
        sans=["variant.fixture.example"],
    )
    values.update(overrides)
    return build_certificate(**values)


def _parse_variant(**overrides) -> TlsCertificate:
    cert = parse_tls_certificate(_variant(**overrides), IP, 443)
    assert cert is not None
    assert cert.subject_cn == "variant.fixture.example"
    assert cert.san_dns_names == ["variant.fixture.example"]
    return cert


@pytest.mark.parametrize(
    "bad_time",
    [
        der_tlv(0x17, b"251301000000Z"),  # month 13
        der_tlv(0x17, b"2501010000Z"),  # too short
        der_tlv(0x17, b"250101000000"),  # no Z
        der_tlv(0x18, b"20250101000000.5Z"),  # fractional seconds
        der_tlv(0x18, b"20250230000000Z"),  # Feb 30
        der_tlv(0x0C, b"20250101000000Z"),  # wrong tag
        der_tlv(0x17, b"25010100000\xffZ"),  # non-ASCII
    ],
)
def test_invalid_not_before_leaves_other_fields(bad_time: bytes) -> None:
    cert = _parse_variant(not_before=bad_time)
    assert cert.not_before is None
    assert cert.not_after == DEFAULT_NOT_AFTER
    assert cert.issuer_dn == ISSUER_DN
    assert (cert.key_type, cert.key_bits) == ("RSA", 2048)
    assert cert.signature_algorithm == "sha256WithRSAEncryption"


def test_invalid_not_after_leaves_not_before() -> None:
    cert = _parse_variant(not_after=der_tlv(0x17, b"991399999999Z"))
    assert cert.not_after is None
    assert cert.not_before == DEFAULT_NOT_BEFORE


def test_utctime_century_rule() -> None:
    cert = _parse_variant(
        not_before=der_utc_time(datetime(1950, 1, 1, tzinfo=timezone.utc)),
        not_after=der_utc_time(datetime(2049, 12, 31, 23, 59, 59, tzinfo=timezone.utc)),
    )
    assert cert.not_before == datetime(1950, 1, 1, tzinfo=timezone.utc)
    assert cert.not_after == datetime(2049, 12, 31, 23, 59, 59, tzinfo=timezone.utc)


def test_unknown_signature_oid_is_dotted() -> None:
    cert = _parse_variant(signature_oid="1.2.3.4.5")
    assert cert.signature_algorithm == "1.2.3.4.5"
    assert (cert.key_type, cert.key_bits) == ("RSA", 2048)


def test_named_signature_and_key_oids() -> None:
    assert _parse_variant(signature_oid="1.2.840.10045.4.1").signature_algorithm == (
        "ecdsa-with-SHA1"
    )
    ed25519 = der_seq(der_seq(der_oid("1.3.101.112")), der_tlv(0x03, b"\x00" + b"\x11" * 32))
    assert (_parse_variant(spki=ed25519).key_type, _parse_variant(spki=ed25519).key_bits) == (
        "Ed25519",
        None,
    )
    p521 = _parse_variant(spki=ec_spki(der_oid("1.3.132.0.35")))
    assert (p521.key_type, p521.key_bits) == ("EC", 521)


def test_unknown_key_oid_is_dotted_without_bits() -> None:
    spki = der_seq(der_seq(der_oid("1.2.3.99")), der_tlv(0x03, b"\x00\x01\x02"))
    cert = _parse_variant(spki=spki)
    assert (cert.key_type, cert.key_bits) == ("1.2.3.99", None)


@pytest.mark.parametrize(
    "params", [der_oid("1.3.132.0.10"), der_tlv(0x05, b""), der_seq(der_int(1))]
)
def test_unnamed_ec_curve_has_no_bits(params: bytes) -> None:
    cert = _parse_variant(spki=ec_spki(params))
    assert (cert.key_type, cert.key_bits) == ("EC", None)


@pytest.mark.parametrize(
    "bit_string",
    [
        der_tlv(0x03, b""),  # empty
        der_tlv(0x03, b"\x07\x30\x00"),  # non-zero unused bits
        der_tlv(0x03, b"\x00\x30\x82\x01\x0a\x02"),  # truncated RSAPublicKey
        der_tlv(0x03, b"\x00garbage"),  # garbled
        der_tlv(0x03, b"\x00" + der_seq(der_int(65537))),  # one INTEGER only
        der_tlv(0x04, b"\x00" + der_seq(der_int(3), der_int(65537))),  # wrong tag
    ],
)
def test_garbled_spki_bit_string_clears_key_fields_only(bit_string: bytes) -> None:
    spki = der_seq(der_seq(der_oid(OID_RSA), der_tlv(0x05, b"")), bit_string)
    cert = _parse_variant(spki=spki)
    assert (cert.key_type, cert.key_bits) == (None, None)
    assert cert.issuer_dn == ISSUER_DN
    assert cert.not_before == DEFAULT_NOT_BEFORE
    assert cert.signature_algorithm == "sha256WithRSAEncryption"


def test_malformed_issuer_leaves_other_fields() -> None:
    cert = _parse_variant(issuer=der_seq(der_tlv(0x30, b"")))
    assert cert.issuer_dn is None
    assert cert.subject_dn == "CN=variant.fixture.example,O=SoT Validator Test"


# --- Robustness and untrusted text -------------------------------------------


def test_malformed_blobs_return_none() -> None:
    der = ssl.PEM_cert_to_DER_cert(TEST_CERT_PEM)
    rng = random.Random(64)
    blobs = [
        b"\x30\x82garbage",
        b"",
        rng.randbytes(20 * 1024),
        der[:-10],
        der + b"\x00",
        b"\x30\x80" + der,
    ]
    blobs.extend(b"\x30\x82" + rng.randbytes(rng.randint(0, 2048)) for _ in range(200))
    for blob in blobs:
        assert parse_tls_certificate(blob, IP, 443) is None
    for not_bytes in ("not-bytes", None, 42, [0x30], memoryview(der)):
        assert parse_tls_certificate(not_bytes, IP, 443) is None
    assert parse_tls_certificate(bytearray(der), IP, 443) is not None


def test_dn_text_is_cleaned_capped_and_hex_encoded() -> None:
    subject = der_name(
        [
            [(OID_O, der_utf8("Evil\x00\x1b[31m\r\nCorp"))],
            [(OID_CN, der_utf8("variant.fixture.example"))],
            [("1.2.3.4", der_tlv(0x02, b"\x01\x02"))],
        ]
    )
    cert = _parse_variant(subject=subject)
    assert cert.subject_dn == "1.2.3.4=#02020102,CN=variant.fixture.example,O=Evil[31m Corp"

    long_issuer = der_name([[(OID_CN, der_utf8("A" * 400 + " +#"))]])
    cert = _parse_variant(issuer=long_issuer)
    assert cert.issuer_dn == "CN=" + "A" * 253
    assert len(cert.issuer_dn) == 256

    escapes = der_name([[(OID_CN, der_utf8('#a"b<c>d;e\\f '))]])
    assert _parse_variant(issuer=escapes).issuer_dn == 'CN=\\#a\\"b\\<c\\>d\\;e\\\\f\\'
    assert _parse_variant(issuer=der_name([[(OID_CN, der_utf8(" x"))]])).issuer_dn == "CN=\\ x"


# --- TlsCertificate and RawServiceBanner -------------------------------------


def test_tls_certificate_round_trip_and_validation() -> None:
    cert = parse_tls_certificate(_load("ec_p384"), IP, 8443)
    assert TlsCertificate.from_dict(cert.to_dict()) == cert
    assert cert.to_dict()["not_after"] == "2060-01-01T00:00:00+00:00"

    naive = TlsCertificate(ip=" 10.0.0.1 ", port=1, not_before="2026-01-01T00:00:00")
    assert naive.ip == "10.0.0.1"
    assert naive.not_before == datetime(2026, 1, 1, tzinfo=timezone.utc)
    shifted = TlsCertificate(ip=IP, port=443, not_after="2026-01-01T02:00:00+02:00")
    assert shifted.not_after == datetime(2026, 1, 1, tzinfo=timezone.utc)
    assert shifted.not_after.tzinfo == timezone.utc

    for bad in (
        dict(ip="2001:db8::1", port=443),
        dict(ip="10.0.0.1", port=0),
        dict(ip="10.0.0.1", port=65536),
        dict(ip="10.0.0.1", port=True),
        dict(ip="10.0.0.1", port="443"),
        dict(ip="10.0.0.1", port=443, key_bits=True),
        dict(ip="10.0.0.1", port=443, key_bits="2048"),
        dict(ip="10.0.0.1", port=443, not_after="soon"),
        dict(ip="10.0.0.1", port=443, subject_cn=5),
        dict(ip="10.0.0.1", port=443, san_dns_names="a.example"),
    ):
        with pytest.raises(ValueError):
            TlsCertificate(**bad)
    with pytest.raises(ValueError):
        TlsCertificate.from_dict({"port": 443})


def test_raw_service_banner_round_trip_with_certificates() -> None:
    certs = [
        parse_tls_certificate(_load(n), IP, p) for n, p in (("sha1", 443), ("rsa1024", 8443))
    ]
    banner = RawServiceBanner(ip=IP, tls_subject_cn="x", tls_certificates=certs)
    data = banner.to_dict()
    assert [c["port"] for c in data["tls_certificates"]] == [443, 8443]
    assert RawServiceBanner.from_dict(data) == banner

    legacy = RawServiceBanner.from_dict({"ip": IP, "tls_subject_cn": "x"})
    assert legacy.tls_certificates == []
    assert RawServiceBanner.from_dict({"ip": IP, "tls_certificates": None}).tls_certificates == []

    many = [{"ip": IP, "port": p} for p in range(1, 40)]
    assert len(RawServiceBanner(ip=IP, tls_certificates=many).tls_certificates) == 16
    for bad in ("x", {"ip": IP, "port": 443}, [42], [("10.0.0.1", 443)], [{"ip": IP}]):
        with pytest.raises(ValueError):
            RawServiceBanner(ip=IP, tls_certificates=bad)


# --- Collector ---------------------------------------------------------------


def _no_http(ip, port, use_tls, timeout_sec):
    return None


def _collect(tls_fn, ports=(443, 8006, 8443)) -> RawServiceBanner:
    return ServiceBannerFingerprinter(tls_fn=tls_fn, http_fn=_no_http).collect(IP, list(ports))


def test_collector_records_certificate_objects_per_port() -> None:
    reference = {
        443: parse_tls_certificate(_load("sha1"), IP, 443),
        8006: parse_tls_certificate(_load("ec_p384"), "10.9.9.9", 1),  # wrong ip/port
        8443: parse_tls_certificate(_load("escaped_dn"), IP, 8443),
    }

    async def tls_fn(ip, port, timeout_sec):
        return reference[port]

    banner = _collect(tls_fn, ports=(8443, 443, 8006))
    assert [(c.ip, c.port) for c in banner.tls_certificates] == [
        (IP, 443),
        (IP, 8006),
        (IP, 8443),
    ]
    assert banner.tls_certificates[1].key_bits == 384
    assert banner.tls_certificates[1].issuer_dn == reference[8006].issuer_dn
    assert reference[8006].ip == "10.9.9.9"  # the callback's object is not mutated
    assert banner.tls_certificates[2].issuer_dn == "CN=Foo\\, Inc,O=R\\+D Lab"

    def pair_fn(ip, port, timeout_sec):
        cert = reference[port]
        return cert.subject_cn, cert.san_dns_names

    pair_banner = _collect(pair_fn, ports=(8443, 443, 8006))
    assert banner.tls_subject_cn == pair_banner.tls_subject_cn == "sha1.fixture.example"
    assert banner.tls_san_dns_names == pair_banner.tls_san_dns_names
    fingerprinter = ServiceBannerFingerprinter()
    assert fingerprinter.fingerprint(banner) == fingerprinter.fingerprint(pair_banner)


def test_collector_legacy_pairs_record_cn_and_sans_only() -> None:
    def tls_fn(ip, port, timeout_sec):
        return {
            443: ("pve01.lab.example", ["pve01.lab.example", "pve01", None, 5]),
            8006: (None, ["  ", "pve01.lab.example"]),
            8443: ("\x00\x01", []),
        }[port]

    banner = _collect(tls_fn)
    assert [c.to_dict() for c in banner.tls_certificates] == [
        TlsCertificate(
            ip=IP,
            port=443,
            subject_cn="pve01.lab.example",
            san_dns_names=["pve01.lab.example", "pve01"],
        ).to_dict(),
        TlsCertificate(ip=IP, port=8006, san_dns_names=["pve01.lab.example"]).to_dict(),
    ]
    assert banner.tls_certificates[0].issuer_dn is None
    assert banner.tls_certificates[0].not_after is None
    assert banner.tls_subject_cn == "pve01.lab.example"
    assert banner.tls_san_dns_names == ["pve01.lab.example", "pve01"]


def test_collector_ignores_empty_and_failed_results() -> None:
    results = {443: (None, []), 8006: None, 8443: "junk"}

    def tls_fn(ip, port, timeout_sec):
        return results[port]

    banner = _collect(tls_fn)
    assert banner.tls_certificates == []
    assert banner.tls_subject_cn is None

    def raising(ip, port, timeout_sec):
        raise RuntimeError("handshake failed")

    assert _collect(raising).tls_certificates == []


def test_collector_skips_entry_that_fails_validation() -> None:
    broken = TlsCertificate(ip="10.9.9.9", port=1, subject_cn="ok.example")
    broken.key_bits = "bad"  # mutated after validation; rebuilding raises

    def tls_fn(ip, port, timeout_sec):
        return broken if port == 443 else ("next.example", [])

    banner = _collect(tls_fn, ports=(443, 8006))
    assert [c.port for c in banner.tls_certificates] == [8006]
    assert banner.tls_subject_cn == "ok.example"


def test_merged_fields_unchanged_by_certificates() -> None:
    cert: Optional[TlsCertificate] = parse_tls_certificate(_load("self_signed"), IP, 443)
    plain = RawServiceBanner(ip=IP, tls_subject_cn=cert.subject_cn)
    with_certs = RawServiceBanner(
        ip=IP, tls_subject_cn=cert.subject_cn, tls_certificates=[cert]
    )
    fingerprinter = ServiceBannerFingerprinter()
    assert fingerprinter.fingerprint(plain) == fingerprinter.fingerprint(with_certs)
    # tls_certificates are not used for hostname extraction
    only_certs = RawServiceBanner(ip=IP, tls_certificates=[cert])
    assert fingerprinter.fingerprint(only_certs).discovered_hostname is None
