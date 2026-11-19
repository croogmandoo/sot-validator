"""Tests for the fingerprinter facade: re-exported names and module size limit."""

from __future__ import annotations

from pathlib import Path

import pytest

import sot_validator.discovery as discovery
import sot_validator.discovery._fingerprint_common as fingerprint_common
import sot_validator.discovery._fingerprint_der as fingerprint_der
import sot_validator.discovery._fingerprint_engine as fingerprint_engine
import sot_validator.discovery._fingerprint_models as fingerprint_models
import sot_validator.discovery._fingerprint_signatures as fingerprint_signatures
import sot_validator.discovery._fingerprint_transport as fingerprint_transport
import sot_validator.discovery.fingerprinter as fingerprinter

DISCOVERY_DIR = Path(__file__).resolve().parents[1] / "src" / "sot_validator" / "discovery"

REEXPORTED_NAMES = [
    ("SSH_BANNER_PORTS", fingerprint_common),
    ("HTTP_BANNER_PORTS", fingerprint_common),
    ("TLS_BANNER_PORTS", fingerprint_common),
    ("TlsCertificate", fingerprint_models),
    ("RawServiceBanner", fingerprint_models),
    ("DeviceFingerprint", fingerprint_models),
    ("ServiceBannerFingerprinter", fingerprint_engine),
    ("parse_tls_certificate", fingerprint_der),
    ("_SIGNATURES", fingerprint_signatures),
    ("_parse_der_certificate", fingerprint_der),
    ("_parse_http_response", fingerprint_transport),
]

PACKAGE_NAMES = [
    "SSH_BANNER_PORTS",
    "HTTP_BANNER_PORTS",
    "TLS_BANNER_PORTS",
    "DeviceFingerprint",
    "RawServiceBanner",
    "ServiceBannerFingerprinter",
    "TlsCertificate",
    "parse_tls_certificate",
]


@pytest.mark.parametrize(
    ("name", "module"), REEXPORTED_NAMES, ids=[name for name, _ in REEXPORTED_NAMES]
)
def test_name_importable_from_fingerprinter(name: str, module: object) -> None:
    namespace: dict[str, object] = {}
    exec(f"from sot_validator.discovery.fingerprinter import {name}", namespace)
    assert namespace[name] is getattr(module, name)


@pytest.mark.parametrize("name", PACKAGE_NAMES)
def test_package_export_is_facade_object(name: str) -> None:
    assert getattr(discovery, name) is getattr(fingerprinter, name)


def test_fingerprinter_defines_no_all() -> None:
    assert not hasattr(fingerprinter, "__all__")


def test_fingerprinter_modules_under_800_lines() -> None:
    private = sorted(DISCOVERY_DIR.glob("_fingerprint_*.py"))
    assert [path.name for path in private] == [
        "_fingerprint_common.py",
        "_fingerprint_der.py",
        "_fingerprint_engine.py",
        "_fingerprint_models.py",
        "_fingerprint_signatures.py",
        "_fingerprint_transport.py",
    ]
    for path in [DISCOVERY_DIR / "fingerprinter.py", *private]:
        line_count = len(path.read_text(encoding="utf-8").splitlines())
        assert line_count < 800, f"{path.name} has {line_count} lines"
