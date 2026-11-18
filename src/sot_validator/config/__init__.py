"""Unified TOML fleet configuration package."""

from __future__ import annotations

from sot_validator.config.loader import (
    AppConfig,
    ConfigError,
    DigestConfig,
    DigestSmtpConfig,
    DigestWebhookConfig,
    PolicyConfig,
    ProxmoxConfig,
    RetentionConfig,
    SecretValue,
    SiteConfig,
    SnmpProfile,
    VCenterConfig,
    load_config,
)

__all__ = [
    "AppConfig",
    "ConfigError",
    "DigestConfig",
    "DigestSmtpConfig",
    "DigestWebhookConfig",
    "PolicyConfig",
    "ProxmoxConfig",
    "RetentionConfig",
    "SecretValue",
    "SiteConfig",
    "SnmpProfile",
    "VCenterConfig",
    "load_config",
]
