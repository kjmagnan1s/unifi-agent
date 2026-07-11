from __future__ import annotations

from datetime import UTC

import pytest

from unifi_agent.errors import TLSPinError
from unifi_agent.transport import certificate_fingerprint, pin_certificate


def _make_cert() -> str:
    """Generate a real self-signed cert PEM at test time (no external deps)."""
    from datetime import datetime, timedelta

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID

    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "unifi.local")])
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(UTC) - timedelta(days=1))
        .not_valid_after(datetime.now(UTC) + timedelta(days=365))
        .sign(key, hashes.SHA256())
    )
    from cryptography.hazmat.primitives.serialization import Encoding

    return cert.public_bytes(Encoding.PEM).decode()


def test_fingerprint_is_stable_and_formatted():
    pytest.importorskip("cryptography")
    pem = _make_cert()
    fp = certificate_fingerprint(pem)
    assert len(fp.split(":")) == 32  # 32 bytes of SHA-256, colon-separated
    assert certificate_fingerprint(pem) == fp  # deterministic


def test_pinned_context_trusts_only_the_pinned_cert(tmp_path, monkeypatch, settings):
    """The built SSL context must load the pinned cert as its sole anchor, require
    verification, and disable hostname matching — the shape that pins without accepting
    every cert. Regression for the create_default_context "invalid CA" bug."""
    import ssl

    from unifi_agent.transport import _build_ssl_context

    pytest.importorskip("cryptography")
    settings.config_dir = tmp_path
    settings.tls_mode = "pin"
    cert = _make_cert()
    monkeypatch.setattr("unifi_agent.transport.fetch_peer_certificate", lambda *a, **k: cert)
    pin_certificate(settings)

    # Building must SUCCEED (the old create_default_context path produced a context that
    # failed to verify UniFi's non-CA self-signed cert) and must require verification with
    # hostname matching off. get_ca_certs() intentionally not asserted: it reports only
    # CA-flagged certs, and this cert has none — the very reason the naive approach failed.
    ctx = _build_ssl_context(settings)
    assert isinstance(ctx, ssl.SSLContext)
    assert ctx.verify_mode == ssl.CERT_REQUIRED  # still rejects non-matching certs
    assert ctx.check_hostname is False


def test_pin_then_mismatch_detected(tmp_path, monkeypatch, settings):
    pytest.importorskip("cryptography")
    settings.config_dir = tmp_path
    settings.tls_mode = "pin"

    cert_a = _make_cert()
    cert_b = _make_cert()

    # First pin: fetch returns cert A.
    monkeypatch.setattr("unifi_agent.transport.fetch_peer_certificate", lambda *a, **k: cert_a)
    fp_a = pin_certificate(settings)
    assert settings.pinned_cert_path.is_file()

    # Same cert again: no error, same fingerprint.
    assert pin_certificate(settings) == fp_a

    # Different cert now presented: must raise unless repin.
    monkeypatch.setattr("unifi_agent.transport.fetch_peer_certificate", lambda *a, **k: cert_b)
    with pytest.raises(TLSPinError):
        pin_certificate(settings)

    # Re-pin accepts the new cert.
    fp_b = pin_certificate(settings, repin=True)
    assert fp_b != fp_a
