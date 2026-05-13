import json
from typing import Any

import pytest
from ops.testing import Harness

import charm  # loaded from src via conftest


class FakePrivateKey:
    def __str__(self) -> str:  # pragma: no cover
        return "FAKE-KEY"


class FakeCSR:
    def __init__(self, pem: str, sha: str):
        self._pem = pem
        self._sha = sha

    def __str__(self):
        return self._pem

    def get_sha256_hex(self) -> str:
        return self._sha


def _monkeypatch_key_and_csr(monkeypatch: pytest.MonkeyPatch, csr_pem: str, csr_sha: str):
    # Patch PrivateKey.generate to avoid cryptography
    monkeypatch.setattr(
        charm.PrivateKey,
        "generate",
        staticmethod(lambda *a, **kw: FakePrivateKey()),
        raising=True,
    )
    # Patch CSR generation to return a deterministic fake CSR
    def fake_generate_csr(self, *, private_key):  # type: ignore[override]
        return FakeCSR(csr_pem, csr_sha)

    monkeypatch.setattr(
        charm.CertificateRequestAttributes,
        "generate_csr",
        fake_generate_csr,
        raising=True,
    )


def _add_relations(h: Harness):
    legacy_rel_id = h.add_relation("legacy-certificates", "keystone")
    h.add_relation_unit(legacy_rel_id, "keystone/0")
    v4_rel_id = h.add_relation("certificates", "lego")
    return legacy_rel_id, v4_rel_id


def test_v1_single_server_request_enqueues_v4_csr(monkeypatch):
    h = Harness(charm.CertificateTranslatorCharm)
    h.begin()
    legacy_rel_id, v4_rel_id = _add_relations(h)

    # Fake crypto
    _monkeypatch_key_and_csr(monkeypatch, csr_pem="FAKE-CSR-PEM", csr_sha="hash123")

    # Ensure secret storage does not explode
    # Force model.get_secret to raise so charm uses unit.add_secret path
    def _raise_get_secret(*args: Any, **kwargs: Any):
        raise Exception("not found")

    h.charm.model.get_secret = _raise_get_secret  # type: ignore[assignment]
    h.charm.unit.add_secret = lambda content, label: None  # type: ignore[assignment]

    # Provide legacy v1 request (top-level single server cert)
    h.update_relation_data(
        legacy_rel_id,
        "keystone/0",
        {
            "common_name": "api.example.com",
            "sans": json.dumps(["api.example.com"]),
        },
    )

    # Assert CSR appended to v4 relation unit databag
    v4_unit_data = h.get_relation_data(v4_rel_id, h.charm.unit.name)
    csr_list = json.loads(v4_unit_data.get("certificate_signing_requests", "[]"))
    assert any(item.get("certificate_signing_request") == "FAKE-CSR-PEM" for item in csr_list)


def test_v4_certificate_publishes_back_to_v1(monkeypatch):
    h = Harness(charm.CertificateTranslatorCharm)
    h.begin()
    legacy_rel_id, v4_rel_id = _add_relations(h)

    # Prepare mapping: CSR hash -> legacy relation mapping record
    rec = charm.CsrRecord(
        csr_sha="hashX",
        csr_pem="FAKE-CSR",
        secret_label="tls-translator-key-hashX",
        legacy_relation_id=legacy_rel_id,
        legacy_unit_key="keystone_0",
        req_type="server",
        cn="api.example.com",
    )
    h.charm.state.csr_map = {rec.csr_sha: json.dumps(rec.__dict__)}

    # Patch certificate parsing to return expected sha for CSR PEM
    class FakeCSRParse:
        def __init__(self, pem):
            self._pem = pem

        def get_sha256_hex(self):
            return "hashX"

        @staticmethod
        def from_string(pem: str):  # type: ignore[override]
            return FakeCSRParse(pem)

    monkeypatch.setattr(charm, "CertificateSigningRequest", FakeCSRParse, raising=True)

    # Provide secret content for private-key lookup used in v1 publish
    class FakeSecret:
        def get_content(self, refresh=False):
            return {"private-key": "FAKE-KEY"}

    h.charm.model.get_secret = lambda label: FakeSecret()  # type: ignore[assignment]

    # Seed app bag to avoid top-level overwrite (force processed_requests path)
    h.update_relation_data(
        legacy_rel_id,
        h.charm.app.name,
        {"keystone_0.server.cert": "EXISTING", "keystone_0.server.key": "EXISTING"},
    )

    # Provider (v4) publishes certificate list in app databag
    provider_payload = [
        {
            "certificate_signing_request": "FAKE-CSR",
            "certificate": "CERT-PEM",
            "ca": "CA-PEM",
            "chain": ["CERT-PEM", "CA-PEM"],
        }
    ]
    h.update_relation_data(v4_rel_id, "lego", {"certificates": json.dumps(provider_payload)})

    # Verify CA and chain
    legacy_app_data = h.get_relation_data(legacy_rel_id, h.charm.app.name)
    legacy_unit_data = h.get_relation_data(legacy_rel_id, h.charm.unit.name)
    assert legacy_app_data.get("ca") == "CA-PEM"
    assert "CERT-PEM" in legacy_app_data.get("chain", "")
    assert "CA-PEM" in legacy_app_data.get("chain", "")
    assert legacy_unit_data.get("ca") == "CA-PEM"
    assert "CERT-PEM" in legacy_unit_data.get("chain", "")
    assert "CA-PEM" in legacy_unit_data.get("chain", "")

    # Verify processed_requests contains cert + key
    processed_key = "keystone_0.processed_requests"
    processed = json.loads(legacy_app_data.get(processed_key, "{}"))
    processed_unit = json.loads(legacy_unit_data.get(processed_key, "{}"))
    assert processed["api.example.com"]["cert"] == "CERT-PEM"
    assert processed["api.example.com"]["key"] == "FAKE-KEY"
    assert processed_unit["api.example.com"]["cert"] == "CERT-PEM"
    assert processed_unit["api.example.com"]["key"] == "FAKE-KEY"
