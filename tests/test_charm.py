import json

import pytest
from scenario import Context, Relation, Secret, State, StoredState

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
    monkeypatch.setattr(
        charm.PrivateKey,
        "generate",
        staticmethod(lambda *a, **kw: FakePrivateKey()),
        raising=True,
    )

    def fake_generate_csr(self, *, private_key):
        return FakeCSR(csr_pem, csr_sha)

    monkeypatch.setattr(
        charm.CertificateRequestAttributes,
        "generate_csr",
        fake_generate_csr,
        raising=True,
    )


def test_v1_single_server_request_enqueues_v4_csr(monkeypatch):
    _monkeypatch_key_and_csr(monkeypatch, csr_pem="FAKE-CSR-PEM", csr_sha="hash123")

    # Patch secret storage: make add_secret a no-op and get_secret raise
    monkeypatch.setattr(
        "ops.model.Unit.add_secret",
        lambda self, content, label: None,
    )
    monkeypatch.setattr(
        "ops.model.Model.get_secret",
        lambda self, **kwargs: (_ for _ in ()).throw(Exception("not found")),
    )

    legacy_rel = Relation(
        endpoint="legacy-certificates",
        remote_app_name="keystone",
        remote_units_data={
            0: {
                "common_name": "api.example.com",
                "sans": json.dumps(["api.example.com"]),
            },
        },
    )
    v4_rel = Relation(
        endpoint="certificates",
        remote_app_name="lego",
    )

    state_in = State(
        relations=[legacy_rel, v4_rel],
        leader=True,
    )

    ctx = Context(charm.CertificateTranslatorCharm)
    state_out = ctx.run(ctx.on.relation_changed(legacy_rel), state_in)

    # Assert CSR appended to v4 relation unit databag
    v4_out = state_out.get_relation(v4_rel.id)
    csr_list = json.loads(v4_out.local_unit_data.get("certificate_signing_requests", "[]"))
    assert any(item.get("certificate_signing_request") == "FAKE-CSR-PEM" for item in csr_list)


def test_v4_certificate_publishes_back_to_v1(monkeypatch):
    legacy_rel = Relation(
        endpoint="legacy-certificates",
        id=10,
        remote_app_name="keystone",
        remote_units_data={0: {}},
        local_app_data={
            "keystone_0.server.cert": "EXISTING",
            "keystone_0.server.key": "EXISTING",
        },
    )
    # v4 provider publishes certificate in app databag
    provider_payload = [
        {
            "certificate_signing_request": "FAKE-CSR",
            "certificate": "CERT-PEM",
            "ca": "CA-PEM",
            "chain": ["CERT-PEM", "CA-PEM"],
        }
    ]
    v4_rel = Relation(
        endpoint="certificates",
        id=20,
        remote_app_name="lego",
        remote_app_data={"certificates": json.dumps(provider_payload)},
    )

    # Prepare CSR mapping in StoredState
    rec = charm.CsrRecord(
        csr_sha="hashX",
        csr_pem="FAKE-CSR",
        secret_label="tls-translator-key-hashX",
        legacy_relation_id=legacy_rel.id,
        legacy_unit_key="keystone_0",
        req_type="server",
        cn="api.example.com",
    )
    stored = StoredState(
        name="state",
        owner_path="CertificateTranslatorCharm",
        content={"csr_map": {rec.csr_sha: json.dumps(rec.__dict__)}},
    )

    # Patch CSR parsing
    class FakeCSRParse:
        def __init__(self, pem):
            self._pem = pem

        def get_sha256_hex(self):
            return "hashX"

        @staticmethod
        def from_string(pem: str):
            return FakeCSRParse(pem)

    monkeypatch.setattr(charm, "CertificateSigningRequest", FakeCSRParse, raising=True)

    # Secret for private key lookup
    pk_secret = Secret(
        {"private-key": "FAKE-KEY"},
        owner="unit",
        label="tls-translator-key-hashX",
    )

    state_in = State(
        relations=[legacy_rel, v4_rel],
        secrets=[pk_secret],
        stored_states=[stored],
        leader=True,
    )

    ctx = Context(charm.CertificateTranslatorCharm)
    state_out = ctx.run(ctx.on.relation_changed(v4_rel), state_in)

    legacy_out = state_out.get_relation(legacy_rel.id)
    app_data = legacy_out.local_app_data
    unit_data = legacy_out.local_unit_data

    # Verify CA and chain
    assert app_data.get("ca") == "CA-PEM"
    assert "CERT-PEM" in app_data.get("chain", "")
    assert "CA-PEM" in app_data.get("chain", "")
    assert unit_data.get("ca") == "CA-PEM"
    assert "CERT-PEM" in unit_data.get("chain", "")
    assert "CA-PEM" in unit_data.get("chain", "")

    # Verify processed_requests contains cert + key
    processed_key = "keystone_0.processed_requests"
    processed = json.loads(app_data.get(processed_key, "{}"))
    processed_unit = json.loads(unit_data.get(processed_key, "{}"))
    assert processed["api.example.com"]["cert"] == "CERT-PEM"
    assert processed["api.example.com"]["key"] == "FAKE-KEY"
    assert processed_unit["api.example.com"]["cert"] == "CERT-PEM"
    assert processed_unit["api.example.com"]["key"] == "FAKE-KEY"
