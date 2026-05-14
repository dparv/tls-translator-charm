#!/usr/bin/env python3

import ipaddress
import json
import logging
from dataclasses import dataclass, asdict
from typing import Dict, List, Optional

from charmlibs.interfaces.tls_certificates import (
    Certificate,
    CertificateRequestAttributes,
    CertificateSigningRequest,
    PrivateKey,
    TLSCertificatesRequiresV4,
)
from ops import main
from ops.charm import CharmBase
from ops.framework import StoredState
from ops.model import ActiveStatus, BlockedStatus, MaintenanceStatus, Relation, Unit

logger = logging.getLogger(__name__)


LEGACY_CA_KEY = "ca"
LEGACY_CHAIN_KEY = "chain"

RFC1918_NETWORKS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
]


def _is_rfc1918_ip(value: str) -> bool:
    try:
        addr = ipaddress.ip_address(value)
        return any(addr in net for net in RFC1918_NETWORKS)
    except ValueError:
        return False


def _is_non_public_domain(value: str) -> bool:
    if value.endswith(".lxd"):
        return True
    if _is_rfc1918_ip(value):
        return True
    return False


def _filter_non_public_sans(sans: List[str]) -> List[str]:
    return [s for s in sans if not _is_non_public_domain(s)]


def _request_has_valid_identifiers(req: "V1Request") -> bool:
    if not _is_non_public_domain(req.cn):
        return True
    filtered_sans = _filter_non_public_sans(req.sans)
    return len(filtered_sans) > 0


@dataclass
class V1Request:
    # type: 'server' | 'client' | 'application'
    req_type: str
    # legacy unit requesting (unit name encoded with '/' -> '_')
    unit_key: str
    # common name for the certificate
    cn: str
    # list of SANs (strings, DNS/IP)
    sans: List[str]
    # whether this is the top-level single server request (special fields)
    is_top_level_server: bool = False


@dataclass
class CsrRecord:
    # sha256 of the CSR (hex) for quick mapping (derived at runtime)
    csr_sha: str
    # raw CSR as PEM
    csr_pem: str
    # secret label storing the private key
    secret_label: str
    # legacy relation id and addressing info
    legacy_relation_id: int
    legacy_unit_key: str
    req_type: str
    cn: str
    # SANs for reconstructing certificate requests
    sans: List[str] = None


class CertificateTranslatorCharm(CharmBase):
    state = StoredState()

    def __init__(self, *args):
        super().__init__(*args)
        # Stored mappings: csr_sha -> CsrRecord (dict serialized as JSON)
        self.state.set_default(csr_map={})

        # Build the current list of certificate requests from stored state
        certificate_requests = self._build_certificate_requests_from_state()

        # v4 side: delegate CSR lifecycle to TLSCertificatesRequiresV4
        self.tls = TLSCertificatesRequiresV4(
            charm=self,
            relationship_name="certificates",
            certificate_requests=certificate_requests,
        )

        # Listen for certificates coming back from the v4 provider
        self.framework.observe(
            self.tls.on.certificate_available, self._on_certificate_available
        )

        # Legacy v1 side: provider
        self.framework.observe(
            self.on["legacy-certificates"].relation_changed,
            self._on_legacy_relation_changed,
        )
        self.framework.observe(
            self.on["legacy-certificates"].relation_broken,
            self._on_legacy_relation_broken,
        )

        self.framework.observe(self.on.install, self._on_install)
        self.framework.observe(self.on.update_status, self._on_update_status)
        self.framework.observe(self.on.start, self._on_start)
        self.framework.observe(self.on.config_changed, self._on_config_changed)

    def _on_install(self, _):
        self.unit.status = MaintenanceStatus("initializing")

    def _on_start(self, _):
        self._backfill_legacy_unit_bags()
        self._refresh_v4_certificate_requests()
        self._update_status()

    def _on_config_changed(self, _):
        self._backfill_legacy_unit_bags()
        self._refresh_v4_certificate_requests()
        self._update_status()

    def _on_update_status(self, _):
        if not self.model.relations.get("certificates"):
            self.unit.status = BlockedStatus("relate to a v4 TLS certificates provider")
            return
        if not self.model.relations.get("legacy-certificates"):
            self.unit.status = BlockedStatus("awaiting legacy tls-certificates requirers")
            return
        self.unit.status = ActiveStatus("bridge operational")

    # ----------------------------- Legacy v1 side -----------------------------
    def _on_legacy_relation_changed(self, event):
        rel: Relation = event.relation
        logger.debug("v1 relation-changed: %s", rel.id)
        # Process legacy requests and create CSRs in v4 relation
        try:
            requests = self._collect_legacy_requests(rel)
        except Exception as e:
            logger.exception("failed to parse legacy requests: %s", e)
            self.unit.status = BlockedStatus("invalid v1 request data")
            return

        if not requests:
            # Nothing to do
            return

        # Ensure v4 relation exists
        v4_rel = self._get_v4_relation()
        if not v4_rel:
            self.unit.status = BlockedStatus("relate :certificates to a v4 provider (lego)")
            return

        # For each outstanding legacy request, generate key + CSR and publish to v4
        for req in requests:
            if self._legacy_request_already_handled(rel, req):
                continue
            if not _request_has_valid_identifiers(req):
                logger.warning(
                    "skipping request CN=%s: no valid public identifiers (all are RFC1918 IP or .lxd domain)",
                    req.cn,
                )
                continue
            if self._csr_for_request_exists(rel.id, req):
                continue
            filtered_req = V1Request(
                req_type=req.req_type,
                unit_key=req.unit_key,
                cn=req.cn if not _is_non_public_domain(req.cn) else req.sans[0] if req.sans else req.cn,
                sans=_filter_non_public_sans(req.sans),
                is_top_level_server=req.is_top_level_server,
            )
            if _is_non_public_domain(filtered_req.cn):
                logger.warning(
                    "skipping request: CN=%s is non-public and no valid SANs available",
                    req.cn,
                )
                continue
            self._create_and_publish_v4_csr(rel, v4_rel, filtered_req)

        # No immediate response on v1; we'll update v1 when certificates arrive on v4

    def _on_legacy_relation_broken(self, event):
        # Clean up any CSR mappings for this relation
        rel_id = event.relation.id
        csr_map = dict(self.state.csr_map)
        to_delete = [k for k, v in csr_map.items() if json.loads(v)["legacy_relation_id"] == rel_id]
        for key in to_delete:
            del csr_map[key]
        self.state.csr_map = csr_map
        # Refresh v4 requests to remove orphaned CSRs
        self._refresh_v4_certificate_requests()

    # Parse requests from the v1 interface (reactive schema)
    def _collect_legacy_requests(self, rel: Relation) -> List[V1Request]:
        reqs: List[V1Request] = []
        # Per-unit requests
        for unit in rel.units:
            reqs.extend(self._parse_unit_requests(rel, unit))
        # Application-scoped (aggregated) requests
        reqs.extend(self._parse_application_requests(rel))
        return reqs

    def _parse_unit_requests(self, rel: Relation, unit: Unit) -> List[V1Request]:
        data_raw = rel.data[unit]
        data_json = _json_view(data_raw)
        unit_name_key = data_raw.get("unit_name") or unit.name.replace("/", "_")
        out: List[V1Request] = []

        # First/top-level server cert request (back-compat fields)
        cn = data_raw.get("common_name")
        sans = data_json.get("sans") or []
        if cn:
            out.append(
                V1Request(
                    req_type="server",
                    unit_key=unit_name_key,
                    cn=cn,
                    sans=list(sans),
                    is_top_level_server=True,
                )
            )

        # Multi server cert requests
        cert_reqs = data_json.get("cert_requests") or {}
        for common_name, payload in cert_reqs.items():
            out.append(
                V1Request(
                    req_type="server",
                    unit_key=unit_name_key,
                    cn=common_name,
                    sans=list(payload.get("sans", [])),
                    is_top_level_server=False,
                )
            )

        # Client cert requests
        client_reqs = data_json.get("client_cert_requests") or {}
        for common_name, payload in client_reqs.items():
            out.append(
                V1Request(
                    req_type="client",
                    unit_key=unit_name_key,
                    cn=common_name,
                    sans=list(payload.get("sans", [])),
                )
            )
        return out

    def _parse_application_requests(self, rel: Relation) -> List[V1Request]:
        # Aggregate all units' app requests by common_name
        aggregate: Dict[str, List[str]] = {}
        for unit in rel.units:
            data_json = _json_view(rel.data[unit])
            app_reqs = data_json.get("application_cert_requests") or {}
            for cn, payload in app_reqs.items():
                items = aggregate.setdefault(cn, [])
                items.append(cn)
                items.extend(list(payload.get("sans", [])))
        out: List[V1Request] = []
        if not aggregate:
            return out
        # Use leader's unit_key for placement of processed application result back per unit
        unit_key = self.unit.name.replace("/", "_")
        for cn, sans in aggregate.items():
            # de-duplicate and sort for stability
            uniq_sans = sorted(set(sans))
            out.append(V1Request(req_type="application", unit_key=unit_key, cn=cn, sans=uniq_sans))
        return out

    def _legacy_request_already_handled(self, rel: Relation, req: V1Request) -> bool:
        # Check if a response has already been written to v1 provider side
        if req.req_type == "server":
            if req.is_top_level_server:
                cert = self._legacy_value(rel, f"{req.unit_key}.server.cert")
                key = self._legacy_value(rel, f"{req.unit_key}.server.key")
                return bool(cert and key)
            # processed_requests JSON
            processed = self._legacy_json(rel, f"{req.unit_key}.processed_requests")
            return req.cn in processed and processed[req.cn].get("cert") and processed[req.cn].get("key")
        if req.req_type == "client":
            processed = self._legacy_json(rel, f"{req.unit_key}.processed_client_requests")
            return req.cn in processed and processed[req.cn].get("cert") and processed[req.cn].get("key")
        if req.req_type == "application":
            processed = self._legacy_json(rel, f"{req.unit_key}.processed_application_requests")
            app_data = processed.get("app_data") or {}
            return bool(app_data.get("cert") and app_data.get("key"))
        return False

    def _csr_for_request_exists(self, legacy_rel_id: int, req: V1Request) -> bool:
        map_key = f"{legacy_rel_id}:{req.unit_key}:{req.req_type}:{req.cn}"
        return map_key in self.state.csr_map

    def _create_and_publish_v4_csr(self, legacy_rel: Relation, v4_rel: Relation, req: V1Request):
        # Build certificate request attributes for this legacy request
        attrs = CertificateRequestAttributes(
            common_name=req.cn,
            sans_dns=set(req.sans) if req.sans else None,
        )

        # Persist mapping (use CN as key since the library manages CSR generation)
        rec = CsrRecord(
            csr_sha="",  # Will be populated when certificate arrives
            csr_pem="",  # Managed by the library
            secret_label="",  # Private key managed by the library
            legacy_relation_id=legacy_rel.id,
            legacy_unit_key=req.unit_key,
            req_type=req.req_type,
            cn=req.cn,
            sans=req.sans,
        )
        # Use a stable key based on legacy relation + unit + type + cn
        map_key = f"{legacy_rel.id}:{req.unit_key}:{req.req_type}:{req.cn}"
        m = dict(self.state.csr_map)
        m[map_key] = json.dumps(asdict(rec))
        self.state.csr_map = m

        # Update the library's certificate requests and trigger sync
        self._refresh_v4_certificate_requests()
        logger.info("queued CSR for CN=%s on v4 via library sync", req.cn)

    def _on_certificate_available(self, event):
        """Handle certificate_available events from the v4 library."""
        csr = event.certificate_signing_request
        cert_pem = str(event.certificate)
        ca_pem = str(event.ca)
        chain_list = [str(c) for c in event.chain]

        # Find the matching legacy record by matching the CSR's CN/SANs
        csr_attrs = CertificateRequestAttributes.from_csr(csr, is_ca=False)
        rec = self._lookup_record_by_attrs(csr_attrs)
        if not rec:
            logger.debug("No legacy mapping found for certificate CN=%s", csr_attrs.common_name)
            return

        # Get private key from the library
        private_key = self.tls.get_private_key()
        if not private_key:
            logger.warning("Private key not available from v4 library")
            return

        self._publish_to_legacy(rec, cert_pem, ca_pem, chain_list, str(private_key))

    def _lookup_record_by_attrs(self, attrs: CertificateRequestAttributes) -> Optional[CsrRecord]:
        """Find a CsrRecord matching the given certificate request attributes."""
        for payload in self.state.csr_map.values():
            rec = CsrRecord(**json.loads(payload))
            if rec.cn == attrs.common_name:
                return rec
        return None

    def _build_certificate_requests_from_state(self) -> list:
        """Build CertificateRequestAttributes list from stored csr_map."""
        requests = []
        seen = set()
        for payload in self.state.csr_map.values():
            rec = CsrRecord(**json.loads(payload))
            if rec.cn not in seen:
                seen.add(rec.cn)
                sans = rec.sans if rec.sans else None
                requests.append(CertificateRequestAttributes(
                    common_name=rec.cn,
                    sans_dns=set(sans) if sans else None,
                ))
        return requests

    def _refresh_v4_certificate_requests(self):
        """Update the library's certificate requests from state and trigger sync."""
        from charmlibs.interfaces.tls_certificates import Mode
        requests = self._build_certificate_requests_from_state()
        self.tls.certificate_requests = requests
        self.tls._certificate_mode_map = {r: Mode.UNIT for r in requests}
        self.tls.sync()

    def _update_status(self):
        if not self.model.relations.get("certificates"):
            self.unit.status = BlockedStatus("relate to a v4 TLS certificates provider")
            return
        if not self.model.relations.get("legacy-certificates"):
            self.unit.status = BlockedStatus("awaiting legacy tls-certificates requirers")
            return
        self.unit.status = ActiveStatus("bridge operational")

    # ------------------------------- v4 side ---------------------------------

    def _publish_to_legacy(
        self, rec: CsrRecord, cert_pem: str, ca_pem: str, chain_list: List[str],
        key_pem: str,
    ) -> None:
        legacy_rel = self.model.get_relation("legacy-certificates", rec.legacy_relation_id)
        if not legacy_rel:
            logger.warning("legacy relation %s not found for CSR %s", rec.legacy_relation_id, rec.csr_sha)
            return

        # Publish CA/chain globally (v1 expects one CA+chain across clients)
        for bag in self._legacy_write_bags(legacy_rel):
            bag[LEGACY_CA_KEY] = ca_pem
        # Concatenate chain as PEM string for v1 consumers
        concatenated_chain = "".join(cert if cert.endswith("\n") else cert + "\n" for cert in chain_list)
        for bag in self._legacy_write_bags(legacy_rel):
            bag[LEGACY_CHAIN_KEY] = concatenated_chain

        # Publish certificate and key according to request type
        if rec.req_type == "server":
            if self._is_top_level_for(rec, legacy_rel):
                for bag in self._legacy_write_bags(legacy_rel):
                    bag[f"{rec.legacy_unit_key}.server.cert"] = cert_pem
                    bag[f"{rec.legacy_unit_key}.server.key"] = key_pem
            else:
                processed_key = f"{rec.legacy_unit_key}.processed_requests"
                current = self._legacy_json(legacy_rel, processed_key)
                current[rec.cn] = {"cert": cert_pem, "key": key_pem}
                payload = json.dumps(current)
                for bag in self._legacy_write_bags(legacy_rel):
                    bag[processed_key] = payload
        elif rec.req_type == "client":
            processed_key = f"{rec.legacy_unit_key}.processed_client_requests"
            current = self._legacy_json(legacy_rel, processed_key)
            current[rec.cn] = {"cert": cert_pem, "key": key_pem}
            payload = json.dumps(current)
            for bag in self._legacy_write_bags(legacy_rel):
                bag[processed_key] = payload
        elif rec.req_type == "application":
            # Write app cert to all units (schema requires per-unit publish)
            for unit in legacy_rel.units:
                unit_key = (legacy_rel.data[unit].get("unit_name") or unit.name).replace("/", "_")
                processed_key = f"{unit_key}.processed_application_requests"
                data = self._legacy_json(legacy_rel, processed_key)
                data["app_data"] = {"cert": cert_pem, "key": key_pem}
                payload = json.dumps(data)
                for bag in self._legacy_write_bags(legacy_rel):
                    bag[processed_key] = payload

        logger.info(
            "published translated cert to legacy relation %s for %s (%s)",
            rec.legacy_relation_id,
            rec.cn,
            rec.req_type,
        )

    def _is_top_level_for(self, rec: CsrRecord, rel: Relation) -> bool:
        # If the incoming request was the single-server top-level, we would have seen it earlier
        # We can't directly infer here; assume top-level if a matching top-level CN is present.
        # Safe default: prefer processed_requests; only set top-level if unset.
        key_cert = self._legacy_value(rel, f"{rec.legacy_unit_key}.server.cert")
        key_key = self._legacy_value(rel, f"{rec.legacy_unit_key}.server.key")
        return not (key_cert or key_key)

    # ------------------------------- Helpers ---------------------------------
    def _get_v4_relation(self) -> Optional[Relation]:
        rels = self.model.relations.get("certificates", [])
        return rels[0] if rels else None

    def _backfill_legacy_unit_bags(self):
        for rel in self.model.relations.get("legacy-certificates", []):
            self._backfill_legacy_unit_bag(rel)

    def _backfill_legacy_unit_bag(self, rel: Relation):
        app_bag = rel.data[self.app]
        unit_bag = rel.data[self.unit]
        copied = False
        for key, value in app_bag.items():
            if key in {LEGACY_CA_KEY, LEGACY_CHAIN_KEY} or key.endswith(
                (
                    ".server.cert",
                    ".server.key",
                    ".processed_requests",
                    ".processed_client_requests",
                    ".processed_application_requests",
                )
            ):
                if value and not unit_bag.get(key):
                    unit_bag[key] = value
                    copied = True
        if copied:
            logger.info("backfilled legacy TLS data into unit bag for relation %s", rel.id)

    def _legacy_write_bags(self, rel: Relation):
        return (rel.data[self.unit], rel.data[self.app])

    def _legacy_value(self, rel: Relation, key: str) -> Optional[str]:
        for bag in self._legacy_write_bags(rel):
            value = bag.get(key)
            if value:
                return value
        return None

    def _legacy_json(self, rel: Relation, key: str) -> Dict[str, dict]:
        for bag in self._legacy_write_bags(rel):
            value = bag.get(key)
            if not value:
                continue
            try:
                return json.loads(value)
            except json.JSONDecodeError:
                continue
        return {}


def _json_view(bag: Dict[str, str]) -> Dict[str, dict]:
    out = {}
    for k, v in bag.items():
        try:
            out[k] = json.loads(v)
        except Exception:
            # not JSON, ignore
            pass
    return out


if __name__ == "__main__":
    main(CertificateTranslatorCharm)
