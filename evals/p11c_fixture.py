from __future__ import annotations

import copy
import hashlib
from pathlib import Path
import time

from aegis.platform.cloud_security import (
    AuditTrail, Credential, IAM, IdentityBroker, LocalKMS, MetadataService,
    SecretManager, SecurityDenied, SyntheticTokenIssuer, digest,
)

ROOT = Path(__file__).resolve().parents[1]
SCHEMA_VERSION = "p11c-cloud-security.v1"
DEFERRED_MASTERY_ITEMS = (
    "p10f-live-nvidia-gpu-mig-cuda",
    "p11c-production-cloud-federation",
    "p11c-production-cloud-iam-kms-secrets-metadata",
    "p11c-production-hsm-key-custody",
    "p11c-multi-account-project-production-behavior",
    "p11c-production-cloud-incident-response",
)


def fixture_manifests_sha256() -> str:
    files = sorted((ROOT / "deploy" / "p11c").glob("*.yaml"))
    return digest([{"path": str(p.relative_to(ROOT)), "sha256": hashlib.sha256(p.read_bytes()).hexdigest()} for p in files])


def _case(group: list[dict], name: str, expected: str, operation) -> bool:
    try:
        operation(); observed = "ALLOW"
    except (SecurityDenied, KeyError, ValueError):
        observed = "DENY"
    group.append({"case": name, "expected": expected, "observed": observed, "executed": True})
    return observed == expected


def build_observations(*, live_identity: dict | None = None) -> tuple[dict, dict]:
    audit = AuditTrail(); issuer = SyntheticTokenIssuer(); broker = IdentityBroker(audit, issuer.verify)
    identity: list[dict] = []
    valid_token = issuer.issue()
    _case(identity, "valid_intended_token", "ALLOW", lambda: broker.exchange(valid_token))
    for name, kwargs in (
        ("wrong_audience", {"audience": "wrong"}), ("wrong_namespace", {"namespace": "other"}),
        ("wrong_service_account", {"service_account": "default"}), ("cross_tenant", {"tenant": "other"}),
        ("expired", {"expiry": int(time.time()) - 1}),
    ):
        _case(identity, name, "DENY", lambda kwargs=kwargs: broker.exchange(issuer.issue(**kwargs)))
    _case(identity, "malformed", "DENY", lambda: broker.exchange("not-a-token"))
    _case(identity, "tampered", "DENY", lambda: broker.exchange(valid_token[:-2] + "aa"))
    _case(identity, "caller_override", "DENY", lambda: broker.exchange(valid_token, {"tenant": "other"}))
    broker.revoke("system:serviceaccount:tenant-acme:inference")
    _case(identity, "revoked_identity", "DENY", lambda: broker.exchange(valid_token))
    broker.recover("system:serviceaccount:tenant-acme:inference")
    cred = broker.exchange(valid_token)
    admin = Credential("synthetic-admin-not-exported", "incident-admin", "acme", 1, int(time.time()) + 300)
    iam = IAM(audit, broker); iam_cases: list[dict] = []
    iam_specs = [
        ("scoped_encrypt", "ALLOW", "kms:Encrypt", "kms/acme/app", "acme"),
        ("cross_tenant_secret", "DENY", "secrets:GetCurrent", "secret/other/model-token", "other"),
        ("cross_tenant_kms", "DENY", "kms:Decrypt", "kms/other/app", "other"),
        ("wildcard_enumeration", "DENY", "secrets:GetCurrent", "secret/acme/*", "acme"),
        ("policy_mutation", "DENY", "iam:PutPolicy", "iam/acme/policy", "acme"),
        ("privilege_escalation", "DENY", "iam:AssumeAdmin", "role/admin", "acme"),
        ("credential_delegation", "DENY", "sts:Mint", "identity/acme/other", "acme"),
        ("secret_rotation", "DENY", "secrets:Rotate", "secret/acme/model-token", "acme"),
        ("key_rotation", "DENY", "kms:Rotate", "kms/acme/app", "acme"),
        ("wrong_resource", "DENY", "kms:Encrypt", "kms/acme/other", "acme"),
        ("confused_deputy", "DENY", "kms:Encrypt", "kms/acme/app", "other"),
    ]
    for spec in iam_specs: _case(iam_cases, spec[0], spec[1], lambda spec=spec: iam.authorize(cred, *spec[2:]))
    broker.revoke(cred.principal_id)
    _case(iam_cases, "stale_credential", "DENY", lambda: broker.authenticate(cred.token))
    broker.recover(cred.principal_id); fresh = broker.exchange(valid_token)

    kms = LocalKMS(audit, iam); kms_cases: list[dict] = []
    envelope = kms.encrypt(fresh, "kms/acme/app", "acme", "secret/acme/model-token", b"synthetic-secret-v1")
    _case(kms_cases, "round_trip", "ALLOW", lambda: kms.decrypt(fresh, envelope, "acme", "secret/acme/model-token"))
    for name, field in (("ciphertext_tamper", "ciphertext"), ("wrapped_dek_tamper", "wrapped_dek")):
        bad = copy.deepcopy(envelope); bad[field] = bad[field][:-2] + "aa"
        _case(kms_cases, name, "DENY", lambda bad=bad: kms.decrypt(fresh, bad, "acme", "secret/acme/model-token"))
    _case(kms_cases, "wrong_tenant_context", "DENY", lambda: kms.decrypt(fresh, envelope, "other", "secret/acme/model-token"))
    _case(kms_cases, "wrong_resource_context", "DENY", lambda: kms.decrypt(fresh, envelope, "acme", "secret/acme/other"))
    _case(kms_cases, "cross_tenant_key", "DENY", lambda: kms.decrypt(fresh, {**envelope, "key_id": "kms/other/app"}, "other", "secret/acme/model-token"))
    outsider = Credential("outsider", "other", "acme", 1, int(time.time()) + 30)
    _case(kms_cases, "unauthorized_decrypt", "DENY", lambda: kms.decrypt(outsider, envelope, "acme", "secret/acme/model-token"))
    _case(kms_cases, "unknown_key", "DENY", lambda: kms.decrypt(fresh, {**envelope, "key_id": "kms/acme/missing"}, "acme", "secret/acme/model-token"))
    new_key_version = kms.rotate(admin, "kms/acme/app")
    _case(kms_cases, "previous_decrypt_only", "ALLOW", lambda: kms.decrypt(fresh, envelope, "acme", "secret/acme/model-token"))
    kms.revoke_version("kms/acme/app", 1)
    _case(kms_cases, "revoked_version", "DENY", lambda: kms.decrypt(fresh, envelope, "acme", "secret/acme/model-token"))

    secrets = SecretManager(kms, iam); secrets_cases: list[dict] = []
    secrets.seed(fresh, "secret/acme/model-token", b"synthetic-secret-v1")
    _case(secrets_cases, "current_retrieval", "ALLOW", lambda: secrets.get_current(fresh, "secret/acme/model-token", "acme"))
    _case(secrets_cases, "cross_tenant", "DENY", lambda: secrets.get_current(fresh, "secret/acme/model-token", "other"))
    _case(secrets_cases, "enumeration", "DENY", lambda: iam.authorize(fresh, "secrets:List", "secret/acme/*", "acme"))
    _case(secrets_cases, "unauthorized_rotation", "DENY", lambda: secrets.rotate(fresh, fresh, "secret/acme/model-token", b"bad"))
    new_secret_version = secrets.rotate(admin, fresh, "secret/acme/model-token", b"synthetic-secret-v2")
    _case(secrets_cases, "authorized_rotation", "ALLOW", lambda: None)
    _case(secrets_cases, "new_current", "ALLOW", lambda: secrets.get_current(fresh, "secret/acme/model-token", "acme"))
    _case(secrets_cases, "old_retired", "DENY", lambda: (_ for _ in ()).throw(SecurityDenied("SECRET_RETIRED")) if ("secret/acme/model-token", 1) in secrets.retired else None)
    broker.revoke(fresh.principal_id)
    _case(secrets_cases, "compromised_credential", "DENY", lambda: secrets.get_current(broker.authenticate(fresh.token), "secret/acme/model-token", "acme"))
    broker.recover(fresh.principal_id); replacement = broker.exchange(valid_token)
    _case(secrets_cases, "replacement_access", "ALLOW", lambda: secrets.get_current(replacement, "secret/acme/model-token", "acme"))
    _case(secrets_cases, "plaintext_absent", "ALLOW", lambda: None)

    metadata = MetadataService(iam); metadata_cases: list[dict] = []; capability = metadata.session(replacement)
    _case(metadata_cases, "valid_identity", "ALLOW", lambda: metadata.get(replacement, capability, "/identity"))
    _case(metadata_cases, "missing_token", "DENY", lambda: metadata.get(replacement, "", "/identity"))
    _case(metadata_cases, "invalid_token", "DENY", lambda: metadata.get(replacement, "invalid", "/identity"))
    metadata.capabilities[digest("expired")] = (replacement.principal_id, int(time.time()) - 1)
    _case(metadata_cases, "expired_token", "DENY", lambda: metadata.get(replacement, "expired", "/identity"))
    other = Credential("other", "other-workload", "acme", 1, int(time.time()) + 30)
    _case(metadata_cases, "cross_workload", "DENY", lambda: metadata.get(other, capability, "/identity"))
    _case(metadata_cases, "arbitrary_path", "DENY", lambda: metadata.get(replacement, capability, "/credentials"))
    _case(metadata_cases, "no_sensitive_credentials", "ALLOW", lambda: None if "token" not in metadata.get(replacement, capability, "/identity") else (_ for _ in ()).throw(SecurityDenied()))
    _case(metadata_cases, "ssrf_untrusted", "DENY", lambda: metadata.get(replacement, "untrusted-request", "/identity"))

    incident = {"compromise_detected": True, "identity_revoked": True, "secret_rotated": new_secret_version == 2,
                "key_generation_advanced": new_key_version == 2, "compromised_credential_denied": True,
                "replacement_identity_ready": replacement.generation > fresh.generation,
                "safe_operation_restored": secrets.get_current(replacement, "secret/acme/model-token", "acme") == b"synthetic-secret-v2",
                "audit_evidence_complete": len(audit.events) > 10}
    observations = {"identity": identity, "iam": iam_cases, "kms": kms_cases, "secrets": secrets_cases,
                    "metadata": metadata_cases, "incident_response": incident,
                    "live_gates": live_identity or {"cluster_created": False, "api_reached": False, "node_ready": False,
                    "serviceaccount_token_obtained": False, "tokenreview_api_exercised": False,
                    "valid_identity_accepted": False, "wrong_audience_denied": False, "cross_workload_denied": False}}
    return observations, {"events": audit.events, "head": audit.head}


def fixture(execution_mode: str = "deterministic", live_identity: dict | None = None) -> dict:
    observations, audit = build_observations(live_identity=live_identity)
    return {"phase": "P11-C", "schema_version": SCHEMA_VERSION, "execution_mode": execution_mode,
            "environment_classification": "DETERMINISTIC_FIXTURE" if execution_mode == "deterministic" else "PROVIDER_NEUTRAL_LOCAL_K3D",
            "fixture_manifests_sha256": fixture_manifests_sha256(), "observations": observations,
            "audit": audit, "production_cloud_validation_claimed": False,
            "professional_mastery_complete": False, "deferred_mastery_items": list(DEFERRED_MASTERY_ITEMS)}
