from __future__ import annotations

import base64
from dataclasses import dataclass
import hashlib
import json
import os
import time
from typing import Callable

from cryptography.exceptions import InvalidTag, InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def canonical_bytes(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def digest(value: object) -> str:
    return hashlib.sha256(canonical_bytes(value)).hexdigest()


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _unb64(data: str) -> bytes:
    return base64.urlsafe_b64decode(data + "=" * (-len(data) % 4))


class SecurityDenied(ValueError):
    pass


class AuditTrail:
    def __init__(self) -> None:
        self.events: list[dict] = []
        self._head = "0" * 64

    def record(self, *, principal_id: str, tenant_id: str, action: str, resource_id: str,
               decision: str, reason_code: str, credential_generation: int = 0,
               key_version: int = 0, secret_version: int = 0, incident_id: str = "") -> dict:
        event = {"order": len(self.events) + 1, "event_id": f"audit-{len(self.events)+1:04d}",
                 "principal_id": principal_id, "tenant_id": tenant_id, "action": action,
                 "resource_id": resource_id, "decision": decision, "reason_code": reason_code,
                 "credential_generation": credential_generation, "key_version": key_version,
                 "secret_version": secret_version, "incident_id": incident_id,
                 "previous_sha256": self._head}
        event["event_sha256"] = digest(event)
        self._head = event["event_sha256"]
        self.events.append(event)
        return event

    @property
    def head(self) -> str:
        return self._head

    @staticmethod
    def validate(events: list[dict]) -> str:
        head = "0" * 64
        for event in events:
            candidate = dict(event)
            claimed = candidate.pop("event_sha256", "")
            if candidate.get("previous_sha256") != head or digest(candidate) != claimed:
                raise SecurityDenied("audit hash-chain mismatch")
            head = claimed
        return head


class SyntheticTokenIssuer:
    def __init__(self) -> None:
        self._key = Ed25519PrivateKey.generate()

    def issue(self, *, cluster: str = "local-k3d", namespace: str = "tenant-acme",
              service_account: str = "inference", tenant: str = "acme",
              audience: str = "aegisdesk-cloud-broker", expiry: int | None = None) -> str:
        payload = {"cluster": cluster, "namespace": namespace, "service_account": service_account,
                   "tenant": tenant, "audience": audience,
                   "subject": f"system:serviceaccount:{namespace}:{service_account}",
                   "expiry": expiry if expiry is not None else int(time.time()) + 300}
        body = _b64(canonical_bytes(payload))
        return body + "." + _b64(self._key.sign(body.encode()))

    def verify(self, token: str) -> dict:
        try:
            body, signature = token.split(".")
            self._key.public_key().verify(_unb64(signature), body.encode())
            return json.loads(_unb64(body))
        except (ValueError, InvalidSignature, json.JSONDecodeError) as exc:
            raise SecurityDenied("TOKEN_INVALID") from exc


@dataclass(frozen=True)
class Credential:
    token: str
    principal_id: str
    tenant_id: str
    generation: int
    expires_at: int


class IdentityBroker:
    def __init__(self, audit: AuditTrail, verifier: Callable[[str], dict]) -> None:
        self.audit, self.verifier = audit, verifier
        self.expected = ("local-k3d", "tenant-acme", "inference", "acme", "aegisdesk-cloud-broker")
        self.generation: dict[str, int] = {}
        self.revoked: set[str] = set()
        self.credentials: dict[str, Credential] = {}

    def exchange(self, token: str, overrides: dict | None = None) -> Credential:
        claims = self.verifier(token)
        identity = (claims.get("cluster"), claims.get("namespace"), claims.get("service_account"), claims.get("tenant"), claims.get("audience"))
        subject = claims.get("subject", "")
        if identity != self.expected or subject != "system:serviceaccount:tenant-acme:inference":
            raise SecurityDenied("IDENTITY_BINDING_DENIED")
        if int(claims.get("expiry", 0)) <= int(time.time()):
            raise SecurityDenied("TOKEN_EXPIRED")
        derived = {"tenant": claims["tenant"], "namespace": claims["namespace"], "service_account": claims["service_account"], "principal": subject}
        if overrides and any(overrides.get(k, v) != v for k, v in derived.items()):
            raise SecurityDenied("CALLER_OVERRIDE_DENIED")
        if subject in self.revoked:
            raise SecurityDenied("IDENTITY_REVOKED")
        generation = self.generation.get(subject, 1)
        raw = _b64(os.urandom(24))
        cred = Credential(raw, subject, claims["tenant"], generation, int(time.time()) + 120)
        self.credentials[digest(raw)] = cred
        self.audit.record(principal_id=subject, tenant_id=claims["tenant"], action="sts:Exchange",
                          resource_id=subject, decision="ALLOW", reason_code="VERIFIED_IDENTITY",
                          credential_generation=generation)
        return cred

    def authenticate(self, raw: str) -> Credential:
        cred = self.credentials.get(digest(raw))
        if not cred or cred.expires_at <= int(time.time()) or cred.principal_id in self.revoked or self.generation.get(cred.principal_id, 1) != cred.generation:
            raise SecurityDenied("CREDENTIAL_STALE_OR_REVOKED")
        return cred

    def revoke(self, principal: str) -> None:
        self.revoked.add(principal)
        self.generation[principal] = self.generation.get(principal, 1) + 1
        self.audit.record(principal_id=principal, tenant_id="acme", action="incident:RevokeIdentity",
                          resource_id=principal, decision="ALLOW", reason_code="IDENTITY_FENCED",
                          credential_generation=self.generation[principal])

    def recover(self, principal: str) -> None:
        self.revoked.discard(principal)


class IAM:
    def __init__(self, audit: AuditTrail, broker: IdentityBroker) -> None:
        self.audit, self.broker = audit, broker
        self.rules = {
            "system:serviceaccount:tenant-acme:inference": {
                ("kms:Encrypt", "kms/acme/app"), ("kms:Decrypt", "kms/acme/app"),
                ("secrets:GetCurrent", "secret/acme/model-token"),
                ("metadata:GetIdentity", "metadata/acme/inference"),
            },
            "incident-admin": {
                ("secrets:Rotate", "secret/acme/model-token"),
                ("kms:Rotate", "kms/acme/app"), ("incident:RevokeIdentity", "identity/acme/inference"),
            },
        }

    def authorize(self, cred: Credential, action: str, resource: str, tenant: str) -> None:
        good = tenant == cred.tenant_id and "*" not in action + resource and (action, resource) in self.rules.get(cred.principal_id, set())
        self.audit.record(principal_id=cred.principal_id, tenant_id=tenant, action=action,
                          resource_id=resource, decision="ALLOW" if good else "DENY",
                          reason_code="EXPLICIT_ALLOW" if good else "IMPLICIT_DENY",
                          credential_generation=cred.generation)
        if not good:
            raise SecurityDenied("IAM_DENY")


class LocalKMS:
    def __init__(self, audit: AuditTrail, iam: IAM) -> None:
        self.audit, self.iam = audit, iam
        self.keys = {"kms/acme/app": {1: os.urandom(32)}}
        self.active = {"kms/acme/app": 1}
        self.states = {("kms/acme/app", 1): "active"}

    @staticmethod
    def context(tenant: str, resource: str, purpose: str, version: int) -> bytes:
        return canonical_bytes({"tenant_id": tenant, "resource_id": resource, "purpose": purpose, "key_version": version})

    def encrypt(self, cred: Credential, key_id: str, tenant: str, resource: str, plaintext: bytes) -> dict:
        self.iam.authorize(cred, "kms:Encrypt", key_id, tenant)
        if key_id not in self.keys: raise SecurityDenied("KEY_UNKNOWN")
        version = self.active[key_id]; dek = os.urandom(32); nonce = os.urandom(12); wrap_nonce = os.urandom(12)
        context = self.context(tenant, resource, "secret", version)
        return {"key_id": key_id, "key_version": version, "tenant_id": tenant, "resource_id": resource,
                "nonce": _b64(nonce), "ciphertext": _b64(AESGCM(dek).encrypt(nonce, plaintext, context)),
                "wrap_nonce": _b64(wrap_nonce), "wrapped_dek": _b64(AESGCM(self.keys[key_id][version]).encrypt(wrap_nonce, dek, context))}

    def decrypt(self, cred: Credential, envelope: dict, tenant: str, resource: str) -> bytes:
        key_id, version = envelope.get("key_id"), int(envelope.get("key_version", 0))
        self.iam.authorize(cred, "kms:Decrypt", key_id, tenant)
        if tenant != envelope.get("tenant_id") or resource != envelope.get("resource_id"): raise SecurityDenied("CONTEXT_MISMATCH")
        if key_id not in self.keys or version not in self.keys[key_id]: raise SecurityDenied("KEY_UNKNOWN")
        if self.states.get((key_id, version)) == "revoked": raise SecurityDenied("KEY_REVOKED")
        context = self.context(tenant, resource, "secret", version)
        try:
            dek = AESGCM(self.keys[key_id][version]).decrypt(_unb64(envelope["wrap_nonce"]), _unb64(envelope["wrapped_dek"]), context)
            return AESGCM(dek).decrypt(_unb64(envelope["nonce"]), _unb64(envelope["ciphertext"]), context)
        except (InvalidTag, KeyError, ValueError) as exc:
            raise SecurityDenied("AUTHENTICATED_DECRYPT_FAILED") from exc

    def rotate(self, operator: Credential, key_id: str) -> int:
        self.iam.authorize(operator, "kms:Rotate", key_id, operator.tenant_id)
        old = self.active[key_id]; self.states[(key_id, old)] = "decrypt-only"
        new = old + 1; self.keys[key_id][new] = os.urandom(32); self.active[key_id] = new; self.states[(key_id, new)] = "active"
        return new

    def revoke_version(self, key_id: str, version: int) -> None:
        self.states[(key_id, version)] = "revoked"


class SecretManager:
    def __init__(self, kms: LocalKMS, iam: IAM) -> None:
        self.kms, self.iam = kms, iam
        self.versions: dict[str, dict[int, dict]] = {}; self.current: dict[str, int] = {}; self.retired: set[tuple[str, int]] = set()

    def seed(self, cred: Credential, secret_id: str, plaintext: bytes) -> None:
        self.versions[secret_id] = {1: self.kms.encrypt(cred, "kms/acme/app", "acme", secret_id, plaintext)}; self.current[secret_id] = 1

    def get_current(self, cred: Credential, secret_id: str, tenant: str) -> bytes:
        self.iam.authorize(cred, "secrets:GetCurrent", secret_id, tenant)
        version = self.current[secret_id]
        if (secret_id, version) in self.retired: raise SecurityDenied("SECRET_RETIRED")
        return self.kms.decrypt(cred, self.versions[secret_id][version], tenant, secret_id)

    def rotate(self, operator: Credential, app_cred: Credential, secret_id: str, plaintext: bytes) -> int:
        self.iam.authorize(operator, "secrets:Rotate", secret_id, operator.tenant_id)
        old = self.current[secret_id]; new = old + 1
        self.versions[secret_id][new] = self.kms.encrypt(app_cred, "kms/acme/app", "acme", secret_id, plaintext)
        self.current[secret_id] = new; self.retired.add((secret_id, old)); return new


class MetadataService:
    def __init__(self, iam: IAM) -> None:
        self.iam = iam; self.capabilities: dict[str, tuple[str, int]] = {}

    def session(self, cred: Credential) -> str:
        self.iam.authorize(cred, "metadata:GetIdentity", "metadata/acme/inference", cred.tenant_id)
        token = _b64(os.urandom(18)); self.capabilities[digest(token)] = (cred.principal_id, int(time.time()) + 30); return token

    def get(self, cred: Credential, capability: str, path: str) -> dict:
        record = self.capabilities.get(digest(capability))
        if not record or record[1] <= int(time.time()): raise SecurityDenied("METADATA_TOKEN_INVALID")
        if record[0] != cred.principal_id: raise SecurityDenied("METADATA_WORKLOAD_MISMATCH")
        if path != "/identity": raise SecurityDenied("METADATA_PATH_DENIED")
        return {"principal_id": cred.principal_id, "tenant_id": cred.tenant_id, "credential_generation": cred.generation}
