from __future__ import annotations

import hashlib
import json
import sqlite3
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from aegis.approvals.durable import DurableApprovalStore
from aegis.effects.checkpoint_receipt_boundary import (
    AuthenticatedCheckpointDurableEffectWorker,
    CheckpointReceiptError,
    CheckpointReceiptGenerationFence,
    CheckpointReceiptReason,
    Ed25519CheckpointReceiptObserver,
)
from aegis.effects.checkpoint_receipt_models import (
    GENESIS_RECEIPT_PREDECESSOR,
    AuthenticatedCheckpointReceipt,
    CheckpointReceiptPayload,
    CheckpointReceiptSource,
    TrustedCheckpointReceiptKey,
    canonical_checkpoint_payload,
    checkpoint_receipt_sha256,
)
from aegis.effects.control_plane_recovery import CrashSafeControlPlaneCoordinator
from aegis.effects.durable import DurableApprovedEffectPipeline, TransactionalEffectCoordinator
from aegis.effects.protected_checkpoint import (
    CheckpointBoundAuthorizationReplica,
    CheckpointBoundSyntheticEffectService,
    ExternallyCheckpointedControlPlaneCoordinator,
    SyntheticProtectedCheckpointAuthority,
)
from aegis.effects.revalidation import RevalidatingEffectOutboxStore, SyntheticAuthorizationStateStore
from aegis.effects.rollback_anchor import AnchoredAuthorizationSigner, ControlPlaneGenerationStore
from aegis.effects.signed_authorization import AuthorizationDecisionSigner, TrustedAuthorizationKeyStore
from aegis.effects.trust_providers import (
    HighImpactTrustProviderFactory,
    LOCAL_SYNTHETIC_TRUST_MANIFEST,
    TrustDeploymentProfile,
    TrustProviderManifest,
)
from aegis.effects.versioned_revalidation import AuthorizationVersionStore, CachedAuthorizationReplica


P3A_POLICY_VERSION = "default-authenticated-high-impact-chain-v1"


@dataclass(frozen=True)
class DefaultHighImpactPaths:
    state_database_path: Path
    execution_database_path: Path
    control_plane_database_path: Path
    protected_checkpoint_database_path: Path
    receipt_witness_database_path: Path

    def __post_init__(self) -> None:
        resolved = {
            Path(self.state_database_path).resolve(),
            Path(self.execution_database_path).resolve(),
            Path(self.control_plane_database_path).resolve(),
            Path(self.protected_checkpoint_database_path).resolve(),
            Path(self.receipt_witness_database_path).resolve(),
        }
        if len(resolved) != 5:
            raise ValueError("P3-A security databases must use distinct local rollback domains")


@dataclass(frozen=True)
class DefaultHighImpactSecurityStack:
    policy_version: str
    paths: DefaultHighImpactPaths
    trust_profile: TrustDeploymentProfile
    trust_manifest: TrustProviderManifest
    authorization_versions: AuthorizationVersionStore
    trusted_authorization_keys: TrustedAuthorizationKeyStore
    generation_store: ControlPlaneGenerationStore
    local_control_plane: CrashSafeControlPlaneCoordinator
    protected_control_plane: ExternallyCheckpointedControlPlaneCoordinator
    checkpoint_source: CheckpointReceiptSource
    checkpoint_fence: CheckpointReceiptGenerationFence
    effect_service: CheckpointBoundSyntheticEffectService
    worker: AuthenticatedCheckpointDurableEffectWorker
    pipeline: DurableApprovedEffectPipeline


class SyntheticProtectedCheckpointReceiptSource:
    """Local synthetic stand-in for a protected signed checkpoint endpoint.

    The signing key is derived only from a public synthetic fixture seed label. The
    source persists predecessor-linked receipts in the same synthetic protected
    domain as the P2-R checkpoint authority so restarts preserve one receipt chain.
    This is lab plumbing, not production key custody.
    """

    def __init__(
        self,
        *,
        checkpoint_authority: SyntheticProtectedCheckpointAuthority,
        authority_id: str,
        audience: str,
        key_id: str,
        key_epoch: int,
        seed_label: str,
    ) -> None:
        self._checkpoint_authority = checkpoint_authority
        self._authority_id = authority_id
        self._audience = audience
        self._key_id = key_id
        self._key_epoch = key_epoch
        seed = hashlib.sha256(seed_label.encode("utf-8")).digest()
        self._private_key = Ed25519PrivateKey.from_private_bytes(seed)
        self._setup()

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self._checkpoint_authority.database_path, timeout=5.0)
        connection.row_factory = sqlite3.Row
        return connection

    def _setup(self) -> None:
        with self._connect() as connection:
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS authenticated_checkpoint_receipts (
                    authority_id TEXT NOT NULL,
                    generation INTEGER NOT NULL CHECK (generation >= 1),
                    receipt_json TEXT NOT NULL,
                    receipt_sha256 TEXT NOT NULL UNIQUE,
                    PRIMARY KEY (authority_id, generation)
                )
                """
            )

    def trusted_key(self) -> TrustedCheckpointReceiptKey:
        public_key = self._private_key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        return TrustedCheckpointReceiptKey(
            authority_id=self._authority_id,
            audience=self._audience,
            key_id=self._key_id,
            key_epoch=self._key_epoch,
            public_key_hex=public_key.hex(),
        )

    def _load_receipt(self, generation: int) -> AuthenticatedCheckpointReceipt | None:
        with self._connect() as connection:
            row = connection.execute(
                """
                SELECT receipt_json
                FROM authenticated_checkpoint_receipts
                WHERE authority_id = ? AND generation = ?
                """,
                (self._authority_id, generation),
            ).fetchone()
        if row is None:
            return None
        return AuthenticatedCheckpointReceipt.model_validate_json(str(row["receipt_json"]))

    def _persist(self, receipt: AuthenticatedCheckpointReceipt) -> None:
        receipt_json = json.dumps(
            receipt.model_dump(mode="json"),
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        )
        digest = checkpoint_receipt_sha256(receipt)
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            existing = connection.execute(
                """
                SELECT receipt_json
                FROM authenticated_checkpoint_receipts
                WHERE authority_id = ? AND generation = ?
                """,
                (self._authority_id, receipt.payload.generation),
            ).fetchone()
            if existing is not None and str(existing["receipt_json"]) != receipt_json:
                raise CheckpointReceiptError(CheckpointReceiptReason.EQUIVOCATION_DETECTED)
            connection.execute(
                """
                INSERT OR IGNORE INTO authenticated_checkpoint_receipts (
                    authority_id, generation, receipt_json, receipt_sha256
                ) VALUES (?, ?, ?, ?)
                """,
                (self._authority_id, receipt.payload.generation, receipt_json, digest),
            )

    def current(self) -> AuthenticatedCheckpointReceipt:
        checkpoint = self._checkpoint_authority.current(self._authority_id)
        existing = self._load_receipt(checkpoint.generation)
        if existing is not None:
            if (
                existing.payload.journal_head_sha256 != checkpoint.journal_head_sha256
                or existing.payload.authority_id != self._authority_id
            ):
                raise CheckpointReceiptError(CheckpointReceiptReason.HISTORY_INVALID)
            return existing

        if checkpoint.generation == 1:
            predecessor = GENESIS_RECEIPT_PREDECESSOR
        else:
            previous = self._load_receipt(checkpoint.generation - 1)
            if previous is None:
                raise CheckpointReceiptError(CheckpointReceiptReason.HISTORY_INVALID)
            predecessor = checkpoint_receipt_sha256(previous)

        payload = CheckpointReceiptPayload(
            authority_id=self._authority_id,
            audience=self._audience,
            key_id=self._key_id,
            key_epoch=self._key_epoch,
            generation=checkpoint.generation,
            journal_head_sha256=checkpoint.journal_head_sha256,
            previous_receipt_sha256=predecessor,
        )
        signature = self._private_key.sign(canonical_checkpoint_payload(payload))
        receipt = AuthenticatedCheckpointReceipt(payload=payload, signature_hex=signature.hex())
        self._persist(receipt)
        return receipt


def _fixture_private_key(seed_label: str) -> Ed25519PrivateKey:
    return Ed25519PrivateKey.from_private_bytes(hashlib.sha256(seed_label.encode("utf-8")).digest())


def _ensure_versions(store: AuthorizationVersionStore, fixture: dict[str, Any]) -> None:
    for tenant in fixture["tenants"]:
        store.ensure(
            tenant_id=str(tenant["tenant_id"]),
            policy_version=int(tenant["policy_version"]),
            revocation_epoch=int(tenant["revocation_epoch"]),
        )


def _authorization_signer(
    *,
    registry: TrustedAuthorizationKeyStore,
    fixture: dict[str, Any],
) -> AuthorizationDecisionSigner:
    issuer_id = str(fixture["issuer_id"])
    audience = str(fixture["audience"])
    keys = tuple(fixture["keys"])
    try:
        current_epoch = registry.current_epoch(issuer_id=issuer_id, audience=audience)
    except KeyError:
        first = min(keys, key=lambda item: int(item["key_epoch"]))
        private_key = _fixture_private_key(str(first["seed_label"]))
        registry.trust_initial_key(
            issuer_id=issuer_id,
            audience=audience,
            key_id=str(first["key_id"]),
            key_epoch=int(first["key_epoch"]),
            public_key_bytes=private_key.public_key().public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw,
            ),
        )
        current_epoch = int(first["key_epoch"])

    matching = [item for item in keys if int(item["key_epoch"]) == current_epoch]
    if len(matching) != 1:
        raise ValueError("current synthetic authorization signing epoch has no unique fixture key")
    key = matching[0]
    return AuthorizationDecisionSigner(
        issuer_id=issuer_id,
        audience=audience,
        key_id=str(key["key_id"]),
        key_epoch=int(key["key_epoch"]),
        private_key=_fixture_private_key(str(key["seed_label"])),
    )


class LocalSyntheticHighImpactTrustProviderFactory:
    """Explicit local provider bundle used only by the synthetic/default lab profile."""

    manifest = LOCAL_SYNTHETIC_TRUST_MANIFEST

    def authorization_signer(
        self,
        *,
        registry: TrustedAuthorizationKeyStore,
        fixture: dict[str, Any],
    ) -> AuthorizationDecisionSigner:
        return _authorization_signer(registry=registry, fixture=fixture)

    def protected_checkpoint_authority(
        self,
        *,
        database_path: Path,
    ) -> SyntheticProtectedCheckpointAuthority:
        return SyntheticProtectedCheckpointAuthority(database_path)

    def checkpoint_receipt_source(
        self,
        *,
        checkpoint_authority: SyntheticProtectedCheckpointAuthority,
        fixture: dict[str, Any],
    ) -> SyntheticProtectedCheckpointReceiptSource:
        return SyntheticProtectedCheckpointReceiptSource(
            checkpoint_authority=checkpoint_authority,
            authority_id=str(fixture["authority_id"]),
            audience=str(fixture["audience"]),
            key_id=str(fixture["key_id"]),
            key_epoch=int(fixture["key_epoch"]),
            seed_label=str(fixture["seed_label"]),
        )

    def checkpoint_receipt_observer(
        self,
        *,
        receipt_source: SyntheticProtectedCheckpointReceiptSource,
        witness_database_path: Path,
    ) -> Ed25519CheckpointReceiptObserver:
        return Ed25519CheckpointReceiptObserver(
            trusted_key=receipt_source.trusted_key(),
            witness_database_path=witness_database_path,
        )


def build_default_high_impact_security_stack(
    *,
    paths: DefaultHighImpactPaths,
    approval_store: DurableApprovalStore,
    outbox_store: RevalidatingEffectOutboxStore,
    authorization_store: SyntheticAuthorizationStateStore,
    authorization_version_fixture: dict[str, Any],
    authorization_key_fixture: dict[str, Any],
    control_plane_fixture: dict[str, Any],
    checkpoint_receipt_fixture: dict[str, Any],
    trust_profile: TrustDeploymentProfile = TrustDeploymentProfile.LOCAL_SYNTHETIC,
    trust_provider_factory: HighImpactTrustProviderFactory | None = None,
) -> DefaultHighImpactSecurityStack:
    if approval_store.database_path.resolve() != Path(paths.state_database_path).resolve():
        raise ValueError("approval store must use the configured P3-A state database")
    if outbox_store.database_path.resolve() != Path(paths.state_database_path).resolve():
        raise ValueError("outbox store must share the approval state database")
    if authorization_store.database_path.resolve() != Path(paths.execution_database_path).resolve():
        raise ValueError("authorization state must share the P3-A execution database")

    provider_factory = trust_provider_factory or LocalSyntheticHighImpactTrustProviderFactory()
    provider_factory.manifest.assert_allowed(trust_profile)

    versions = AuthorizationVersionStore(paths.execution_database_path)
    _ensure_versions(versions, authorization_version_fixture)

    registry = TrustedAuthorizationKeyStore(paths.execution_database_path)
    signer = provider_factory.authorization_signer(
        registry=registry,
        fixture=authorization_key_fixture,
    )

    authority_id = str(control_plane_fixture["authority_id"])
    initial_generation = int(control_plane_fixture["initial_generation"])
    generation_store = ControlPlaneGenerationStore(paths.control_plane_database_path)
    local = CrashSafeControlPlaneCoordinator(
        execution_database_path=paths.execution_database_path,
        generation_store=generation_store,
        authority_id=authority_id,
    )
    protected_authority = provider_factory.protected_checkpoint_authority(
        database_path=paths.protected_checkpoint_database_path,
    )
    protected = ExternallyCheckpointedControlPlaneCoordinator(
        local_coordinator=local,
        checkpoint_authority=protected_authority,
    )
    try:
        generation_store.current(authority_id)
    except KeyError:
        protected.initialize(generation=initial_generation)
    else:
        protected.recover()

    receipt_source = provider_factory.checkpoint_receipt_source(
        checkpoint_authority=protected_authority,
        fixture=checkpoint_receipt_fixture,
    )
    trusted_checkpoint_key = receipt_source.trusted_key()
    if trusted_checkpoint_key.authority_id != authority_id:
        raise ValueError("checkpoint receipt authority must match the control-plane authority")
    observer = provider_factory.checkpoint_receipt_observer(
        receipt_source=receipt_source,
        witness_database_path=paths.receipt_witness_database_path,
    )
    checkpoint_fence = CheckpointReceiptGenerationFence(
        local_coordinator=local,
        receipt_source=receipt_source,
        receipt_observer=observer,
    )
    checkpoint_fence.current_active_generation()

    replica = CachedAuthorizationReplica(
        authorization_store=authorization_store,
        version_store=versions,
    )
    anchored_replica = CheckpointBoundAuthorizationReplica(
        authorization_replica=replica,
        signer=AnchoredAuthorizationSigner(signer),
        generation_fence=checkpoint_fence,
    )
    effect_service = CheckpointBoundSyntheticEffectService(
        paths.execution_database_path,
        authoritative_versions=versions,
        trusted_keys=registry,
        generation_store=generation_store,
        authority_id=authority_id,
        generation_fence=checkpoint_fence,
        expected_issuer_id=str(authorization_key_fixture["issuer_id"]),
        expected_audience=str(authorization_key_fixture["audience"]),
    )
    worker = AuthenticatedCheckpointDurableEffectWorker(
        outbox_store=outbox_store,
        effect_service=effect_service,
        authorization_replica=anchored_replica,
    )
    pipeline = DurableApprovedEffectPipeline(
        coordinator=TransactionalEffectCoordinator(approval_store),
        worker=worker,
    )
    return DefaultHighImpactSecurityStack(
        policy_version=P3A_POLICY_VERSION,
        paths=paths,
        trust_profile=trust_profile,
        trust_manifest=provider_factory.manifest,
        authorization_versions=versions,
        trusted_authorization_keys=registry,
        generation_store=generation_store,
        local_control_plane=local,
        protected_control_plane=protected,
        checkpoint_source=receipt_source,
        checkpoint_fence=checkpoint_fence,
        effect_service=effect_service,
        worker=worker,
        pipeline=pipeline,
    )
