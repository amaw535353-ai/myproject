from __future__ import annotations

import hashlib
import hmac
from dataclasses import dataclass
from enum import StrEnum
from typing import Protocol, runtime_checkable

from aegis.agent.checkpoint_keys import (
    CheckpointEncryptionKeyProvider,
    CheckpointKeyState,
    LocalSyntheticCheckpointKey,
    LocalSyntheticCheckpointKeyProvider,
)
from aegis.agent.checkpoint_trust import (
    CheckpointTrustProviderDescriptor,
    CheckpointTrustProviderManifest,
    CheckpointTrustSurface,
)
from aegis.effects.trust_providers import TrustDeploymentProfile, TrustProviderKind


P4G_CHECKPOINT_EXTERNAL_CONTRACT_POLICY_VERSION = (
    "synthetic-external-checkpoint-adapter-contract-harness-v1"
)


class CheckpointExternalContractReason(StrEnum):
    ADAPTER_SURFACE_MISSING = "checkpoint_external_adapter_surface_missing"
    ADAPTER_PROVIDER_ID_MISMATCH = "checkpoint_external_adapter_provider_id_mismatch"
    EXTERNAL_KEY_CUSTODY_REQUIRED = "checkpoint_external_adapter_key_custody_required"
    ANCHOR_ROLLBACK_REJECTED = "checkpoint_external_anchor_rollback_rejected"
    ANCHOR_CONFLICT = "checkpoint_external_anchor_conflict"
    BACKUP_AUTHENTICATION_FAILED = "checkpoint_external_backup_authentication_failed"
    RECOVERY_AUTHORIZATION_DENIED = "checkpoint_external_recovery_authorization_denied"


class CheckpointExternalContractError(RuntimeError):
    def __init__(
        self,
        reason: CheckpointExternalContractReason,
        *,
        surface: CheckpointTrustSurface | None = None,
    ) -> None:
        self.reason = reason
        self.surface = surface
        detail = reason.value if surface is None else f"{reason.value}:{surface.value}"
        super().__init__(detail)


@dataclass(frozen=True)
class ExternalAnchorHead:
    generation: int
    checkpoint_id: str
    checkpoint_digest: str


@dataclass(frozen=True)
class RecoveryAuthorizationRequest:
    request_id: str
    operator_id: str
    backup_authenticated: bool
    monotonic_anchor_verified: bool


@runtime_checkable
class ExternalCheckpointIntegrityAdapter(Protocol):
    surface: CheckpointTrustSurface
    provider_id: str
    external_key_custody: bool
    synthetic_in_process: bool
    operationally_external: bool

    def authenticate(self, payload: bytes) -> str: ...

    def verify(self, payload: bytes, authenticator: str) -> bool: ...


@runtime_checkable
class ExternalCheckpointAnchorAdapter(Protocol):
    surface: CheckpointTrustSurface
    provider_id: str
    synthetic_in_process: bool
    operationally_external: bool

    def current_head(self, scope: str) -> ExternalAnchorHead | None: ...

    def advance(
        self,
        scope: str,
        *,
        generation: int,
        checkpoint_id: str,
        checkpoint_digest: str,
        expected_generation: int | None,
    ) -> ExternalAnchorHead: ...


@runtime_checkable
class ExternalCheckpointBackupAuthenticationAdapter(Protocol):
    surface: CheckpointTrustSurface
    provider_id: str
    external_key_custody: bool
    synthetic_in_process: bool
    operationally_external: bool

    def authenticate(self, payload: bytes) -> str: ...

    def verify_or_raise(self, payload: bytes, authenticator: str) -> None: ...


@runtime_checkable
class ExternalCheckpointRecoveryAuthorityAdapter(Protocol):
    surface: CheckpointTrustSurface
    provider_id: str
    synthetic_in_process: bool
    operationally_external: bool

    def authorize_restore(self, request: RecoveryAuthorizationRequest) -> None: ...


class SyntheticExternalStyleCheckpointEncryptionAdapter:
    """In-process contract double for an externally-custodied encryption service.

    The wrapped AES-GCM key material remains local synthetic fixture material so
    the adapter is deliberately not operationally external. The public contract
    exposes encrypt/decrypt operations rather than raw key bytes, allowing the
    P4-G harness to exercise the P4-F production-profile composition shape without
    making a production custody claim.
    """

    surface = CheckpointTrustSurface.ENCRYPTION_KEY_CUSTODY
    synthetic_in_process = True
    operationally_external = False

    def __init__(
        self,
        *,
        provider_id: str = "synthetic-external-contract-checkpoint-encryption",
        external_key_custody: bool = True,
    ) -> None:
        key_id = "synthetic-external-contract-checkpoint-aesgcm-v1"
        key = hashlib.sha256(
            b"aegisdesk-p4g-synthetic-external-contract-encryption-key-v1"
        ).digest()
        self.provider_id = provider_id
        self.external_key_custody = bool(external_key_custody)
        self._provider = LocalSyntheticCheckpointKeyProvider(
            active_key_id=key_id,
            keys={
                key_id: LocalSyntheticCheckpointKey(
                    key_id=key_id,
                    key=key,
                    state=CheckpointKeyState.ACTIVE,
                )
            },
        )

    @property
    def active_key_id(self) -> str:
        return self._provider.active_key_id

    def encrypt(self, plaintext: bytes, *, aad: bytes) -> bytes:
        return self._provider.encrypt(plaintext, aad=aad)

    def decrypt(self, envelope: bytes, *, aad: bytes) -> bytes:
        return self._provider.decrypt(envelope, aad=aad)

    def envelope_key_id(self, envelope: bytes) -> str:
        return self._provider.envelope_key_id(envelope)

    def key_state(self, key_id: str) -> CheckpointKeyState | None:
        return self._provider.key_state(key_id)


class SyntheticExternalStyleCheckpointIntegrityAdapter:
    surface = CheckpointTrustSurface.INTEGRITY_KEY_CUSTODY
    synthetic_in_process = True
    operationally_external = False
    external_key_custody = True

    def __init__(
        self,
        *,
        provider_id: str = "synthetic-external-contract-checkpoint-integrity",
    ) -> None:
        self.provider_id = provider_id
        self._key = hashlib.sha256(
            b"aegisdesk-p4g-synthetic-external-contract-integrity-key-v1"
        ).digest()

    def authenticate(self, payload: bytes) -> str:
        return hmac.new(self._key, bytes(payload), hashlib.sha256).hexdigest()

    def verify(self, payload: bytes, authenticator: str) -> bool:
        expected = self.authenticate(payload)
        return hmac.compare_digest(expected, str(authenticator))


class SyntheticExternalStyleCheckpointAnchorAdapter:
    surface = CheckpointTrustSurface.MONOTONIC_ANCHOR
    synthetic_in_process = True
    operationally_external = False

    def __init__(
        self,
        *,
        provider_id: str = "synthetic-external-contract-checkpoint-anchor",
    ) -> None:
        self.provider_id = provider_id
        self._heads: dict[str, ExternalAnchorHead] = {}

    def current_head(self, scope: str) -> ExternalAnchorHead | None:
        return self._heads.get(str(scope))

    def advance(
        self,
        scope: str,
        *,
        generation: int,
        checkpoint_id: str,
        checkpoint_digest: str,
        expected_generation: int | None,
    ) -> ExternalAnchorHead:
        key = str(scope)
        current = self._heads.get(key)
        current_generation = None if current is None else current.generation
        if current_generation != expected_generation:
            raise CheckpointExternalContractError(
                CheckpointExternalContractReason.ANCHOR_CONFLICT,
                surface=self.surface,
            )
        if generation < 1:
            raise CheckpointExternalContractError(
                CheckpointExternalContractReason.ANCHOR_ROLLBACK_REJECTED,
                surface=self.surface,
            )
        if current is None:
            if generation != 1:
                raise CheckpointExternalContractError(
                    CheckpointExternalContractReason.ANCHOR_CONFLICT,
                    surface=self.surface,
                )
        elif generation <= current.generation:
            raise CheckpointExternalContractError(
                CheckpointExternalContractReason.ANCHOR_ROLLBACK_REJECTED,
                surface=self.surface,
            )
        elif generation != current.generation + 1:
            raise CheckpointExternalContractError(
                CheckpointExternalContractReason.ANCHOR_CONFLICT,
                surface=self.surface,
            )
        head = ExternalAnchorHead(
            generation=generation,
            checkpoint_id=str(checkpoint_id),
            checkpoint_digest=str(checkpoint_digest),
        )
        self._heads[key] = head
        return head


class SyntheticExternalStyleCheckpointBackupAuthenticationAdapter:
    surface = CheckpointTrustSurface.BACKUP_AUTHENTICATION
    synthetic_in_process = True
    operationally_external = False
    external_key_custody = True

    def __init__(
        self,
        *,
        provider_id: str = "synthetic-external-contract-checkpoint-backup-auth",
    ) -> None:
        self.provider_id = provider_id
        self._key = hashlib.sha256(
            b"aegisdesk-p4g-synthetic-external-contract-backup-auth-key-v1"
        ).digest()

    def authenticate(self, payload: bytes) -> str:
        return hmac.new(self._key, bytes(payload), hashlib.sha256).hexdigest()

    def verify_or_raise(self, payload: bytes, authenticator: str) -> None:
        expected = self.authenticate(payload)
        if not hmac.compare_digest(expected, str(authenticator)):
            raise CheckpointExternalContractError(
                CheckpointExternalContractReason.BACKUP_AUTHENTICATION_FAILED,
                surface=self.surface,
            )


class SyntheticExternalStyleCheckpointRecoveryAuthorityAdapter:
    surface = CheckpointTrustSurface.RECOVERY_AUTHORITY
    synthetic_in_process = True
    operationally_external = False

    def __init__(
        self,
        *,
        provider_id: str = "synthetic-external-contract-checkpoint-recovery",
        allowed_operator_ids: frozenset[str] = frozenset({"synthetic-recovery-operator"}),
    ) -> None:
        self.provider_id = provider_id
        self._allowed_operator_ids = frozenset(allowed_operator_ids)

    def authorize_restore(self, request: RecoveryAuthorizationRequest) -> None:
        if (
            request.operator_id not in self._allowed_operator_ids
            or not request.backup_authenticated
            or not request.monotonic_anchor_verified
        ):
            raise CheckpointExternalContractError(
                CheckpointExternalContractReason.RECOVERY_AUTHORIZATION_DENIED,
                surface=self.surface,
            )


@dataclass(frozen=True)
class CheckpointExternalTrustAdapterBundle:
    manifest: CheckpointTrustProviderManifest
    encryption: CheckpointEncryptionKeyProvider
    integrity: ExternalCheckpointIntegrityAdapter
    anchor: ExternalCheckpointAnchorAdapter
    backup_authentication: ExternalCheckpointBackupAuthenticationAdapter
    recovery_authority: ExternalCheckpointRecoveryAuthorityAdapter
    policy_version: str = P4G_CHECKPOINT_EXTERNAL_CONTRACT_POLICY_VERSION

    def _adapters(self) -> dict[CheckpointTrustSurface, object]:
        return {
            CheckpointTrustSurface.ENCRYPTION_KEY_CUSTODY: self.encryption,
            CheckpointTrustSurface.INTEGRITY_KEY_CUSTODY: self.integrity,
            CheckpointTrustSurface.MONOTONIC_ANCHOR: self.anchor,
            CheckpointTrustSurface.BACKUP_AUTHENTICATION: self.backup_authentication,
            CheckpointTrustSurface.RECOVERY_AUTHORITY: self.recovery_authority,
        }

    def assert_contract_profile(
        self,
        profile: TrustDeploymentProfile = TrustDeploymentProfile.PRODUCTION_EXTERNAL_REQUIRED,
    ) -> None:
        self.manifest.assert_allowed(profile)
        descriptors = {provider.surface: provider for provider in self.manifest.providers}
        adapters = self._adapters()
        for surface in CheckpointTrustSurface:
            adapter = adapters.get(surface)
            if adapter is None:
                raise CheckpointExternalContractError(
                    CheckpointExternalContractReason.ADAPTER_SURFACE_MISSING,
                    surface=surface,
                )
            descriptor = descriptors[surface]
            adapter_provider_id = str(getattr(adapter, "provider_id", ""))
            if adapter_provider_id != descriptor.provider_id:
                raise CheckpointExternalContractError(
                    CheckpointExternalContractReason.ADAPTER_PROVIDER_ID_MISMATCH,
                    surface=surface,
                )
            if surface in {
                CheckpointTrustSurface.ENCRYPTION_KEY_CUSTODY,
                CheckpointTrustSurface.INTEGRITY_KEY_CUSTODY,
                CheckpointTrustSurface.BACKUP_AUTHENTICATION,
            } and not bool(getattr(adapter, "external_key_custody", False)):
                raise CheckpointExternalContractError(
                    CheckpointExternalContractReason.EXTERNAL_KEY_CUSTODY_REQUIRED,
                    surface=surface,
                )

    def production_runtime_eligible(self) -> bool:
        try:
            self.assert_contract_profile(TrustDeploymentProfile.PRODUCTION_EXTERNAL_REQUIRED)
        except Exception:
            return False
        return all(
            bool(getattr(adapter, "operationally_external", False))
            and not bool(getattr(adapter, "synthetic_in_process", True))
            for adapter in self._adapters().values()
        )

    def public_posture(self) -> tuple[dict[str, object], ...]:
        adapters = self._adapters()
        return tuple(
            {
                "surface": surface.value,
                "provider_id": str(getattr(adapters[surface], "provider_id", "")),
                "synthetic_in_process": bool(
                    getattr(adapters[surface], "synthetic_in_process", True)
                ),
                "operationally_external": bool(
                    getattr(adapters[surface], "operationally_external", False)
                ),
            }
            for surface in sorted(CheckpointTrustSurface, key=lambda item: item.value)
        )


def _descriptor(
    surface: CheckpointTrustSurface,
    provider_id: str,
) -> CheckpointTrustProviderDescriptor:
    key_surfaces = {
        CheckpointTrustSurface.ENCRYPTION_KEY_CUSTODY,
        CheckpointTrustSurface.INTEGRITY_KEY_CUSTODY,
        CheckpointTrustSurface.BACKUP_AUTHENTICATION,
    }
    return CheckpointTrustProviderDescriptor(
        surface=surface,
        provider_id=provider_id,
        kind=TrustProviderKind.EXTERNAL,
        independent_failure_domain=True,
        external_key_custody=surface in key_surfaces,
        rollback_resistant_state=surface is CheckpointTrustSurface.MONOTONIC_ANCHOR,
        external_recovery_authority=surface is CheckpointTrustSurface.RECOVERY_AUTHORITY,
    )


def build_synthetic_external_checkpoint_contract_bundle(
    *,
    encryption_provider_id: str = "synthetic-external-contract-checkpoint-encryption",
    encryption_external_key_custody: bool = True,
) -> CheckpointExternalTrustAdapterBundle:
    encryption = SyntheticExternalStyleCheckpointEncryptionAdapter(
        provider_id=encryption_provider_id,
        external_key_custody=encryption_external_key_custody,
    )
    integrity = SyntheticExternalStyleCheckpointIntegrityAdapter()
    anchor = SyntheticExternalStyleCheckpointAnchorAdapter()
    backup_authentication = SyntheticExternalStyleCheckpointBackupAuthenticationAdapter()
    recovery_authority = SyntheticExternalStyleCheckpointRecoveryAuthorityAdapter()
    adapters = (
        encryption,
        integrity,
        anchor,
        backup_authentication,
        recovery_authority,
    )
    manifest = CheckpointTrustProviderManifest(
        providers=tuple(
            _descriptor(adapter.surface, str(adapter.provider_id))
            for adapter in adapters
        )
    )
    return CheckpointExternalTrustAdapterBundle(
        manifest=manifest,
        encryption=encryption,
        integrity=integrity,
        anchor=anchor,
        backup_authentication=backup_authentication,
        recovery_authority=recovery_authority,
    )
