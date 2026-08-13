from __future__ import annotations

from aegis.effects.control_plane_recovery import (
    ControlPlaneCrashPoint,
    ControlPlaneMutation,
    ControlPlaneMutationKind,
    SyntheticControlPlaneCrash,
)
from aegis.effects.rollback_anchor import ControlPlaneGenerationStore
from aegis.effects.signed_authorization import TrustedAuthorizationKeyStore
from aegis.effects.versioned_revalidation import VersionedAuthorizationController


class VulnerableUncoordinatedControlPlane:
    """Intentionally performs execution-state and anchor writes without a recovery journal."""

    def __init__(
        self,
        *,
        controller: VersionedAuthorizationController,
        trusted_keys: TrustedAuthorizationKeyStore,
        generation_store: ControlPlaneGenerationStore,
        authority_id: str,
    ) -> None:
        self.controller = controller
        self.trusted_keys = trusted_keys
        self.generation_store = generation_store
        self.authority_id = authority_id

    def _apply(self, mutation: ControlPlaneMutation) -> None:
        if mutation.kind is ControlPlaneMutationKind.SUBJECT_ACTIVE:
            assert mutation.user_id is not None and mutation.active is not None
            self.controller.set_subject_active(mutation.user_id, mutation.active)
            return
        if mutation.kind is ControlPlaneMutationKind.PASSWORD_RESET_ENABLED:
            assert mutation.tenant_id is not None and mutation.password_reset_enabled is not None
            self.controller.set_password_reset_enabled(
                mutation.tenant_id,
                mutation.password_reset_enabled,
            )
            return
        assert mutation.issuer_id is not None
        assert mutation.audience is not None
        assert mutation.key_id is not None
        assert mutation.key_epoch is not None
        assert mutation.public_key_hex is not None
        self.trusted_keys.rotate_key(
            issuer_id=mutation.issuer_id,
            audience=mutation.audience,
            key_id=mutation.key_id,
            key_epoch=mutation.key_epoch,
            public_key_bytes=bytes.fromhex(mutation.public_key_hex),
        )

    def commit(
        self,
        *,
        change_id: str,
        mutation: ControlPlaneMutation,
        crash_at: ControlPlaneCrashPoint | None = None,
    ) -> int:
        del change_id  # No durable change identity exists in this intentionally vulnerable baseline.
        current_generation = self.generation_store.current(self.authority_id)
        self._apply(mutation)
        if crash_at is ControlPlaneCrashPoint.AFTER_EXECUTION_APPLY:
            # INTENTIONALLY VULNERABLE: the execution database is already committed,
            # but there is no pending journal or applied-generation marker to fence it.
            raise SyntheticControlPlaneCrash(crash_at)
        return self.generation_store.advance(
            authority_id=self.authority_id,
            expected_current=current_generation,
        )
