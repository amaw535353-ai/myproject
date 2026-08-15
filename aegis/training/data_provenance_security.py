from __future__ import annotations

import re

from .data_provenance_types import (
    DatasetSplit,
    TrainingDataDecision,
    TrainingDataRejectReason,
    TrainingDataRisk,
    TrainingDatasetManifest,
    TrainingDatasetPolicy,
    TrainingDatasetRequest,
    VerifiedTrainingDatasetAssessment,
    ZERO_SHA256,
    P9A_ASSESSMENT_MODE,
    P9A_ASSESSMENT_SCHEMA_VERSION,
    P9A_DATASET_POLICY_VERSION,
    P9A_DATASET_SCHEMA_VERSION,
    deterministic_transform_output_digest,
    digest_json,
    raw_dataset_digest,
    reject,
    training_dataset_manifest_digest,
    transform_evidence_digest,
)

_SHA256_RE = re.compile(r"^[0-9a-fA-F]{64}$")


class TrainingDatasetProvenanceAnalyzer:
    def __init__(self, policy: TrainingDatasetPolicy):
        self.policy = policy
        self._validate_policy()

    @staticmethod
    def _sha(value: str) -> bool:
        return bool(_SHA256_RE.fullmatch(str(value)))

    def _validate_policy(self) -> None:
        p = self.policy
        if p.policy_version != P9A_DATASET_POLICY_VERSION:
            reject(TrainingDataRejectReason.POLICY_INVALID, "unexpected policy version")
        if not p.expected_manifest_id or not p.expected_dataset_id or not p.expected_dataset_version:
            reject(TrainingDataRejectReason.POLICY_INVALID, "dataset identity pins are required")
        if not self._sha(p.expected_manifest_sha256) or not self._sha(p.expected_final_dataset_sha256):
            reject(TrainingDataRejectReason.POLICY_INVALID, "manifest/final dataset pins must be sha256")
        key_sets = [
            set(p.expected_record_sha256_by_id),
            set(p.expected_record_source_by_id),
            set(p.expected_record_key_by_id),
            set(p.expected_parent_record_ids_by_id),
            set(p.expected_split_by_record_id),
        ]
        if not key_sets or any(keys != key_sets[0] for keys in key_sets[1:]):
            reject(TrainingDataRejectReason.POLICY_INVALID, "record policy maps must cover identical record IDs")
        if set(p.expected_source_revision_by_id) != set(p.expected_source_snapshot_sha256_by_id):
            reject(TrainingDataRejectReason.POLICY_INVALID, "source policy maps must cover identical source IDs")
        transform_ids = set(p.expected_transform_order)
        if len(transform_ids) != len(p.expected_transform_order):
            reject(TrainingDataRejectReason.POLICY_INVALID, "duplicate transform IDs")
        if set(p.expected_transform_kind_by_id) != transform_ids:
            reject(TrainingDataRejectReason.POLICY_INVALID, "transform kind pins must cover transform order")
        if set(p.expected_transform_owner_by_id) != transform_ids:
            reject(TrainingDataRejectReason.POLICY_INVALID, "transform owner pins must cover transform order")
        if set(p.expected_transform_config_sha256_by_id) != transform_ids:
            reject(TrainingDataRejectReason.POLICY_INVALID, "transform config pins must cover transform order")
        for digest in (
            list(p.expected_record_sha256_by_id.values())
            + list(p.expected_source_snapshot_sha256_by_id.values())
            + list(p.expected_transform_config_sha256_by_id.values())
        ):
            if not self._sha(str(digest)):
                reject(TrainingDataRejectReason.POLICY_INVALID, "evidence pins must be sha256")
        if p.max_manifest_age_seconds < 0 or p.max_future_skew_seconds < 0 or p.max_source_age_seconds < 0:
            reject(TrainingDataRejectReason.POLICY_INVALID, "freshness limits must be non-negative")

    def _validate_manifest_shape(self, manifest: TrainingDatasetManifest) -> None:
        if manifest.schema_version != P9A_DATASET_SCHEMA_VERSION:
            reject(TrainingDataRejectReason.MANIFEST_INVALID, "unexpected manifest schema")
        if manifest.manifest_id != self.policy.expected_manifest_id:
            reject(TrainingDataRejectReason.MANIFEST_INVALID, "manifest identity mismatch")
        if manifest.dataset_id != self.policy.expected_dataset_id or manifest.dataset_version != self.policy.expected_dataset_version:
            reject(TrainingDataRejectReason.MANIFEST_INVALID, "dataset identity mismatch")
        if not self._sha(manifest.final_dataset_sha256):
            reject(TrainingDataRejectReason.MANIFEST_INVALID, "final dataset digest must be sha256")
        source_ids = [s.source_id for s in manifest.source_snapshots]
        if len(source_ids) != len(set(source_ids)):
            reject(TrainingDataRejectReason.MANIFEST_INVALID, "duplicate source IDs")
        record_ids = [r.record_id for r in manifest.records]
        if len(record_ids) != len(set(record_ids)):
            reject(TrainingDataRejectReason.MANIFEST_INVALID, "duplicate record IDs")
        record_keys = [(r.source_id, r.source_record_key) for r in manifest.records]
        if len(record_keys) != len(set(record_keys)):
            reject(TrainingDataRejectReason.MANIFEST_INVALID, "duplicate source record keys")
        transform_ids = [t.transform_id for t in manifest.transforms]
        if len(transform_ids) != len(set(transform_ids)):
            reject(TrainingDataRejectReason.MANIFEST_INVALID, "duplicate transform IDs")
        for s in manifest.source_snapshots:
            if not s.source_id or not s.owner or not s.uri or not s.revision or not self._sha(s.snapshot_sha256):
                reject(TrainingDataRejectReason.MANIFEST_INVALID, "invalid source snapshot")
        for r in manifest.records:
            if not r.record_id or not r.source_id or not r.source_record_key or not self._sha(r.payload_sha256):
                reject(TrainingDataRejectReason.MANIFEST_INVALID, "invalid record evidence")
            if len(set(r.parent_record_ids)) != len(r.parent_record_ids):
                reject(TrainingDataRejectReason.MANIFEST_INVALID, "duplicate parent record IDs")
        for split in DatasetSplit:
            ids = tuple(manifest.split_record_ids_by_split.get(split, ()))
            if len(ids) != len(set(ids)):
                reject(TrainingDataRejectReason.MANIFEST_INVALID, f"duplicate record inside {split.value} split")
        for t in manifest.transforms:
            if not t.transform_id or not t.owner:
                reject(TrainingDataRejectReason.MANIFEST_INVALID, "invalid transform identity")
            if not all(self._sha(v) for v in (t.config_sha256, t.input_dataset_sha256, t.output_dataset_sha256, t.predecessor_transform_sha256)):
                reject(TrainingDataRejectReason.MANIFEST_INVALID, "transform digests must be sha256")
            if t.network_operations < 0:
                reject(TrainingDataRejectReason.MANIFEST_INVALID, "network operation count cannot be negative")

    def derive(self, manifest: TrainingDatasetManifest, now: int) -> tuple[TrainingDataRisk, ...]:
        self._validate_manifest_shape(manifest)
        p = self.policy
        risks: set[TrainingDataRisk] = set()

        sources = {s.source_id: s for s in manifest.source_snapshots}
        expected_source_ids = set(p.expected_source_snapshot_sha256_by_id)
        if set(sources) != expected_source_ids:
            risks.add(TrainingDataRisk.SOURCE_IDENTITY_MISMATCH)
        for source_id in sorted(expected_source_ids.intersection(sources)):
            source = sources[source_id]
            if source.owner not in p.trusted_source_owners:
                risks.add(TrainingDataRisk.SOURCE_OWNER_UNTRUSTED)
            prefix = p.allowed_source_uri_prefix_by_owner.get(source.owner)
            if prefix is None or not source.uri.startswith(prefix):
                risks.add(TrainingDataRisk.SOURCE_URI_UNTRUSTED)
            if source.revision != p.expected_source_revision_by_id[source_id]:
                risks.add(TrainingDataRisk.SOURCE_REVISION_MISMATCH)
            if source.snapshot_sha256.casefold() != p.expected_source_snapshot_sha256_by_id[source_id].casefold():
                risks.add(TrainingDataRisk.SOURCE_DIGEST_MISMATCH)
            if source.observed_at_epoch > manifest.created_at_epoch + p.max_future_skew_seconds:
                risks.add(TrainingDataRisk.SOURCE_TIME_INVALID)
            if manifest.created_at_epoch - source.observed_at_epoch > p.max_source_age_seconds:
                risks.add(TrainingDataRisk.SOURCE_TIME_INVALID)

        records = {r.record_id: r for r in manifest.records}
        expected_record_ids = set(p.expected_record_sha256_by_id)
        if set(records) != expected_record_ids:
            risks.add(TrainingDataRisk.RECORD_COVERAGE_MISMATCH)
        for record_id in sorted(expected_record_ids.intersection(records)):
            record = records[record_id]
            if record.payload_sha256.casefold() != p.expected_record_sha256_by_id[record_id].casefold():
                risks.add(TrainingDataRisk.RECORD_DIGEST_MISMATCH)
            if record.source_id != p.expected_record_source_by_id[record_id]:
                risks.add(TrainingDataRisk.RECORD_SOURCE_MISMATCH)
            if record.source_record_key != p.expected_record_key_by_id[record_id]:
                risks.add(TrainingDataRisk.RECORD_KEY_MISMATCH)
            if tuple(record.parent_record_ids) != tuple(p.expected_parent_record_ids_by_id[record_id]):
                risks.add(TrainingDataRisk.RECORD_PARENT_MISMATCH)
            if record.source_id not in sources:
                risks.add(TrainingDataRisk.RECORD_SOURCE_MISMATCH)
            if any(parent not in records for parent in record.parent_record_ids):
                risks.add(TrainingDataRisk.RECORD_PARENT_MISSING)

        split_membership: dict[str, list[DatasetSplit]] = {}
        for split in DatasetSplit:
            for record_id in manifest.split_record_ids_by_split.get(split, ()):
                split_membership.setdefault(record_id, []).append(split)
        if set(split_membership) != set(records):
            risks.add(TrainingDataRisk.SPLIT_COVERAGE_MISMATCH)
        if any(len(splits) != 1 for splits in split_membership.values()):
            risks.add(TrainingDataRisk.SPLIT_OVERLAP)
        for record_id, expected_split in p.expected_split_by_record_id.items():
            actual = split_membership.get(record_id, [])
            if actual != [expected_split]:
                risks.add(TrainingDataRisk.SPLIT_ASSIGNMENT_MISMATCH)
            if expected_split in {DatasetSplit.VALIDATION, DatasetSplit.TEST} and DatasetSplit.TRAIN in actual:
                risks.add(TrainingDataRisk.HOLDOUT_LEAKAGE)

        expected_transform_ids = p.expected_transform_order
        actual_transform_ids = tuple(t.transform_id for t in manifest.transforms)
        if actual_transform_ids != expected_transform_ids:
            risks.add(TrainingDataRisk.TRANSFORM_COVERAGE_MISMATCH)
        current_input = raw_dataset_digest(manifest)
        previous_transform_sha = ZERO_SHA256
        for transform in manifest.transforms:
            if transform.transform_id not in p.expected_transform_kind_by_id:
                risks.add(TrainingDataRisk.TRANSFORM_UNAUTHORIZED)
            else:
                if transform.kind != p.expected_transform_kind_by_id[transform.transform_id]:
                    risks.add(TrainingDataRisk.TRANSFORM_UNAUTHORIZED)
                if transform.owner != p.expected_transform_owner_by_id[transform.transform_id]:
                    risks.add(TrainingDataRisk.TRANSFORM_OWNER_MISMATCH)
                if transform.config_sha256.casefold() != p.expected_transform_config_sha256_by_id[transform.transform_id].casefold():
                    risks.add(TrainingDataRisk.TRANSFORM_CONFIG_MISMATCH)
            if transform.input_dataset_sha256.casefold() != current_input.casefold():
                risks.add(TrainingDataRisk.TRANSFORM_CHAIN_BROKEN)
            if transform.predecessor_transform_sha256.casefold() != previous_transform_sha.casefold():
                risks.add(TrainingDataRisk.TRANSFORM_CHAIN_BROKEN)
            expected_output = deterministic_transform_output_digest(
                current_input,
                transform.transform_id,
                transform.kind,
                transform.owner,
                transform.config_sha256,
            )
            if transform.output_dataset_sha256.casefold() != expected_output.casefold():
                risks.add(TrainingDataRisk.TRANSFORM_CHAIN_BROKEN)
            if transform.network_operations != 0:
                risks.add(TrainingDataRisk.NETWORK_SIDE_EFFECT_REPORTED)
            current_input = transform.output_dataset_sha256
            previous_transform_sha = transform_evidence_digest(transform)

        if manifest.final_dataset_sha256.casefold() != current_input.casefold():
            risks.add(TrainingDataRisk.FINAL_DATASET_DIGEST_MISMATCH)
        if manifest.final_dataset_sha256.casefold() != p.expected_final_dataset_sha256.casefold():
            risks.add(TrainingDataRisk.FINAL_DATASET_DIGEST_MISMATCH)

        return tuple(sorted(risks, key=lambda risk: risk.value))

    def evaluate(self, request: TrainingDatasetRequest, manifest: TrainingDatasetManifest) -> VerifiedTrainingDatasetAssessment:
        self._validate_manifest_shape(manifest)
        actual_manifest_sha = training_dataset_manifest_digest(manifest)
        if actual_manifest_sha.casefold() != self.policy.expected_manifest_sha256.casefold():
            reject(TrainingDataRejectReason.MANIFEST_DIGEST_MISMATCH, "manifest differs from policy-pinned evidence")
        if request.manifest_id != manifest.manifest_id or request.manifest_sha256.casefold() != actual_manifest_sha:
            reject(TrainingDataRejectReason.REQUEST_INVALID, "request manifest binding mismatch")
        if request.dataset_id != manifest.dataset_id or request.dataset_version != manifest.dataset_version:
            reject(TrainingDataRejectReason.REQUEST_INVALID, "request dataset identity mismatch")
        if request.evaluated_at_epoch < manifest.created_at_epoch - self.policy.max_future_skew_seconds:
            reject(TrainingDataRejectReason.REQUEST_INVALID, "evaluation predates manifest beyond allowed skew")
        if request.evaluated_at_epoch > manifest.created_at_epoch + self.policy.max_manifest_age_seconds:
            reject(TrainingDataRejectReason.REQUEST_INVALID, "manifest is stale")

        risks = self.derive(manifest, request.evaluated_at_epoch)
        decision = TrainingDataDecision.DENY if risks else TrainingDataDecision.ALLOW
        source_ids = tuple(sorted(s.source_id for s in manifest.source_snapshots))
        split_counts = {split: len(tuple(manifest.split_record_ids_by_split.get(split, ()))) for split in DatasetSplit}
        if request.declared_source_ids != source_ids:
            reject(TrainingDataRejectReason.DECLARED_SUMMARY_MISMATCH, "declared source IDs differ from evidence")
        if request.declared_record_count != len(manifest.records):
            reject(TrainingDataRejectReason.DECLARED_SUMMARY_MISMATCH, "declared record count differs from evidence")
        if dict(request.declared_split_counts) != split_counts:
            reject(TrainingDataRejectReason.DECLARED_SUMMARY_MISMATCH, "declared split counts differ from evidence")
        if request.declared_final_dataset_sha256.casefold() != manifest.final_dataset_sha256.casefold():
            reject(TrainingDataRejectReason.DECLARED_SUMMARY_MISMATCH, "declared final dataset digest differs from evidence")
        expected_safe = decision == TrainingDataDecision.ALLOW
        if request.declared_training_data_safe != expected_safe or request.declared_provenance_complete != expected_safe:
            reject(TrainingDataRejectReason.DECLARED_SUMMARY_MISMATCH, "caller-declared training safety differs from derived evidence")

        source_risks = {
            TrainingDataRisk.SOURCE_IDENTITY_MISMATCH,
            TrainingDataRisk.SOURCE_OWNER_UNTRUSTED,
            TrainingDataRisk.SOURCE_URI_UNTRUSTED,
            TrainingDataRisk.SOURCE_REVISION_MISMATCH,
            TrainingDataRisk.SOURCE_DIGEST_MISMATCH,
            TrainingDataRisk.SOURCE_TIME_INVALID,
        }
        record_risks = {
            TrainingDataRisk.RECORD_COVERAGE_MISMATCH,
            TrainingDataRisk.RECORD_DIGEST_MISMATCH,
            TrainingDataRisk.RECORD_SOURCE_MISMATCH,
            TrainingDataRisk.RECORD_KEY_MISMATCH,
            TrainingDataRisk.RECORD_PARENT_MISMATCH,
            TrainingDataRisk.RECORD_PARENT_MISSING,
        }
        split_risks = {
            TrainingDataRisk.SPLIT_COVERAGE_MISMATCH,
            TrainingDataRisk.SPLIT_ASSIGNMENT_MISMATCH,
            TrainingDataRisk.SPLIT_OVERLAP,
            TrainingDataRisk.HOLDOUT_LEAKAGE,
        }
        transform_risks = {
            TrainingDataRisk.TRANSFORM_COVERAGE_MISMATCH,
            TrainingDataRisk.TRANSFORM_UNAUTHORIZED,
            TrainingDataRisk.TRANSFORM_OWNER_MISMATCH,
            TrainingDataRisk.TRANSFORM_CONFIG_MISMATCH,
            TrainingDataRisk.TRANSFORM_CHAIN_BROKEN,
            TrainingDataRisk.FINAL_DATASET_DIGEST_MISMATCH,
            TrainingDataRisk.NETWORK_SIDE_EFFECT_REPORTED,
        }
        risk_set = set(risks)
        assessment_payload = {
            "manifest_id": manifest.manifest_id,
            "dataset_id": manifest.dataset_id,
            "dataset_version": manifest.dataset_version,
            "decision": decision,
            "risks": risks,
            "sources": source_ids,
            "record_count": len(manifest.records),
            "split_counts": split_counts,
            "transform_count": len(manifest.transforms),
            "final_dataset_sha256": manifest.final_dataset_sha256.casefold(),
            "schema": P9A_ASSESSMENT_SCHEMA_VERSION,
            "mode": P9A_ASSESSMENT_MODE,
        }
        return VerifiedTrainingDatasetAssessment(
            manifest_id=manifest.manifest_id,
            dataset_id=manifest.dataset_id,
            dataset_version=manifest.dataset_version,
            decision=decision,
            risks=risks,
            source_count=len(manifest.source_snapshots),
            record_count=len(manifest.records),
            split_counts=split_counts,
            transform_count=len(manifest.transforms),
            final_dataset_sha256=manifest.final_dataset_sha256.casefold(),
            exact_manifest_binding_verified=True,
            trusted_source_snapshots_verified=not bool(risk_set.intersection(source_risks)),
            record_hash_coverage_verified=not bool(risk_set.intersection(record_risks)),
            split_isolation_verified=not bool(risk_set.intersection(split_risks)),
            transform_lineage_verified=not bool(risk_set.intersection(transform_risks)),
            caller_declared_training_data_safety_trusted=False,
            production_data_lake_integration=False,
            production_training_pipeline_attestation=False,
            cryptographic_source_authentication=False,
            network_operations=sum(t.network_operations for t in manifest.transforms),
            assessment_schema_version=P9A_ASSESSMENT_SCHEMA_VERSION,
            assessment_mode=P9A_ASSESSMENT_MODE,
            assessment_evidence_sha256=digest_json(assessment_payload),
        )
