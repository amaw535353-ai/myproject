from __future__ import annotations

from dataclasses import replace
import hashlib

from aegis.training.data_provenance_types import (
    DatasetRecordEvidence,
    DatasetSourceSnapshot,
    DatasetSplit,
    DatasetTransformEvidence,
    TrainingDataDecision,
    TrainingDatasetManifest,
    TrainingDatasetPolicy,
    TrainingDatasetRequest,
    TransformKind,
    ZERO_SHA256,
    P9A_DATASET_POLICY_VERSION,
    P9A_DATASET_SCHEMA_VERSION,
    deterministic_transform_output_digest,
    raw_dataset_digest,
    training_dataset_manifest_digest,
    transform_evidence_digest,
)

NOW = 1_800_000_000
MANIFEST_ID = "p9a-training-dataset-manifest-001"
DATASET_ID = "aegisdesk-helpdesk-training"
DATASET_VERSION = "2026.08-p9a"


def h(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


SOURCE_IDS = ("src-helpdesk", "src-security", "src-synthetic")
RECORD_IDS = tuple(f"record-{i:02d}" for i in range(1, 13))
TRAIN_IDS = RECORD_IDS[:6]
VALIDATION_IDS = RECORD_IDS[6:9]
TEST_IDS = RECORD_IDS[9:]
TRANSFORM_IDS = ("transform-normalize", "transform-dedupe", "transform-canonicalize")


def _source_for_index(i: int) -> str:
    if i <= 4:
        return "src-helpdesk"
    if i <= 8:
        return "src-security"
    return "src-synthetic"


def _build_manifest() -> TrainingDatasetManifest:
    sources = (
        DatasetSourceSnapshot(
            source_id="src-helpdesk",
            owner="curated-helpdesk",
            uri="dataset://curated/helpdesk/support-tickets",
            revision="support-tickets@2026-08-01",
            snapshot_sha256=h("source:helpdesk:2026-08-01"),
            observed_at_epoch=NOW - 3600,
        ),
        DatasetSourceSnapshot(
            source_id="src-security",
            owner="security-curation",
            uri="dataset://curated/security/runbooks",
            revision="security-runbooks@2026-08-02",
            snapshot_sha256=h("source:security:2026-08-02"),
            observed_at_epoch=NOW - 3000,
        ),
        DatasetSourceSnapshot(
            source_id="src-synthetic",
            owner="aegis-synthetic",
            uri="dataset://synthetic/aegisdesk/adversarial",
            revision="synthetic-adversarial@2026-08-03",
            snapshot_sha256=h("source:synthetic:2026-08-03"),
            observed_at_epoch=NOW - 2400,
        ),
    )
    records = tuple(
        DatasetRecordEvidence(
            record_id=record_id,
            source_id=_source_for_index(i),
            source_record_key=f"source-key-{i:02d}",
            payload_sha256=h(f"payload:{record_id}:canonical-v1"),
            parent_record_ids=(),
        )
        for i, record_id in enumerate(RECORD_IDS, start=1)
    )
    provisional = TrainingDatasetManifest(
        schema_version=P9A_DATASET_SCHEMA_VERSION,
        manifest_id=MANIFEST_ID,
        dataset_id=DATASET_ID,
        dataset_version=DATASET_VERSION,
        created_at_epoch=NOW,
        source_snapshots=sources,
        records=records,
        split_record_ids_by_split={
            DatasetSplit.TRAIN: TRAIN_IDS,
            DatasetSplit.VALIDATION: VALIDATION_IDS,
            DatasetSplit.TEST: TEST_IDS,
        },
        transforms=(),
        final_dataset_sha256=ZERO_SHA256,
    )
    current = raw_dataset_digest(provisional)
    transforms: list[DatasetTransformEvidence] = []
    previous = ZERO_SHA256
    profiles = (
        ("transform-normalize", TransformKind.NORMALIZE_TEXT, "training-platform", h("cfg:normalize:v1")),
        ("transform-dedupe", TransformKind.DEDUPLICATE_EXACT, "training-platform", h("cfg:dedupe:v1")),
        ("transform-canonicalize", TransformKind.CANONICALIZE_FIELDS, "training-platform", h("cfg:canonicalize:v1")),
    )
    for transform_id, kind, owner, config_sha in profiles:
        output = deterministic_transform_output_digest(current, transform_id, kind, owner, config_sha)
        transform = DatasetTransformEvidence(
            transform_id=transform_id,
            kind=kind,
            owner=owner,
            config_sha256=config_sha,
            input_dataset_sha256=current,
            output_dataset_sha256=output,
            predecessor_transform_sha256=previous,
            network_operations=0,
        )
        transforms.append(transform)
        current = output
        previous = transform_evidence_digest(transform)
    return replace(provisional, transforms=tuple(transforms), final_dataset_sha256=current)


def build_fixture() -> dict[str, object]:
    manifest = _build_manifest()
    source_by_id = {s.source_id: s for s in manifest.source_snapshots}
    record_by_id = {r.record_id: r for r in manifest.records}
    expected_split = {record_id: DatasetSplit.TRAIN for record_id in TRAIN_IDS}
    expected_split.update({record_id: DatasetSplit.VALIDATION for record_id in VALIDATION_IDS})
    expected_split.update({record_id: DatasetSplit.TEST for record_id in TEST_IDS})
    policy = TrainingDatasetPolicy(
        policy_version=P9A_DATASET_POLICY_VERSION,
        expected_manifest_id=MANIFEST_ID,
        expected_dataset_id=DATASET_ID,
        expected_dataset_version=DATASET_VERSION,
        expected_manifest_sha256=training_dataset_manifest_digest(manifest),
        trusted_source_owners=("curated-helpdesk", "security-curation", "aegis-synthetic"),
        allowed_source_uri_prefix_by_owner={
            "curated-helpdesk": "dataset://curated/helpdesk/",
            "security-curation": "dataset://curated/security/",
            "aegis-synthetic": "dataset://synthetic/aegisdesk/",
        },
        expected_source_revision_by_id={source_id: source_by_id[source_id].revision for source_id in SOURCE_IDS},
        expected_source_snapshot_sha256_by_id={source_id: source_by_id[source_id].snapshot_sha256 for source_id in SOURCE_IDS},
        expected_record_sha256_by_id={record_id: record_by_id[record_id].payload_sha256 for record_id in RECORD_IDS},
        expected_record_source_by_id={record_id: record_by_id[record_id].source_id for record_id in RECORD_IDS},
        expected_record_key_by_id={record_id: record_by_id[record_id].source_record_key for record_id in RECORD_IDS},
        expected_parent_record_ids_by_id={record_id: record_by_id[record_id].parent_record_ids for record_id in RECORD_IDS},
        expected_split_by_record_id=expected_split,
        expected_transform_order=TRANSFORM_IDS,
        expected_transform_kind_by_id={t.transform_id: t.kind for t in manifest.transforms},
        expected_transform_owner_by_id={t.transform_id: t.owner for t in manifest.transforms},
        expected_transform_config_sha256_by_id={t.transform_id: t.config_sha256 for t in manifest.transforms},
        expected_final_dataset_sha256=manifest.final_dataset_sha256,
        max_manifest_age_seconds=300,
        max_future_skew_seconds=5,
        max_source_age_seconds=86_400,
    )
    request = TrainingDatasetRequest(
        manifest_id=MANIFEST_ID,
        manifest_sha256=training_dataset_manifest_digest(manifest),
        dataset_id=DATASET_ID,
        dataset_version=DATASET_VERSION,
        evaluated_at_epoch=NOW,
        declared_source_ids=tuple(sorted(SOURCE_IDS)),
        declared_record_count=len(RECORD_IDS),
        declared_split_counts={
            DatasetSplit.TRAIN: len(TRAIN_IDS),
            DatasetSplit.VALIDATION: len(VALIDATION_IDS),
            DatasetSplit.TEST: len(TEST_IDS),
        },
        declared_final_dataset_sha256=manifest.final_dataset_sha256,
        declared_training_data_safe=True,
        declared_provenance_complete=True,
    )
    return {"manifest": manifest, "policy": policy, "request": request}


def rebind_manifest(fixture: dict[str, object], manifest: TrainingDatasetManifest) -> dict[str, object]:
    policy = fixture["policy"]
    request = fixture["request"]
    assert isinstance(policy, TrainingDatasetPolicy)
    assert isinstance(request, TrainingDatasetRequest)
    digest = training_dataset_manifest_digest(manifest)
    result = dict(fixture)
    result["manifest"] = manifest
    result["policy"] = replace(policy, expected_manifest_sha256=digest)
    result["request"] = replace(
        request,
        manifest_sha256=digest,
        declared_source_ids=tuple(sorted(s.source_id for s in manifest.source_snapshots)),
        declared_record_count=len(manifest.records),
        declared_split_counts={split: len(tuple(manifest.split_record_ids_by_split.get(split, ()))) for split in DatasetSplit},
        declared_final_dataset_sha256=manifest.final_dataset_sha256,
    )
    return result
