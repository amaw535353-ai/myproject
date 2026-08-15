from __future__ import annotations

from dataclasses import replace
import hashlib
import json
from typing import Callable

from aegis.training import (
    DatasetSourceSnapshot,
    DatasetSplit,
    DatasetTransformEvidence,
    TrainingDataDecision,
    TrainingDataSecurityRejected,
    TrainingDatasetProvenanceAnalyzer,
    TransformKind,
    deterministic_transform_output_digest,
)
from aegis.vulnerable.training_data_provenance import VulnerableCallerDeclaredTrainingDataTrust
from evals.p9a_fixture import (
    NOW,
    RECORD_IDS,
    SOURCE_IDS,
    TEST_IDS,
    TRAIN_IDS,
    VALIDATION_IDS,
    build_fixture,
    h,
    rebind_manifest,
)

Fixture = dict[str, object]
Attack = Callable[[Fixture], Fixture]


def _source_attack(index: int, **changes) -> Attack:
    def mutate(f: Fixture) -> Fixture:
        manifest = f["manifest"]
        sources = list(manifest.source_snapshots)
        sources[index] = replace(sources[index], **changes)
        return rebind_manifest(f, replace(manifest, source_snapshots=tuple(sources)))
    return mutate


def _record_attack(index: int, **changes) -> Attack:
    def mutate(f: Fixture) -> Fixture:
        manifest = f["manifest"]
        records = list(manifest.records)
        records[index] = replace(records[index], **changes)
        return rebind_manifest(f, replace(manifest, records=tuple(records)))
    return mutate


def _transform_attack(index: int, **changes) -> Attack:
    def mutate(f: Fixture) -> Fixture:
        manifest = f["manifest"]
        transforms = list(manifest.transforms)
        transforms[index] = replace(transforms[index], **changes)
        return rebind_manifest(f, replace(manifest, transforms=tuple(transforms)))
    return mutate


def _request_attack(**changes) -> Attack:
    def mutate(f: Fixture) -> Fixture:
        out = dict(f)
        out["request"] = replace(f["request"], **changes)
        return out
    return mutate


def _move_split(record_id: str, target: DatasetSplit) -> Attack:
    def mutate(f: Fixture) -> Fixture:
        manifest = f["manifest"]
        split_map = {split: list(manifest.split_record_ids_by_split.get(split, ())) for split in DatasetSplit}
        for split in DatasetSplit:
            if record_id in split_map[split]:
                split_map[split].remove(record_id)
        split_map[target].append(record_id)
        changed = replace(manifest, split_record_ids_by_split={k: tuple(v) for k, v in split_map.items()})
        return rebind_manifest(f, changed)
    return mutate


def _overlap_into_train(record_id: str) -> Attack:
    def mutate(f: Fixture) -> Fixture:
        manifest = f["manifest"]
        split_map = {split: list(manifest.split_record_ids_by_split.get(split, ())) for split in DatasetSplit}
        split_map[DatasetSplit.TRAIN].append(record_id)
        changed = replace(manifest, split_record_ids_by_split={k: tuple(v) for k, v in split_map.items()})
        return rebind_manifest(f, changed)
    return mutate


def _drop_from_split(record_id: str) -> Attack:
    def mutate(f: Fixture) -> Fixture:
        manifest = f["manifest"]
        split_map = {split: list(manifest.split_record_ids_by_split.get(split, ())) for split in DatasetSplit}
        for split in DatasetSplit:
            if record_id in split_map[split]:
                split_map[split].remove(record_id)
        changed = replace(manifest, split_record_ids_by_split={k: tuple(v) for k, v in split_map.items()})
        return rebind_manifest(f, changed)
    return mutate


def _build_cases() -> list[tuple[str, Attack]]:
    cases: list[tuple[str, Attack]] = []

    def manifest_unsealed(f: Fixture) -> Fixture:
        out = dict(f)
        out["manifest"] = replace(f["manifest"], created_at_epoch=NOW - 1)
        return out
    cases.append(("manifest-outer-digest-substitution", manifest_unsealed))
    cases.extend(
        [
            ("request-manifest-id", _request_attack(manifest_id="caller-manifest")),
            ("request-manifest-sha", _request_attack(manifest_sha256=h("caller-manifest-sha"))),
            ("request-dataset-id", _request_attack(dataset_id="other-dataset")),
            ("request-dataset-version", _request_attack(dataset_version="other-version")),
            ("request-evaluation-too-old", _request_attack(evaluated_at_epoch=NOW - 6)),
            ("request-evaluation-stale", _request_attack(evaluated_at_epoch=NOW + 301)),
            ("request-source-summary", _request_attack(declared_source_ids=("src-helpdesk",))),
            ("request-record-count", _request_attack(declared_record_count=999)),
            (
                "request-split-counts",
                _request_attack(
                    declared_split_counts={DatasetSplit.TRAIN: 12, DatasetSplit.VALIDATION: 0, DatasetSplit.TEST: 0}
                ),
            ),
            ("request-final-digest", _request_attack(declared_final_dataset_sha256=h("caller-final"))),
        ]
    )

    for i, source_id in enumerate(SOURCE_IDS):
        cases.extend(
            [
                (f"source-owner-{source_id}", _source_attack(i, owner="untrusted-uploader")),
                (f"source-uri-{source_id}", _source_attack(i, uri="https://attacker.invalid/dataset")),
                (f"source-revision-{source_id}", _source_attack(i, revision="mutable-latest")),
                (f"source-digest-{source_id}", _source_attack(i, snapshot_sha256=h(f"tampered:{source_id}"))),
                (f"source-future-{source_id}", _source_attack(i, observed_at_epoch=NOW + 10)),
                (f"source-too-old-{source_id}", _source_attack(i, observed_at_epoch=NOW - 86_401)),
            ]
        )

        def drop_source(f: Fixture, index=i) -> Fixture:
            manifest = f["manifest"]
            sources = list(manifest.source_snapshots)
            del sources[index]
            return rebind_manifest(f, replace(manifest, source_snapshots=tuple(sources)))
        cases.append((f"source-drop-{source_id}", drop_source))

    def add_unknown_source(f: Fixture) -> Fixture:
        manifest = f["manifest"]
        extra = DatasetSourceSnapshot(
            source_id="src-unknown",
            owner="untrusted-uploader",
            uri="dataset://unknown/raw",
            revision="latest",
            snapshot_sha256=h("unknown-source"),
            observed_at_epoch=NOW,
        )
        return rebind_manifest(f, replace(manifest, source_snapshots=manifest.source_snapshots + (extra,)))
    cases.append(("source-extra-unknown", add_unknown_source))

    for i, record_id in enumerate(RECORD_IDS):
        current_source = "src-helpdesk" if i < 4 else ("src-security" if i < 8 else "src-synthetic")
        other_source = next(source_id for source_id in SOURCE_IDS if source_id != current_source)
        known_parent = RECORD_IDS[(i + 1) % len(RECORD_IDS)]
        cases.extend(
            [
                (f"record-digest-{record_id}", _record_attack(i, payload_sha256=h(f"tampered:{record_id}"))),
                (f"record-source-{record_id}", _record_attack(i, source_id=other_source)),
                (f"record-key-{record_id}", _record_attack(i, source_record_key=f"swapped-key-{i:02d}")),
                (f"record-parent-{record_id}", _record_attack(i, parent_record_ids=(known_parent,))),
                (f"record-parent-missing-{record_id}", _record_attack(i, parent_record_ids=("missing-parent",))),
            ]
        )

    def drop_record(f: Fixture) -> Fixture:
        manifest = f["manifest"]
        return rebind_manifest(f, replace(manifest, records=manifest.records[:-1]))
    cases.append(("record-coverage-drop", drop_record))

    def add_record(f: Fixture) -> Fixture:
        manifest = f["manifest"]
        extra = replace(
            manifest.records[0],
            record_id="record-extra",
            source_record_key="source-key-extra",
            payload_sha256=h("record-extra"),
        )
        return rebind_manifest(f, replace(manifest, records=manifest.records + (extra,)))
    cases.append(("record-coverage-extra", add_record))

    expected_split = {}
    for rid in TRAIN_IDS:
        expected_split[rid] = DatasetSplit.TRAIN
    for rid in VALIDATION_IDS:
        expected_split[rid] = DatasetSplit.VALIDATION
    for rid in TEST_IDS:
        expected_split[rid] = DatasetSplit.TEST
    next_split = {
        DatasetSplit.TRAIN: DatasetSplit.VALIDATION,
        DatasetSplit.VALIDATION: DatasetSplit.TEST,
        DatasetSplit.TEST: DatasetSplit.TRAIN,
    }
    for record_id in RECORD_IDS:
        cases.append((f"split-move-{record_id}", _move_split(record_id, next_split[expected_split[record_id]])))
        cases.append((f"split-drop-{record_id}", _drop_from_split(record_id)))
    for record_id in VALIDATION_IDS + TEST_IDS:
        cases.append((f"holdout-overlap-train-{record_id}", _overlap_into_train(record_id)))

    for i, transform_id in enumerate(("transform-normalize", "transform-dedupe", "transform-canonicalize")):
        alternate_kind = TransformKind.CANONICALIZE_FIELDS if i != 2 else TransformKind.NORMALIZE_TEXT
        cases.extend(
            [
                (f"transform-kind-{transform_id}", _transform_attack(i, kind=alternate_kind)),
                (f"transform-owner-{transform_id}", _transform_attack(i, owner="caller-plugin")),
                (f"transform-config-{transform_id}", _transform_attack(i, config_sha256=h(f"changed-config:{transform_id}"))),
                (f"transform-input-{transform_id}", _transform_attack(i, input_dataset_sha256=h(f"wrong-input:{transform_id}"))),
                (f"transform-output-{transform_id}", _transform_attack(i, output_dataset_sha256=h(f"wrong-output:{transform_id}"))),
                (f"transform-predecessor-{transform_id}", _transform_attack(i, predecessor_transform_sha256=h(f"wrong-prev:{transform_id}"))),
                (f"transform-network-{transform_id}", _transform_attack(i, network_operations=1)),
            ]
        )

    def reorder_transforms(f: Fixture) -> Fixture:
        manifest = f["manifest"]
        transforms = (manifest.transforms[1], manifest.transforms[0], manifest.transforms[2])
        return rebind_manifest(f, replace(manifest, transforms=transforms))
    cases.append(("transform-order-swap", reorder_transforms))

    def drop_transform(f: Fixture) -> Fixture:
        manifest = f["manifest"]
        return rebind_manifest(f, replace(manifest, transforms=manifest.transforms[:-1]))
    cases.append(("transform-coverage-drop", drop_transform))

    def extra_transform(f: Fixture) -> Fixture:
        manifest = f["manifest"]
        current = manifest.final_dataset_sha256
        transform_id = "transform-caller-extra"
        kind = TransformKind.NORMALIZE_TEXT
        owner = "training-platform"
        cfg = h("caller-extra-config")
        output = deterministic_transform_output_digest(current, transform_id, kind, owner, cfg)
        extra = DatasetTransformEvidence(
            transform_id=transform_id,
            kind=kind,
            owner=owner,
            config_sha256=cfg,
            input_dataset_sha256=current,
            output_dataset_sha256=output,
            predecessor_transform_sha256=h("caller-extra-predecessor"),
            network_operations=0,
        )
        return rebind_manifest(
            f,
            replace(manifest, transforms=manifest.transforms + (extra,), final_dataset_sha256=output),
        )
    cases.append(("transform-coverage-extra", extra_transform))

    def final_digest_attack(f: Fixture) -> Fixture:
        manifest = f["manifest"]
        return rebind_manifest(f, replace(manifest, final_dataset_sha256=h("substituted-final-dataset")))
    cases.append(("final-dataset-digest", final_digest_attack))

    def wrong_schema(f: Fixture) -> Fixture:
        manifest = replace(f["manifest"], schema_version="caller-schema-v0")
        return rebind_manifest(f, manifest)
    cases.append(("manifest-schema", wrong_schema))

    def duplicate_source_id(f: Fixture) -> Fixture:
        manifest = f["manifest"]
        sources = list(manifest.source_snapshots)
        sources[1] = replace(sources[1], source_id=sources[0].source_id)
        return rebind_manifest(f, replace(manifest, source_snapshots=tuple(sources)))
    cases.append(("manifest-duplicate-source-id", duplicate_source_id))

    def duplicate_record_id(f: Fixture) -> Fixture:
        manifest = f["manifest"]
        records = list(manifest.records)
        records[1] = replace(records[1], record_id=records[0].record_id)
        return rebind_manifest(f, replace(manifest, records=tuple(records)))
    cases.append(("manifest-duplicate-record-id", duplicate_record_id))

    def duplicate_source_key(f: Fixture) -> Fixture:
        manifest = f["manifest"]
        records = list(manifest.records)
        records[1] = replace(records[1], source_id=records[0].source_id, source_record_key=records[0].source_record_key)
        return rebind_manifest(f, replace(manifest, records=tuple(records)))
    cases.append(("manifest-duplicate-source-record-key", duplicate_source_key))

    for owner in ("curated-helpdesk", "security-curation", "aegis-synthetic"):
        def remove_owner(f: Fixture, current=owner) -> Fixture:
            out = dict(f)
            p = f["policy"]
            out["policy"] = replace(p, trusted_source_owners=tuple(x for x in p.trusted_source_owners if x != current))
            return out
        cases.append((f"policy-remove-trusted-owner-{owner}", remove_owner))

    return cases


CASES = tuple(_build_cases())
EXPECTED_ADVERSARIAL_CASES = 157


def _hardened_accepts(f: Fixture) -> bool:
    try:
        assessment = TrainingDatasetProvenanceAnalyzer(f["policy"]).evaluate(f["request"], f["manifest"])
        return assessment.decision == TrainingDataDecision.ALLOW
    except TrainingDataSecurityRejected:
        return False


def run() -> dict[str, object]:
    if len(CASES) != EXPECTED_ADVERSARIAL_CASES:
        raise AssertionError(f"P9-A corpus drift: expected {EXPECTED_ADVERSARIAL_CASES}, got {len(CASES)}")
    vulnerable = VulnerableCallerDeclaredTrainingDataTrust()
    vulnerable_success = 0
    hardened_success = 0
    blocked_names: list[str] = []
    for name, attack in CASES:
        fixture = attack(build_fixture())
        if vulnerable.accepts(
            declared_training_data_safe=fixture["request"].declared_training_data_safe,
            declared_provenance_complete=fixture["request"].declared_provenance_complete,
        ):
            vulnerable_success += 1
        if _hardened_accepts(fixture):
            hardened_success += 1
        else:
            blocked_names.append(name)

    safe_accepts = 0
    safe_total = 4
    for offset in (0, 1, 2, 3):
        fixture = build_fixture()
        fixture["request"] = replace(fixture["request"], evaluated_at_epoch=NOW + offset)
        safe_accepts += int(_hardened_accepts(fixture))

    dataset_payload = json.dumps([name for name, _ in CASES], separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    return {
        "adversarial_cases": len(CASES),
        "vulnerable_asr": f"{vulnerable_success}/{len(CASES)}",
        "hardened_asr": f"{hardened_success}/{len(CASES)}",
        "hardened_fpr": f"{safe_total - safe_accepts}/{safe_total}",
        "safe_task_rate": f"{safe_accepts}/{safe_total}",
        "dataset_sha256": hashlib.sha256(dataset_payload).hexdigest(),
        "blocked_case_count": len(blocked_names),
    }


if __name__ == "__main__":
    print(json.dumps(run(), indent=2, sort_keys=True))
