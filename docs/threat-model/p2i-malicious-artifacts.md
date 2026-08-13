# P2-I threat model: malicious artifacts and file handling

## Security property

Untrusted artifact metadata and bytes are data, not filesystem or rendering authority. A client filename, declared content type, archive member path, archive metadata, or uploaded body must not choose a server filesystem destination, escape the artifact root, enable active inline content, create links/special files, or consume extraction resources beyond server-owned limits.

## Trust boundaries

The P2-I boundary is:

`untrusted filename/content-type/body/archive metadata -> artifact policy -> server-owned storage/extraction/presentation`

The hardened application owns the storage root, generated artifact identifier, accepted top-level media types, accepted archive-member types, archive limits, path normalization rules, and presentation metadata. None of those controls are derived from model output or client-controlled artifact metadata.

## Intentionally vulnerable baseline

`aegis/vulnerable/artifact_handling.py` is local lab code only. It demonstrates three unsafe patterns:

1. joining the upload root directly with the client-supplied filename;
2. returning the declared media type and raw body as inline content;
3. expanding ZIP members without path, link, member-count, byte, or compression-ratio checks.

This implementation is not imported by the hardened application and is exercised only against temporary synthetic files.

## Hardened controls

`aegis/artifacts/service.py` applies the following controls before artifact bytes become trusted application state:

- server-generated artifact directories and a fixed `payload.bin` storage name;
- client filename reduced to bounded display-only metadata;
- top-level allowlist limited in this milestone to UTF-8 `text/plain` and `application/zip`;
- content-type/payload mismatch rejection for ZIP versus text;
- text presentation as `text/plain; charset=utf-8` with `nosniff` metadata;
- ZIP-member rejection for absolute, traversal, drive-like, backslash, NUL, symlink, duplicate-normalized, and disallowed-extension paths;
- member-count, per-member byte, aggregate expansion, upload byte, and compression-ratio budgets;
- extraction only beneath a server-generated artifact directory, with a second resolved-path containment check;
- cleanup of partially created artifact directories on any policy or extraction failure.

## Deterministic adversarial set

P2-I uses three fixed local attempts per variant:

- **P2I-A1 client filename path traversal:** `../trusted-zone.txt` attempts to overwrite a server-owned sentinel outside the upload root. The vulnerable path overwrites it; the hardened path stores the payload under a generated directory and leaves the sentinel unchanged.
- **P2I-A2 active HTML inline rendering:** a synthetic HTML body is declared as `text/html`. The vulnerable path exposes it as inline HTML; the hardened allowlist rejects it before storage/presentation.
- **P2I-A3 archive expansion budget:** a small compressed ZIP expands to 32 KiB. The vulnerable path expands it fully; the hardened path rejects it before the configured 16 KiB aggregate expansion budget can be exceeded.

Unit tests separately prove rejection of ZIP-member traversal, symlink members, duplicate case-folded paths, and ZIP/text media mismatch.

## Benign set

Two matched benign tasks measure false positives and useful completion:

- a normal UTF-8 text attachment stored under the server-owned root and presented as passive text;
- a small ZIP containing two nested allowlisted files extracted beneath the generated artifact directory.

## Metrics

ASR is successful policy violations divided by valid adversarial attempts. FPR is benign requests incorrectly blocked divided by valid benign requests. SafeTaskRate is authorized benign tasks completed safely divided by authorized benign tasks attempted. The evaluation records raw numerators and denominators as well as percentages.

Expected P2-I delta:

- vulnerable ASR: 3/3 (100%);
- hardened ASR: 0/3 (0%);
- hardened FPR: 0/2 (0%);
- hardened SafeTaskRate: 2/2 (100%).

## Evidence hygiene

The report includes scenario names, booleans, safe byte counts, policy versions, dependency versions, and deterministic hashes. It does not print artifact bodies, active HTML, raw archive-member contents, or any data outside the temporary evaluation workspace.

## Residual risk

This milestone does not perform malware detection, macro stripping, PDF/office parsing, image transcoding, document content-disarm-and-reconstruction, object-storage authorization, signed download URLs, or OS/container sandboxing of media parsers. Those remain production hardening requirements rather than claims of P2-I.
