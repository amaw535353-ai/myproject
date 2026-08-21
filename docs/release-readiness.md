# Release readiness

This checklist records prerequisites for a possible v0.101.0 release. It does not claim that a release, release date, package publication, or production-ready deployment exists.

## Governance and repository state

- [x] The owner selected Apache-2.0 and the repository contains the official license text and consistent package metadata.
- [x] `SECURITY.md` is approved and included in the repository source tree.
- [x] GitHub Private Vulnerability Reporting is enabled and `SECURITY.md` identifies it as the private reporting route.
- [x] The latest observed `main` checks are green at baseline `71907423fb2a30df40993adc639368cd03a26512`.
- [ ] Every open pull request has a reviewed disposition; no closure or merge is implied by this checklist.
- [ ] The changelog has an owner-approved v0.101.0 release section. `Unreleased` alone is not a release record.

## Reproducibility and package evidence

- [ ] Reproduce the deterministic portfolio demo from the exact release candidate and retain sanitized output.
- [ ] Build both source and wheel artifacts from a clean release candidate and validate their name, version, license metadata, contents, and installation.
- [ ] Complete reviewed-baseline, tracked-file, and Git-history secret checks for the exact release candidate.
- [ ] Confirm every required check on `main` is green and record the check identities and URLs.
- [ ] Preserve the deterministic, live-local, and production evidence boundaries in the README, changelog, package metadata, and release notes.

## Release mechanics

- [ ] Decide whether the v0.101.0 tag must be signed and record the signer/verification procedure without publishing private key material.
- [ ] Define the release artifacts and SHA-256 checksum file, and verify checksums before publication.
- [ ] Confirm the tag, package version, artifact metadata, and release notes all identify v0.101.0 without inventing a release date.
- [ ] State explicitly that this security lab is not production-ready and that no production-readiness claim is part of the release.

No tag, release, package publication, or release date is created by this document.
