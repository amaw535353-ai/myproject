# O1 Local Onyx Lab

This guide is intentionally local-only. It must never be used against Onyx Cloud, a public Onyx deployment, a third-party environment, or infrastructure without explicit authorization.

## Pinned source

Use Onyx commit:

```text
cbfd6b327b348beac532801306de63eed8551248
```

Record the actual checked-out SHA before each run. Do not use `latest` as evidence identity.

## Deployment approach

The inspected Onyx repository documents Docker Compose under `deployment/docker_compose/` and supports `docker compose up -d` from that directory after copying `env.template` to `.env`. O1 should prefer this repository-controlled Compose path rather than the guided installer, because the installer is designed to obtain a current version while the security program requires an exact pinned source revision.

Suggested owner workflow after cloning the authorized Onyx fork:

```bash
git checkout cbfd6b327b348beac532801306de63eed8551248
printf 'Onyx commit: '; git rev-parse HEAD
cd deployment/docker_compose
cp -n env.template .env
# Edit only synthetic/local settings. Do not add production credentials.
docker compose config >/tmp/onyx-o1-compose.rendered.yml
docker compose up -d
docker compose ps
```

The exact compose filename/image build strategy must be confirmed during implementation for the owner's fork. If the compose configuration would pull an image not demonstrably corresponding to the pinned source, the run must record that mismatch and cannot claim source-to-runtime commit identity until the image is built or otherwise bound to the pinned revision.

## Network containment

O1 requires a compose override that publishes the application only on loopback. Do not change host firewall settings silently. If an Onyx service must be reachable by AegisDesk, publish only the minimum required port to `127.0.0.1`. Internal Postgres, Redis, index, model, and worker services should remain on the Docker network unless a specific test requires otherwise.

A future O1 implementation should provide a reviewed override fixture rather than instructing users to expose all compose ports.

## Synthetic organization

Provision only synthetic identities:

- synthetic administrator
- `alice` — engineering
- `bob` — HR
- `attacker` — no private group

Use generated lab-only passwords stored in runtime environment or an ignored local fixture file. Never commit them.

Create synthetic documents with unique canaries:

- public handbook
- engineering runbook
- HR compensation
- engineering secret used for revocation
- poisoned public document

The content must contain no real employee, customer, ticket, or production information.

## Lab marker

O1 requires a positive target marker before attack cases. The exact mechanism will be chosen during adapter implementation, but it must be created by local setup and unavailable by default on public Onyx services. AegisDesk must validate the marker together with local/private host validation and `AEGIS_ONYX_LAB_ACK=YES`.

## Health and cleanup

Baseline health inspection:

```bash
cd deployment/docker_compose
docker compose ps
docker compose logs --tail=100
```

Non-destructive stop:

```bash
cd deployment/docker_compose
docker compose down
```

Full synthetic-lab reset may remove lab volumes only after the owner explicitly chooses that action. The security harness must not silently delete volumes or alter host firewall/security configuration.

## Evidence boundary

A successful local run is `live-local`, not production evidence. If the runtime image/checkout cannot be bound to the recorded Onyx SHA, target validation or provenance is incomplete and the requested live-local verification is `BLOCKED`.