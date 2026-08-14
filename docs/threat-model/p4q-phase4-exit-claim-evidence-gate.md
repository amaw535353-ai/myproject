# P4-Q Phase 4 Exit Claim / Evidence Gate

## Security property

Phase 4 must end with a machine-readable record of what the checkpoint-hardening work actually proves and, equally importantly, what it does not prove. A milestone is not considered evidence-complete merely because code or a threat-model document exists. P4-Q requires the complete P4-A through P4-P sequence, its deterministic evaluation module, CI invocation, implementation evidence paths, explicit supported claims, and explicit residual assumptions.

The exit gate must fail closed if any included Phase 4 implementation is reclassified as production-ready, operationally external, or an independent failure domain without a new reviewed policy change. It must also fail if supported-claim text starts asserting production checkpoint durability, production external trust, production disaster recovery, exactly-once execution, distributed transaction/consensus, or an independent failure domain.

## Threats

The gate addresses evidence drift rather than a new runtime exploit. The modeled failures are:

- a Phase 4 milestone disappears from the expected A-through-P sequence;
- a threat model, deterministic evaluation, or implementation evidence path is removed while progress documentation still says the milestone is complete;
- CI stops running one of the Phase 4 milestone evaluations;
- the exit gate itself is omitted from the Phase 4 workflow;
- a local or synthetic harness is silently relabeled as production-ready or operationally external;
- a supported claim grows beyond what the evidence establishes;
- residual assumptions are omitted, making the evidence appear stronger than it is;
- Phase 3 integration gaps reappear while Phase 4 is declared closed.

## Machine-readable evidence register

`aegis/security/phase4_controls.py` is the canonical P4-Q registry. Each P4-A through P4-P entry records:

- milestone id and title;
- threat-model path;
- deterministic evaluation module and derived command;
- evidence posture: `default_local`, `policy_boundary`, or `synthetic_lab`;
- implementation evidence paths;
- supported claims;
- residual assumptions;
- explicit booleans for production readiness, operational externality, and independent failure-domain status.

The same module records global Phase 4 boundary claims and residual assumptions. Current included implementations deliberately set production external checkpoint/lifecycle providers, production durability and disaster recovery, distributed transaction/consensus, exactly-once execution, independent failure domain, real external trust operations, and network requirements to false.

## Exit checks

`evals.p4q_phase4_exit_gate` requires:

1. exact ordered milestones P4-A through P4-P;
2. every milestone threat model, evaluation module, and implementation evidence path to exist;
3. `.github/workflows/phase3.yml` to invoke every Phase 4 evaluation and P4-Q itself on `main`;
4. every milestone to declare at least one supported claim and residual assumption;
5. supported claims to contain none of the prohibited production/distributed claims;
6. every included milestone implementation to remain non-production, non-external, and non-independent-failure-domain unless the policy is explicitly redesigned;
7. the global boundary claim map to preserve all required false production/distributed claims;
8. the expected evidence-posture distribution: seven default-local controls, two policy boundaries, and seven synthetic lab milestones;
9. Phase 3 integration gaps to remain zero;
10. Phase 4 progress documentation to state Phase 4 completion and the Phase 5 transition.

The report includes a deterministic SHA-256 hash over the complete evidence register, boundary claims, residual assumptions, and P4-Q policy version.

## What passing P4-Q means

Passing P4-Q means the repository contains a complete, CI-enforced, internally consistent body of deterministic checkpoint-security evidence for P4-A through P4-P. It means the default local checkpoint path has strict serialization, local integrity/confidentiality/key-lifecycle controls, authenticated backup/restore, explicit provider seams and lifecycle capabilities, and that later synthetic harnesses exercise trust-policy, failure, fencing, restart, rollback, provider-outcome, and provider-internal crash-recovery semantics.

Passing P4-Q does **not** convert synthetic contracts into production infrastructure. It does not establish production checkpoint durability, disaster recovery, remote key custody, independent rollback resistance, distributed fencing, distributed transactions, consensus, exactly-once execution, or a production external lifecycle/checkpoint provider.

## Residual risk

All current checkpoint trust components can ultimately share host fate. A host compromise or coordinated rollback can affect checkpoint data, local integrity/encryption keys, lifecycle journals, witnesses, provider-command state, and provider-outcome state. The Phase 4 work deliberately records these limitations instead of treating local HMAC separation as an independent trust domain.

P4-Q also does not evaluate model weights, adapters, fine-tunes, model registries, training data, model signatures, inference-runtime provenance, or model extraction/privacy attacks. Those are outside the checkpoint-security phase.

## Phase 5 entry gate

After P4-Q, checkpoint hardening is considered complete for the current lab scope. Phase 5 should shift the project to **model and AI supply-chain security**. The first milestone should define model-artifact provenance and safe loading boundaries before adding broader model poisoning, malicious adapter/fine-tune, model privacy, and adversarial-ML evaluations.
