# CI consolidation plan

No workflow execution is changed by this plan. Read-only inspection on 2026-08-20 found no repository rulesets, but the branch-protection endpoint returned `403 Resource not accessible by integration`; required-check settings therefore remain unknown. Every historical workflow also publishes the job name `tests`, so changing commands without confirming the protected check identity could break required checks.

## Proposed ownership

| Workflow | Keep check/job name | Targeted tests after owner approval | Existing explicit evaluations/labs retained |
|---|---|---|---|
| `ci.yml` | `tests` | Complete `python -m pytest` suite; the only full-suite run | P2-A through P2-S |
| `quality.yml` | `quality` | Focused portfolio, evidence drift, formatting, lint, types, static security, dependencies, and secrets | Deterministic portfolio demo |
| `phase3.yml` | `tests` | `tests/security/test_p3*.py tests/security/test_p4*.py` | P3/P4 commands already listed in the workflow |
| `phase5.yml` | `tests` | `tests/security/test_p5*.py` | P5-A through P5-I |
| `phase6.yml` | `tests` | `tests/security/test_p6*.py` | P6-A through P6-F |
| `phase7.yml` | `tests` | `tests/security/test_p7*.py` | P7-A through P7-I |
| `phase8.yml` | `tests` | `tests/security/test_p8*.py` | P8-A through P8-L |
| `phase9.yml` | `tests` | `tests/security/test_p9*.py` | P9-A through P9-I |
| `phase10.yml` | `tests` | `tests/security/test_p10*.py` | P10-A through P10-I and bounded local labs |
| `phase11.yml` | `tests` | `tests/security/test_p11*.py` | P11-A through P11-F and bounded validations |

This would remove nine redundant full-suite invocations per push or pull request while retaining one complete suite, focused phase tests, explicit evaluations, labs, and current check names. Actual Actions-minute reduction depends on runner timing and is not estimated without billing data.

## Decisions and proof still needed

1. An administrator must export branch-protection and organization ruleset required-check configuration, including workflow/job identity rather than display name alone.
2. The owner must confirm that Phase 3 intentionally owns both P3 and P4 tests and that `ci` remains the sole complete-suite workflow.
3. Each proposed glob must pass and collect the intended tests on a clean GitHub runner before workflow edits merge.
4. Compare check-run names on a test PR and confirm no protected context disappears.

Risks include ambiguous duplicate `tests` contexts, missed shared regression coverage, phase tests that depend on broader fixtures, and required checks becoming pending after a workflow/job identity change.
