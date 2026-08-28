# AegisDesk deterministic portfolio demonstration

Status: **VERIFIED**

Code revision: `<revision>`

| Case | Vulnerable ASR | Hardened ASR | FPR | SafeTaskRate |
|---|---:|---:|---:|---:|
| indirect_prompt_injection | 3/3 | 0/3 | 0/1 | 1/1 |
| multi_agent_human_approval | 92/92 | 0/92 | 0/3 | 3/3 |
| model_container_supply_chain | not_reported_by_source | 0/45 | 0/15 | 15/15 |
| inference_tenant_isolation | 136/136 | 0/136 | 0/4 | 4/4 |

Reproduce: `python scripts/run_portfolio_demo.py --docs-sample`

Limitations:
- Fake/no-model evidence is not real-model validation.
- Synthetic local controls are not production or cloud validation.
- The live-model command is separate and fails closed when unconfigured.
