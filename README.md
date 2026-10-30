# MalSkills

MalSkills is a neuro-symbolic analyzer for detecting malicious agent Skills
across prompts, source code, manifests, configuration files, and setup scripts.
It reports a binary `malicious` or `benign` verdict with the
Security-Sensitive Operations (SSOs), dependency graph, matched behavior rules,
and reasoning proofs behind the decision.

![MalSkills pipeline](assets/malskills.png)

> [!IMPORTANT]
> **Extended baseline reproduction notice.** The paper's RQ1 compared MalSkills
> with five baselines using `gpt-5.3-codex-medium`. This repository integrates
> 22 baseline adapters and defaults LLM-backed analysis to `gpt-5.6-luna`.

## How it works

1. **SSO extraction** identifies behavior-neutral sensitive operations using
   2,665 Semgrep rules across 10 languages, Markdown/Shell rules, and an
   optional batched LLM semantic pass.
2. **SDG construction** builds a Skill Dependency Graph over Artifacts, SSOs,
   Operands, and Values. YASA and cross-artifact resolution recover object
   identity and directional value flow.
3. **Behavior reasoning** executes 10 connected graph rules covering Data
   Exfiltration, Credential Theft, Remote Code Execution, Malware Delivery,
   Persistence, Reverse Shell, Ransomware, Resource Abuse, and Privilege
   Escalation.


## Repository layout

- `malskills/`: analyzer, CLI, SDG compiler, reasoning, and adapters
- `malskills/rules/`: Markdown/Shell SSO rules and SDG workflow rules
- `semgrep_rules/`: 2,665 neutral code-level SSO rules
- `experiments/`: benchmark, ablation, and LLM comparison drivers
- `data/ground_truth/`: checked-in benchmark inputs
- `baseline/`: pinned third-party baseline implementations
- `vendor/yasa/`: pinned YASA value-flow engine
- `assets/`: paper artifacts and figures

## Installation

The complete setup requires Python 3.10+, Semgrep, Git submodules, Node.js for
the YASA value-flow engine, and either an authenticated Codex CLI or an
OpenAI-compatible API. Individual baselines may additionally require Go,
Docker, sandboxes, or service tokens.

```bash
git clone --recurse-submodules https://github.com/security-pride/MalSkills.git
cd MalSkills

python3 -m venv .venv
.venv/bin/pip install -e '.[analysis]'
.venv/bin/semgrep --version

# Build the YASA value-flow engine.
(cd vendor/yasa && npm ci && npx tsc)

# Codex CLI mode only:
codex login
```

`node` must stay on `PATH` when MalSkills runs, not only while building.
Without `vendor/yasa/dist/main.js` or without `node`, `YasaAdapter.available()`
returns false and the value-flow stage is skipped without an error.

Synchronize submodules in an existing checkout with:

```bash
git submodule sync --recursive
git submodule update --init --recursive
```

Baseline dependencies are not installed by the root package; use an isolated
environment for each baseline and follow its upstream installation guidance.

## Quick start

Analyze one Skill with the configured complete pipeline:

```bash
.venv/bin/malskills analyze-skill path/to/skill \
  --output output/example \
  --llm-config malskills.toml
```

Run a reduced static analysis without LLM or deep value-flow analysis:

```bash
.venv/bin/malskills analyze-skill path/to/skill \
  --output output/example-static \
  --disable-llm-sso-extraction \
  --disable-llm-object-analysis \
  --disable-yasa \
  --disable-cross-artifact-resolution \
  --reasoning-mode formal
```

Render an existing result directory:

```bash
.venv/bin/malskills render-report --results output/example
```

## LLM configuration

The single repository-relative [malskills.toml](malskills.toml) configures
MalSkills and every LLM-backed baseline. Its default is:

```toml
[llm]
mode = "codex_cli"
model = "gpt-5.6-luna"
reasoning_effort = "low"
timeout_sec = 300
enable_thinking = false

[llm.sso_extraction]
enabled = true

[llm.object_analysis]
enabled = true

[llm.pattern_reasoning]
enabled = true

[llm.rule_feedback]
enabled = false
```

For an OpenAI-compatible API, change `mode` and `model` in the same TOML
file, then initialize the ignored environment file:

```bash
cp .env.example .env
chmod 600 .env
# Set MALSKILLS_LLM_BASE_URL and MALSKILLS_LLM_API_KEY in .env.
```

`OPENAI_BASE_URL` and `OPENAI_API_KEY` are compatibility aliases; the
`MALSKILLS_*` names take precedence. Keep credentials and machine-specific
paths in `.env`, while model selection, timeouts, reasoning effort, and stage
enablement belong in `malskills.toml`.

| Stage | Purpose | Default |
|---|---|---:|
| `sso_extraction` | Supplement static findings and operand bindings | enabled |
| `object_analysis` | Resolve remaining sink operands | enabled |
| `pattern_reasoning` | Review uncovered connected SDG workflows | enabled |
| `rule_feedback` | Propose reusable rules from LLM-only findings | disabled |

Environment variables can override global or stage TOML settings. Inspect the
effective configuration before a long run:

```bash
.venv/bin/malskills show-llm-config --llm-config malskills.toml
```

## Analysis outputs

The canonical analysis path is:

```text
SSOFinding -> SSO -> Operand -> Value -> Pattern -> Verdict
```

`SSOFinding` is a source-grounded extractor record rather than an SDG node.
The SDG contains `Artifact -> SSO -> Operand -> Value` relations and
directional `Value -> Value` propagation.

| Output | Contents |
|---|---|
| `verdict.json`, `human_report.md` | Verdict, behavior matches, and summary |
| `artifacts.json` | Normalized artifact inventory |
| `sso_findings.json`, `ssos.json` | Source findings and normalized SSOs |
| `operands.json`, `values.json`, `operand_resolutions.json` | Bound objects, values, and flow provenance |
| `sdg.json`, `sdg.dot` | Machine-readable and Graphviz SDG |
| `pattern_summary.json`, `proofs.json` | Graph matches and reasoning traces |
| `analysis_metadata.json`, `output_manifest.json` | Runtime metadata and output schema |
| `workflow_discoveries.json`, `feedback_loop.json` | Optional LLM discoveries and rule candidates |

## Large-corpus scanning

`scan-corpus` deterministically samples a registry-style corpus, supports
parallel workers and resume, and expects
`<corpus-root>/<source>/<package>/.../SKILL.md`.

```bash
.venv/bin/malskills scan-corpus \
  --corpus-root /path/to/skills \
  --output output/corpus-scan-2000 \
  --sample-size 2000 \
  --seed 1337 \
  --workers 4 \
  --profile full \
  --llm-config malskills.toml
```

| Profile | Extraction and reasoning | Rule candidates |
|---|---|---|
| `static` | Static extraction and formal graph rules | disabled |
| `full` | Static analysis plus TOML-enabled LLM stages | controlled by `rule_feedback.enabled` |

The `full` profile respects every TOML stage switch. Results are checkpointed
in `scan_results.jsonl`; use `--resume` after interruption and
`--retain all|malicious|none` to control detailed case outputs. Exact duplicate
primary Skill content is removed by default. Because the corpus is unlabeled,
flag rate is neither precision nor malware prevalence.

## Benchmark reproduction

The checked-in benchmark contains 100 malicious and 100 benign Skills:

```bash
.venv/bin/malskills build-benchmark-index \
  --root . \
  --output output/ground_truth_final_benchmark.json

.venv/bin/malskills run-eval \
  --benchmark output/ground_truth_final_benchmark.json \
  --output output/rq1_malskills_current \
  --variant benchmark_full \
  --llm-config malskills.toml
```

The evaluator prints colored per-sample stage events and a 30-second `WAIT`
heartbeat. Use `--progress-interval`, `--color`, or `--quiet` to adjust it.
`suspicious` baseline results are excluded from the confusion matrix and
reported through coverage; errors remain non-malicious predictions. Always
report coverage, suspicious results, and errors with precision, recall, FPR,
and F1.

| Variant | Change from `benchmark_full` |
|---|---|
| `benchmark_semgrep_findings_only` | Disable LLM SSO extraction |
| `benchmark_llm_findings_only` | Disable Semgrep findings |
| `benchmark_formal_reasoning_only` | Force formal graph reasoning |
| `benchmark_llm_reasoning_only` | Force LLM behavior reasoning |
| `benchmark_no_yasa` | Disable YASA value-flow analysis |
| `benchmark_no_cross_artifact_resolution` | Disable cross-artifact resolution |
| `benchmark_static_only` | Disable LLM, YASA, and cross-artifact resolution |

The RQ3 driver is
[experiments/run_rq3_llm_comparison.py](experiments/run_rq3_llm_comparison.py).

## Baseline integrations

Every adapter preserves its upstream report and emits a normalized manifest.
LLM-backed adapters share the backend and model in `malskills.toml`.

| Tool | Availability | Additional runtime |
|---|---|---|
| skill-security-audit | default | Python |
| skill-security-scan | default | Python |
| skills_security_audit | default | Python |
| Caterpillar | default | Node.js + LLM |
| ClawScan by ClawGuard | default | Node.js |
| Cisco AI Defense Skill Scanner | default | Python + LLM |
| Nova Proximity | default | Python + LLM |
| GoPlus AgentGuard | default | Node.js |
| NVIDIA SkillSpector | default | Python + LLM |
| AgentVerus Scanner | default | Node.js 22+ |
| SkillTotal | default | Python 3.10+ |
| ClawVet | default | Node.js 22+ |
| Razin | default | Python 3.12+ |
| OpenClaw ClawScan | default | Go |
| SkillFortify | default | Python 3.11+ |
| MaliciousAgentSkillsBench | opt-in | LLM + `codex-skill-sandbox` |
| Snyk Agent Scan | opt-in | `SNYK_TOKEN` |
| Tencent AI-Infra-Guard | opt-in | LLM |
| SkillSieve | opt-in | LLM |
| SkillWard | opt-in | LLM + Docker sandbox |
| Runtime Skill Audit | opt-in | LLM + OpenClaw + Docker |
| Enkrypt AI Skill Sentinel | opt-in | LLM; optional VirusTotal |

Run the default study, adding `--include-optional-baselines` only after the
additional dependencies are ready:

```bash
.venv/bin/python experiments/run_benchmark_study.py \
  --benchmark output/ground_truth_final_benchmark.json \
  --output output/benchmark_study
```

AI-Infra-Guard and Runtime-Skill-Audit are pinned to MalSkills-maintained forks
with minimal compatibility fixes; attribution and upstream history are
preserved. LLM-backed tools use a short-lived local bridge so Codex CLI and API
mode share one configuration without exposing the upstream key in reports.

## Rule learning

Rule learning is opt-in. It accumulates recurring LLM-only SSOs and uncovered
connected workflows without changing active rules during the producing scan.

```bash
.venv/bin/malskills analyze-skill path/to/skill \
  --output output/example-learning \
  --rule-store output/learned-rules \
  --collect-rule-candidates \
  --rule-group-id campaign-or-dedup-id

.venv/bin/malskills rules list --store output/learned-rules
.venv/bin/malskills rules validate <candidate-id> \
  --store output/learned-rules \
  --manifest held-out.json
.venv/bin/malskills rules promote <candidate-id> \
  --store output/learned-rules \
  --approved-by <reviewer>
```

## Citation

MalSkills was accepted at ASE '26. The paper is distributed under
[CC BY-NC-ND 4.0](https://creativecommons.org/licenses/by-nc-nd/4.0/).

```bibtex
@inproceedings{wang2026malskills,
  author    = {Wang, Shenao and He, Junjie and Zhao, Yanjie and Wang, Yayi and Yu, Kan and Wang, Haoyu},
  title     = {{MalSkills}: Detecting Malicious Skills in the Agentic Supply Chain via Neuro-Symbolic Reasoning},
  booktitle = {Proceedings of the 41st IEEE/ACM International Conference on Automated Software Engineering (ASE '26)},
  year      = {2026},
  month     = oct,
  address   = {Munich, Germany},
  publisher = {Association for Computing Machinery},
  isbn      = {979-8-4007-2882-2},
  doi       = {10.1145/3832783.3834375},
  url       = {https://doi.org/10.1145/3832783.3834375}
}
```
If you have any questions, please contact shenaowang@hust.edu.cn.

## Project

- [Contributing](CONTRIBUTING.md)
- [Security policy](SECURITY.md)
- [Apache License 2.0](LICENSE)
- [Third-party and dataset notices](THIRD_PARTY_NOTICES.md)
