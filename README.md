\# AI Model Ingestion Gate



> A policy-driven CI gate that scans a Hugging Face model's artifacts and dependencies, emits a CycloneDX ML-BOM, and decides \*\*PASS / WARN / BLOCK\*\* before the model is allowed into deployment.



\*\*Status:\*\* 🚧 v1 in progress — built in phases. See \[Roadmap](#roadmap) for the current state.



\---



\## Why this exists



Most AI security work assumes the model is already trusted and running. It secures what a model \*does\* at runtime, or how it \*serves\*. Almost nothing checks the one moment that comes first: \*\*the instant a model artifact enters your system.\*\*



In 2026 that moment is a real attack surface. Model weights ship in formats (pickle) that can execute code on load, dependency chains around `transformers`/`langchain` are targets for confusion attacks, and provenance is usually unverified. Regulators have caught up too — the G7's minimum-elements guidance for AI SBOMs makes a machine-readable model bill of materials a compliance artifact, not just a nice-to-have.



This project closes that gap: it decides \*\*whether a model should be admitted at all\*\* — before it's ever deployed.



\## Where it sits in the model lifecycle



```mermaid

flowchart LR

&#x20;   A\[Model acquired] --> B\[Model served] --> C\[Model runtime I/O] --> D\[Detection / SOC]



&#x20;   A -.covered by.-> AG\[\*\*AI Model Ingestion Gate\*\*<br/>this project]

&#x20;   B -.covered by.-> VL\[vllm-inference-stack]

&#x20;   C -.covered by.-> GW\[llm-guardrails-gateway]

&#x20;   D -.covered by.-> CX\[Cortex-Chain / aiops-log-anomaly]



&#x20;   style AG fill:#1e2327,color:#fff,stroke:#4a9,stroke-width:2px

```



Each control point secures a different stage of a model's life. This project owns the \*\*ingestion\*\* stage — the only one the others don't cover. It secures \*whether a model should ever be admitted\*, not what it does once it's trusted.



\## What this is / isn't



\*\*It is\*\* an \*orchestration and policy layer.\* It wires together best-in-class open-source scanners into a single, standards-compliant, policy-driven gate that runs in CI.



\*\*It is not\*\* a new scanner engine. It does not reinvent pickle inspection or vulnerability databases — it composes existing tools (`picklescan`/`modelscan`, OSV) and adds the layer that's actually missing: a \*\*policy-as-code decision\*\* and \*\*CI enforcement\*\*, backed by a standard \*\*CycloneDX ML-BOM\*\*.



The differentiator is the integration + policy + enforcement, and that framing is deliberate.



\## How it works (v1)



```

HF model ref ──► \[1] Artifact Scanner ─┐

&#x20;                \[2] Dependency Scanner ─┼─► \[4] ML-BOM (CycloneDX)

&#x20;                \[3] OSV Correlation ────┘         │

&#x20;                                                  ▼

&#x20;                                        \[5] Policy Engine ──► PASS / WARN / BLOCK

&#x20;                                                  │

&#x20;                                                  ▼

&#x20;                                        \[6] GitHub Action (CI gate)

```



1\. \*\*Artifact scanner\*\* — pulls model repo metadata and file list, flags unsafe serialization (pickle/`.bin` vs `.safetensors`), runs pickle-opcode inspection.

2\. \*\*Dependency scanner\*\* — extracts declared dependencies from the model repo.

3\. \*\*OSV correlation\*\* — queries the OSV API (no key required) and maps results to severity.

4\. \*\*ML-BOM generator\*\* — emits a schema-valid \*\*CycloneDX\*\* bill of materials: model as the primary component, dependencies as components, vulnerabilities attached.

5\. \*\*Policy engine\*\* — reads findings + ML-BOM against a YAML policy and returns PASS / WARN / BLOCK.

6\. \*\*CI gate\*\* — a GitHub Action that exits non-zero on BLOCK, failing the build.



\## Quickstart



```bash

pip install -e .



\# Scan a public model and print findings

aisentinel scan <hf-org/model-id>



\# Scan + generate a CycloneDX ML-BOM

aisentinel scan <hf-org/model-id> --sbom out.cdx.json



\# Apply a policy and get a gate decision (non-zero exit on BLOCK)

aisentinel scan <hf-org/model-id> --policy policies/default.yaml

```



\### Example output



```

AI-SENTINEL — Model Ingestion Report

Model:    example/model

Revision: 7f82c9



\[PASS]  Artifact inspection      (safetensors only)

\[WARN]  Provenance not verified

\[FAIL]  Vulnerable dependency    (1 HIGH — CVE-XXXX-XXXXX)

\[PASS]  ML-BOM generated         (CycloneDX 1.6, schema-valid)



Findings: 1 HIGH, 1 MEDIUM

Decision: BLOCKED

```



\## Policy-as-code



Policy is declarative YAML — the same mental model as admission policy in Kubernetes, applied to model ingestion instead of workloads.



```yaml

policies:

&#x20; unsafe\_serialization:     { action: BLOCK }   # pickle / arbitrary code on load

&#x20; critical\_dependency:      { action: BLOCK }   # HIGH/CRITICAL CVE in deps

&#x20; missing\_provenance:       { action: WARN }    # unsigned / unverified source

&#x20; license\_risk:             { action: WARN }

```



\## Standards



The bill of materials is \*\*CycloneDX ML-BOM\*\* — the established standard — not a custom format. This keeps output ingestible by any tool that already speaks CycloneDX and aligns with current AI-SBOM guidance.



\## Roadmap



\*\*v1 (in progress) — the ingestion gate\*\*

\- \[x] Repo skeleton + CLI

\- \[ ] Artifact scanner (serialization detection + pickle inspection)

\- \[ ] Dependency scanner

\- \[ ] OSV correlation

\- \[ ] CycloneDX ML-BOM generation

\- \[ ] Policy engine

\- \[ ] GitHub Action + demo repo (vulnerable model blocks a real PR)



\*\*Phase 2 (deliberately deferred — not yet built)\*\*



These are intentionally out of v1 scope. v1 ships one control point done end-to-end rather than several half-built:

\- Runtime security lab (Falco: process/file/network anomaly detection on a live GPU workload)

\- Dashboard + API

\- Model signing / verification (Sigstore/Cosign, in-toto)

\- NVD correlation, MITRE ATLAS technique mapping

\- RunPod GPU deployment scenarios



\## How it fits the wider portfolio



| Repo | Control point |

|---|---|

| `eks-devsecops-pipeline` | Cloud + Kubernetes + CI/CD |

| `kyverno-policy-as-code` | Admission policy / K8s governance |

| `secure-aws-baseline` | Cloud security infrastructure |

| `llm-guardrails-gateway` | LLM runtime I/O security |

| `Cortex-Chain` | SOC triage \& analytics |

| `vllm-inference-stack` | Secure / observable LLM serving |

| \*\*`ai-model-ingestion-gate`\*\* | \*\*AI model supply chain — ingestion gate\*\* |



This project reuses the policy-as-code thinking from the Kyverno work and the fail-the-build CI pattern from the DevSecOps pipeline, pointed at a new control point. The skills compound rather than repeat.



\## License



TBD



