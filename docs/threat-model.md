# Threat Model

This document describes what the AI Model Ingestion Gate is designed to defend
against, what it explicitly does **not** defend against, and the reasoning
behind those boundaries. Being precise about scope is part of the design: a
security tool that overstates its coverage is more dangerous than one that is
honest about its limits.

## What we are protecting

The integrity of a system that **ingests third-party AI models** (primarily from
public hubs such as Hugging Face). The protected asset is the deployment
environment — the CI pipeline, the model registry, and ultimately the runtime
that will load a model. The goal is to decide, before a model is admitted,
whether loading or shipping it introduces unacceptable risk.

## Who we are defending against

- **A malicious or compromised model publisher** who embeds executable payloads
  in model weights (pickle deserialization) so that merely loading the model
  runs attacker code.
- **A supply-chain attacker** who ships, or induces a dependency on, a package
  version with a known, exploitable vulnerability.
- **An honest contributor who makes an unsafe change by accident** — e.g. bumps
  a model to a pickle-serialized variant, or to a model built on an outdated,
  vulnerable framework — without realizing the risk. In practice this is the
  most common case, and the gate is designed to catch it in code review.

## Threats in scope (and how the gate addresses each)

| Threat | Mechanism | Gate response |
|---|---|---|
| Code execution on model load | Pickle `GLOBAL`/`REDUCE` opcodes in `.bin`/`.pt`/`.pkl` weights | modelscan opcode inspection on local files; format-level flag on remote listings |
| Unsafe serialization format | Model ships pickle instead of safetensors | Flagged; policy decides WARN vs BLOCK |
| Known-vulnerable dependencies | Declared dependencies with CVEs | OSV correlation, severity-mapped, policy-gated |
| Vulnerable build provenance | Model built with an outdated framework version | Framework-provenance scan (informational; see below) |
| Silent inventory drift | An approved model becomes vulnerable when a new CVE is published | Scheduled cloud re-scan with alerting |
| Unreviewed introduction of any of the above | A pull request adds a risky model | CI gate + branch protection block the merge |

## Threats explicitly OUT of scope

These are real risks that this tool does **not** address. Listing them is
deliberate — knowing the boundary is as important as the coverage.

- **Runtime behavior of a loaded model.** Once a model is admitted and running,
  this tool has no visibility. Prompt injection, data exfiltration at inference
  time, and jailbreaks are the domain of a runtime guardrail
  (`llm-guardrails-gateway`), not an ingestion gate.
- **Malicious behavior encoded in the weights themselves.** A backdoored model
  whose *weights* (not its serialization) cause harmful outputs on a trigger is
  not detectable by opcode or dependency analysis. Detecting model backdoors is
  an open research problem and out of scope.
- **Novel or obfuscated serialization exploits** that modelscan does not yet
  recognize. The tool is only as strong as the scanners it orchestrates; a
  zero-day pickle technique would pass until the underlying scanner is updated.
- **Compromise of the trusted inputs themselves.** If OSV, the Hugging Face API,
  or the CI runner were compromised or spoofed, the gate's decisions could be
  subverted. The tool trusts these sources.
- **Deep inspection of remote models.** The remote path lists files and reads
  small metadata over the HF REST API; it does not download and opcode-scan full
  weights. Deep inspection requires a local checkout (as in CI).
- **Runtime exploitability of a build-provenance finding.** The framework
  version in a model's `config.json` is the version that *built* the model, not
  the version it will *run* under. A finding here indicates an old toolchain, not
  a live vulnerability — so it is reported for awareness and never used to block.
  Blocking on it would reject safe models and erode trust in the gate.

## Trust assumptions

The gate treats the following as trusted, and its guarantees are conditional on
them:

- The OSV database returns accurate, current advisory data.
- The Hugging Face REST API returns the true file list and file contents for a model.
- modelscan correctly identifies dangerous operators it knows about.
- The CI runner and its checkout are not compromised.
- For the cloud scanner: the AWS account, IAM boundaries, and the deployed code are not tampered with.

## Design principles that follow from this model

- **Fail safe.** When a pickle file cannot be deep-inspected, it is treated as
  risky (HIGH) rather than assumed safe.
- **Precise, not merely strict.** A pickle verified clean is a warning, not a
  block. Over-blocking trains teams to disable the gate, which protects nothing.
- **Signal vs. gate.** Findings that indicate risk but not proof of
  exploitability (build provenance) inform rather than block.
- **Enforcement, not advice.** In CI, a BLOCK is made binding by branch
  protection — the tool prevents the merge rather than merely warning about it.

## Known limitations and future work

- No detection of weight-level backdoors (research problem).
- Deep opcode inspection only on local/CI checkouts, not remote listings.
- Dependency coverage is limited to what a model declares; it does not resolve a
  full transitive runtime tree.
- No cryptographic provenance/signature verification yet (Sigstore/Cosign,
  in-toto) — a natural next addition.
- Detection strength is bounded by the underlying scanners (modelscan, OSV);
  the tool inherits their blind spots.
