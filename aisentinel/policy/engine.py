"""Policy engine: turn scan findings into a single PASS / WARN / BLOCK decision."""

from dataclasses import dataclass, field
import yaml

# Ordered from least to most severe. Index is used to pick the "winning" action.
_ACTION_RANK = {"ALLOW": 0, "PASS": 0, "WARN": 1, "BLOCK": 2}


@dataclass
class Decision:
    verdict: str                       # PASS | WARN | BLOCK
    triggered: list[dict] = field(default_factory=list)  # rules that fired


def load_policy(path: str) -> dict:
    with open(path, "r", encoding="utf-8") as fh:
        return yaml.safe_load(fh)


def _rule_for_finding(check: str, severity: str, policy: dict) -> tuple[str, str, str]:
    """
    Resolve a finding to (rule_name, action, reason).
    Vulnerability findings are mapped by severity to vulnerability_<sev> rules.
    """
    rules = policy.get("rules", {})
    default_action = policy.get("default_action", "WARN")

    # Vulnerability findings use a severity-based rule name.
    if check == "vulnerability":
        rule_name = f"vulnerability_{severity.lower()}"
    else:
        rule_name = check

    rule = rules.get(rule_name)
    if rule is None:
        return (rule_name, default_action, "No explicit rule; default action applied.")
    return (rule_name, rule.get("action", default_action), rule.get("reason", ""))


def evaluate(artifact_findings, osv_report, policy: dict) -> Decision:
    """
    Combine artifact findings and OSV vulnerabilities against the policy.
    The most severe action across everything becomes the verdict.
    """
    decision = Decision(verdict="PASS")
    winning_rank = 0

    def consider(check: str, severity: str, detail: str):
        nonlocal winning_rank
        rule_name, action, reason = _rule_for_finding(check, severity, policy)
        rank = _ACTION_RANK.get(action.upper(), 1)
        if action.upper() in ("WARN", "BLOCK"):
            decision.triggered.append({
                "rule": rule_name,
                "action": action.upper(),
                "detail": detail,
                "reason": reason,
            })
        if rank > winning_rank:
            winning_rank = rank

    # Artifact findings (skip pure INFO like safe_serialization).
    for f in artifact_findings:
        if f.severity in ("INFO",):
            continue
        consider(f.check, f.severity, f.message)

    # Vulnerability findings.
    if osv_report is not None:
        for v in osv_report.vulnerabilities:
            consider("vulnerability", v.severity, f"{v.package}=={v.version} {v.vuln_id}")

    decision.verdict = {0: "PASS", 1: "WARN", 2: "BLOCK"}[winning_rank]
    return decision