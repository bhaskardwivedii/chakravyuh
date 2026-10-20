"""
Default-deny policy engine for the Chakravyuh broker.

Addresses recommended verticals 2 ("Network Segmentation & Traffic Control")
and 3 ("Access Control & Secrets Management"), and objective 01 ("Isolate
Without Breaking Function").

The broker is the ONLY component allowed to bridge lanes. Every request through
it is evaluated against a policy-as-code ruleset loaded from `policy.yaml`. The
model is explicit allowlisting: anything not matched by an allow rule is denied,
and the decision (allow/deny + matched rule) is returned so the broker can audit
it.

Access is both capability-based (the caller must present a capability token that
grants the action) and attribute-based (rules constrain which lane, phase and
target are permissible). This mirrors a real OPA/Rego deployment; we keep a
self-contained evaluator here so the PoC runs with no external policy server,
and document the OPA mapping in the README.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

import yaml


@dataclass
class Decision:
    allow: bool
    rule: Optional[str]
    reason: str

    def as_dict(self) -> dict:
        return {"allow": self.allow, "rule": self.rule, "reason": self.reason}


class PolicyEngine:
    """
    Evaluates (subject, action, target, phase) tuples against allow rules.

    A request is allowed iff some rule matches ALL of its constraints. Rule
    fields left unset act as wildcards. Everything else is denied by default.
    """

    def __init__(self, rules: list[dict]):
        self.rules = rules

    @classmethod
    def from_file(cls, path: str) -> "PolicyEngine":
        with open(path) as fh:
            doc = yaml.safe_load(fh)
        return cls(doc.get("allow", []))

    @staticmethod
    def _match(rule_val, actual) -> bool:
        if rule_val is None or rule_val == "*":
            return True
        if isinstance(rule_val, list):
            return actual in rule_val
        return rule_val == actual

    def evaluate(self, subject: str, action: str, target: str,
                 phase: str, capabilities: list[str] | None = None) -> Decision:
        caps = set(capabilities or [])
        for rule in self.rules:
            if not self._match(rule.get("subject"), subject):
                continue
            if not self._match(rule.get("action"), action):
                continue
            if not self._match(rule.get("target"), target):
                continue
            if not self._match(rule.get("phase"), phase):
                continue
            required = rule.get("requires_capability")
            if required and required not in caps:
                continue
            return Decision(True, rule.get("name", "unnamed"),
                            f"matched allow rule '{rule.get('name', 'unnamed')}'")
        return Decision(False, None,
                        f"default-deny: no allow rule for "
                        f"({subject}->{target}:{action} in phase {phase})")
