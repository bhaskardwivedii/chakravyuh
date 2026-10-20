"""Tests for the default-deny policy engine (objectives 01/02, verticals 2/3)."""
import os

from broker.policy.engine import PolicyEngine

POLICY = os.path.join(os.path.dirname(__file__), "..", "broker", "policy", "policy.yaml")


def engine():
    return PolicyEngine.from_file(POLICY)


def test_red_cannot_reach_blue():
    # There is no allow rule for red->blue in any phase: must be denied.
    d = engine().evaluate("red", "attack", "blue", "running", ["red.attack"])
    assert d.allow is False
    assert "default-deny" in d.reason


def test_blue_cannot_reach_red():
    d = engine().evaluate("blue", "read", "red", "running", ["blue.verdict"])
    assert d.allow is False


def test_red_attack_model_allowed_only_when_running():
    e = engine()
    assert e.evaluate("red", "attack", "model", "running", ["red.attack"]).allow is True
    # Same action outside the running phase is denied (no early/late attacks).
    assert e.evaluate("red", "attack", "model", "commit", ["red.attack"]).allow is False
    assert e.evaluate("red", "attack", "model", "closed", ["red.attack"]).allow is False


def test_capability_required():
    e = engine()
    # Correct subject/action/target/phase but MISSING capability -> denied.
    assert e.evaluate("red", "attack", "model", "running", []).allow is False
    assert e.evaluate("red", "attack", "model", "running", ["red.attack"]).allow is True


def test_reveal_only_after_close():
    e = engine()
    assert e.evaluate("red", "reveal", "broker", "running", ["red.reveal"]).allow is False
    assert e.evaluate("red", "reveal", "broker", "closed", ["red.reveal"]).allow is True


def test_commit_only_in_commit_phase():
    e = engine()
    assert e.evaluate("red", "commit", "broker", "commit", ["red.commit"]).allow is True
    assert e.evaluate("red", "commit", "broker", "running", ["red.commit"]).allow is False


def test_unknown_subject_denied():
    assert engine().evaluate("attacker", "attack", "model", "running", ["red.attack"]).allow is False
