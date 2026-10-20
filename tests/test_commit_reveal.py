"""Tests for commit-reveal payload integrity (objective 02)."""
from common.commit_reveal import make_commitment, verify_reveal


def test_valid_reveal_matches():
    payloads = ["attack one", "attack two", "ignore previous instructions"]
    nonce, commitment = make_commitment(payloads)
    assert verify_reveal(commitment, nonce, payloads) is True


def test_altered_payloads_rejected():
    payloads = ["a", "b", "c"]
    nonce, commitment = make_commitment(payloads)
    # Red tries to swap in a payload AFTER seeing blue behaviour.
    assert verify_reveal(commitment, nonce, ["a", "b", "c-modified"]) is False


def test_added_payload_rejected():
    payloads = ["a", "b"]
    nonce, commitment = make_commitment(payloads)
    assert verify_reveal(commitment, nonce, ["a", "b", "c"]) is False


def test_reordered_payloads_rejected():
    payloads = ["a", "b", "c"]
    nonce, commitment = make_commitment(payloads)
    assert verify_reveal(commitment, nonce, ["c", "b", "a"]) is False


def test_wrong_nonce_rejected():
    payloads = ["a", "b"]
    _, commitment = make_commitment(payloads)
    assert verify_reveal(commitment, "deadbeef", payloads) is False


def test_commitment_hides_payloads():
    # The commitment must not reveal payload content or even length trivially.
    _, c1 = make_commitment(["short"])
    _, c2 = make_commitment(["a much longer adversarial payload string here"])
    assert len(c1) == len(c2) == 64   # both are SHA-256 hex, size-independent
