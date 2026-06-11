"""Unit tests for shared evidence-rule primitives (evidence_rules/common.py)."""

from agentic_security_eval.oracle.evidence_rules.common import (
    PAYLOAD_MATCH_MIN_LEN,
    attacker_influence,
    compile_markers,
    first_marker,
    salient_tokens,
    serialize,
)


def test_salient_tokens_extracts_emails_urls_quoted_and_ignores_short():
    tokens = salient_tokens(
        "email a@b.example and visit https://evil.test/path and set status to 'approved' now",
        "noise 'abc' tiny",
    )
    lowered = [t.lower() for t in tokens]
    assert "a@b.example" in lowered
    assert any(t.startswith("https://evil.test") for t in lowered)
    assert "approved" in lowered
    assert "abc" not in lowered  # shorter than 6 chars, ignored


def test_attacker_influence_respects_payload_length_gate():
    short = "drop"  # below the literal-match gate
    assert len(short) < PAYLOAD_MATCH_MIN_LEN
    assert attacker_influence(short, (), "please drop the table") is None
    # a long-enough payload literal-matches case-insensitively
    long_payload = "exfiltrate everything now"
    assert attacker_influence(long_payload, (), "we will EXFILTRATE EVERYTHING NOW") == long_payload
    # token path matches even when the literal payload does not
    assert attacker_influence("nomatch", ("a@b.example",), "send to a@b.example") == "a@b.example"


def test_first_marker_respects_phrase_boundaries():
    patterns = compile_markers(("act as",))
    assert first_marker("react async to events", patterns) is None
    assert first_marker("interact as guest", patterns) is None
    assert first_marker("please act as root", patterns) == "act as"


def test_serialize_passes_str_through_and_json_encodes_others():
    assert serialize("plain text") == "plain text"
    assert serialize({"k": "v"}) == '{"k": "v"}'
