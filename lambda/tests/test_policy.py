# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
import sys
import os
import json
import re

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from handler import build_shared_policy_document, T1_POLICY_ARN, T2_POLICY_ARN, OPUS_KEYWORDS, SONNET_KEYWORDS


def _iam_wildcard_matches(pattern: str, arn: str) -> bool:
    """Simulate IAM resource-wildcard matching: '*' matches any sequence of chars
    (including '/'). Used to prove a deny pattern would (or would not) match a given
    model ARN — including model IDs that do not exist yet."""
    regex = "^" + re.escape(pattern).replace(r"\*", ".*") + "$"
    return re.match(regex, arn) is not None


def test_empty_usernames_returns_empty_condition() -> None:
    """An empty username list produces an empty saml:sub condition."""
    doc = build_shared_policy_document(OPUS_KEYWORDS, [])
    assert doc["Statement"][0]["Condition"]["StringEquals"]["saml:sub"] == []


def test_usernames_appear_in_condition() -> None:
    """Supplied usernames appear directly in the saml:sub StringEquals condition."""
    doc = build_shared_policy_document(OPUS_KEYWORDS, ["alice", "bob"])
    condition = doc["Statement"][0]["Condition"]
    # Must use StringEquals and saml:sub — not aws:RoleSessionName or aws:userid
    assert "StringEquals" in condition
    assert "aws:RoleSessionName" not in condition.get("StringEquals", {})
    assert "aws:userid" not in condition.get("StringEquals", {})
    usernames = condition["StringEquals"]["saml:sub"]
    assert sorted(usernames) == ["alice", "bob"]


def test_t1_denies_opus_family_by_wildcard() -> None:
    """T1 denies the Opus family via a name wildcard (foundation-model + inference-profile)."""
    doc = build_shared_policy_document(OPUS_KEYWORDS, ["alice"])
    resources = doc["Statement"][0]["Resource"]
    assert any("foundation-model/*opus*" in r for r in resources)
    assert any("inference-profile/*opus*" in r for r in resources)
    assert not any("haiku" in r for r in resources)
    assert not any("sonnet" in r for r in resources)


def test_t2_denies_sonnet_family_by_wildcard() -> None:
    """T2 denies the Sonnet family via a name wildcard (foundation-model + inference-profile)."""
    doc = build_shared_policy_document(SONNET_KEYWORDS, ["alice"])
    resources = doc["Statement"][0]["Resource"]
    assert any("foundation-model/*sonnet*" in r for r in resources)
    assert any("inference-profile/*sonnet*" in r for r in resources)
    assert not any("haiku" in r for r in resources)
    assert not any("opus" in r for r in resources)


def test_t1_wildcard_does_not_match_any_sonnet_arn() -> None:
    """Cross-tier isolation: a T1 (opus) pattern must never MATCH a Sonnet ARN at
    IAM-evaluation time — proven with the simulator, not just substring absence.
    Catches a future refactor that transposed or merged the keyword lists."""
    t1 = build_shared_policy_document(OPUS_KEYWORDS, ["alice"])["Statement"][0]["Resource"]
    sonnet_arns = [
        "arn:aws:bedrock:us-east-1::foundation-model/anthropic.claude-sonnet-4-20250514-v1:0",
        "arn:aws:bedrock:us-east-1::foundation-model/anthropic.claude-sonnet-5",
        "arn:aws:bedrock:us-east-1:123456789012:inference-profile/us.anthropic.claude-sonnet-4-6",
        "arn:aws:bedrock:us-east-1::inference-profile/global.anthropic.claude-sonnet-4-6",
    ]
    for arn in sonnet_arns:
        assert not any(_iam_wildcard_matches(p, arn) for p in t1), \
            f"T1 (opus) pattern must not match Sonnet ARN: {arn}"


def test_t2_wildcard_does_not_match_any_opus_arn() -> None:
    """Cross-tier isolation: a T2 (sonnet) pattern must never MATCH an Opus ARN."""
    t2 = build_shared_policy_document(SONNET_KEYWORDS, ["alice"])["Statement"][0]["Resource"]
    opus_arns = [
        "arn:aws:bedrock:us-east-1::foundation-model/anthropic.claude-opus-4-8",
        "arn:aws:bedrock:us-east-1::foundation-model/anthropic.claude-opus-4-1-20250805-v1:0",
        "arn:aws:bedrock:us-east-1:123456789012:inference-profile/us.anthropic.claude-opus-4-8",
        "arn:aws:bedrock:us-east-1::inference-profile/global.anthropic.claude-opus-4-8",
    ]
    for arn in opus_arns:
        assert not any(_iam_wildcard_matches(p, arn) for p in t2), \
            f"T2 (sonnet) pattern must not match Opus ARN: {arn}"


def test_wildcard_covers_current_and_future_opus_models() -> None:
    """The T1 wildcard matches today's Opus IDs AND a hypothetical future Opus that
    is not enumerated anywhere — this is the whole point of family enforcement."""
    doc = build_shared_policy_document(OPUS_KEYWORDS, ["alice"])
    resources = doc["Statement"][0]["Resource"]
    current = "arn:aws:bedrock:us-east-1::foundation-model/anthropic.claude-opus-4-8"
    future = "arn:aws:bedrock:us-east-1::foundation-model/anthropic.claude-opus-9-99-v1:0"
    future_profile = "arn:aws:bedrock:us-east-1:123456789012:inference-profile/us.anthropic.claude-opus-9-99-v1:0"
    assert any(_iam_wildcard_matches(p, current) for p in resources)
    assert any(_iam_wildcard_matches(p, future) for p in resources)
    assert any(_iam_wildcard_matches(p, future_profile) for p in resources)


def test_wildcard_covers_legacy_claude3_opus_and_sonnet() -> None:
    """Legacy Claude 3 IDs still contain the family keyword, so they remain covered."""
    t1 = build_shared_policy_document(OPUS_KEYWORDS, ["alice"])["Statement"][0]["Resource"]
    t2 = build_shared_policy_document(SONNET_KEYWORDS, ["alice"])["Statement"][0]["Resource"]
    legacy_opus = "arn:aws:bedrock:us-east-1::foundation-model/anthropic.claude-3-opus-20240229-v1:0"
    legacy_sonnet = "arn:aws:bedrock:us-east-1::foundation-model/anthropic.claude-3-sonnet-20240229-v1:0:200k"
    assert any(_iam_wildcard_matches(p, legacy_opus) for p in t1)
    assert any(_iam_wildcard_matches(p, legacy_sonnet) for p in t2)


def test_wildcard_never_matches_any_haiku() -> None:
    """No T1 or T2 pattern may ever match a Haiku ARN — Haiku is never denied."""
    t1 = build_shared_policy_document(OPUS_KEYWORDS, ["alice"])["Statement"][0]["Resource"]
    t2 = build_shared_policy_document(SONNET_KEYWORDS, ["alice"])["Statement"][0]["Resource"]
    haiku_ids = [
        "arn:aws:bedrock:us-east-1::foundation-model/anthropic.claude-haiku-4-5-20251001-v1:0",
        "arn:aws:bedrock:us-east-1::foundation-model/anthropic.claude-3-haiku-20240307-v1:0",
        "arn:aws:bedrock:us-east-1:123456789012:inference-profile/us.anthropic.claude-3-5-haiku-20241022-v1:0",
        # newer Haiku via inference profile — completes the ARN-form matrix
        "arn:aws:bedrock:us-east-1:123456789012:inference-profile/us.anthropic.claude-haiku-4-5-20251001-v1:0",
        "arn:aws:bedrock:us-east-1::inference-profile/global.anthropic.claude-haiku-4-5-20251001-v1:0",
    ]
    for arn in haiku_ids:
        assert not any(_iam_wildcard_matches(p, arn) for p in t1)
        assert not any(_iam_wildcard_matches(p, arn) for p in t2)


def test_inference_profile_wildcard_covers_all_prefixes() -> None:
    """Inference profile ARNs wildcard account and region so us.*/global. both match.
    The global form has an EMPTY account segment (`us-east-1::inference-profile/...`);
    the pattern's `*:*:` matches it because `.*` matches the empty string."""
    doc = build_shared_policy_document(OPUS_KEYWORDS, ["alice"])
    resources = doc["Statement"][0]["Resource"]
    profile_arns = [r for r in resources if "inference-profile" in r]
    global_profile = "arn:aws:bedrock:us-east-1::inference-profile/global.anthropic.claude-opus-4-8"
    us_profile = "arn:aws:bedrock:us-east-1:123456789012:inference-profile/us.anthropic.claude-opus-4-8"
    assert any(_iam_wildcard_matches(p, global_profile) for p in profile_arns)
    assert any(_iam_wildcard_matches(p, us_profile) for p in profile_arns)


def test_t2_inference_profile_wildcard_covers_global_sonnet() -> None:
    """T2's inference-profile wildcard covers the global.* Sonnet form too (parallel
    to the Opus coverage above — the incident model was a Sonnet)."""
    doc = build_shared_policy_document(SONNET_KEYWORDS, ["alice"])
    profile_arns = [r for r in doc["Statement"][0]["Resource"] if "inference-profile" in r]
    global_sonnet = "arn:aws:bedrock:us-east-1::inference-profile/global.anthropic.claude-sonnet-4-6"
    us_sonnet = "arn:aws:bedrock:us-east-1:123456789012:inference-profile/us.anthropic.claude-sonnet-5"
    assert any(_iam_wildcard_matches(p, global_sonnet) for p in profile_arns)
    assert any(_iam_wildcard_matches(p, us_sonnet) for p in profile_arns)


def test_all_four_deny_actions_present() -> None:
    """All four deny actions (InvokeModel, InvokeModelWithResponseStream, Converse, ConverseStream) must be present."""
    doc = build_shared_policy_document(OPUS_KEYWORDS, ["alice"])
    actions = doc["Statement"][0]["Action"]
    assert "bedrock:InvokeModel" in actions
    assert "bedrock:InvokeModelWithResponseStream" in actions
    assert "bedrock:Converse" in actions
    assert "bedrock:ConverseStream" in actions


def test_haiku_never_in_deny() -> None:
    """The literal substring 'haiku' must never appear in a T1 or T2 deny resource."""
    t1 = build_shared_policy_document(OPUS_KEYWORDS, ["alice"])
    t2 = build_shared_policy_document(SONNET_KEYWORDS, ["alice"])
    for doc in [t1, t2]:
        all_resources = [r for s in doc["Statement"] for r in s["Resource"]]
        assert not any("haiku" in r for r in all_resources)


def test_policy_constants_use_bedrock_enforcement_naming() -> None:
    """T1 and T2 policy ARNs follow the BedrockEnforcement-T1/-T2 naming convention
    and are well-formed IAM policy ARNs. The account segment is resolved dynamically
    via STS (see handler._enforcement_account_id) rather than hardcoded, so this only
    asserts the ARN shape, not a specific account ID."""
    assert re.match(r"^arn:aws:iam::\d+:policy/BedrockEnforcement-T1$", T1_POLICY_ARN)
    assert re.match(r"^arn:aws:iam::\d+:policy/BedrockEnforcement-T2$", T2_POLICY_ARN)


def test_policy_is_valid_json() -> None:
    """The policy document must be JSON-serializable."""
    doc = build_shared_policy_document(OPUS_KEYWORDS, ["alice", "bob"])
    json.dumps(doc)
