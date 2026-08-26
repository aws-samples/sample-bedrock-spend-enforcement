# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
import sys
import os
import json
from typing import Any
from unittest.mock import MagicMock, patch

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

import pytest
from handler import (
    write_shared_policy, update_shared_cmps, _build_state_item,
    _ensure_policy_version_slots, _batch_read_items, _batch_write_items,
    T1_POLICY_ARN, T2_POLICY_ARN, OPUS_KEYWORDS,
)


def test_ensure_policy_version_slots_deletes_oldest_when_full() -> None:
    """When at the 5-version IAM limit, the oldest non-default version is deleted."""
    mock_iam = MagicMock()
    mock_iam.list_policy_versions.return_value = {"Versions": [
        {"IsDefaultVersion": True,  "VersionId": "v5", "CreateDate": "2026-01-05"},
        {"IsDefaultVersion": False, "VersionId": "v1", "CreateDate": "2026-01-01"},
        {"IsDefaultVersion": False, "VersionId": "v2", "CreateDate": "2026-01-02"},
        {"IsDefaultVersion": False, "VersionId": "v3", "CreateDate": "2026-01-03"},
        {"IsDefaultVersion": False, "VersionId": "v4", "CreateDate": "2026-01-04"},
    ]}
    _ensure_policy_version_slots(mock_iam, T1_POLICY_ARN)
    mock_iam.delete_policy_version.assert_called_once()
    assert mock_iam.delete_policy_version.call_args[1]["VersionId"] == "v1"


def test_ensure_policy_version_slots_noop_under_limit() -> None:
    """Fewer than 5 versions requires no deletion."""
    mock_iam = MagicMock()
    mock_iam.list_policy_versions.return_value = {"Versions": [
        {"IsDefaultVersion": True, "VersionId": "v1", "CreateDate": "2026-01-01"},
    ]}
    _ensure_policy_version_slots(mock_iam, T1_POLICY_ARN)
    mock_iam.delete_policy_version.assert_not_called()


def test_write_shared_policy_emits_metric_on_oversize() -> None:
    """An oversized policy emits a CloudWatch metric instead of writing."""
    mock_iam = MagicMock()
    big_list = [f"user.with.long.name.{i}" for i in range(600)]
    with patch("handler.boto3") as mock_boto3:
        mock_cw = MagicMock()
        mock_boto3.client.return_value = mock_cw
        write_shared_policy(T1_POLICY_ARN, OPUS_KEYWORDS, big_list, mock_iam)
        mock_iam.create_policy_version.assert_not_called()
        mock_cw.put_metric_data.assert_called_once()
        kwargs = mock_cw.put_metric_data.call_args[1]
        assert kwargs["Namespace"] == "BedrockSpendEnforcement"


def test_build_state_item_uses_decimal_spend() -> None:
    """A state item's spend_usd is a Decimal (not a string) — required for DynamoDB numeric storage."""
    item = _build_state_item("alice", 125.0, ["opus"], {"t1"})
    assert item["user_id"] == "alice"
    assert item["active_denies"] == ["opus"]
    assert float(item["spend_usd"]) == pytest.approx(125.0)
    assert not isinstance(item["spend_usd"], str)
    assert item["notified_tiers"] == {"t1"}


def test_build_state_item_omits_notified_tiers_when_empty() -> None:
    """An empty notified_tiers set is omitted entirely, not written as an empty collection."""
    item = _build_state_item("alice", 50.0, [], set())
    assert "notified_tiers" not in item


def test_batch_write_items_chunks_at_25() -> None:
    """More than 25 items triggers two batch_write_item calls, not one oversized request."""
    with patch("handler._dynamodb") as mock_dynamodb_factory:
        mock_dynamodb_factory.return_value.batch_write_item.return_value = {}
        items = [{"user_id": f"user{i}"} for i in range(30)]
        _batch_write_items("t", items)
    calls = mock_dynamodb_factory.return_value.batch_write_item.call_args_list
    assert len(calls) == 2
    assert len(calls[0].kwargs["RequestItems"]["t"]) == 25
    assert len(calls[1].kwargs["RequestItems"]["t"]) == 5


def test_batch_write_items_retries_unprocessed_items() -> None:
    """UnprocessedItems from a throttled batch is retried until it's empty."""
    with patch("handler._dynamodb") as mock_dynamodb_factory:
        mock_dynamodb_factory.return_value.batch_write_item.side_effect = [
            {"UnprocessedItems": {"t": [{"PutRequest": {"Item": {"user_id": "bob"}}}]}},
            {},
        ]
        _batch_write_items("t", [{"user_id": "alice"}, {"user_id": "bob"}])
    assert mock_dynamodb_factory.return_value.batch_write_item.call_count == 2


def test_batch_write_items_fails_soft_on_exception() -> None:
    """A batch write failure is logged and swallowed — must not raise and abort the run."""
    with patch("handler._dynamodb", side_effect=Exception("throttled")):
        _batch_write_items("t", [{"user_id": "alice"}])  # should not raise


def test_batch_write_items_empty_input_skips_aws_call() -> None:
    """An empty items list makes no DynamoDB call at all."""
    with patch("handler._dynamodb") as mock_dynamodb_factory:
        _batch_write_items("t", [])
    mock_dynamodb_factory.assert_not_called()


def test_write_shared_policy_skips_if_too_large() -> None:
    """An oversized policy document is skipped entirely (no create_policy_version call)."""
    mock_iam = MagicMock()
    big_list = [f"user.with.long.name.{i}" for i in range(600)]
    write_shared_policy(T1_POLICY_ARN, OPUS_KEYWORDS, big_list, mock_iam)
    mock_iam.create_policy_version.assert_not_called()


def test_write_shared_policy_calls_create_policy_version() -> None:
    """A normal-sized policy update calls create_policy_version with SetAsDefault."""
    mock_iam = MagicMock()
    mock_iam.list_policy_versions.return_value = {
        "Versions": [{"IsDefaultVersion": True, "VersionId": "v1", "CreateDate": "2026-01-01"}]
    }
    write_shared_policy(T1_POLICY_ARN, OPUS_KEYWORDS, ["alice"], mock_iam)
    mock_iam.create_policy_version.assert_called_once()
    call_kwargs = mock_iam.create_policy_version.call_args[1]
    assert call_kwargs["PolicyArn"] == T1_POLICY_ARN
    assert call_kwargs["SetAsDefault"] is True


def test_write_shared_policy_writes_empty_list() -> None:
    """An empty username list must still be written so all users are un-denied."""
    mock_iam = MagicMock()
    mock_iam.list_policy_versions.return_value = {
        "Versions": [{"IsDefaultVersion": True, "VersionId": "v1", "CreateDate": "2026-01-01"}]
    }
    write_shared_policy(T1_POLICY_ARN, OPUS_KEYWORDS, [], mock_iam)
    mock_iam.create_policy_version.assert_called_once()


def test_update_shared_cmps_writes_both_policies() -> None:
    """Both T1 and T2 policies are written in a single update_shared_cmps call."""
    mock_iam = MagicMock()
    mock_iam.list_policy_versions.return_value = {
        "Versions": [{"IsDefaultVersion": True, "VersionId": "v1", "CreateDate": "2026-01-01"}]
    }
    update_shared_cmps(["alice"], ["alice"], mock_iam)
    arns_written = [c[1]["PolicyArn"] for c in mock_iam.create_policy_version.call_args_list]
    assert T1_POLICY_ARN in arns_written
    assert T2_POLICY_ARN in arns_written


def test_update_shared_cmps_sends_opus_to_t1_and_sonnet_to_t2() -> None:
    """The T1 policy document must contain the *opus* wildcard and the T2 document
    the *sonnet* wildcard — proves the keyword lists aren't transposed between tiers."""
    mock_iam = MagicMock()
    mock_iam.list_policy_versions.return_value = {
        "Versions": [{"IsDefaultVersion": True, "VersionId": "v1", "CreateDate": "2026-01-01"}]
    }
    update_shared_cmps(["alice"], ["alice"], mock_iam)
    docs_by_arn = {
        c[1]["PolicyArn"]: c[1]["PolicyDocument"]
        for c in mock_iam.create_policy_version.call_args_list
    }
    t1_doc = docs_by_arn[T1_POLICY_ARN]
    t2_doc = docs_by_arn[T2_POLICY_ARN]
    assert "*opus*" in t1_doc and "*sonnet*" not in t1_doc
    assert "*sonnet*" in t2_doc and "*opus*" not in t2_doc
    # sanity: both are still valid JSON policy documents
    json.loads(t1_doc)
    json.loads(t2_doc)


def test_update_shared_cmps_uses_custom_arns() -> None:
    """update_shared_cmps writes to the provided ARNs, not the module defaults."""
    mock_iam = MagicMock()
    mock_iam.list_policy_versions.return_value = {
        "Versions": [{"IsDefaultVersion": True, "VersionId": "v1", "CreateDate": "2026-01-01"}]
    }
    custom_t1 = "arn:aws:iam::123456789012:policy/BedrockEnforcement-T1-custom"
    custom_t2 = "arn:aws:iam::123456789012:policy/BedrockEnforcement-T2-custom"
    update_shared_cmps(["alice"], ["alice"], mock_iam, t1_policy_arn=custom_t1, t2_policy_arn=custom_t2)
    arns_written = [c[1]["PolicyArn"] for c in mock_iam.create_policy_version.call_args_list]
    assert custom_t1 in arns_written
    assert custom_t2 in arns_written
    assert T1_POLICY_ARN not in arns_written
    assert T2_POLICY_ARN not in arns_written


def test_update_shared_cmps_t2_runs_even_if_t1_fails() -> None:
    """A T1 write failure must not prevent the T2 write from running."""
    mock_iam = MagicMock()
    mock_iam.list_policy_versions.return_value = {
        "Versions": [{"IsDefaultVersion": True, "VersionId": "v1", "CreateDate": "2026-01-01"}]
    }
    # First create_policy_version (T1) raises; T2 must still be attempted.
    mock_iam.create_policy_version.side_effect = [Exception("T1 boom"), None]
    update_shared_cmps(["alice"], ["bob"], mock_iam)
    assert mock_iam.create_policy_version.call_count == 2


def test_batch_read_items_empty_input_short_circuits() -> None:
    """No user_ids means no DynamoDB call at all, not a zero-key batch_get_item."""
    with patch("handler._dynamodb") as mock_dynamodb_factory:
        result = _batch_read_items("some-table", [])
    mock_dynamodb_factory.assert_not_called()
    assert result == {}


def test_batch_read_items_chunks_at_100() -> None:
    """More than 100 user_ids splits into multiple batch_get_item calls."""
    user_ids = [f"user{i}" for i in range(150)]
    mock_dynamodb = MagicMock()
    mock_dynamodb.batch_get_item.return_value = {"Responses": {"t": []}, "UnprocessedKeys": {}}
    with patch("handler._dynamodb", return_value=mock_dynamodb):
        _batch_read_items("t", user_ids)
    assert mock_dynamodb.batch_get_item.call_count == 2
    first_chunk_keys = mock_dynamodb.batch_get_item.call_args_list[0].kwargs["RequestItems"]["t"]["Keys"]
    second_chunk_keys = mock_dynamodb.batch_get_item.call_args_list[1].kwargs["RequestItems"]["t"]["Keys"]
    assert len(first_chunk_keys) == 100
    assert len(second_chunk_keys) == 50


def test_batch_read_items_retries_unprocessed_keys() -> None:
    """UnprocessedKeys from one call are retried, not the whole chunk from scratch."""
    mock_dynamodb = MagicMock()
    mock_dynamodb.batch_get_item.side_effect = [
        {
            "Responses": {"t": [{"user_id": "alice", "spend_usd": "1"}]},
            "UnprocessedKeys": {"t": {"Keys": [{"user_id": "bob"}]}},
        },
        {"Responses": {"t": [{"user_id": "bob", "spend_usd": "2"}]}, "UnprocessedKeys": {}},
    ]
    with patch("handler._dynamodb", return_value=mock_dynamodb):
        result = _batch_read_items("t", ["alice", "bob"])
    assert mock_dynamodb.batch_get_item.call_count == 2
    assert result["alice"]["spend_usd"] == "1"
    assert result["bob"]["spend_usd"] == "2"


def test_batch_read_items_fails_closed_on_exception() -> None:
    """A DynamoDB error for a chunk is logged and skipped, never raised — same
    fail-closed contract as _read_item, so a lookup failure can't drop a user
    from enforcement."""
    with patch("handler._dynamodb", side_effect=Exception("throttled")):
        result = _batch_read_items("t", ["alice", "bob"])
    assert result == {}


def test_handler_builds_tier_lists_and_writes_cmps() -> None:
    """Handler correctly assigns users to T1/T2 tier lists based on spend vs limit."""
    captured: dict[str, Any] = {}

    def fake_update(t1: list[str], t2: list[str], iam: object, **kwargs: Any) -> list[dict[str, Any]]:
        """Capture the call's tier lists."""
        captured["t1"] = t1
        captured["t2"] = t2
        return []

    spend = {
        # >= 150 → opus + sonnet
        "over_t2": 200.0,
        # >= 120, < 150 → opus only
        "over_t1": 130.0,
        # below T1 → neither
        "under": 50.0,
    }
    with patch("handler._query_cost_view_rows", return_value=[]), \
         patch("handler.query_spend_by_person", return_value=spend), \
         patch("handler._batch_read_items", return_value={}), \
         patch("handler._batch_write_items"), \
         patch("handler.boto3.client", return_value=MagicMock()), \
         patch("handler.update_shared_cmps", side_effect=fake_update):
        from handler import handler
        handler({}, None)

    assert sorted(captured["t1"]) == ["over_t1", "over_t2"]
    assert captured["t2"] == ["over_t2"]


def test_handler_empty_spend_writes_empty_cmps() -> None:
    """With no spend data, the CMP write receives empty lists (reset path)."""
    captured: dict[str, Any] = {}
    with patch("handler._query_cost_view_rows", return_value=[]), \
         patch("handler.query_spend_by_person", return_value={}), \
         patch("handler.boto3.client", return_value=MagicMock()), \
         patch("handler.update_shared_cmps", side_effect=lambda t1, t2, iam, **kw: captured.update(t1=t1, t2=t2) or []):
        from handler import handler
        handler({}, None)
    assert captured["t1"] == []
    assert captured["t2"] == []


def test_handler_per_user_exception_does_not_abort(monkeypatch: pytest.MonkeyPatch) -> None:
    """An exception while processing one user is logged and skipped; other users
    and the CMP write still proceed (the run does not abort)."""
    monkeypatch.delenv("SLACK_BOT_TOKEN", raising=False)
    captured: dict[str, Any] = {}
    spend = {"alice": 130.0, "bob": 160.0}

    def fake_notify(user_id: str, *args: Any, **kwargs: Any) -> set[str]:
        """Raise for alice (mid-iteration failure), succeed for bob."""
        if user_id == "alice":
            raise RuntimeError("notify failed")
        return set()

    # alice is at T1 ($130 >= 80% of $150), bob is at T2 ($160 >= $150).
    with patch("handler._query_cost_view_rows", return_value=[]), \
         patch("handler.query_spend_by_person", return_value=spend), \
         patch("handler._batch_read_items", return_value={}), \
         patch("handler.boto3.client", return_value=MagicMock()), \
         patch("handler._notify_if_new_tier", side_effect=fake_notify), \
         patch("handler._batch_write_items"), \
         patch("handler.update_shared_cmps", side_effect=lambda t1, t2, iam, **kw: captured.update(t1=t1, t2=t2) or []):
        from handler import handler
        handler({}, None)

    # bob processed normally despite alice raising mid-loop.
    assert "bob" in captured["t1"]
    assert "bob" in captured["t2"]
    assert "alice" in captured["t1"]
    assert "alice" not in captured["t2"]


def test_handler_read_error_still_enforces_on_spend(monkeypatch: pytest.MonkeyPatch) -> None:
    """A DynamoDB read error must NOT drop a user from enforcement (fail-closed):
    the real _batch_read_items swallows the error and returns {}, so the user
    is still denied based on spend against the default limit."""
    monkeypatch.delenv("SLACK_BOT_TOKEN", raising=False)
    captured: dict[str, Any] = {}
    # well over the $150 default → T2
    spend = {"alice": 200.0}

    # Patch _dynamodb (one layer below _batch_read_items) so the REAL
    # _batch_read_items runs and exercises its internal try/except fail-soft path.
    with patch("handler._query_cost_view_rows", return_value=[]), \
         patch("handler.query_spend_by_person", return_value=spend), \
         patch("handler._dynamodb", side_effect=Exception("throttled")), \
         patch("handler.boto3.client", return_value=MagicMock()), \
         patch("handler._batch_write_items"), \
         patch("handler.update_shared_cmps", side_effect=lambda t1, t2, iam, **kw: captured.update(t1=t1, t2=t2) or []):
        from handler import handler
        handler({}, None)

    # Even though every read raised internally, alice is still enforced at T1+T2.
    assert "alice" in captured["t1"]
    assert "alice" in captured["t2"]


# ── Pure derive helpers (M2: read each DynamoDB item once, derive many values) ──

def test_limit_from_item_returns_custom() -> None:
    """Derives the custom limit from an already-fetched exceptions item."""
    from handler import _limit_from_item
    assert _limit_from_item({"daily_limit_usd": "300"}) == pytest.approx(300.0)


def test_limit_from_item_defaults_for_block_only_row() -> None:
    """A block-only row (no daily_limit_usd) derives the default, no raise."""
    from handler import _limit_from_item, DEFAULT_DAILY_LIMIT as DFLT
    assert _limit_from_item({"manual_block": True}) == DFLT
    assert _limit_from_item({}) == DFLT


def test_limit_from_item_defaults_on_bad_value() -> None:
    """An unparseable daily_limit_usd derives the default rather than raising."""
    from handler import _limit_from_item, DEFAULT_DAILY_LIMIT as DFLT
    assert _limit_from_item({"daily_limit_usd": "not-a-number"}) == DFLT


def test_limit_from_item_respects_future_expiry() -> None:
    """A custom limit with a future limit_expires_at is still honored."""
    from handler import _limit_from_item
    from datetime import datetime, timezone, timedelta
    future = (datetime.now(timezone.utc) + timedelta(days=1)).isoformat()
    assert _limit_from_item({"daily_limit_usd": "300", "limit_expires_at": future}) == pytest.approx(300.0)


def test_limit_from_item_defaults_after_expiry() -> None:
    """A custom limit whose limit_expires_at has passed derives the default."""
    from handler import _limit_from_item, DEFAULT_DAILY_LIMIT as DFLT
    from datetime import datetime, timezone, timedelta
    past = (datetime.now(timezone.utc) - timedelta(days=1)).isoformat()
    assert _limit_from_item({"daily_limit_usd": "300", "limit_expires_at": past}) == DFLT


def test_limit_from_item_no_expiry_never_expires() -> None:
    """Absent limit_expires_at means the custom limit never expires."""
    from handler import _limit_from_item
    assert _limit_from_item({"daily_limit_usd": "300"}) == pytest.approx(300.0)


def test_limit_expired_false_when_absent() -> None:
    """No limit_expires_at means not expired."""
    from handler import _limit_expired
    assert _limit_expired({}) is False
    assert _limit_expired({"daily_limit_usd": "300"}) is False


def test_limit_expired_malformed_date_is_expired() -> None:
    """A malformed limit_expires_at must NOT raise; fails closed to expired (reverts to default)."""
    from handler import _limit_expired
    assert _limit_expired({"limit_expires_at": "garbage"}) is True


def test_blocked_from_item_indefinite() -> None:
    """manual_block True with no blocked_until is an active (indefinite) block."""
    from handler import _blocked_from_item
    assert _blocked_from_item({"manual_block": True}) is True


def test_blocked_from_item_false_when_no_flag() -> None:
    """No manual_block flag is not blocked."""
    from handler import _blocked_from_item
    assert _blocked_from_item({}) is False
    assert _blocked_from_item({"daily_limit_usd": "300"}) is False


def test_blocked_from_item_respects_expiry() -> None:
    """A future blocked_until is active; a past one is not."""
    from handler import _blocked_from_item
    from datetime import datetime, timezone, timedelta
    future = (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat()
    past   = (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat()
    assert _blocked_from_item({"manual_block": True, "blocked_until": future}) is True
    assert _blocked_from_item({"manual_block": True, "blocked_until": past})   is False


def test_blocked_from_item_malformed_date_is_not_blocked() -> None:
    """A malformed blocked_until must NOT raise (would drop the user); treat as not blocked."""
    from handler import _blocked_from_item
    assert _blocked_from_item({"manual_block": True, "blocked_until": "garbage"}) is False


def test_notified_tiers_from_item() -> None:
    """Derives the notified_tiers set from an already-fetched state item."""
    from handler import _notified_tiers_from_item
    assert _notified_tiers_from_item({"notified_tiers": {"warn", "t1"}}) == {"warn", "t1"}
    assert _notified_tiers_from_item({}) == set()
    assert _notified_tiers_from_item(None) == set()


def test_ensure_policy_version_slots_raises_if_all_default() -> None:
    """Raises RuntimeError when all 5 versions are default (IAM invariant violated)."""
    mock_iam = MagicMock()
    mock_iam.list_policy_versions.return_value = {"Versions": [
        {"IsDefaultVersion": True, "VersionId": f"v{i}", "CreateDate": f"2026-01-0{i}"}
        for i in range(1, 6)
    ]}
    with pytest.raises(RuntimeError, match="all 5 versions"):
        _ensure_policy_version_slots(mock_iam, T1_POLICY_ARN)


def test_update_shared_cmps_continues_after_t2_failure() -> None:
    """A T2 write failure is logged and swallowed; the function still returns."""
    mock_iam = MagicMock()
    mock_iam.list_policy_versions.return_value = {
        "Versions": [{"IsDefaultVersion": True, "VersionId": "v1", "CreateDate": "2026-01-01"}]
    }
    mock_iam.create_policy_version.side_effect = [None, Exception("T2 boom")]
    update_shared_cmps(["alice"], ["bob"], mock_iam)
    assert mock_iam.create_policy_version.call_count == 2
