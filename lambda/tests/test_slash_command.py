# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
import sys
import os
import hashlib
import hmac
import json
import time
from typing import Any
from unittest.mock import MagicMock, patch

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

import pytest
from slash_command import (
    _verify_slack_signature,
    _handle_gateway,
    _handle_async,
    _get_spend,
    _get_limit,
    _get_limit_and_expiry,
    _resolve_username,
    DEFAULT_DAILY_LIMIT,
)


def _make_signature(secret: str, timestamp: str, body: str) -> str:
    """Build a valid Slack HMAC-SHA256 signature."""
    return "v0=" + hmac.new(
        secret.encode(),
        f"v0:{timestamp}:{body}".encode(),
        hashlib.sha256,
    ).hexdigest()


# ── _verify_slack_signature ───────────────────────────────────────────────────

def test_verify_valid_signature(monkeypatch: pytest.MonkeyPatch) -> None:
    """A valid, fresh signature returns True."""
    monkeypatch.setenv("SLACK_SIGNING_SECRET", "testsecret")
    ts = str(int(time.time()))
    body = "command=%2Fbedrock-spend&user_id=U123"
    sig = _make_signature("testsecret", ts, body)
    assert _verify_slack_signature(sig, ts, body) is True


def test_verify_rejects_stale_timestamp(monkeypatch: pytest.MonkeyPatch) -> None:
    """A signature with a timestamp older than SIGNATURE_MAX_AGE_SECONDS is rejected."""
    monkeypatch.setenv("SLACK_SIGNING_SECRET", "testsecret")
    ts = str(int(time.time()) - 400)
    body = "command=%2Fbedrock-spend"
    sig = _make_signature("testsecret", ts, body)
    assert _verify_slack_signature(sig, ts, body) is False


def test_verify_rejects_wrong_signature(monkeypatch: pytest.MonkeyPatch) -> None:
    """A signature that doesn't match the expected HMAC is rejected."""
    monkeypatch.setenv("SLACK_SIGNING_SECRET", "testsecret")
    ts = str(int(time.time()))
    body = "command=%2Fbedrock-spend"
    assert _verify_slack_signature("v0=badhash", ts, body) is False


def test_verify_rejects_missing_secret(monkeypatch: pytest.MonkeyPatch) -> None:
    """Missing SLACK_SIGNING_SECRET rejects all requests."""
    monkeypatch.delenv("SLACK_SIGNING_SECRET", raising=False)
    ts = str(int(time.time()))
    body = "command=%2Fbedrock-spend"
    sig = _make_signature("", ts, body)
    assert _verify_slack_signature(sig, ts, body) is False


def test_verify_handles_non_numeric_timestamp(monkeypatch: pytest.MonkeyPatch) -> None:
    """A non-numeric timestamp returns False, not an exception."""
    monkeypatch.setenv("SLACK_SIGNING_SECRET", "testsecret")
    assert _verify_slack_signature("v0=abc", "notanumber", "body") is False


# ── _get_spend / _get_limit ───────────────────────────────────────────────────

def test_get_spend_returns_value() -> None:
    """Returns spend_usd from the state table."""
    mock_table = MagicMock()
    mock_table.get_item.return_value = {"Item": {"spend_usd": "127.50"}}
    with patch("slash_command._dynamodb_resource") as mock_ddb:
        mock_ddb.Table.return_value = mock_table
        assert _get_spend("alice.smith") == pytest.approx(127.50)


def test_get_spend_returns_zero_when_absent() -> None:
    """Returns 0.0 when the user has no state record."""
    mock_table = MagicMock()
    mock_table.get_item.return_value = {}
    with patch("slash_command._dynamodb_resource") as mock_ddb:
        mock_ddb.Table.return_value = mock_table
        assert _get_spend("alice.smith") == pytest.approx(0.0)


def test_get_limit_returns_custom() -> None:
    """Returns the custom limit when present in the exceptions table."""
    mock_table = MagicMock()
    mock_table.get_item.return_value = {"Item": {"daily_limit_usd": "300"}}
    with patch("slash_command._dynamodb_resource") as mock_ddb:
        mock_ddb.Table.return_value = mock_table
        assert _get_limit("alice.smith") == pytest.approx(300.0)


def test_get_limit_returns_custom_when_expiry_in_future() -> None:
    """A custom limit with a future limit_expires_at is still honored."""
    from datetime import datetime, timezone, timedelta
    future = (datetime.now(timezone.utc) + timedelta(days=1)).isoformat()
    mock_table = MagicMock()
    mock_table.get_item.return_value = {"Item": {"daily_limit_usd": "300", "limit_expires_at": future}}
    with patch("slash_command._dynamodb_resource") as mock_ddb:
        mock_ddb.Table.return_value = mock_table
        assert _get_limit("alice.smith") == pytest.approx(300.0)


def test_get_limit_falls_back_to_default_when_expired() -> None:
    """A custom limit whose limit_expires_at has passed reverts to the default."""
    from datetime import datetime, timezone, timedelta
    past = (datetime.now(timezone.utc) - timedelta(days=1)).isoformat()
    mock_table = MagicMock()
    mock_table.get_item.return_value = {"Item": {"daily_limit_usd": "300", "limit_expires_at": past}}
    with patch("slash_command._dynamodb_resource") as mock_ddb:
        mock_ddb.Table.return_value = mock_table
        assert _get_limit("alice.smith") == DEFAULT_DAILY_LIMIT


# ── _get_limit_and_expiry ─────────────────────────────────────────────────────

def test_get_limit_and_expiry_returns_both_in_one_read() -> None:
    """Returns (limit, expiry) from a single get_item call when the custom limit is active."""
    from datetime import datetime, timezone, timedelta
    future = (datetime.now(timezone.utc) + timedelta(days=1)).isoformat()
    mock_table = MagicMock()
    mock_table.get_item.return_value = {"Item": {"daily_limit_usd": "300", "limit_expires_at": future}}
    with patch("slash_command._dynamodb_resource") as mock_ddb:
        mock_ddb.Table.return_value = mock_table
        assert _get_limit_and_expiry("alice.smith") == (pytest.approx(300.0), future)
    mock_table.get_item.assert_called_once()


def test_get_limit_and_expiry_no_expiry_when_never_expires() -> None:
    """Expiry is None when the custom limit has no expiry."""
    mock_table = MagicMock()
    mock_table.get_item.return_value = {"Item": {"daily_limit_usd": "300"}}
    with patch("slash_command._dynamodb_resource") as mock_ddb:
        mock_ddb.Table.return_value = mock_table
        limit, expiry = _get_limit_and_expiry("alice.smith")
    assert limit == pytest.approx(300.0)
    assert expiry is None


def test_get_limit_and_expiry_falls_back_to_default_when_expired() -> None:
    """Both limit and expiry revert to defaults once limit_expires_at has passed."""
    from datetime import datetime, timezone, timedelta
    past = (datetime.now(timezone.utc) - timedelta(days=1)).isoformat()
    mock_table = MagicMock()
    mock_table.get_item.return_value = {"Item": {"daily_limit_usd": "300", "limit_expires_at": past}}
    with patch("slash_command._dynamodb_resource") as mock_ddb:
        mock_ddb.Table.return_value = mock_table
        assert _get_limit_and_expiry("alice.smith") == (DEFAULT_DAILY_LIMIT, None)


def test_get_limit_and_expiry_defaults_when_no_custom_limit() -> None:
    """Returns (default, None) when there's no custom limit at all."""
    mock_table = MagicMock()
    mock_table.get_item.return_value = {}
    with patch("slash_command._dynamodb_resource") as mock_ddb:
        mock_ddb.Table.return_value = mock_table
        assert _get_limit_and_expiry("alice.smith") == (DEFAULT_DAILY_LIMIT, None)


def test_get_limit_and_expiry_defaults_on_dynamodb_error() -> None:
    """Returns (default, None) when DynamoDB raises."""
    with patch("slash_command._dynamodb_resource") as mock_ddb:
        mock_ddb.Table.return_value.get_item.side_effect = Exception("throttled")
        assert _get_limit_and_expiry("alice.smith") == (DEFAULT_DAILY_LIMIT, None)


def test_get_spend_returns_zero_when_stale() -> None:
    """Returns 0.0 when the state record's updated_at predates the current window."""
    from datetime import datetime, timezone, timedelta
    stale_ts = (datetime.now(timezone.utc) - timedelta(days=2)).isoformat()
    with patch("slash_command._dynamodb_resource") as mock_ddb:
        mock_ddb.Table.return_value.get_item.return_value = {
            "Item": {"spend_usd": "152.50", "updated_at": stale_ts}
        }
        assert _get_spend("alice.smith") == pytest.approx(0.0)


def test_get_spend_returns_value_for_current_window() -> None:
    """Returns spend_usd when the state record is within the current 0400-UTC window."""
    from datetime import datetime, timedelta, timezone
    current_ts = datetime.now(timezone.utc).isoformat()
    # Anchored an hour before "now" rather than at today's 04:00 UTC — pinning to
    # 04:00 made this test fail whenever CI ran between 00:00-03:59 UTC, since
    # current_ts (actual now) would then be *before* that window_start.
    window_start = datetime.now(timezone.utc) - timedelta(hours=1)
    with patch("slash_command._dynamodb_resource") as mock_ddb, \
         patch("slash_command._current_window_start", return_value=window_start):
        mock_ddb.Table.return_value.get_item.return_value = {
            "Item": {"spend_usd": "75.00", "updated_at": current_ts}
        }
        assert _get_spend("alice.smith") == pytest.approx(75.0)


def test_get_limit_returns_default_on_dynamodb_error() -> None:
    """Returns DEFAULT_DAILY_LIMIT when DynamoDB raises."""
    with patch("slash_command._dynamodb_resource") as mock_ddb:
        mock_ddb.Table.return_value.get_item.side_effect = Exception("throttled")
        assert _get_limit("alice.smith") == DEFAULT_DAILY_LIMIT


# ── _handle_gateway ────────────────────────────────────────────────────────────

def test_handle_gateway_valid_signature_acks(monkeypatch: pytest.MonkeyPatch) -> None:
    """A valid signature triggers async self-invoke and returns 200 ack."""
    monkeypatch.setenv("SLACK_SIGNING_SECRET", "testsecret")
    ts = str(int(time.time()))
    body = "command=%2Fbedrock-spend&user_id=U123&channel_id=C1&response_url=https%3A%2F%2Fx"
    sig = _make_signature("testsecret", ts, body)
    event = {
        "body": body,
        "headers": {"X-Slack-Signature": sig, "X-Slack-Request-Timestamp": ts},
        "isBase64Encoded": False,
    }
    with patch("slash_command._lambda_client") as mock_lambda:
        resp = _handle_gateway(event)
    assert resp["statusCode"] == 200
    mock_lambda.invoke.assert_called_once()


def test_handle_gateway_invalid_signature_rejects(monkeypatch: pytest.MonkeyPatch) -> None:
    """An invalid signature returns 403 without invoking anything."""
    monkeypatch.setenv("SLACK_SIGNING_SECRET", "testsecret")
    ts = str(int(time.time()))
    body = "command=%2Fbedrock-spend"
    event = {
        "body": body,
        "headers": {"X-Slack-Signature": "v0=bad", "X-Slack-Request-Timestamp": ts},
        "isBase64Encoded": False,
    }
    with patch("slash_command._lambda_client") as mock_lambda:
        resp = _handle_gateway(event)
    assert resp["statusCode"] == 403
    mock_lambda.invoke.assert_not_called()


def test_handle_gateway_base64_body_decoded(monkeypatch: pytest.MonkeyPatch) -> None:
    """A base64-encoded body is decoded before signature verification."""
    import base64
    monkeypatch.setenv("SLACK_SIGNING_SECRET", "testsecret")
    ts = str(int(time.time()))
    body = "command=%2Fbedrock-spend&user_id=U123&response_url=https%3A%2F%2Fx"
    sig = _make_signature("testsecret", ts, body)
    encoded = base64.b64encode(body.encode()).decode()
    event = {
        "body": encoded,
        "headers": {"X-Slack-Signature": sig, "X-Slack-Request-Timestamp": ts},
        "isBase64Encoded": True,
    }
    with patch("slash_command._lambda_client") as mock_lambda:
        resp = _handle_gateway(event)
    assert resp["statusCode"] == 200
    mock_lambda.invoke.assert_called_once()


def test_handle_gateway_invoke_failure_returns_ephemeral(monkeypatch: pytest.MonkeyPatch) -> None:
    """If self-invoke fails, an ephemeral error is returned instead of raising."""
    monkeypatch.setenv("SLACK_SIGNING_SECRET", "testsecret")
    ts = str(int(time.time()))
    body = "command=%2Fbedrock-spend&user_id=U123"
    sig = _make_signature("testsecret", ts, body)
    event = {
        "body": body,
        "headers": {"X-Slack-Signature": sig, "X-Slack-Request-Timestamp": ts},
        "isBase64Encoded": False,
    }
    with patch("slash_command._lambda_client") as mock_lambda:
        mock_lambda.invoke.side_effect = Exception("boom")
        resp = _handle_gateway(event)
    assert resp["statusCode"] == 200
    assert "Something went wrong" in resp["body"]


# ── _handle_async (spend) ─────────────────────────────────────────────────────

def test_handle_async_spend_success() -> None:
    """A resolvable user gets their spend/limit posted via response_url."""
    event: dict[str, Any] = {
        "command": "/bedrock-spend",
        "text": "",
        "caller_slack_id": "U123",
        "channel_id": "",
        "response_url": "https://hooks.slack.com/foo",
    }
    with patch("slash_command._resolve_username", return_value="alice.smith"), \
         patch("slash_command._get_spend", return_value=42.0), \
         patch("slash_command._get_limit_and_expiry", return_value=(150.0, None)), \
         patch("notifier.slash_command_text", return_value="some text") as mock_text, \
         patch("slash_command._post_result") as mock_post:
        resp = _handle_async(event)
    assert resp["statusCode"] == 200
    mock_text.assert_called_once_with(42.0, 150.0, None)
    mock_post.assert_called_once()


def test_handle_async_spend_unresolvable_user() -> None:
    """An unresolvable Slack user gets an apologetic message instead of a crash."""
    event: dict[str, Any] = {
        "command": "/bedrock-spend",
        "text": "",
        "caller_slack_id": "U999",
        "channel_id": "",
        "response_url": "https://hooks.slack.com/foo",
    }
    with patch("slash_command._resolve_username", return_value=None), \
         patch("slash_command._post_result") as mock_post:
        resp = _handle_async(event)
    assert resp["statusCode"] == 200
    assert "Couldn't identify" in mock_post.call_args[0][0]


def test_handle_async_unknown_command() -> None:
    """An unrecognised command posts an 'Unknown command' message."""
    event: dict[str, Any] = {
        "command": "/bedrock-mystery",
        "text": "",
        "caller_slack_id": "U123",
        "channel_id": "",
        "response_url": "https://hooks.slack.com/foo",
    }
    with patch("slash_command._post_result") as mock_post:
        resp = _handle_async(event)
    assert resp["statusCode"] == 200
    assert "Unknown command" in mock_post.call_args[0][0]


def test_handle_async_missing_keys_returns_200() -> None:
    """A malformed async payload (missing required keys) returns 200 without raising."""
    resp = _handle_async({})
    assert resp["statusCode"] == 200


def test_handle_async_exception_posts_apology() -> None:
    """An unexpected exception during dispatch posts an apology instead of raising."""
    event: dict[str, Any] = {
        "command": "/bedrock-spend",
        "text": "",
        "caller_slack_id": "U123",
        "channel_id": "",
        "response_url": "https://hooks.slack.com/foo",
    }
    with patch("slash_command._async_spend", side_effect=Exception("boom")), \
         patch("slash_command._post_result") as mock_post:
        resp = _handle_async(event)
    assert resp["statusCode"] == 200
    assert "problem" in mock_post.call_args[0][0]


# ── Admin command parsing ─────────────────────────────────────────────────────

from slash_command import (
    _parse_block_command, _parse_unblock_command, _parse_limit_command,
    _parse_duration, _parse_limit_duration, _is_admin, _apply_block, _remove_block, _set_limit,
    _validate_limit_amount, _execute_action, _handle_interact_async, _handle_interact_gateway,
    _async_admin_command,
)


def test_parse_duration_empty_returns_indefinite() -> None:
    """Empty raw duration returns (None, 'indefinitely')."""
    result = _parse_duration("")
    assert result == (None, "indefinitely")


def test_parse_duration_valid() -> None:
    """Valid duration string returns (timedelta, label)."""
    from datetime import timedelta
    result = _parse_duration("3d")
    assert result is not None
    td, label = result
    assert td == timedelta(days=3)
    assert label == "3 days"


def test_parse_duration_invalid_returns_none() -> None:
    """Unrecognised duration returns None."""
    assert _parse_duration("99z") is None


def test_parse_duration_hours_label() -> None:
    """A sub-day duration produces an hour-based label."""
    from datetime import timedelta
    result = _parse_duration("4h")
    assert result == (timedelta(hours=4), "4 hours")


def test_parse_duration_singular_hour_label() -> None:
    """A 1-hour duration produces a singular label."""
    from datetime import timedelta
    result = _parse_duration("1h")
    assert result == (timedelta(hours=1), "1 hour")


# ── _parse_limit_duration ──────────────────────────────────────────────────────

def test_parse_limit_duration_empty_returns_default() -> None:
    """Empty raw defaults to DEFAULT_LIMIT_EXPIRY_DAYS."""
    from datetime import timedelta
    from slash_command import DEFAULT_LIMIT_EXPIRY_DAYS
    result = _parse_limit_duration("")
    assert result == (timedelta(days=DEFAULT_LIMIT_EXPIRY_DAYS), f"{DEFAULT_LIMIT_EXPIRY_DAYS} days")


def test_parse_limit_duration_never() -> None:
    """'never' returns (None, 'never')."""
    assert _parse_limit_duration("never") == (None, "never")
    assert _parse_limit_duration("NEVER") == (None, "never")


def test_parse_limit_duration_days() -> None:
    """Nd parses to a day-based timedelta."""
    from datetime import timedelta
    assert _parse_limit_duration("30d") == (timedelta(days=30), "30 days")
    assert _parse_limit_duration("1d") == (timedelta(days=1), "1 day")


def test_parse_limit_duration_weeks() -> None:
    """Nw parses to a week-based timedelta."""
    from datetime import timedelta
    assert _parse_limit_duration("2w") == (timedelta(weeks=2), "2 weeks")
    assert _parse_limit_duration("1w") == (timedelta(weeks=1), "1 week")


def test_parse_limit_duration_months() -> None:
    """Nmo parses to a 30-day-unit timedelta."""
    from datetime import timedelta
    assert _parse_limit_duration("3mo") == (timedelta(days=90), "3 months")
    assert _parse_limit_duration("1mo") == (timedelta(days=30), "1 month")


def test_parse_limit_duration_invalid_returns_none() -> None:
    """Unrecognised duration string returns None."""
    assert _parse_limit_duration("99z") is None
    assert _parse_limit_duration("abc") is None
    assert _parse_limit_duration("0d") is None


def test_parse_limit_duration_rejects_huge_digit_count() -> None:
    """A 6+ digit amount is rejected before it can risk an OverflowError in timedelta()."""
    assert _parse_limit_duration("999999d") is None


# ── _parse_block_command / _parse_unblock_command ─────────────────────────────

def test_parse_block_command_no_args() -> None:
    """Block with no args posts usage and returns None."""
    with patch("slash_command._post_response_url") as mock_post:
        result = _parse_block_command([], "https://slack.com/cb")
    assert result is None
    assert "Usage" in mock_post.call_args[0][1]


def test_parse_block_command_invalid_duration() -> None:
    """Block with bad duration posts error and returns None."""
    with patch("slash_command._post_response_url") as mock_post:
        result = _parse_block_command(["alice.smith", "99z"], "https://slack.com/cb")
    assert result is None
    assert "Unknown duration" in mock_post.call_args[0][1]


def test_parse_block_command_valid_indefinite() -> None:
    """Block with just a username returns confirm blocks for indefinite duration."""
    result = _parse_block_command(["alice.smith"], "https://slack.com/cb")
    assert result is not None
    assert "indefinitely" in result[0]["text"]["text"]


def test_parse_block_command_valid_with_duration() -> None:
    """Block with a valid duration returns confirm blocks including the restore time."""
    result = _parse_block_command(["alice.smith", "1d"], "https://slack.com/cb")
    assert result is not None
    text = result[0]["text"]["text"]
    assert "1 day" in text
    assert "Access restored after" in text


def test_parse_unblock_command_no_args() -> None:
    """Unblock with no args posts usage and returns None."""
    with patch("slash_command._post_response_url") as mock_post:
        result = _parse_unblock_command([], "https://slack.com/cb")
    assert result is None
    assert "Usage" in mock_post.call_args[0][1]


def test_parse_unblock_command_valid() -> None:
    """Unblock with a username returns confirm blocks."""
    result = _parse_unblock_command(["alice.smith"], "https://slack.com/cb")
    assert result is not None
    assert "alice.smith" in result[0]["text"]["text"]


# ── _parse_limit_command ───────────────────────────────────────────────────────

def test_parse_limit_command_no_args() -> None:
    """Limit with no args posts usage."""
    with patch("slash_command._post_response_url") as mock_post:
        result = _parse_limit_command([], "https://slack.com/cb")
    assert result is None
    assert "Usage" in mock_post.call_args[0][1]


def test_parse_limit_command_invalid_amount() -> None:
    """Limit with bad amount posts error."""
    with patch("slash_command._post_response_url") as mock_post:
        result = _parse_limit_command(["alice.smith", "abc"], "https://slack.com/cb")
    assert result is None
    assert "Invalid amount" in mock_post.call_args[0][1]


@pytest.mark.parametrize(
    "raw,expected_amount",
    [("$300", 300.0), ("300", 300.0), ("$1,000", 1000.0), ("$300.50", 300.5), ("$ 300", 300.0)],
)
def test_validate_limit_amount_strips_currency_formatting(raw: str, expected_amount: float) -> None:
    """A leading $ and thousands-separator commas are stripped before parsing."""
    amount, error = _validate_limit_amount(raw)
    assert error is None
    assert amount == pytest.approx(expected_amount)


@pytest.mark.parametrize("raw", ["abc", "", "-$300", "$abc"])
def test_validate_limit_amount_rejects_unparseable(raw: str) -> None:
    """Non-numeric or non-positive input is rejected with an error message."""
    amount, error = _validate_limit_amount(raw)
    assert amount is None
    assert error is not None


@pytest.mark.parametrize("bad", ["nan", "inf", "-inf"])
def test_parse_limit_command_rejects_non_finite(bad: str) -> None:
    """nan/inf/-inf are rejected at parse time before reaching the confirmation prompt."""
    with patch("slash_command._post_response_url") as mock_post:
        result = _parse_limit_command(["alice.smith", bad], "https://slack.com/cb")
    assert result is None
    assert mock_post.call_args is not None


def test_parse_limit_command_valid() -> None:
    """Limit with valid username+amount returns confirm blocks."""
    result = _parse_limit_command(["alice.smith", "300"], "https://slack.com/cb")
    assert result is not None
    text = result[0]["text"]["text"]
    assert "alice.smith" in text
    assert "$300" in text


def test_parse_limit_command_defaults_to_30_days() -> None:
    """Limit with no duration arg defaults to DEFAULT_LIMIT_EXPIRY_DAYS."""
    from slash_command import DEFAULT_LIMIT_EXPIRY_DAYS
    result = _parse_limit_command(["alice.smith", "300"], "https://slack.com/cb")
    assert result is not None
    text = result[0]["text"]["text"]
    assert f"{DEFAULT_LIMIT_EXPIRY_DAYS} days" in text


def test_parse_limit_command_explicit_duration() -> None:
    """Limit with an explicit duration uses that instead of the default."""
    result = _parse_limit_command(["alice.smith", "300", "90d"], "https://slack.com/cb")
    assert result is not None
    text = result[0]["text"]["text"]
    assert "90 days" in text


def test_parse_limit_command_never_expires() -> None:
    """Limit with 'never' duration omits the revert note."""
    result = _parse_limit_command(["alice.smith", "300", "never"], "https://slack.com/cb")
    assert result is not None
    text = result[0]["text"]["text"]
    assert "never" in text
    assert "Reverts to default" not in text


def test_parse_limit_command_with_jira_ticket() -> None:
    """Limit with a valid Jira ticket includes it in the confirmation and payload."""
    result = _parse_limit_command(["alice.smith", "300", "30d", "TICKET-1234"], "https://slack.com/cb")
    assert result is not None
    text = result[0]["text"]["text"]
    assert "TICKET-1234" in text
    button_value = json.loads(result[1]["elements"][0]["value"])
    assert button_value["jira_ticket"] == "TICKET-1234"


def test_parse_limit_command_without_jira_ticket_is_none() -> None:
    """Limit without a Jira ticket arg has jira_ticket=None in the payload and no ticket line."""
    result = _parse_limit_command(["alice.smith", "300", "30d"], "https://slack.com/cb")
    assert result is not None
    text = result[0]["text"]["text"]
    assert "Jira ticket" not in text
    button_value = json.loads(result[1]["elements"][0]["value"])
    assert button_value["jira_ticket"] is None


def test_parse_limit_command_jira_ticket_normalized_to_uppercase() -> None:
    """A lowercase Jira ticket is normalized to uppercase."""
    result = _parse_limit_command(["alice.smith", "300", "30d", "ticket-1234"], "https://slack.com/cb")
    assert result is not None
    text = result[0]["text"]["text"]
    assert "TICKET-1234" in text


def test_parse_limit_command_invalid_jira_ticket_rejected() -> None:
    """An invalid Jira ticket format posts an error and returns None."""
    with patch("slash_command._post_response_url") as mock_post:
        result = _parse_limit_command(["alice.smith", "300", "30d", "notaticket"], "https://slack.com/cb")
    assert result is None
    assert "Invalid Jira ticket" in mock_post.call_args[0][1]


def test_parse_limit_command_extra_args_after_jira_ticket_rejected() -> None:
    """A space-separated ticket (e.g. 'TICKET 1234') is rejected as an extra arg, not silently dropped."""
    with patch("slash_command._post_response_url") as mock_post:
        result = _parse_limit_command(["alice.smith", "300", "30d", "TICKET", "1234"], "https://slack.com/cb")
    assert result is None
    assert "Unexpected extra argument" in mock_post.call_args[0][1]


def test_parse_limit_command_invalid_duration() -> None:
    """Limit with bad duration posts error."""
    with patch("slash_command._post_response_url") as mock_post:
        result = _parse_limit_command(["alice.smith", "300", "99z"], "https://slack.com/cb")
    assert result is None
    assert "Unknown duration" in mock_post.call_args[0][1]


def test_parse_limit_command_huge_duration_rejected_cleanly() -> None:
    """A 6+ digit duration is rejected with a normal error, not an OverflowError."""
    with patch("slash_command._post_response_url") as mock_post:
        result = _parse_limit_command(["alice.smith", "300", "999999d"], "https://slack.com/cb")
    assert result is None
    assert "Unknown duration" in mock_post.call_args[0][1]


def test_parse_limit_command_rejects_above_ceiling() -> None:
    """An amount above MAX_SETTABLE_LIMIT is rejected with a ceiling-specific message."""
    from slash_command import MAX_SETTABLE_LIMIT
    with patch("slash_command._post_response_url") as mock_post:
        result = _parse_limit_command(["alice.smith", str(MAX_SETTABLE_LIMIT + 1)], "https://slack.com/cb")
    assert result is None
    assert "exceeds the maximum settable daily limit" in mock_post.call_args[0][1]


def test_parse_limit_command_allows_at_ceiling() -> None:
    """An amount exactly at MAX_SETTABLE_LIMIT is allowed."""
    from slash_command import MAX_SETTABLE_LIMIT
    result = _parse_limit_command(["alice.smith", str(MAX_SETTABLE_LIMIT)], "https://slack.com/cb")
    assert result is not None


# ── _is_admin ──────────────────────────────────────────────────────────────────

def test_is_admin_true(monkeypatch: pytest.MonkeyPatch) -> None:
    """A Slack ID in ADMIN_SLACK_IDS is recognized as admin."""
    monkeypatch.setenv("ADMIN_SLACK_IDS", "U123,U456")
    assert _is_admin("U123") is True


def test_is_admin_false(monkeypatch: pytest.MonkeyPatch) -> None:
    """A Slack ID not in ADMIN_SLACK_IDS is not admin."""
    monkeypatch.setenv("ADMIN_SLACK_IDS", "U123,U456")
    assert _is_admin("U999") is False


def test_is_admin_empty_env(monkeypatch: pytest.MonkeyPatch) -> None:
    """Empty ADMIN_SLACK_IDS means nobody is admin."""
    monkeypatch.delenv("ADMIN_SLACK_IDS", raising=False)
    assert _is_admin("U123") is False


# ── _apply_block / _remove_block / _set_limit ─────────────────────────────────

def test_apply_block_with_duration() -> None:
    """Applying a block with until_iso writes manual_block and blocked_until."""
    mock_table = MagicMock()
    with patch("slash_command._dynamodb_resource") as mock_ddb:
        mock_ddb.Table.return_value = mock_table
        _apply_block("alice.smith", "2026-01-01T00:00:00+00:00")
    call = mock_table.update_item.call_args[1]
    assert call["Key"] == {"user_id": "alice.smith"}
    assert "blocked_until" in call["UpdateExpression"]
    assert call["ExpressionAttributeValues"][":u"] == "2026-01-01T00:00:00+00:00"


def test_apply_block_indefinite_removes_blocked_until() -> None:
    """Applying an indefinite block (until_iso=None) removes any prior blocked_until."""
    mock_table = MagicMock()
    with patch("slash_command._dynamodb_resource") as mock_ddb:
        mock_ddb.Table.return_value = mock_table
        _apply_block("alice.smith", None)
    call = mock_table.update_item.call_args[1]
    assert "REMOVE blocked_until" in call["UpdateExpression"]


def test_remove_block() -> None:
    """Removing a block clears manual_block and blocked_until."""
    mock_table = MagicMock()
    with patch("slash_command._dynamodb_resource") as mock_ddb:
        mock_ddb.Table.return_value = mock_table
        _remove_block("alice.smith")
    call = mock_table.update_item.call_args[1]
    assert call["Key"] == {"user_id": "alice.smith"}
    assert "REMOVE manual_block, blocked_until" in call["UpdateExpression"]


def test_set_limit_with_expiry() -> None:
    """Setting a limit with an expiry writes daily_limit_usd, granted_by, granted_at, limit_expires_at."""
    mock_table = MagicMock()
    with patch("slash_command._dynamodb_resource") as mock_ddb:
        mock_ddb.Table.return_value = mock_table
        _set_limit("alice.smith", 300.0, "U_ADMIN", expires_at="2026-01-01T00:00:00+00:00")
    call = mock_table.update_item.call_args[1]
    assert call["Key"] == {"user_id": "alice.smith"}
    assert call["ExpressionAttributeValues"][":v"] == "300.0"
    assert call["ExpressionAttributeValues"][":by"] == "U_ADMIN"
    assert "limit_expires_at" in call["UpdateExpression"]


def test_set_limit_never_expires_removes_prior_expiry() -> None:
    """Setting a limit with no expiry (never) removes any prior limit_expires_at."""
    mock_table = MagicMock()
    with patch("slash_command._dynamodb_resource") as mock_ddb:
        mock_ddb.Table.return_value = mock_table
        _set_limit("alice.smith", 300.0, "U_ADMIN", expires_at=None)
    call = mock_table.update_item.call_args[1]
    assert "REMOVE limit_expires_at" in call["UpdateExpression"]


def test_set_limit_with_jira_ticket() -> None:
    """Setting a limit with a jira_ticket writes it alongside the limit."""
    mock_table = MagicMock()
    with patch("slash_command._dynamodb_resource") as mock_ddb:
        mock_ddb.Table.return_value = mock_table
        _set_limit("alice.smith", 300.0, "U_ADMIN", jira_ticket="TICKET-1234")
    call = mock_table.update_item.call_args[1]
    assert call["ExpressionAttributeValues"][":ticket"] == "TICKET-1234"
    assert "jira_ticket" in call["UpdateExpression"]


def test_set_limit_without_jira_ticket_removes_prior() -> None:
    """Setting a limit without a jira_ticket removes any prior ticket."""
    mock_table = MagicMock()
    with patch("slash_command._dynamodb_resource") as mock_ddb:
        mock_ddb.Table.return_value = mock_table
        _set_limit("alice.smith", 300.0, "U_ADMIN")
    call = mock_table.update_item.call_args[1]
    assert "REMOVE" in call["UpdateExpression"]
    assert "jira_ticket" in call["UpdateExpression"]


# ── _execute_action ────────────────────────────────────────────────────────────

def test_execute_action_block() -> None:
    """Executing a block action calls _apply_block and posts a confirmation."""
    with patch("slash_command._apply_block") as mock_apply, \
         patch("slash_command._invoke_enforcement_lambda"), \
         patch("slash_command._post_result") as mock_post:
        _execute_action(
            "block", "alice.smith", {"until_iso": None, "label": "indefinitely"},
            "https://cb", "C1", "U_ADMIN",
        )
    mock_apply.assert_called_once_with("alice.smith", None)
    assert "blocked" in mock_post.call_args[0][0]


def test_execute_action_unblock() -> None:
    """Executing an unblock action calls _remove_block and posts a confirmation."""
    with patch("slash_command._remove_block") as mock_remove, \
         patch("slash_command._invoke_enforcement_lambda"), \
         patch("slash_command._post_result") as mock_post:
        _execute_action("unblock", "alice.smith", {}, "https://cb", "C1", "U_ADMIN")
    mock_remove.assert_called_once_with("alice.smith")
    assert "lifted" in mock_post.call_args[0][0]


def test_execute_action_limit() -> None:
    """Executing a limit action calls _set_limit and posts a confirmation."""
    with patch("slash_command._set_limit") as mock_set, \
         patch("slash_command._post_result") as mock_post:
        _execute_action(
            "limit", "alice.smith",
            {"amount": 300.0, "expires_at": "2026-01-01T00:00:00+00:00", "duration_label": "30 days"},
            "https://cb", "C1", "U_ADMIN",
        )
    mock_set.assert_called_once_with(
        "alice.smith", 300.0, "U_ADMIN", "2026-01-01T00:00:00+00:00", None
    )
    assert "$300" in mock_post.call_args[0][0]


def test_execute_action_limit_never_expires() -> None:
    """A limit action with no expires_at posts a 'does not expire' message."""
    with patch("slash_command._set_limit"), \
         patch("slash_command._post_result") as mock_post:
        _execute_action(
            "limit", "alice.smith", {"amount": 300.0, "expires_at": None},
            "https://cb", "C1", "U_ADMIN",
        )
    assert "does not expire" in mock_post.call_args[0][0]


def test_execute_action_limit_with_jira_ticket() -> None:
    """A limit action with a jira_ticket includes it in the confirmation message."""
    with patch("slash_command._set_limit") as mock_set, \
         patch("slash_command._post_result") as mock_post:
        _execute_action(
            "limit", "alice.smith",
            {"amount": 300.0, "expires_at": None, "jira_ticket": "TICKET-1234"},
            "https://cb", "C1", "U_ADMIN",
        )
    mock_set.assert_called_once_with("alice.smith", 300.0, "U_ADMIN", None, "TICKET-1234")
    assert "TICKET-1234" in mock_post.call_args[0][0]


def test_execute_action_limit_rejects_forged_amount_at_execution() -> None:
    """A tampered/replayed button value carrying an above-ceiling amount is rejected
    at execution time even though it already passed parse-time validation once."""
    from slash_command import MAX_SETTABLE_LIMIT
    with patch("slash_command._set_limit") as mock_set, \
         patch("slash_command._post_result") as mock_post:
        _execute_action(
            "limit", "alice.smith", {"amount": MAX_SETTABLE_LIMIT + 500},
            "https://cb", "C1", "U_ADMIN",
        )
    mock_set.assert_not_called()
    assert "exceeds the maximum settable daily limit" in mock_post.call_args[0][0]


def test_execute_action_limit_rejects_forged_nan_at_execution() -> None:
    """A tampered button value carrying amount='nan' is rejected, not written to DynamoDB."""
    with patch("slash_command._set_limit") as mock_set, \
         patch("slash_command._post_result") as mock_post:
        _execute_action("limit", "alice.smith", {"amount": "nan"}, "https://cb", "C1", "U_ADMIN")
    mock_set.assert_not_called()
    assert "Invalid amount" in mock_post.call_args[0][0]


def test_execute_action_unknown() -> None:
    """An unrecognised action posts a fallback message."""
    with patch("slash_command._post_result") as mock_post:
        _execute_action("mystery", "alice.smith", {}, "https://cb", "C1", "U_ADMIN")
    assert "Unrecognised action" in mock_post.call_args[0][0]


# ── _handle_interact_gateway / _handle_interact_async ─────────────────────────

def test_handle_interact_gateway_valid_signature(monkeypatch: pytest.MonkeyPatch) -> None:
    """A valid signature on an interact payload self-invokes async and acks."""
    monkeypatch.setenv("SLACK_SIGNING_SECRET", "testsecret")
    payload = json.dumps({
        "actions": [{"action_id": "confirm_action", "value": "{}"}],
        "user": {"id": "U_ADMIN"},
        "channel": {"id": "C1"},
        "response_url": "https://cb",
    })
    body = f"payload={payload}"
    ts = str(int(time.time()))
    sig = _make_signature("testsecret", ts, body)
    event = {
        "body": body,
        "headers": {"X-Slack-Signature": sig, "X-Slack-Request-Timestamp": ts},
        "isBase64Encoded": False,
    }
    with patch("slash_command._lambda_client") as mock_lambda:
        resp = _handle_interact_gateway(event)
    assert resp["statusCode"] == 200
    mock_lambda.invoke.assert_called_once()


def test_handle_interact_gateway_invalid_signature(monkeypatch: pytest.MonkeyPatch) -> None:
    """An invalid signature on an interact payload returns 403."""
    monkeypatch.setenv("SLACK_SIGNING_SECRET", "testsecret")
    event = {
        "body": "payload=%7B%7D",
        "headers": {"X-Slack-Signature": "v0=bad", "X-Slack-Request-Timestamp": str(int(time.time()))},
        "isBase64Encoded": False,
    }
    resp = _handle_interact_gateway(event)
    assert resp["statusCode"] == 403


def test_handle_interact_async_cancel_action_no_op() -> None:
    """A cancel_action does nothing (the interaction gateway already ACKed) and returns 200."""
    event = {
        "action_id": "cancel_action",
        "value": "cancel",
        "caller_slack_id": "U_ADMIN",
        "channel_id": "C1",
        "response_url": "",
    }
    with patch("slash_command._post_result") as mock_post:
        resp = _handle_interact_async(event)
    assert resp["statusCode"] == 200
    mock_post.assert_not_called()


def test_handle_interact_async_non_admin_rejected() -> None:
    """A non-admin caller confirming an action gets a permission-denied message."""
    event = {
        "action_id": "confirm_action",
        "value": json.dumps({"action": "block", "username": "alice.smith"}),
        "caller_slack_id": "U_NOTADMIN",
        "channel_id": "C1",
        "response_url": "https://cb",
    }
    with patch("slash_command._is_admin", return_value=False), \
         patch("slash_command._post_result") as mock_post:
        resp = _handle_interact_async(event)
    assert resp["statusCode"] == 200
    assert "administrators" in mock_post.call_args[0][0]


def test_handle_interact_async_invalid_json_value() -> None:
    """A malformed JSON value posts an error instead of crashing."""
    event = {
        "action_id": "confirm_action",
        "value": "not-json",
        "caller_slack_id": "U_ADMIN",
        "channel_id": "C1",
        "response_url": "https://cb",
    }
    with patch("slash_command._is_admin", return_value=True), \
         patch("slash_command._post_result") as mock_post:
        resp = _handle_interact_async(event)
    assert resp["statusCode"] == 200
    assert "went wrong" in mock_post.call_args[0][0]


def test_handle_interact_async_missing_keys_returns_200() -> None:
    """A malformed interact_async payload (missing required keys) returns 200 without raising."""
    resp = _handle_interact_async({})
    assert resp["statusCode"] == 200


def test_handle_interact_async_executes_valid_action() -> None:
    """A valid confirm_action from an admin dispatches to _execute_action."""
    event = {
        "action_id": "confirm_action",
        "value": json.dumps({"action": "unblock", "username": "alice.smith"}),
        "caller_slack_id": "U_ADMIN",
        "channel_id": "C1",
        "response_url": "https://cb",
    }
    with patch("slash_command._is_admin", return_value=True), \
         patch("slash_command._execute_action") as mock_exec:
        resp = _handle_interact_async(event)
    assert resp["statusCode"] == 200
    mock_exec.assert_called_once()


def test_async_admin_command_non_admin_rejected() -> None:
    """A non-admin caller running an admin slash command gets a permission-denied message."""
    with patch("slash_command._is_admin", return_value=False), \
         patch("slash_command._post_response_url") as mock_post:
        resp = _async_admin_command("/bedrock-block", "alice.smith", "U_NOTADMIN", "C1", "https://cb")
    assert resp["statusCode"] == 200
    assert "administrators" in mock_post.call_args[0][1]


def test_async_admin_command_posts_confirmation() -> None:
    """A valid admin command posts a Block Kit confirmation via chat_postEphemeral."""
    with patch("slash_command._is_admin", return_value=True), \
         patch("slash_command.WebClient") as mock_webclient_cls, \
         patch.dict(os.environ, {"SLACK_BOT_TOKEN": "test-token"}):
        mock_client = MagicMock()
        mock_webclient_cls.return_value = mock_client
        resp = _async_admin_command("/bedrock-unblock", "alice.smith", "U_ADMIN", "C1", "https://cb")
    assert resp["statusCode"] == 200
    mock_client.chat_postEphemeral.assert_called_once()


def test_async_admin_command_confirmation_post_failure() -> None:
    """If posting the confirmation prompt fails, an error is posted via response_url."""
    with patch("slash_command._is_admin", return_value=True), \
         patch("slash_command.WebClient") as mock_webclient_cls, \
         patch("slash_command._post_response_url") as mock_post_resp, \
         patch.dict(os.environ, {"SLACK_BOT_TOKEN": "test-token"}):
        mock_client = MagicMock()
        mock_client.chat_postEphemeral.side_effect = Exception("boom")
        mock_webclient_cls.return_value = mock_client
        resp = _async_admin_command("/bedrock-unblock", "alice.smith", "U_ADMIN", "C1", "https://cb")
    assert resp["statusCode"] == 200
    assert "Failed to show confirmation" in mock_post_resp.call_args[0][1]


# ── _resolve_username ──────────────────────────────────────────────────────────

def test_resolve_username_success() -> None:
    """A successful users_info call returns the username portion of the email."""
    with patch("slash_command.WebClient") as mock_webclient_cls, \
         patch.dict(os.environ, {"SLACK_BOT_TOKEN": "test-token"}):
        mock_client = MagicMock()
        mock_client.users_info.return_value = {"user": {"profile": {"email": "alice.smith@example.com"}}}
        mock_webclient_cls.return_value = mock_client
        assert _resolve_username("U123") == "alice.smith"


def test_resolve_username_failure_returns_none() -> None:
    """An exception during lookup returns None instead of raising."""
    with patch("slash_command.WebClient") as mock_webclient_cls, \
         patch.dict(os.environ, {"SLACK_BOT_TOKEN": "test-token"}):
        mock_client = MagicMock()
        mock_client.users_info.side_effect = Exception("boom")
        mock_webclient_cls.return_value = mock_client
        assert _resolve_username("U123") is None


# ── New helper coverage ───────────────────────────────────────────────────────

from slash_command import (
    _run_validated_action, _decode_request, _dispatch_interact,
    _dispatch_confirmed_action, _post_result, _post_ephemeral_api,
)


def test_run_validated_action_bad_json() -> None:
    """Bad JSON in value posts error and returns without crashing."""
    with patch("slash_command._post_response_url") as mock_post:
        _run_validated_action("not-json", "https://cb", "", "U123ADMIN")
    assert "went wrong" in mock_post.call_args[0][1]


def test_run_validated_action_invalid_username() -> None:
    """Invalid username in parsed value is rejected."""
    with patch("slash_command._post_response_url") as mock_post:
        _run_validated_action(
            json.dumps({"action": "block", "username": "pedro"}), "https://cb", "", "U123ADMIN"
        )
    assert "Invalid username" in mock_post.call_args[0][1]


def test_run_validated_action_executes_valid() -> None:
    """Valid payload calls _execute_action, threading the granting admin's id through."""
    with patch("slash_command._execute_action") as mock_exec:
        _run_validated_action(
            json.dumps({"action": "block", "username": "alice.smith"}), "https://cb", "", "U123ADMIN"
        )
    mock_exec.assert_called_once_with(
        "block", "alice.smith", {"action": "block", "username": "alice.smith"}, "https://cb", "", "U123ADMIN"
    )


def test_run_validated_action_execute_exception_posts_apology() -> None:
    """An exception inside _execute_action is caught and posts an apology."""
    with patch("slash_command._execute_action", side_effect=Exception("boom")), \
         patch("slash_command._post_result") as mock_post:
        _run_validated_action(
            json.dumps({"action": "block", "username": "alice.smith"}), "https://cb", "", "U123ADMIN"
        )
    assert "problem executing" in mock_post.call_args[0][0]


def test_decode_request_base64() -> None:
    """A base64-encoded event body is decoded and headers are lowercased."""
    import base64
    body = "payload=%7B%7D"
    encoded = base64.b64encode(body.encode()).decode()
    raw_body, headers = _decode_request(
        {"body": encoded, "isBase64Encoded": True, "headers": {"X-Foo": "bar"}}
    )
    assert raw_body == body
    assert headers == {"x-foo": "bar"}


def test_decode_request_plain() -> None:
    """A plain (non-base64) event body passes through unchanged."""
    raw_body, headers = _decode_request(
        {"body": "payload=%7B%7D", "isBase64Encoded": False, "headers": {}}
    )
    assert raw_body == "payload=%7B%7D"
    assert headers == {}


def test_dispatch_interact_no_actions_acks() -> None:
    """A payload with no actions returns a plain ack without invoking anything."""
    payload = json.dumps({"actions": []})
    with patch("slash_command._lambda_client") as mock_lambda:
        resp = _dispatch_interact(f"payload={payload}")
    assert resp["statusCode"] == 200
    mock_lambda.invoke.assert_not_called()


def test_dispatch_interact_invalid_json_returns_400() -> None:
    """Malformed JSON in the payload param returns 400."""
    resp = _dispatch_interact("payload=not-json")
    assert resp["statusCode"] == 400


def test_dispatch_interact_invokes_async() -> None:
    """A well-formed action payload self-invokes interact_async mode."""
    payload = json.dumps({
        "actions": [{"action_id": "confirm_action", "value": "{}"}],
        "user": {"id": "U_ADMIN"},
        "channel": {"id": "C1"},
        "response_url": "https://cb",
    })
    with patch("slash_command._lambda_client") as mock_lambda:
        resp = _dispatch_interact(f"payload={payload}")
    assert resp["statusCode"] == 200
    mock_lambda.invoke.assert_called_once()
    call_payload = json.loads(mock_lambda.invoke.call_args[1]["Payload"])
    assert call_payload["mode"] == "interact_async"


def test_dispatch_interact_invoke_failure_returns_ephemeral() -> None:
    """If self-invoke fails, an ephemeral error is returned instead of raising."""
    payload = json.dumps({
        "actions": [{"action_id": "confirm_action", "value": "{}"}],
        "user": {"id": "U_ADMIN"},
    })
    with patch("slash_command._lambda_client") as mock_lambda:
        mock_lambda.invoke.side_effect = Exception("boom")
        resp = _dispatch_interact(f"payload={payload}")
    assert resp["statusCode"] == 200
    assert "problem dispatching" in resp["body"]


def test_dispatch_confirmed_action_cancel_via_value() -> None:
    """A cancel via value='cancel' (even with a different action_id) is a no-op."""
    with patch("slash_command._post_result") as mock_post:
        _dispatch_confirmed_action("some_id", "cancel", "U_ADMIN", "C1", "https://cb")
    mock_post.assert_not_called()


def test_dispatch_confirmed_action_non_admin() -> None:
    """A non-admin caller confirming any action gets a permission-denied message."""
    with patch("slash_command._is_admin", return_value=False), \
         patch("slash_command._post_result") as mock_post:
        _dispatch_confirmed_action("confirm_action", "{}", "U_NOTADMIN", "C1", "https://cb")
    assert "administrators" in mock_post.call_args[0][0]


def test_post_result_prefers_ephemeral_api_when_channel_present() -> None:
    """When channel_id+user_id are present, _post_ephemeral_api is used over response_url."""
    with patch("slash_command._post_ephemeral_api") as mock_api, \
         patch("slash_command._post_response_url") as mock_url:
        _post_result("hello", "https://cb", "C1", "U1")
    mock_api.assert_called_once_with("C1", "U1", "hello")
    mock_url.assert_not_called()


def test_post_result_falls_back_to_response_url() -> None:
    """When channel_id is absent, _post_response_url is used instead."""
    with patch("slash_command._post_ephemeral_api") as mock_api, \
         patch("slash_command._post_response_url") as mock_url:
        _post_result("hello", "https://cb", "", "")
    mock_api.assert_not_called()
    mock_url.assert_called_once_with("https://cb", "hello")


def test_post_result_no_delivery_path_logs_warning() -> None:
    """When neither channel_id nor response_url is present, nothing is posted (logged only)."""
    with patch("slash_command._post_ephemeral_api") as mock_api, \
         patch("slash_command._post_response_url") as mock_url:
        _post_result("hello", "", "", "")
    mock_api.assert_not_called()
    mock_url.assert_not_called()


def test_post_ephemeral_api_missing_token_logs_error() -> None:
    """Missing SLACK_BOT_TOKEN skips the API call and logs an error instead of a silent not_authed."""
    with patch.dict(os.environ, {}, clear=True), \
         patch("slash_command.WebClient") as mock_webclient_cls:
        _post_ephemeral_api("C1", "U1", "hello")
    mock_webclient_cls.assert_not_called()


def test_post_ephemeral_api_success() -> None:
    """A configured token calls chat_postEphemeral with the right args."""
    with patch.dict(os.environ, {"SLACK_BOT_TOKEN": "test-token"}), \
         patch("slash_command.WebClient") as mock_webclient_cls:
        mock_client = MagicMock()
        mock_webclient_cls.return_value = mock_client
        _post_ephemeral_api("C1", "U1", "hello")
    mock_client.chat_postEphemeral.assert_called_once_with(channel="C1", user="U1", text="hello")


def test_post_ephemeral_api_exception_is_caught() -> None:
    """An exception from chat_postEphemeral is caught, not raised."""
    with patch.dict(os.environ, {"SLACK_BOT_TOKEN": "test-token"}), \
         patch("slash_command.WebClient") as mock_webclient_cls:
        mock_client = MagicMock()
        mock_client.chat_postEphemeral.side_effect = Exception("boom")
        mock_webclient_cls.return_value = mock_client
        # must not raise
        _post_ephemeral_api("C1", "U1", "hello")
