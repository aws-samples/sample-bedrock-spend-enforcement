# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
import sys
import os
from unittest.mock import MagicMock, patch

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from notifier import (
    spend_warning_text,
    t1_blocked_text,
    t2_blocked_text,
    slash_command_text,
)


def test_spend_warning_text_contains_spend() -> None:
    """70% warning includes the actual spend amount."""
    text = spend_warning_text(105.0, 150.0)
    assert "$105.00" in text


def test_t1_blocked_text_contains_spend() -> None:
    """T1 message includes the actual spend amount."""
    text = t1_blocked_text(120.0, 150.0)
    assert "$120.00" in text


def test_t2_blocked_text_contains_spend() -> None:
    """T2 message includes the actual spend amount."""
    text = t2_blocked_text(150.0, 150.0)
    assert "$150.00" in text


def test_slash_command_text_under_70() -> None:
    """Under 70% shows all models available."""
    text = slash_command_text(50.0, 150.0)
    assert "Opus, Sonnet, and Haiku" in text
    assert "Nothing to report" in text


def test_slash_command_text_warn_tier() -> None:
    """70-80% shows warning with thresholds."""
    text = slash_command_text(110.0, 150.0)
    assert "$110.00" in text
    assert "Haiku is never restricted" in text


def test_slash_command_text_t1_tier() -> None:
    """80-100% shows Opus withdrawn."""
    text = slash_command_text(130.0, 150.0)
    assert "$130.00" in text
    assert "Opus has been withdrawn" in text


def test_slash_command_text_t2_tier() -> None:
    """At limit shows Opus and Sonnet unavailable."""
    text = slash_command_text(150.0, 150.0)
    assert "$150.00" in text
    assert "Haiku remains" in text


def test_slash_command_text_custom_limit() -> None:
    """Custom limit scales thresholds correctly."""
    text = slash_command_text(250.0, 300.0)
    assert "$250.00" in text
    assert "Opus has been withdrawn" in text


def test_slash_command_text_zero_spend() -> None:
    """Zero spend is handled without division errors."""
    text = slash_command_text(0.0, 150.0)
    assert "0%" in text


def test_slash_command_text_includes_expiry_when_given() -> None:
    """Passing limit_expires_at appends a revert-date note."""
    text = slash_command_text(50.0, 300.0, limit_expires_at="2026-08-24T00:00:00+00:00")
    assert "2026-08-24" in text
    assert "reverts to the default" in text


def test_slash_command_text_omits_expiry_when_absent() -> None:
    """No limit_expires_at means no revert-date note."""
    text = slash_command_text(50.0, 300.0)
    assert "reverts to the default" not in text


# ── send_dm / _resolve_slack_user_id ─────────────────────────────────────────

def test_resolve_slack_user_id_returns_id(monkeypatch: pytest.MonkeyPatch) -> None:
    """Returns Slack user ID on successful email lookup."""
    monkeypatch.setenv("SLACK_BOT_TOKEN", "test-token")
    mock_client = MagicMock()
    mock_client.users_lookupByEmail.return_value = {"user": {"id": "U123ABC"}}
    with patch("slack_sdk.WebClient", return_value=mock_client):
        from notifier import _resolve_slack_user_id
        assert _resolve_slack_user_id("alice.smith") == "U123ABC"


def test_resolve_slack_user_id_returns_none_on_api_error(monkeypatch: pytest.MonkeyPatch) -> None:
    """Returns None when the Slack API call fails."""
    monkeypatch.setenv("SLACK_BOT_TOKEN", "test-token")
    from slack_sdk.errors import SlackApiError
    mock_client = MagicMock()
    mock_client.users_lookupByEmail.side_effect = SlackApiError("err", {"ok": False, "error": "users_not_found"})
    with patch("slack_sdk.WebClient", return_value=mock_client):
        from notifier import _resolve_slack_user_id
        assert _resolve_slack_user_id("nobody") is None


# ── _slack_client retry configuration ─────────────────────────────────────────


def test_slack_client_configures_rate_limit_retry_handler(monkeypatch: pytest.MonkeyPatch) -> None:
    """The Slack client is constructed with a capped RateLimitErrorRetryHandler.

    Verifying every username against Slack (not just unknown-format ones) means
    far more lookups per run — this handler lets a transient 429 retry with
    Slack's own Retry-After backoff instead of immediately giving up.
    """
    monkeypatch.setenv("SLACK_BOT_TOKEN", "test-token")
    from slack_sdk.http_retry.builtin_handlers import RateLimitErrorRetryHandler
    from notifier import _slack_client

    client = _slack_client()
    assert any(isinstance(h, RateLimitErrorRetryHandler) for h in client.retry_handlers)
    handler = next(h for h in client.retry_handlers if isinstance(h, RateLimitErrorRetryHandler))
    assert handler.max_retry_count == 2


# ── resolve_slack_id_with_status ──────────────────────────────────────────────


def test_resolve_with_status_returns_id_not_definite_not_found(monkeypatch: pytest.MonkeyPatch) -> None:
    """A successful lookup returns (slack_id, False) — found, so 'not found' is trivially false."""
    monkeypatch.setenv("SLACK_BOT_TOKEN", "test-token")
    mock_client = MagicMock()
    mock_client.users_lookupByEmail.return_value = {"user": {"id": "U123ABC"}}
    with patch("slack_sdk.WebClient", return_value=mock_client):
        from notifier import resolve_slack_id_with_status
        assert resolve_slack_id_with_status("alice.smith") == ("U123ABC", False)


def test_resolve_with_status_users_not_found_is_definite(monkeypatch: pytest.MonkeyPatch) -> None:
    """Slack's explicit 'users_not_found' error is a confirmed negative — safe to cache."""
    monkeypatch.setenv("SLACK_BOT_TOKEN", "test-token")
    from slack_sdk.errors import SlackApiError
    mock_client = MagicMock()
    mock_client.users_lookupByEmail.side_effect = SlackApiError("err", {"ok": False, "error": "users_not_found"})
    with patch("slack_sdk.WebClient", return_value=mock_client):
        from notifier import resolve_slack_id_with_status
        assert resolve_slack_id_with_status("zz.testuser") == (None, True)


def test_resolve_with_status_other_slack_error_is_not_definite(monkeypatch: pytest.MonkeyPatch) -> None:
    """A non-'users_not_found' Slack error (e.g. rate limited past retry budget) is not a confirmed negative."""
    monkeypatch.setenv("SLACK_BOT_TOKEN", "test-token")
    from slack_sdk.errors import SlackApiError
    mock_client = MagicMock()
    mock_client.users_lookupByEmail.side_effect = SlackApiError("err", {"ok": False, "error": "ratelimited"})
    with patch("slack_sdk.WebClient", return_value=mock_client):
        from notifier import resolve_slack_id_with_status
        assert resolve_slack_id_with_status("someone") == (None, False)


def test_resolve_with_status_unexpected_exception_is_not_definite(monkeypatch: pytest.MonkeyPatch) -> None:
    """A non-SlackApiError exception (network failure, etc.) is not a confirmed negative."""
    monkeypatch.setenv("SLACK_BOT_TOKEN", "test-token")
    mock_client = MagicMock()
    mock_client.users_lookupByEmail.side_effect = Exception("connection reset")
    with patch("slack_sdk.WebClient", return_value=mock_client):
        from notifier import resolve_slack_id_with_status
        assert resolve_slack_id_with_status("someone") == (None, False)


def test_send_dm_sends_message(monkeypatch: pytest.MonkeyPatch) -> None:
    """send_dm calls chat_postMessage when user is resolved."""
    monkeypatch.setenv("SLACK_BOT_TOKEN", "test-token")
    mock_client = MagicMock()
    mock_client.users_lookupByEmail.return_value = {"user": {"id": "U123ABC"}}
    with patch("slack_sdk.WebClient", return_value=mock_client):
        from notifier import send_dm
        send_dm("alice.smith", "Good morning.")
    mock_client.chat_postMessage.assert_called_once()
    call_kwargs = mock_client.chat_postMessage.call_args[1]
    assert call_kwargs["channel"] == "U123ABC"
    assert "Good morning" in call_kwargs["text"]


def test_send_dm_skips_when_user_unresolvable(monkeypatch: pytest.MonkeyPatch) -> None:
    """send_dm does nothing when the Slack user cannot be resolved."""
    monkeypatch.setenv("SLACK_BOT_TOKEN", "test-token")
    mock_client = MagicMock()
    mock_client.users_lookupByEmail.side_effect = Exception("not found")
    with patch("slack_sdk.WebClient", return_value=mock_client):
        from notifier import send_dm
        send_dm("ghost.user", "Hello?")
    mock_client.chat_postMessage.assert_not_called()


def test_send_dm_handles_post_failure(monkeypatch: pytest.MonkeyPatch) -> None:
    """send_dm logs and swallows exceptions from chat_postMessage."""
    monkeypatch.setenv("SLACK_BOT_TOKEN", "test-token")
    from slack_sdk.errors import SlackApiError
    mock_client = MagicMock()
    mock_client.users_lookupByEmail.return_value = {"user": {"id": "U123ABC"}}
    mock_client.chat_postMessage.side_effect = SlackApiError("err", {"ok": False, "error": "channel_not_found"})
    with patch("slack_sdk.WebClient", return_value=mock_client):
        from notifier import send_dm
        # should not raise
        send_dm("alice.smith", "text")
