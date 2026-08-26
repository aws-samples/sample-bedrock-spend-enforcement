# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
import sys
import os
from unittest.mock import patch

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from handler import calculate_notification_tier, _notify_if_new_tier


# ── calculate_notification_tier ───────────────────────────────────────────────

def test_tier_none_below_70() -> None:
    """Spend below 70% returns None — no notification."""
    assert calculate_notification_tier(100.0, 150.0) is None


def test_tier_warn_at_70() -> None:
    """Spend exactly at 70% returns warn tier."""
    assert calculate_notification_tier(105.0, 150.0) == "warn"


def test_tier_warn_between_70_and_80() -> None:
    """Spend between 70% and 80% returns warn tier."""
    assert calculate_notification_tier(110.0, 150.0) == "warn"


def test_tier_t1_at_80() -> None:
    """Spend exactly at 80% returns t1 tier."""
    assert calculate_notification_tier(120.0, 150.0) == "t1"


def test_tier_t1_between_80_and_100() -> None:
    """Spend between 80% and 100% returns t1 tier."""
    assert calculate_notification_tier(140.0, 150.0) == "t1"


def test_tier_t2_at_100() -> None:
    """Spend at the daily limit returns t2 tier."""
    assert calculate_notification_tier(150.0, 150.0) == "t2"


def test_tier_t2_above_100() -> None:
    """Spend above the daily limit returns t2 tier."""
    assert calculate_notification_tier(200.0, 150.0) == "t2"


def test_tier_scales_with_custom_limit() -> None:
    """Custom limit scales all tier boundaries proportionally."""
    assert calculate_notification_tier(200.0, 300.0) is None
    assert calculate_notification_tier(210.0, 300.0) == "warn"
    assert calculate_notification_tier(240.0, 300.0) == "t1"
    assert calculate_notification_tier(300.0, 300.0) == "t2"


# ── _notify_if_new_tier ───────────────────────────────────────────────────────

def test_no_notification_without_slack_token(monkeypatch: pytest.MonkeyPatch) -> None:
    """No DM is sent and notified_tiers is unchanged when SLACK_BOT_TOKEN is absent."""
    monkeypatch.delenv("SLACK_BOT_TOKEN", raising=False)
    with patch("notifier.send_dm") as mock_dm:
        result = _notify_if_new_tier("alice", 105.0, 150.0, set())
    mock_dm.assert_not_called()
    assert result == set()


def test_sends_warn_dm_on_first_cross(monkeypatch: pytest.MonkeyPatch) -> None:
    """Sends a warn DM when user first crosses 70% with no prior notifications."""
    monkeypatch.setenv("SLACK_BOT_TOKEN", "test-token")
    with patch("notifier.send_dm") as mock_dm, \
         patch("notifier.spend_warning_text", return_value="warn text"):
        result = _notify_if_new_tier("alice", 105.0, 150.0, set())
    mock_dm.assert_called_once_with("alice", "warn text")
    assert "warn" in result


def test_sends_t1_and_warn_when_jumping_to_t1(monkeypatch: pytest.MonkeyPatch) -> None:
    """Sends both warn and t1 DMs when user jumps straight to 80% with no prior notifications."""
    monkeypatch.setenv("SLACK_BOT_TOKEN", "test-token")
    with patch("notifier.send_dm") as mock_dm, \
         patch("notifier.spend_warning_text", return_value="warn text"), \
         patch("notifier.t1_blocked_text", return_value="t1 text"):
        result = _notify_if_new_tier("alice", 125.0, 150.0, set())
    assert mock_dm.call_count == 2
    assert "warn" in result
    assert "t1" in result


def test_no_duplicate_warn_dm(monkeypatch: pytest.MonkeyPatch) -> None:
    """Does not resend warn DM if already notified."""
    monkeypatch.setenv("SLACK_BOT_TOKEN", "test-token")
    with patch("notifier.send_dm") as mock_dm:
        result = _notify_if_new_tier("alice", 110.0, 150.0, {"warn"})
    mock_dm.assert_not_called()
    assert result == {"warn"}


def test_sends_t1_when_warn_already_sent(monkeypatch: pytest.MonkeyPatch) -> None:
    """Only sends t1 DM when warn was already sent."""
    monkeypatch.setenv("SLACK_BOT_TOKEN", "test-token")
    with patch("notifier.send_dm") as mock_dm, \
         patch("notifier.t1_blocked_text", return_value="t1 text"):
        result = _notify_if_new_tier("alice", 125.0, 150.0, {"warn"})
    mock_dm.assert_called_once_with("alice", "t1 text")
    assert result == {"warn", "t1"}


def test_resets_notified_tiers_below_70(monkeypatch: pytest.MonkeyPatch) -> None:
    """Clears notified_tiers when spend drops back below 70% (daily reset)."""
    monkeypatch.setenv("SLACK_BOT_TOKEN", "test-token")
    with patch("notifier.send_dm"):
        result = _notify_if_new_tier("alice", 50.0, 150.0, {"warn", "t1"})
    assert result == set()


def test_all_three_tiers_sent_on_first_t2(monkeypatch: pytest.MonkeyPatch) -> None:
    """Sends warn, t1, and t2 DMs when user jumps straight to 100% with no prior notifications."""
    monkeypatch.setenv("SLACK_BOT_TOKEN", "test-token")
    with patch("notifier.send_dm") as mock_dm, \
         patch("notifier.spend_warning_text", return_value="warn"), \
         patch("notifier.t1_blocked_text", return_value="t1"), \
         patch("notifier.t2_blocked_text", return_value="t2"):
        result = _notify_if_new_tier("alice", 160.0, 150.0, set())
    assert mock_dm.call_count == 3
    assert result == {"warn", "t1", "t2"}


def test_message_builders_called_with_no_address_argument(monkeypatch: pytest.MonkeyPatch) -> None:
    """Tier message builders are called with just (spend, limit) — no honorific/address parameter."""
    monkeypatch.setenv("SLACK_BOT_TOKEN", "test-token")
    with patch("notifier.send_dm"), \
         patch("notifier.spend_warning_text", return_value="w") as mock_warn, \
         patch("notifier.t1_blocked_text", return_value="t1"):
        _notify_if_new_tier("alice", 125.0, 150.0, set())
    mock_warn.assert_called_once_with(125.0, 150.0)
