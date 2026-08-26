# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from handler import calculate_required_denies

# Threshold logic. Reset is handled by the cost view's daily window (it only
# returns today's spend), so there is no should_reset() to test anymore.


def test_below_t1_no_denies() -> None:
    """Spend below the T1 threshold produces no denies."""
    assert calculate_required_denies(100.0, 150.0) == []


def test_at_t1_deny_opus() -> None:
    """Spend exactly at the T1 threshold denies Opus."""
    assert calculate_required_denies(120.0, 150.0) == ["opus"]


def test_above_t1_below_t2_deny_opus_only() -> None:
    """Spend between T1 and T2 denies only Opus, not Sonnet."""
    assert calculate_required_denies(140.0, 150.0) == ["opus"]


def test_at_t2_deny_opus_and_sonnet() -> None:
    """Spend exactly at the T2 threshold denies both Opus and Sonnet."""
    assert calculate_required_denies(150.0, 150.0) == ["opus", "sonnet"]


def test_above_t2_deny_opus_and_sonnet() -> None:
    """Spend over the T2 threshold denies both Opus and Sonnet."""
    assert calculate_required_denies(200.0, 150.0) == ["opus", "sonnet"]


def test_zero_spend_no_denies() -> None:
    """After the 0400 reset the view returns ~0 for a user; they must be un-denied."""
    assert calculate_required_denies(0.0, 150.0) == []


def test_custom_limit_scales_thresholds() -> None:
    """A custom daily limit scales both T1 and T2 thresholds proportionally."""
    # custom $300 limit — T1 at $240, T2 at $300
    assert calculate_required_denies(230.0, 300.0) == []
    assert calculate_required_denies(240.0, 300.0) == ["opus"]
    assert calculate_required_denies(300.0, 300.0) == ["opus", "sonnet"]
