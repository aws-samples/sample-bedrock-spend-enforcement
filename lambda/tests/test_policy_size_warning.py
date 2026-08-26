# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
import sys
import os
from unittest.mock import MagicMock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from handler import (
    write_shared_policy,
    update_shared_cmps,
    POLICY_SIZE_WARN_THRESHOLD,
    POLICY_SIZE_CRITICAL_THRESHOLD,
    MAX_POLICY_SIZE,
    OPUS_KEYWORDS,
    T1_POLICY_ARN,
)


# ── write_shared_policy warning level ─────────────────────────────────────────
#
# The CloudWatch alarm on PolicySizeOverflow (see infra/lambda.yaml) covers the
# operator-facing side of an approaching IAM size ceiling generically; these
# tests cover the size-tier classification itself (_size_warning_level, via its
# only caller write_shared_policy).

def test_write_shared_policy_returns_none_below_threshold() -> None:
    """No warning returned when policy is well under the 80% threshold."""
    mock_iam = MagicMock()
    mock_iam.list_policy_versions.return_value = {
        "Versions": [{"IsDefaultVersion": True, "VersionId": "v1", "CreateDate": "2026-01-01"}]
    }
    result = write_shared_policy(T1_POLICY_ARN, OPUS_KEYWORDS, ["alice.smith"], mock_iam)
    assert result is None


def test_write_shared_policy_returns_warn_level_between_80_and_95() -> None:
    """Warning dict with level='warn' returned when doc is between 80% and 95%.

    300 users of the form user.name-NNN produces a 5141-byte document —
    verified directly against build_shared_policy_document; falls between
    POLICY_SIZE_WARN_THRESHOLD (4915) and POLICY_SIZE_CRITICAL_THRESHOLD (5836).
    """
    mock_iam = MagicMock()
    mock_iam.list_policy_versions.return_value = {
        "Versions": [{"IsDefaultVersion": True, "VersionId": "v1", "CreateDate": "2026-01-01"}]
    }
    big_list = [f"user.name-{i:03d}" for i in range(300)]
    result = write_shared_policy(T1_POLICY_ARN, OPUS_KEYWORDS, big_list, mock_iam)
    assert result is not None
    assert result["level"] == "warn"
    assert result["tier"] == "BedrockEnforcement-T1"
    assert POLICY_SIZE_WARN_THRESHOLD <= result["doc_size"] < POLICY_SIZE_CRITICAL_THRESHOLD
    assert result["user_count"] == 300
    mock_iam.create_policy_version.assert_called_once()


def test_write_shared_policy_returns_critical_level_above_95() -> None:
    """Warning dict with level='critical' returned when doc exceeds 95%.

    355 users produces a 6021-byte document — above POLICY_SIZE_CRITICAL_THRESHOLD
    (5836) but below MAX_POLICY_SIZE (6144).
    """
    mock_iam = MagicMock()
    mock_iam.list_policy_versions.return_value = {
        "Versions": [{"IsDefaultVersion": True, "VersionId": "v1", "CreateDate": "2026-01-01"}]
    }
    big_list = [f"user.name-{i:03d}" for i in range(355)]
    result = write_shared_policy(T1_POLICY_ARN, OPUS_KEYWORDS, big_list, mock_iam)
    assert result is not None
    assert result["level"] == "critical"
    assert result["doc_size"] >= POLICY_SIZE_CRITICAL_THRESHOLD
    assert result["doc_size"] <= MAX_POLICY_SIZE
    assert result["user_count"] == 355
    mock_iam.create_policy_version.assert_called_once()


def test_write_shared_policy_oversize_returns_none_not_warning() -> None:
    """An oversize skip returns None — it has its own metric path, not a warning."""
    mock_iam = MagicMock()
    big_list = [f"user.with.long.name.{i}" for i in range(600)]
    result = write_shared_policy(T1_POLICY_ARN, OPUS_KEYWORDS, big_list, mock_iam)
    assert result is None
    mock_iam.create_policy_version.assert_not_called()


# ── update_shared_cmps warning passthrough ────────────────────────────────────

def test_update_shared_cmps_returns_empty_list_normally() -> None:
    """No warnings from a normal-sized update."""
    mock_iam = MagicMock()
    mock_iam.list_policy_versions.return_value = {
        "Versions": [{"IsDefaultVersion": True, "VersionId": "v1", "CreateDate": "2026-01-01"}]
    }
    warnings = update_shared_cmps(["alice.smith"], ["alice.smith"], mock_iam)
    assert warnings == []


def test_update_shared_cmps_collects_warnings_from_both_tiers() -> None:
    """Warnings from both T1 and T2 writes are collected and returned."""
    mock_iam = MagicMock()
    mock_iam.list_policy_versions.return_value = {
        "Versions": [{"IsDefaultVersion": True, "VersionId": "v1", "CreateDate": "2026-01-01"}]
    }
    big_list = [f"user.name-{i:03d}" for i in range(300)]
    warnings = update_shared_cmps(big_list, big_list, mock_iam)
    assert len(warnings) == 2
    tiers = {w["tier"] for w in warnings}
    assert "BedrockEnforcement-T1" in tiers
    assert "BedrockEnforcement-T2" in tiers
