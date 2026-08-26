# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
import sys
import os
from typing import Any
from unittest.mock import MagicMock, patch

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

import pytest
from handler import (
    _query_cost_view_rows,
    query_spend_by_person,
    query_unmapped_models,
    _alert_unmapped_models,
    ATHENA_DATABASE,
    COST_VIEW,
    ATHENA_WORKGROUP,
)


def _row(
    person: str = "",
    model: str = "",
    raw_model: str = "",
    usage_type: str = "human",
    arn: str = "",
    spend: float = 0.0,
    invocations: int = 1,
) -> dict[str, Any]:
    """Build one cost-view row dict, matching _query_cost_view_rows' parsed shape."""
    return {
        "person": person,
        "model": model,
        "raw_model": raw_model,
        "usage_type": usage_type,
        "arn": arn,
        "spend": spend,
        "invocations": invocations,
    }


# ── _query_cost_view_rows (the single shared Athena query) ───────────────────

def _athena_client_returning_cost_view_rows(rows: list[tuple[Any, ...]]) -> MagicMock:
    """Build a mock Athena client whose query SUCCEEDS and paginates `rows`,
    where each row is (person, model, raw_model, usage_type, arn, spend, invocations)."""
    client = MagicMock()
    client.start_query_execution.return_value = {"QueryExecutionId": "qid-1"}
    client.get_query_execution.return_value = {
        "QueryExecution": {"Status": {"State": "SUCCEEDED"}}
    }
    columns = ["person", "model", "raw_model", "usage_type", "arn", "spend", "invocations"]
    header = {"Data": [{"VarCharValue": c} for c in columns]}
    data_rows = [
        {"Data": [{"VarCharValue": str(v)} for v in row]} for row in rows
    ]
    paginator = MagicMock()
    paginator.paginate.return_value = [{"ResultSet": {"Rows": [header] + data_rows}}]
    client.get_paginator.return_value = paginator
    return client


def test_cost_view_query_targets_view_and_workgroup_with_no_filter() -> None:
    """The single shared query has no WHERE clause — filtering happens in Python
    across the derivations, since each needs a different filter/grouping."""
    client = _athena_client_returning_cost_view_rows([])
    with patch("handler._athena", return_value=client):
        _query_cost_view_rows()
    kwargs = client.start_query_execution.call_args[1]
    query = kwargs["QueryString"]
    assert f"{ATHENA_DATABASE}.{COST_VIEW}" in query
    assert "WHERE" not in query
    assert kwargs["WorkGroup"] == ATHENA_WORKGROUP


def test_cost_view_query_groups_by_all_dimensions() -> None:
    """GROUP BY must include every column consumers key on, so SUM/COUNT stay accurate
    when rolled up by any subset in Python."""
    client = _athena_client_returning_cost_view_rows([])
    with patch("handler._athena", return_value=client):
        _query_cost_view_rows()
    query = client.start_query_execution.call_args[1]["QueryString"]
    for col in ["person", "model", "raw_model", "usage_type", "arn"]:
        assert col in query
    assert "SUM(estimated_cost)" in query
    assert "COUNT(*)" in query


def test_cost_view_query_parses_rows() -> None:
    """Rows are returned as a list of dicts with spend as float and invocations as int."""
    client = _athena_client_returning_cost_view_rows(
        [("alice", "Sonnet 5", "anthropic.claude-sonnet-5", "human", "arn:x", "12.5", "3")]
    )
    with patch("handler._athena", return_value=client):
        rows = _query_cost_view_rows()
    assert len(rows) == 1
    assert rows[0]["person"] == "alice"
    assert rows[0]["spend"] == pytest.approx(12.5)
    assert rows[0]["invocations"] == 3


def test_cost_view_query_skips_unparseable_rows() -> None:
    """A row with a non-numeric spend is dropped, not fatal to the whole query."""
    client = _athena_client_returning_cost_view_rows(
        [
            ("alice", "Sonnet 5", "x", "human", "arn:x", "NULL", "1"),
            ("bob", "Sonnet 5", "x", "human", "arn:x", "5.0", "2"),
        ]
    )
    with patch("handler._athena", return_value=client):
        rows = _query_cost_view_rows()
    assert len(rows) == 1
    assert rows[0]["person"] == "bob"


def test_cost_view_query_raises_on_failed_state() -> None:
    """A FAILED Athena query raises RuntimeError so the Lambda surfaces the error."""
    client = MagicMock()
    client.start_query_execution.return_value = {"QueryExecutionId": "qid-1"}
    client.get_query_execution.return_value = {
        "QueryExecution": {"Status": {"State": "FAILED", "StateChangeReason": "boom"}}
    }
    with patch("handler._athena", return_value=client):
        with pytest.raises(RuntimeError, match="FAILED"):
            _query_cost_view_rows()


def test_cost_view_query_raises_on_timeout() -> None:
    """Athena query that never completes raises RuntimeError after the deadline."""
    import time as time_mod
    client = MagicMock()
    client.start_query_execution.return_value = {"QueryExecutionId": "qid-1"}
    client.get_query_execution.return_value = {
        "QueryExecution": {"Status": {"State": "RUNNING"}}
    }
    with patch("handler._athena", return_value=client), \
         patch("handler.time") as mock_time:
        mock_time.time.side_effect = [0.0, 241.0, 241.0]
        mock_time.sleep = time_mod.sleep
        with pytest.raises(RuntimeError, match="timed out"):
            _query_cost_view_rows()


def test_cost_view_query_handles_multiple_pages() -> None:
    """The header row appears only on page 1; page 2's first row is real data."""
    client = MagicMock()
    client.start_query_execution.return_value = {"QueryExecutionId": "qid-1"}
    client.get_query_execution.return_value = {
        "QueryExecution": {"Status": {"State": "SUCCEEDED"}}
    }
    columns = ["person", "model", "raw_model", "usage_type", "arn", "spend", "invocations"]
    header = {"Data": [{"VarCharValue": c} for c in columns]}
    row1 = {"Data": [{"VarCharValue": v} for v in ("alice", "Sonnet 5", "x", "human", "arn:x", "10.0", "1")]}
    row2 = {"Data": [{"VarCharValue": v} for v in ("bob", "Sonnet 5", "x", "human", "arn:x", "20.0", "2")]}
    page1 = {"ResultSet": {"Rows": [header, row1]}}
    page2 = {"ResultSet": {"Rows": [row2]}}
    paginator = MagicMock()
    paginator.paginate.return_value = [page1, page2]
    client.get_paginator.return_value = paginator
    with patch("handler._athena", return_value=client):
        rows = _query_cost_view_rows()
    assert {r["person"] for r in rows} == {"alice", "bob"}


# ── query_spend_by_person (pure derivation) ───────────────────────────────────

def test_spend_by_person_sums_human_rows_only() -> None:
    """Non-human usage_type rows are excluded."""
    rows = [
        _row(person="alice", usage_type="human", spend=10.0),
        _row(person="alice", usage_type="human", spend=5.0),
        _row(person="alice", usage_type="non-human", spend=999.0),
    ]
    result = query_spend_by_person(rows)
    assert result == {"alice": pytest.approx(15.0)}


def test_spend_by_person_skips_rows_with_no_person() -> None:
    """A row with a blank person is skipped."""
    rows = [_row(person="", usage_type="human", spend=10.0), _row(person="bob", usage_type="human", spend=5.0)]
    result = query_spend_by_person(rows)
    assert result == {"bob": pytest.approx(5.0)}


def test_spend_by_person_empty_rows_returns_empty_dict() -> None:
    """No rows means an empty dict, not an error."""
    assert query_spend_by_person([]) == {}


# ── query_unmapped_models (pure derivation) ───────────────────────────────────

def test_unmapped_models_counts_invocations_by_raw_model() -> None:
    """Invocation counts for the same raw_model sum across rows; other models are ignored."""
    rows = [
        _row(raw_model="anthropic.claude-opus-5", model="Unknown", invocations=5),
        _row(raw_model="anthropic.claude-opus-5", model="Unknown", invocations=3),
        _row(raw_model="anthropic.claude-sonnet-5", model="Sonnet 5", invocations=100),
    ]
    result = query_unmapped_models(rows)
    assert result == {"anthropic.claude-opus-5": 8}


def test_unmapped_models_empty_when_no_unknown_rows() -> None:
    """No 'Unknown' rows means an empty dict, not an error."""
    rows = [_row(raw_model="anthropic.claude-sonnet-5", model="Sonnet 5", invocations=100)]
    assert query_unmapped_models(rows) == {}


def test_unmapped_models_empty_rows_returns_empty_dict() -> None:
    """No rows at all means an empty dict, not an error."""
    assert query_unmapped_models([]) == {}


# ── _alert_unmapped_models (log + CloudWatch metric only) ─────────────────────

def test_alert_unmapped_models_noop_when_empty() -> None:
    """No unmapped models means no CloudWatch call at all."""
    with patch("boto3.client") as mock_boto:
        _alert_unmapped_models({})
    mock_boto.assert_not_called()


def test_alert_unmapped_models_emits_metric_per_raw_model() -> None:
    """Each unmapped raw_model gets its own CloudWatch metric datapoint."""
    cw = MagicMock()
    with patch("boto3.client", return_value=cw):
        _alert_unmapped_models({"anthropic.claude-sonnet-5": 42})
    kwargs = cw.put_metric_data.call_args[1]
    assert kwargs["Namespace"] == "BedrockSpendEnforcement"
    metric = kwargs["MetricData"][0]
    assert metric["MetricName"] == "UnmappedModelSpend"
    assert metric["Dimensions"] == [{"Name": "RawModel", "Value": "anthropic.claude-sonnet-5"}]
    assert metric["Value"] == pytest.approx(42.0)


def test_alert_unmapped_models_swallows_cloudwatch_errors() -> None:
    """A CloudWatch failure must not raise — detection already logged via logger.exception."""
    cw = MagicMock()
    cw.put_metric_data.side_effect = RuntimeError("boom")
    with patch("boto3.client", return_value=cw):
        _alert_unmapped_models({"anthropic.claude-sonnet-5": 1})
