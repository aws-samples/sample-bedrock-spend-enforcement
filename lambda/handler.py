# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
import boto3
import json
import logging
import os
import time
from datetime import datetime, timezone
from decimal import Decimal
from collections.abc import Iterable
from typing import Any, Protocol

logger = logging.getLogger()
logger.setLevel(logging.INFO)

ATHENA_DATABASE = "default"
COST_VIEW = "bedrock_cost_today"
ATHENA_WORKGROUP = "primary"
ATHENA_RESULTS_BUCKET = os.environ["ATHENA_RESULTS_BUCKET"]

STATE_TABLE = os.environ.get("STATE_TABLE", "bedrock-spend-enforcement-state")
EXCEPTIONS_TABLE = os.environ.get("EXCEPTIONS_TABLE", "bedrock-spend-enforcement-exceptions")

DEFAULT_DAILY_LIMIT = 150.0
T0_THRESHOLD_RATIO = 0.70
T1_THRESHOLD_RATIO = 0.80

OPUS_KEYWORDS = ["opus"]
SONNET_KEYWORDS = ["sonnet"]

DENY_ACTIONS = [
    "bedrock:InvokeModel",
    "bedrock:InvokeModelWithResponseStream",
    "bedrock:Converse",
    "bedrock:ConverseStream",
]


def _enforcement_account_id() -> str:
    """Return the AWS account this Lambda is running in, resolved via STS.

    Dynamic resolution (instead of a hardcoded account-ID env var) means a
    reader can deploy this Lambda into their own account with zero extra
    configuration — nothing needs to be passed back into the Lambda's
    environment.
    """
    return boto3.client("sts").get_caller_identity()["Account"]


_ENFORCEMENT_ACCOUNT_ID = _enforcement_account_id()
T1_POLICY_ARN = f"arn:aws:iam::{_ENFORCEMENT_ACCOUNT_ID}:policy/BedrockEnforcement-T1"
T2_POLICY_ARN = f"arn:aws:iam::{_ENFORCEMENT_ACCOUNT_ID}:policy/BedrockEnforcement-T2"
MAX_POLICY_SIZE = 6144
POLICY_SIZE_WARN_RATIO = 0.80
POLICY_SIZE_CRITICAL_RATIO = 0.95
POLICY_SIZE_WARN_THRESHOLD = int(MAX_POLICY_SIZE * POLICY_SIZE_WARN_RATIO)
POLICY_SIZE_CRITICAL_THRESHOLD = int(MAX_POLICY_SIZE * POLICY_SIZE_CRITICAL_RATIO)


class _IAMClient(Protocol):
    """Structural type for the IAM boto3 client methods used by enforcement writes."""

    def list_policy_versions(self, **kwargs: object) -> dict[str, Any]: ...
    def delete_policy_version(self, **kwargs: object) -> dict[str, Any]: ...
    def create_policy_version(self, **kwargs: object) -> dict[str, Any]: ...


class _AthenaQueryClient(Protocol):
    """Structural type for the Athena boto3 client methods used by spend queries."""

    def get_query_execution(self, **kwargs: object) -> dict[str, Any]: ...


# ── Threshold logic ───────────────────────────────────────────────────────────


def calculate_required_denies(spend_usd: float, daily_limit: float) -> list[str]:
    if spend_usd >= daily_limit:
        return ["opus", "sonnet"]
    elif spend_usd >= daily_limit * T1_THRESHOLD_RATIO:
        return ["opus"]
    else:
        return []


def calculate_notification_tier(spend_usd: float, daily_limit: float) -> str | None:
    """Return the highest tier the user has crossed, or None if below 70%.

    Tiers: t2 (100%), t1 (80%), warn (70%).
    """
    if spend_usd >= daily_limit:
        tier: str | None = "t2"
    elif spend_usd >= daily_limit * T1_THRESHOLD_RATIO:
        tier = "t1"
    elif spend_usd >= daily_limit * T0_THRESHOLD_RATIO:
        tier = "warn"
    else:
        tier = None
    return tier


# ── IAM policy document ─────────────────────────────────────────────────────────


def _model_arns(keywords: list[str]) -> list[str]:
    """Return the deny-resource ARNs for each family keyword.

    Each keyword (e.g. "opus") produces a name-wildcard ARN for both invocation
    forms: the direct foundation-model ARN and the cross-region inference-profile ARN
    engineers actually invoke through.
    """
    arns = []
    for kw in keywords:
        arns.append(f"arn:aws:bedrock:*::foundation-model/*{kw}*")
        arns.append(f"arn:aws:bedrock:*:*:inference-profile/*{kw}*")
    return arns


def build_shared_policy_document(keywords: list[str], usernames: list[str]) -> dict[str, Any]:
    """Build a shared-CMP deny document for one tier's family keywords + username list."""
    return {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "DenyModels",
                "Effect": "Deny",
                "Action": DENY_ACTIONS,
                "Resource": _model_arns(keywords),
                "Condition": {
                    "StringEquals": {
                        "saml:sub": usernames,
                    }
                },
            }
        ],
    }


# ── AWS clients ──────────────────────────────────────────────────────────────


def _athena():
    return boto3.client("athena")


def _dynamodb():
    return boto3.resource("dynamodb")


# ── Athena ───────────────────────────────────────────────────────────────────


def _wait_for_athena_query(client: _AthenaQueryClient, execution_id: str) -> None:
    """Poll until the Athena query succeeds, fails, or exceeds the 4-minute deadline."""
    deadline = time.time() + 240
    while True:
        if time.time() > deadline:
            raise RuntimeError(f"Athena query {execution_id} timed out after 240s")
        status = client.get_query_execution(QueryExecutionId=execution_id)
        state = status["QueryExecution"]["Status"]["State"]
        if state == "SUCCEEDED":
            return
        if state in ("FAILED", "CANCELLED"):
            reason = status["QueryExecution"]["Status"].get("StateChangeReason", "unknown")
            raise RuntimeError(f"Athena query {state}: {reason}")
        time.sleep(2)


_COST_VIEW_GROUP_COLUMNS = ["person", "model", "raw_model", "usage_type", "arn"]


def _parse_cost_view_rows(pages: Iterable[dict[str, Any]]) -> list[dict[str, Any]]:
    """Convert Athena paginator output into a list of {column: value} dicts.

    `spend` is parsed as float and `invocations` as int; a row with either field
    unparseable is dropped (matches the previous per-query skip-and-warn behavior).
    """
    rows: list[dict[str, Any]] = []
    headers: list[str] | None = None
    for page in pages:
        result_rows = page["ResultSet"]["Rows"]
        if headers is None:
            if not result_rows:
                continue
            headers = [col.get("VarCharValue", "") for col in result_rows[0]["Data"]]
            result_rows = result_rows[1:]
        for row in result_rows:
            values = [col.get("VarCharValue") for col in row["Data"]]
            record = dict(zip(headers, values))
            try:
                record["spend"] = float(record.get("spend") or 0)
                record["invocations"] = int(record.get("invocations") or 0)
            except (ValueError, TypeError):
                logger.warning("Skipping unparseable cost-view row: %r", record)
                continue
            rows.append(record)
    return rows


def _query_cost_view_rows() -> list[dict[str, Any]]:
    """Single Athena query backing every cost-view derivation below.

    Grouped at (person, model, raw_model, usage_type, arn) — the finest
    grain any current consumer needs — with SUM(estimated_cost) and COUNT(*) per group.
    query_spend_by_person and query_unmapped_models both roll this single result up
    in Python instead of each re-scanning the view independently.

    This matters because the underlying source tables are JSON (row-oriented) — Athena
    must deserialize a full row before applying any WHERE/column projection, so column
    pruning and predicate pushdown don't reduce bytes scanned. Separate queries against
    the same view scan the same bytes over and over; one combined query scans it once.
    Athena billing is $/TB scanned, so consolidating onto one shared query is a real
    cost reduction, not a hypothetical one.
    """
    query = (
        f"SELECT {', '.join(_COST_VIEW_GROUP_COLUMNS)}, "
        "SUM(estimated_cost) AS spend, COUNT(*) AS invocations "
        f"FROM {ATHENA_DATABASE}.{COST_VIEW} "
        f"GROUP BY {', '.join(_COST_VIEW_GROUP_COLUMNS)}"
    )
    client = _athena()
    response = client.start_query_execution(
        QueryString=query,
        QueryExecutionContext={"Database": ATHENA_DATABASE},
        ResultConfiguration={"OutputLocation": ATHENA_RESULTS_BUCKET},
        WorkGroup=ATHENA_WORKGROUP,
    )
    execution_id = response["QueryExecutionId"]
    _wait_for_athena_query(client, execution_id)
    paginator = client.get_paginator("get_query_results")
    pages = paginator.paginate(QueryExecutionId=execution_id)
    return _parse_cost_view_rows(pages)


def query_spend_by_person(rows: list[dict[str, Any]]) -> dict[str, float]:
    """
    Return {person: total_usd_spend_today} for human users, derived from cost-view rows.
    The view restricts to today's 0400-UTC window, so spend resets automatically.
    """
    spend: dict[str, float] = {}
    for row in rows:
        if row.get("usage_type") != "human":
            continue
        person = row.get("person")
        if not person:
            continue
        spend[person] = spend.get(person, 0.0) + row["spend"]
    return spend


def query_unmapped_models(rows: list[dict[str, Any]]) -> dict[str, int]:
    """Return {raw_model: invocation_count} for rows the view couldn't price."""
    unmapped: dict[str, int] = {}
    for row in rows:
        if row.get("model") != "Unknown":
            continue
        raw_model = row.get("raw_model")
        if not raw_model:
            continue
        unmapped[raw_model] = unmapped.get(raw_model, 0) + row["invocations"]
    return unmapped


def _alert_unmapped_models(unmapped: dict[str, int]) -> None:
    """Log + emit a CloudWatch metric per unmapped raw_model."""
    if not unmapped:
        return
    logger.error(
        "UNMAPPED_MODEL_SPEND: %d raw model id(s) priced via fallback tier, not their "
        "real rate — add them to the view's model CASE and pricing CASE: %s",
        len(unmapped),
        unmapped,
    )
    try:
        boto3.client("cloudwatch").put_metric_data(
            Namespace="BedrockSpendEnforcement",
            MetricData=[
                {
                    "MetricName": "UnmappedModelSpend",
                    "Dimensions": [{"Name": "RawModel", "Value": raw_model}],
                    "Value": float(count),
                    "Unit": "Count",
                }
                for raw_model, count in unmapped.items()
            ],
        )
    except Exception:
        logger.exception("Failed to emit UnmappedModelSpend metric")


def _check_unmapped_models(cost_view_rows: list[dict[str, Any]]) -> None:
    """Check for unmapped models, never letting a failure block enforcement."""
    try:
        _alert_unmapped_models(query_unmapped_models(cost_view_rows))
    except Exception:
        logger.exception("Failed to check for unmapped models — enforcement continues")


# ── DynamoDB ──────────────────────────────────────────────────────────────────


def _read_item(table_name: str, user_id: str) -> dict[str, Any]:
    """Fetch one item by user_id, returning {} on miss or error."""
    try:
        return _dynamodb().Table(table_name).get_item(Key={"user_id": user_id}).get("Item") or {}
    except Exception:
        logger.exception("%s lookup failed for %s", table_name, user_id)
        return {}


def _batch_read_items(table_name: str, user_ids: list[str]) -> dict[str, dict[str, Any]]:
    """Fetch many items by user_id via batch_get_item, chunked at DynamoDB's 100-key limit.

    Replaces one get_item per user (2 sequential round-trips per person in the
    enforcement loop) with a handful of batched calls — at a few hundred users
    that's a couple of round-trips instead of several hundred, which matters
    because a run that's still reading state when the next 15-minute schedule
    fires risks two overlapping invocations racing to write the same CMPs (see
    ReservedConcurrentExecutions in infra/lambda.yaml, which makes that race
    structurally impossible regardless of read latency — this function is the
    other half: keep runs fast enough that overlap is unlikely in the first
    place).

    A user_id missing from the result (not found, or its whole chunk failed) is
    indistinguishable from a miss to every caller — same fail-closed contract as
    _read_item: a lookup failure must not drop a user from enforcement, so a
    chunk-level exception is logged and skipped rather than raised.
    """
    result: dict[str, dict[str, Any]] = {}
    unique_ids = list(dict.fromkeys(user_ids))
    for i in range(0, len(unique_ids), 100):
        chunk = unique_ids[i : i + 100]
        try:
            request: dict[str, Any] = {table_name: {"Keys": [{"user_id": uid} for uid in chunk]}}
            dynamodb = _dynamodb()
            # UnprocessedKeys is DynamoDB's own partial-throttle signal — retry only
            # those, not the whole chunk, and give up after a bounded number of tries.
            for _ in range(5):
                response = dynamodb.batch_get_item(RequestItems=request)
                for item in response.get("Responses", {}).get(table_name, []):
                    result[item["user_id"]] = item
                request = response.get("UnprocessedKeys") or {}
                if not request:
                    break
            else:
                logger.error("%s batch_get_item: gave up on UnprocessedKeys after 5 tries", table_name)
        except Exception:
            logger.exception("%s batch lookup failed for a chunk of %d users", table_name, len(chunk))
    return result


def _limit_expired(item: dict[str, Any]) -> bool:
    """Return True if item's limit_expires_at has passed or is malformed. Absent means never expires.

    Fails closed (malformed → expired → default limit) rather than open: a custom
    limit is already a deviation from the default, so a corrupted expiry should not
    let it silently persist forever.
    """
    expires_at = item.get("limit_expires_at")
    if not expires_at:
        return False
    try:
        return datetime.fromisoformat(expires_at) <= datetime.now(timezone.utc)
    except (ValueError, TypeError):
        logger.exception("Malformed limit_expires_at %r — treating as expired", expires_at)
        return True


def _limit_from_item(item: dict[str, Any]) -> float:
    """Derive the daily limit from an exceptions item (default if absent/unparseable/expired)."""
    try:
        if "daily_limit_usd" in item and not _limit_expired(item):
            return float(item["daily_limit_usd"])
    except (ValueError, TypeError):
        logger.exception("Unparseable daily_limit_usd %r, using default", item.get("daily_limit_usd"))
    return DEFAULT_DAILY_LIMIT


def _blocked_from_item(item: dict[str, Any]) -> bool:
    """Derive active manual-block status from an exceptions item."""
    if not item.get("manual_block"):
        return False
    blocked_until = item.get("blocked_until")
    blocked = True
    if blocked_until:
        try:
            blocked = datetime.fromisoformat(blocked_until) > datetime.now(timezone.utc)
        except (ValueError, TypeError):
            logger.exception("Malformed blocked_until %r — treating as not blocked", blocked_until)
            blocked = False
    return blocked


def _notified_tiers_from_item(item: dict[str, Any] | None) -> set[str]:
    """Derive the already-notified tier set from a state item."""
    if item and "notified_tiers" in item:
        return set(item["notified_tiers"])
    return set()


def _build_state_item(
    user_id: str,
    spend_usd: float,
    active_denies: list[str],
    notified_tiers: set[str],
) -> dict[str, Any]:
    """Build one person's state-table item. Pure — no I/O — so the per-person
    loop can build items without writing them one at a time; see
    _batch_write_items for the actual persistence."""
    item: dict[str, Any] = {
        "user_id": user_id,
        "updated_at": datetime.now(timezone.utc).isoformat(),
        "spend_usd": Decimal(str(round(spend_usd, 4))),
        "active_denies": active_denies,
    }
    if notified_tiers:
        item["notified_tiers"] = notified_tiers
    return item


def _batch_write_items(table_name: str, items: list[dict[str, Any]]) -> None:
    """Write many items via batch_write_item, chunked at DynamoDB's 25-item limit.

    Mirrors _batch_read_items: UnprocessedItems (DynamoDB's partial-throttle
    signal) is retried up to 5 times per chunk; a chunk that still fails after
    that, or raises outright, is logged and dropped rather than raising —
    those people's state simply isn't refreshed this run and self-corrects
    next run, same fail-soft contract as every other DynamoDB helper here.
    """
    if not items:
        return
    for i in range(0, len(items), 25):
        chunk = items[i : i + 25]
        try:
            request: dict[str, Any] = {
                table_name: [{"PutRequest": {"Item": item}} for item in chunk]
            }
            dynamodb = _dynamodb()
            for _ in range(5):
                response = dynamodb.batch_write_item(RequestItems=request)
                request = response.get("UnprocessedItems") or {}
                if not request:
                    break
            else:
                logger.error(
                    "%s batch_write_item: gave up on UnprocessedItems after 5 tries "
                    "(%d items in this chunk not persisted)",
                    table_name, len(chunk),
                )
        except Exception:
            logger.exception("%s batch write failed for a chunk of %d items", table_name, len(chunk))


# ── IAM policy version management ───────────────────────────────────────────────


def _ensure_policy_version_slots(iam_client: _IAMClient, policy_arn: str) -> None:
    """Delete oldest non-default version if at the 5-version IAM limit."""
    versions = iam_client.list_policy_versions(PolicyArn=policy_arn)["Versions"]
    if len(versions) < 5:
        return
    non_default = [v for v in versions if not v["IsDefaultVersion"]]
    if not non_default:
        raise RuntimeError(f"Cannot free a version slot for {policy_arn}: all 5 versions are set as default")
    oldest = sorted(non_default, key=lambda v: v["CreateDate"])[0]
    iam_client.delete_policy_version(PolicyArn=policy_arn, VersionId=oldest["VersionId"])


def _emit_oversize_metric(policy_arn: str, user_count: int) -> None:
    """Emit a CloudWatch metric so an oversize skip is alarmable."""
    try:
        tier = policy_arn.rsplit("/", 1)[-1]
        boto3.client("cloudwatch").put_metric_data(
            Namespace="BedrockSpendEnforcement",
            MetricData=[
                {
                    "MetricName": "PolicySizeOverflow",
                    "Dimensions": [{"Name": "Tier", "Value": tier}],
                    "Value": float(user_count),
                    "Unit": "Count",
                }
            ],
        )
    except Exception as exc:
        logger.error("Failed to emit PolicySizeOverflow metric: %s", exc)


def _size_warning_level(policy_arn: str, doc_size: int, user_count: int) -> dict[str, Any] | None:
    """Classify a successfully-written policy doc's size into a warning dict, or None.

    Split out of write_shared_policy so that function keeps a single return in
    its success path.
    """
    if doc_size >= POLICY_SIZE_CRITICAL_THRESHOLD:
        level = "critical"
    elif doc_size >= POLICY_SIZE_WARN_THRESHOLD:
        level = "warn"
    else:
        return None
    tier = policy_arn.rsplit("/", 1)[-1]
    return {"tier": tier, "doc_size": doc_size, "user_count": user_count, "level": level}


def write_shared_policy(
    policy_arn: str,
    keywords: list[str],
    usernames: list[str],
    iam_client: _IAMClient,
) -> dict[str, Any] | None:
    """Write a new default version of a shared deny CMP.

    Returns a warning dict with level='warn' (>=80%) or level='critical' (>=95%)
    when the policy doc approaches the IAM 6144-byte ceiling, so the caller can
    surface this to the operator. Returns None at normal sizes or on an oversize
    skip (oversize has its own CloudWatch metric path).
    """
    doc = json.dumps(build_shared_policy_document(keywords, usernames), separators=(",", ":"))
    doc_size = len(doc)

    if doc_size > MAX_POLICY_SIZE:
        logger.error(
            "CMP_WRITE_SKIPPED_OVERSIZE: %s exceeds %d chars (%d chars, %d users) — "
            "PREVIOUS deny version remains in force; denies and resets are stale for this tier",
            policy_arn,
            MAX_POLICY_SIZE,
            doc_size,
            len(usernames),
        )
        _emit_oversize_metric(policy_arn, len(usernames))
        return None

    _ensure_policy_version_slots(iam_client, policy_arn)
    iam_client.create_policy_version(
        PolicyArn=policy_arn,
        PolicyDocument=doc,
        SetAsDefault=True,
    )
    logger.info("Updated %s with %d users", policy_arn, len(usernames))

    return _size_warning_level(policy_arn, doc_size, len(usernames))


def update_shared_cmps(
    t1_users: list[str],
    t2_users: list[str],
    iam_client: _IAMClient,
    *,
    t1_policy_arn: str = T1_POLICY_ARN,
    t2_policy_arn: str = T2_POLICY_ARN,
) -> list[dict[str, Any]]:
    """Rewrite both shared CMPs. Returns a list of size-warning dicts (may be empty).

    Each write is independent so a failure on T1 does not prevent the T2 update.
    """
    warnings: list[dict[str, Any]] = []
    try:
        w = write_shared_policy(t1_policy_arn, OPUS_KEYWORDS, t1_users, iam_client)
        if w:
            warnings.append(w)
    except Exception as exc:
        logger.error("Failed to update T1 CMP: %s", exc, exc_info=True)
    try:
        w = write_shared_policy(t2_policy_arn, SONNET_KEYWORDS, t2_users, iam_client)
        if w:
            warnings.append(w)
    except Exception as exc:
        logger.error("Failed to update T2 CMP: %s", exc, exc_info=True)
    return warnings


# ── Entry point ───────────────────────────────────────────────────────────────


_TIER_ORDER = ["warn", "t1", "t2"]


def _newly_crossed_tiers(spend_usd: float, limit: float, notified_tiers: set[str]) -> list[str]:
    """Return tiers (in _TIER_ORDER) that spend_usd crosses beyond notified_tiers."""
    tier = calculate_notification_tier(spend_usd, limit)
    if tier is None:
        return []
    return [t for t in _TIER_ORDER if t not in notified_tiers and _TIER_ORDER.index(t) <= _TIER_ORDER.index(tier)]


def _notify_if_new_tier(
    person: str,
    spend_usd: float,
    limit: float,
    notified_tiers: set[str],
) -> set[str]:
    """Send a DM if the user has crossed a tier they haven't been notified about yet."""
    if not os.environ.get("SLACK_BOT_TOKEN"):
        return notified_tiers

    from notifier import send_dm, spend_warning_text, t1_blocked_text, t2_blocked_text

    tier = calculate_notification_tier(spend_usd, limit)

    if tier is None:
        return set()

    new_tiers = notified_tiers.copy()
    crossed = _newly_crossed_tiers(spend_usd, limit, notified_tiers)
    if crossed:
        for t in crossed:
            if t == "warn":
                text = spend_warning_text(spend_usd, limit)
            elif t == "t1":
                text = t1_blocked_text(spend_usd, limit)
            else:
                text = t2_blocked_text(spend_usd, limit)
            send_dm(person, text)
            new_tiers.add(t)

    return new_tiers


def handler(event: dict[str, Any], context: object) -> None:
    """Lambda entry point: query today's spend, then rewrite enforcement CMPs.

    Emits a TIMING log line per phase (athena_and_parse, batch_reads,
    per_person_loop, state_writes, cmp_writes, total). If a run ever gets slow enough that
    the next 15-minute schedule fires before it finishes, EventBridge's
    default async retry can stack a second invocation on top of a
    still-running one — whichever finishes LAST would win the CMP write, not
    whichever had the freshest spend window, silently undoing a correct run
    with stale data. ReservedConcurrentExecutions in infra/lambda.yaml makes
    that race structurally impossible regardless of latency; these logs are
    for diagnosing latency itself before it gets that far — grep CloudWatch
    Logs for "TIMING" to see where a slow run actually spent its time.
    """
    run_start = time.monotonic()
    cost_view_rows = _query_cost_view_rows()
    spend_by_person = query_spend_by_person(cost_view_rows)
    _check_unmapped_models(cost_view_rows)
    logger.info(
        "TIMING athena_and_parse=%.1fs rows=%d persons=%d",
        time.monotonic() - run_start, len(cost_view_rows), len(spend_by_person),
    )
    iam_client = boto3.client("iam")

    t1_users: list[str] = []
    t2_users: list[str] = []

    # Batched up front instead of two get_item calls per person inside the loop —
    # at a few hundred people that's the difference between a couple of
    # round-trips and several hundred sequential ones. See _batch_read_items.
    persons = list(spend_by_person.keys())
    batch_read_start = time.monotonic()
    exception_items = _batch_read_items(EXCEPTIONS_TABLE, persons)
    state_items = _batch_read_items(STATE_TABLE, persons)
    logger.info(
        "TIMING batch_reads=%.1fs persons=%d", time.monotonic() - batch_read_start, len(persons)
    )

    loop_start = time.monotonic()
    notify_count = 0
    state_updates: list[dict[str, Any]] = []
    for person, spend_usd in spend_by_person.items():
        try:
            exc_item = exception_items.get(person, {})
            state_item = state_items.get(person, {})

            limit = _limit_from_item(exc_item)
            if _blocked_from_item(exc_item):
                required_denies = ["opus", "sonnet"]
            else:
                required_denies = calculate_required_denies(spend_usd, limit)
            if "opus" in required_denies:
                t1_users.append(person)
            if "sonnet" in required_denies:
                t2_users.append(person)

            notified_tiers_before = _notified_tiers_from_item(state_item)
            notified_tiers_after = _notify_if_new_tier(person, spend_usd, limit, notified_tiers_before)
            if notified_tiers_after != notified_tiers_before:
                notify_count += 1
            state_updates.append(_build_state_item(person, spend_usd, required_denies, notified_tiers_after))
        except Exception as exc:
            logger.error("Error processing user %s: %s", person, exc, exc_info=True)
    logger.info(
        "TIMING per_person_loop=%.1fs persons=%d dms_sent=%d",
        time.monotonic() - loop_start, len(spend_by_person), notify_count,
    )

    state_write_start = time.monotonic()
    _batch_write_items(STATE_TABLE, state_updates)
    logger.info(
        "TIMING state_writes=%.1fs persons=%d", time.monotonic() - state_write_start, len(state_updates)
    )

    cmp_write_start = time.monotonic()
    size_warnings = update_shared_cmps(t1_users, t2_users, iam_client)
    for w in size_warnings:
        logger.warning(
            "POLICY_SIZE_WARNING: tier=%s level=%s doc_size=%d user_count=%d",
            w["tier"],
            w["level"],
            w["doc_size"],
            w["user_count"],
        )
    logger.info("TIMING cmp_writes=%.1fs", time.monotonic() - cmp_write_start)
    logger.info("TIMING total=%.1fs", time.monotonic() - run_start)
