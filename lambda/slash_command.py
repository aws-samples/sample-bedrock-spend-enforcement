# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""
Bedrock cost controls slash commands and interaction handler.

Slash commands:
  /bedrock-spend                         — show caller's current spend
  /bedrock-block <username> [duration]   — block a user (admin only, requires confirm)
  /bedrock-unblock <username>            — remove manual block (admin only, requires confirm)
  /bedrock-limit <username> <amount> [duration|never] [jira_ticket]
                                          — set custom daily limit (admin only, requires confirm)
                                            duration: Nd/Nw/Nmo, defaults to DEFAULT_LIMIT_EXPIRY_DAYS
                                            jira_ticket: optional, PROJECT-123 format (case-insensitive)

Interactive callbacks:
  POST /bedrock-interact — handles button confirm/cancel from block/unblock/limit prompts

Invocation modes:
  gateway — verify HMAC, ACK immediately, self-invoke async
  async   — do the real work, post result via response_url
  interact_gateway — verify HMAC on button callback, ACK, self-invoke async
  interact_async — execute confirmed admin action
"""

import base64
import hashlib
import hmac
import json
import logging
import math
import os
import re
import time
from datetime import datetime, timedelta, timezone
from typing import Any
from urllib.parse import parse_qs

import boto3
from botocore.client import BaseClient
from botocore.config import Config
from slack_sdk import WebClient

logger = logging.getLogger()
logger.setLevel(logging.INFO)

STATE_TABLE = os.environ.get("STATE_TABLE", "bedrock-cost-controls-state")
EXCEPTIONS_TABLE = os.environ.get("EXCEPTIONS_TABLE", "bedrock-cost-controls-exceptions")
DEFAULT_DAILY_LIMIT = 150.0
# Hard ceiling on a single /bedrock-limit grant. Prevents an admin (or a
# compromised admin session) from silently un-capping a user with an absurd
# value. Sits above the $500 anomaly-alert threshold so the detective alert
# still fires for high-but-plausible grants before this preventive cap rejects.
MAX_SETTABLE_LIMIT = float(os.environ.get("MAX_SETTABLE_LIMIT", "1000"))
# Default expiry for a /bedrock-limit grant when no duration is given.
DEFAULT_LIMIT_EXPIRY_DAYS = int(os.environ.get("DEFAULT_LIMIT_EXPIRY_DAYS", "30"))
SIGNATURE_MAX_AGE_SECONDS = 300
_CONTENT_TYPE_JSON = "application/json"

_BOTO_CONFIG = Config(connect_timeout=5, read_timeout=5)
_lambda_client: BaseClient = boto3.client("lambda", config=Config(connect_timeout=3, read_timeout=3))
_dynamodb_resource = boto3.resource("dynamodb", config=_BOTO_CONFIG)

# Duration string → timedelta. None means indefinite block.
_DURATION_MAP: dict[str, timedelta | None] = {
    "1h": timedelta(hours=1),
    "2h": timedelta(hours=2),
    "4h": timedelta(hours=4),
    "8h": timedelta(hours=8),
    "12h": timedelta(hours=12),
    "24h": timedelta(hours=24),
    "1d": timedelta(days=1),
    "2d": timedelta(days=2),
    "3d": timedelta(days=3),
    "7d": timedelta(days=7),
    "1w": timedelta(weeks=1),
    "2w": timedelta(weeks=2),
}
_VALID_USERNAME = re.compile(r"^[a-z]+(?:-[a-z]+)*\.[a-z]+(?:-[a-z]+)*$")
_JIRA_TICKET_RE = re.compile(r"^[A-Za-z]+-\d+$")
_VALID_DURATIONS = ", ".join(
    sorted(_DURATION_MAP.keys(), key=lambda k: _DURATION_MAP[k] or timedelta.max)
)


# ── Auth ──────────────────────────────────────────────────────────────────────

def _is_admin(caller_slack_id: str) -> bool:
    """Return True if the caller is in ADMIN_SLACK_IDS."""
    admin_ids = {uid.strip() for uid in os.environ.get("ADMIN_SLACK_IDS", "").split(",") if uid.strip()}
    return caller_slack_id in admin_ids


# ── Signature verification ────────────────────────────────────────────────────

def _verify_slack_signature(signature: str, timestamp: str, body: str) -> bool:
    """Return True if the Slack HMAC-SHA256 signature is valid and not stale."""
    secret = os.environ.get("SLACK_SIGNING_SECRET", "")
    if not secret:
        logger.error("SLACK_SIGNING_SECRET is not configured")
        return False
    try:
        stale = abs(int(time.time()) - int(timestamp)) > SIGNATURE_MAX_AGE_SECONDS
        expected = "v0=" + hmac.new(
            secret.encode(),
            f"v0:{timestamp}:{body}".encode(),
            hashlib.sha256,
        ).hexdigest()
        return not stale and hmac.compare_digest(expected, signature)
    except (ValueError, TypeError):
        logger.exception("Error verifying Slack signature")
        return False


# ── Slack helpers ─────────────────────────────────────────────────────────────

def _ack() -> dict[str, Any]:
    """Return an empty 200 to satisfy Slack's 3-second window."""
    return {"statusCode": 200, "body": ""}


def _ephemeral(text: str) -> dict[str, Any]:
    """Return an ephemeral Slack response visible only to the caller."""
    return {
        "statusCode": 200,
        "headers": {"Content-Type": _CONTENT_TYPE_JSON},
        "body": json.dumps({"response_type": "ephemeral", "text": text}),
    }


def _post_response_url(response_url: str, text: str) -> None:
    """POST an ephemeral message back to Slack via response_url."""
    import urllib.request
    payload = json.dumps(
        {"response_type": "ephemeral", "replace_original": False, "text": text}
    ).encode()
    req = urllib.request.Request(
        response_url, data=payload, headers={"Content-Type": _CONTENT_TYPE_JSON}
    )
    try:
        urllib.request.urlopen(req, timeout=5)
    except Exception:
        logger.exception("Failed to post to response_url")


def _post_ephemeral_api(channel_id: str, user_id: str, text: str) -> None:
    """Post an ephemeral message via the Slack Web API (chat_postEphemeral).

    Fails loudly on missing token rather than making a real HTTP call that would
    silently get not_authed — which would leave _post_result believing delivery
    succeeded when it hasn't.
    """
    token = os.environ.get("SLACK_BOT_TOKEN", "")
    if not token:
        logger.error(
            "SLACK_BOT_TOKEN not configured — ephemeral delivery skipped channel=%s user=%s",
            channel_id,
            user_id,
        )
        return
    try:
        WebClient(token=token).chat_postEphemeral(channel=channel_id, user=user_id, text=text)
    except Exception:
        logger.exception("Failed to post ephemeral via API channel=%s user=%s", channel_id, user_id)


def _post_result(text: str, response_url: str, channel_id: str, user_id: str) -> None:
    """Post a result message — prefers chat_postEphemeral when channel_id is present.

    Delivery paths (first match wins):
      1. channel_id + user_id present  → chat_postEphemeral via Web API
      2. response_url present          → POST to response_url

    Note: response_url is a fallback for the *absent channel_id* case only. If
    chat_postEphemeral fails (e.g. bot not in channel), _post_result does NOT
    retry via response_url — operators should ensure SLACK_BOT_TOKEN is valid.
    """
    if channel_id and user_id:
        _post_ephemeral_api(channel_id, user_id, text)
    elif response_url:
        _post_response_url(response_url, text)
    else:
        logger.warning("No channel_id or response_url available — result not delivered: %s", text)


def _resolve_username(caller_slack_id: str) -> str | None:
    """Resolve Slack user ID → SSO username via profile email."""
    try:
        client = WebClient(token=os.environ["SLACK_BOT_TOKEN"])
        info = client.users_info(user=caller_slack_id)
        email: str = info["user"]["profile"]["email"]
        return email.split("@")[0]
    except Exception:
        logger.exception("Could not resolve username for %s", caller_slack_id)
        return None


# ── DynamoDB helpers ──────────────────────────────────────────────────────────

def _current_window_start() -> datetime:
    """Return the start of the current 0400-UTC enforcement window."""
    now = datetime.now(timezone.utc)
    reset = now.replace(hour=4, minute=0, second=0, microsecond=0)
    return reset if now >= reset else reset - timedelta(days=1)


def _is_stale(updated_at: str) -> bool:
    """Return True if updated_at predates the current 0400-UTC enforcement window."""
    try:
        return datetime.fromisoformat(updated_at) < _current_window_start()
    except (ValueError, TypeError):
        return False


def _get_spend(username: str) -> float:
    """Return today's spend for username from the state table (0.0 if no record or stale)."""
    try:
        table = _dynamodb_resource.Table(STATE_TABLE)
        response = table.get_item(Key={"user_id": username}, ProjectionExpression="spend_usd, updated_at")
        item = response.get("Item")
        valid = item and "spend_usd" in item and not _is_stale(item.get("updated_at", ""))
        return float(item["spend_usd"]) if valid else 0.0
    except Exception:
        logger.exception("Failed to read spend for %s", username)
    return 0.0


def _limit_expired(item: dict[str, Any]) -> bool:
    """Return True if item's limit_expires_at has passed or is malformed. Absent means never expires.

    Fails closed (malformed → expired → default limit), matching handler.py's
    _limit_expired — a corrupted expiry must not let a custom limit persist forever.
    """
    expires_at = item.get("limit_expires_at")
    if not expires_at:
        return False
    try:
        return datetime.fromisoformat(expires_at) <= datetime.now(timezone.utc)
    except (ValueError, TypeError):
        logger.exception("Malformed limit_expires_at %r — treating as expired", expires_at)
        return True


def _get_limit_and_expiry(username: str) -> tuple[float, str | None]:
    """Return (daily_limit, limit_expires_at) from a single read of the exceptions table.

    One get_item call serving both /bedrock-spend's limit and its expiry note —
    they were previously two separate reads of the same record.
    """
    try:
        table = _dynamodb_resource.Table(EXCEPTIONS_TABLE)
        response = table.get_item(Key={"user_id": username})
        item = response.get("Item")
        if item and "daily_limit_usd" in item and not _limit_expired(item):
            return float(item["daily_limit_usd"]), item.get("limit_expires_at")
    except Exception:
        logger.exception("Failed to read limit for %s", username)
    return DEFAULT_DAILY_LIMIT, None


def _get_limit(username: str) -> float:
    """Return the user's daily limit from the exceptions table, or the default."""
    return _get_limit_and_expiry(username)[0]


def _apply_block(username: str, until_iso: str | None) -> None:
    """Write a manual block to the exceptions table, preserving existing fields."""
    table = _dynamodb_resource.Table(EXCEPTIONS_TABLE)
    # Use UpdateItem for atomic attribute-level write — avoids race with enforcement Lambda
    # and preserves any existing daily_limit_usd on the same item.
    update_expr = "SET manual_block = :t"
    expr_values: dict[str, Any] = {":t": True}
    if until_iso:
        update_expr += ", blocked_until = :u"
        expr_values[":u"] = until_iso
    else:
        update_expr += " REMOVE blocked_until"
    table.update_item(
        Key={"user_id": username},
        UpdateExpression=update_expr,
        ExpressionAttributeValues=expr_values,
    )


def _remove_block(username: str) -> None:
    """Remove a manual block from the exceptions table atomically."""
    table = _dynamodb_resource.Table(EXCEPTIONS_TABLE)
    table.update_item(
        Key={"user_id": username},
        UpdateExpression="REMOVE manual_block, blocked_until",
    )


def _set_limit(
    username: str,
    limit: float,
    granted_by: str,
    expires_at: str | None = None,
    jira_ticket: str | None = None,
) -> None:
    """Set a custom daily limit in the exceptions table atomically.

    Records granted_by (the admin's Slack user id) and granted_at (ISO-8601 UTC)
    alongside the limit so every exception grant is auditable after the fact.
    expires_at (ISO-8601 UTC) is written when the grant has a deadline; None
    means indefinite ("never") and REMOVEs any expiry left over from a prior grant.
    jira_ticket, when given, is stored alongside the grant for traceability; None
    REMOVEs any ticket left over from a prior grant.
    """
    table = _dynamodb_resource.Table(EXCEPTIONS_TABLE)
    update_expr = "SET daily_limit_usd = :v, granted_by = :by, granted_at = :at"
    expr_values: dict[str, Any] = {
        ":v": str(limit),
        ":by": granted_by,
        ":at": datetime.now(timezone.utc).isoformat(),
    }
    remove_attrs = []
    if expires_at:
        update_expr += ", limit_expires_at = :exp"
        expr_values[":exp"] = expires_at
    else:
        remove_attrs.append("limit_expires_at")
    if jira_ticket:
        update_expr += ", jira_ticket = :ticket"
        expr_values[":ticket"] = jira_ticket
    else:
        remove_attrs.append("jira_ticket")
    if remove_attrs:
        update_expr += " REMOVE " + ", ".join(remove_attrs)
    table.update_item(
        Key={"user_id": username},
        UpdateExpression=update_expr,
        ExpressionAttributeValues=expr_values,
    )


def _invoke_enforcement_lambda() -> None:
    """Fire the enforcement Lambda async so CMPs are rewritten immediately."""
    enforcement_fn = os.environ.get("ENFORCEMENT_FUNCTION_NAME", "bedrock-cost-controls")
    try:
        _lambda_client.invoke(
            FunctionName=enforcement_fn,
            InvocationType="Event",
            Payload=b"{}",
        )
        logger.info("Triggered enforcement Lambda rewrite")
    except Exception:
        logger.exception("Failed to invoke enforcement Lambda")


# ── Confirmation UI ───────────────────────────────────────────────────────────

def _confirm_blocks(
    action_type: str, description: str, action_payload: dict[str, Any]
) -> list[dict[str, Any]]:
    """Build Block Kit confirmation blocks with Yes/Cancel buttons."""
    return [
        {
            "type": "section",
            "text": {"type": "mrkdwn", "text": description},
        },
        {
            "type": "actions",
            "elements": [
                {
                    "type": "button",
                    "text": {"type": "plain_text", "text": "Yes, do it"},
                    "style": "danger",
                    "action_id": "confirm_action",
                    "value": json.dumps({"action": action_type, **action_payload}),
                },
                {
                    "type": "button",
                    "text": {"type": "plain_text", "text": "Cancel"},
                    "action_id": "cancel_action",
                    "value": "cancel",
                },
            ],
        },
    ]


# ── Duration parsing ──────────────────────────────────────────────────────────

def _parse_duration(raw: str) -> tuple[timedelta | None, str] | None:
    """Parse a duration string. Returns (timedelta_or_None, human_label), or None if invalid.

    Empty/omitted raw returns (None, 'indefinitely') for indefinite block.
    An unrecognised non-empty string returns None to signal a parse error.
    """
    if not raw:
        return None, "indefinitely"
    td = _DURATION_MAP.get(raw.lower())
    if td is None:
        return None  # type: ignore[return-value]  # signals invalid input
    total_hours = int(td.total_seconds() // 3600)
    if total_hours % 24 == 0:
        days = total_hours // 24
        label = f"{days} day{'s' if days != 1 else ''}"
    else:
        label = f"{total_hours} hour{'s' if total_hours != 1 else ''}"
    return td, label


# Digits bounded to 5 (max 99999) so the largest possible amount*30 (months, in
# days) — 2,999,970 — stays far under timedelta.max (~999,999,999 days) and never
# risks the OverflowError an unbounded \d+ would let through to timedelta().
_LIMIT_DURATION_RE = re.compile(r"^(\d{1,5})(d|w|mo)$")


def _limit_duration_from_match(amount: int, unit: str) -> tuple[timedelta, str]:
    """Build the (timedelta, label) pair for a matched amount+unit pair."""
    if unit == "d":
        return timedelta(days=amount), f"{amount} day{'s' if amount != 1 else ''}"
    if unit == "w":
        return timedelta(weeks=amount), f"{amount} week{'s' if amount != 1 else ''}"
    return timedelta(days=amount * 30), f"{amount} month{'s' if amount != 1 else ''}"


def _parse_explicit_limit_duration(raw: str) -> tuple[timedelta, str] | None:
    """Parse a non-empty, non-"never" duration string like 30d/2w/3mo, or None if invalid."""
    match = _LIMIT_DURATION_RE.match(raw.lower())
    if not match or int(match.group(1)) <= 0:
        return None
    return _limit_duration_from_match(int(match.group(1)), match.group(2))


def _parse_limit_duration(raw: str) -> tuple[timedelta | None, str] | None:
    """Parse a /bedrock-limit expiry string. Returns (timedelta_or_None, human_label), or None if invalid.

    Empty/omitted raw defaults to DEFAULT_LIMIT_EXPIRY_DAYS. "never" returns (None, "never")
    for no expiry. Supports Nd (days), Nw (weeks), Nmo (months, treated as 30-day units).
    """
    if not raw:
        return timedelta(days=DEFAULT_LIMIT_EXPIRY_DAYS), f"{DEFAULT_LIMIT_EXPIRY_DAYS} days"
    if raw.lower() == "never":
        return None, "never"
    return _parse_explicit_limit_duration(raw)


# ── Entry point ───────────────────────────────────────────────────────────────

def lambda_handler(event: dict[str, Any], context: object) -> dict[str, Any]:
    """Entry point — routes gateway, async, interact_gateway, and interact_async modes."""
    mode = event.get("mode")
    handlers = {
        "async": _handle_async,
        "interact_async": _handle_interact_async,
    }
    if mode in handlers:
        return handlers[mode](event)
    if event.get("interact"):
        return _handle_interact_gateway(event)
    return _handle_gateway(event)


# ── Slash command gateway ─────────────────────────────────────────────────────

def _handle_gateway(event: dict[str, Any]) -> dict[str, Any]:
    """Verify signature, ACK, self-invoke async for all slash commands."""
    raw_body = event.get("body", "") or ""
    if event.get("isBase64Encoded"):
        raw_body = base64.b64decode(raw_body).decode("utf-8")
    headers = {k.lower(): v for k, v in (event.get("headers") or {}).items()}

    valid = _verify_slack_signature(
        headers.get("x-slack-signature", ""),
        headers.get("x-slack-request-timestamp", ""),
        raw_body,
    )
    if not valid:
        logger.warning("Invalid Slack signature")
        return {"statusCode": 403, "body": ""}

    params = {k: v[0] for k, v in parse_qs(raw_body).items()}
    try:
        _lambda_client.invoke(
            FunctionName=os.environ.get("AWS_LAMBDA_FUNCTION_NAME", ""),
            InvocationType="Event",
            Payload=json.dumps({
                "mode": "async",
                "command": params.get("command", ""),
                "text": params.get("text", "").strip(),
                "caller_slack_id": params.get("user_id", ""),
                "channel_id": params.get("channel_id", ""),
                "response_url": params.get("response_url", ""),
            }).encode(),
        )
        result = _ack()
    except Exception:
        logger.exception("Failed to self-invoke async")
        result = _ephemeral("Something went wrong. Please try again in a moment.")

    return result


def _handle_async(event: dict[str, Any]) -> dict[str, Any]:
    """Route async slash command to the right handler."""
    try:
        command = event["command"]
        text = event.get("text", "")
        caller_slack_id = event["caller_slack_id"]
        channel_id = event.get("channel_id", "")
        response_url = event["response_url"]
    except KeyError:
        logger.exception("Malformed async payload")
        return {"statusCode": 200}

    try:
        if command == "/bedrock-spend":
            _async_spend(caller_slack_id, channel_id, response_url)
        elif command in ("/bedrock-block", "/bedrock-unblock", "/bedrock-limit"):
            _async_admin_command(command, text, caller_slack_id, channel_id, response_url)
        else:
            _post_result(f"Unknown command: {command}", response_url, channel_id, caller_slack_id)
    except Exception:
        logger.exception("Error in async handler for %s", command)
        _post_result(
            "There was a problem handling that command. Please try again.",
            response_url, channel_id, caller_slack_id,
        )

    return {"statusCode": 200}


def _async_spend(caller_slack_id: str, channel_id: str, response_url: str) -> dict[str, Any]:
    """Handle /bedrock-spend."""
    from notifier import slash_command_text
    username = _resolve_username(caller_slack_id)
    if not username:
        _post_result(
            "Couldn't identify your Slack account for this request.",
            response_url, channel_id, caller_slack_id,
        )
        return {"statusCode": 200}
    spend = _get_spend(username)
    limit, limit_expires_at = _get_limit_and_expiry(username)
    _post_result(
        slash_command_text(spend, limit, limit_expires_at),
        response_url, channel_id, caller_slack_id,
    )
    return {"statusCode": 200}


def _async_admin_command(
    command: str, text: str, caller_slack_id: str, channel_id: str, response_url: str
) -> dict[str, Any]:
    """Parse admin commands and post a Block Kit confirmation prompt."""
    if not _is_admin(caller_slack_id):
        _post_response_url(
            response_url,
            "That command is reserved for administrators.",
        )
        return {"statusCode": 200}

    blocks = _parse_admin_command(command, text, response_url)
    if blocks is None:
        return {"statusCode": 200}

    client = WebClient(token=os.environ["SLACK_BOT_TOKEN"])
    try:
        client.chat_postEphemeral(
            channel=channel_id,
            user=caller_slack_id,
            blocks=blocks,
            text="Confirmation required",
        )
    except Exception:
        logger.exception("Failed to post confirmation prompt")
        _post_response_url(response_url, "Failed to show confirmation. Please try again.")

    return {"statusCode": 200}


def _parse_admin_command(
    command: str, text: str, response_url: str
) -> list[dict[str, Any]] | None:
    """Parse the command text and return confirmation blocks, or None if already responded."""
    parts = text.split()

    if command == "/bedrock-block":
        return _parse_block_command(parts, response_url)
    if command == "/bedrock-unblock":
        return _parse_unblock_command(parts, response_url)
    return _parse_limit_command(parts, response_url)


def _parse_block_command(
    parts: list[str], response_url: str
) -> list[dict[str, Any]] | None:
    """Parse /bedrock-block args and return confirm blocks, or None if already responded."""
    if not parts:
        _post_response_url(
            response_url,
            f"Usage: `/bedrock-block <username> [duration]`\n"
            f"Valid durations: {_VALID_DURATIONS} (omit for indefinite)",
        )
        return None
    username = parts[0]
    raw_duration = parts[1] if len(parts) > 1 else ""
    parsed = _parse_duration(raw_duration)
    if parsed is None:
        _post_response_url(
            response_url,
            f"Unknown duration `{raw_duration}`. Valid durations: {_VALID_DURATIONS}",
        )
        return None
    td, label = parsed
    until_iso: str | None = (datetime.now(timezone.utc) + td).isoformat() if td else None
    description = f"Block *{username}* from Bedrock for *{label}*?"
    if until_iso:
        description += f"\nAccess restored after: {until_iso[:16]} UTC"
    return _confirm_blocks("block", description, {"username": username, "until_iso": until_iso, "label": label})


def _parse_unblock_command(
    parts: list[str], response_url: str
) -> list[dict[str, Any]] | None:
    """Parse /bedrock-unblock args and return confirm blocks, or None if already responded."""
    if not parts:
        _post_response_url(response_url, "Usage: `/bedrock-unblock <username>`")
        return None
    username = parts[0]
    return _confirm_blocks("unblock", f"Remove the manual block on *{username}*?", {"username": username})


def _limit_amount_error(amount: float) -> str | None:
    """Return a rejection message if amount is not a valid daily limit, else None.

    Single source of truth for amount validation, shared by the parse-time
    `_validate_limit_amount` and the execution-time re-check in `_execute_action`
    (defense-in-depth against a tampered/replayed button value bypassing the
    parse-time check). Rejects:
      - non-finite values — `float("nan") > MAX_SETTABLE_LIMIT` is False, so a
        forged `"amount": "nan"` would otherwise write nan into daily_limit_usd
        and silently zero out enforcement (every spend comparison vs nan is False);
        `inf`/`-inf` are likewise not real limits.
      - non-positive values.
      - values above the ceiling.
    """
    if not math.isfinite(amount) or amount <= 0:
        return f"Invalid amount: `{amount}`. Please provide a positive number."
    if amount > MAX_SETTABLE_LIMIT:
        return (
            f"${amount:.0f} exceeds the maximum settable daily limit of "
            f"${MAX_SETTABLE_LIMIT:.0f}. Please choose a lower figure."
        )
    return None


def _validate_limit_amount(raw: str) -> tuple[float | None, str | None]:
    """Validate a /bedrock-limit amount string.

    Returns (amount, None) when valid, or (None, error_message) when not —
    keeping all the rejection branches here so the caller stays under the
    3-return limit.

    Strips a leading currency symbol before parsing (e.g. "$300") — the bot's
    own confirmation/result messages format amounts with a leading "$" (e.g.
    "set limit to *$300*"), so admins pasting that format back in should not
    be rejected. Thousands-separator commas (e.g. "$1,000") are also stripped
    as a convenience for manually-typed amounts — the bot's own messages don't
    use comma formatting (f"${amount:.0f}" prints "$1000", not "$1,000").
    """
    cleaned = raw.strip().lstrip("$").replace(",", "")
    try:
        amount = float(cleaned)
    except ValueError:
        return None, f"Invalid amount: `{raw}`. Please provide a positive number."
    error = _limit_amount_error(amount)
    return (None, error) if error else (amount, None)


def _build_limit_confirmation(
    username: str, amount: float, td: timedelta | None, label: str, jira_ticket: str | None
) -> list[dict[str, Any]]:
    """Build the /bedrock-limit confirmation blocks for an already-validated amount+duration."""
    expires_at: str | None = (datetime.now(timezone.utc) + td).isoformat() if td else None
    direction = "raise" if amount > DEFAULT_DAILY_LIMIT else "lower"
    description = (
        f"Set *{username}*'s daily limit to *${amount:.0f}*"
        f" (default is ${DEFAULT_DAILY_LIMIT:.0f})?\nThis will *{direction}* their limit "
        f"for *{label}*."
    )
    if expires_at:
        description += f"\nReverts to default after: {expires_at[:16]} UTC"
    if jira_ticket:
        description += f"\nJira ticket: *{jira_ticket}*"
    return _confirm_blocks(
        "limit", description,
        {
            "username": username, "amount": amount, "expires_at": expires_at,
            "duration_label": label, "jira_ticket": jira_ticket,
        },
    )


def _validate_jira_ticket(parts: list[str]) -> tuple[str | None, str | None]:
    """Validate the optional 4th /bedrock-limit arg as a PROJECT-123-style Jira ticket.

    Returns (jira_ticket, None) when valid or absent, or (None, error_message) when not.
    Extra tokens beyond the 4th (e.g. a fat-fingered `TICKET 1234` with a space instead
    of a hyphen) are rejected rather than silently dropped — silently storing the
    truncated "TICKET" would defeat the point of a traceable ticket reference.
    Normalizes to uppercase so `ticket-1234` and `TICKET-1234` are equivalent.
    """
    if len(parts) > 4:
        return None, (
            f"Unexpected extra argument `{' '.join(parts[4:])}` after the Jira ticket. "
            "Did you mean to write it without a space, e.g. `TICKET-1234`?"
        )
    if len(parts) <= 3:
        return None, None
    raw_ticket = parts[3]
    is_valid = bool(_JIRA_TICKET_RE.match(raw_ticket))
    error = None if is_valid else f"Invalid Jira ticket: `{raw_ticket}`. Expected format like `TICKET-1234`."
    return (raw_ticket.upper() if is_valid else None), error


def _validate_limit_args(
    parts: list[str],
) -> tuple[str, float, timedelta | None, str, str | None, str | None]:
    """Validate a /bedrock-limit amount + optional duration + optional jira ticket.

    Returns (username, amount, timedelta_or_None, duration_label, jira_ticket, error_message).
    error_message is None on success; the other fields are only meaningful then —
    keeping every rejection branch here so _parse_limit_command stays under the
    3-return limit, same rationale as _validate_limit_amount.
    """
    username = parts[0]
    amount, amount_error = _validate_limit_amount(parts[1])
    if amount_error:
        return username, 0.0, None, "", None, amount_error
    raw_duration = parts[2] if len(parts) > 2 else ""
    parsed = _parse_limit_duration(raw_duration)
    if parsed is None:
        error = f"Unknown duration `{raw_duration}`. Use `Nd`, `Nw`, `Nmo`, or `never`."
        return username, amount, None, "", None, error
    td, label = parsed
    jira_ticket, ticket_error = _validate_jira_ticket(parts)
    if ticket_error:
        td, label, jira_ticket = None, "", None
    return username, amount, td, label, jira_ticket, ticket_error


def _parse_limit_command(
    parts: list[str], response_url: str
) -> list[dict[str, Any]] | None:
    """Parse /bedrock-limit args and return confirm blocks, or None if already responded."""
    if len(parts) < 2:
        _post_response_url(
            response_url,
            "Usage: `/bedrock-limit <username> <amount> [duration|never] [jira_ticket]`\n"
            "Example: `/bedrock-limit jane.smith 300` (defaults to "
            f"{DEFAULT_LIMIT_EXPIRY_DAYS} days)\n"
            "Example: `/bedrock-limit jane.smith 300 90d`\n"
            "Example: `/bedrock-limit jane.smith 300 never`\n"
            "Example: `/bedrock-limit jane.smith 300 30d TICKET-1234`",
        )
        return None
    username, amount, td, label, jira_ticket, error = _validate_limit_args(parts)
    if error:
        _post_response_url(response_url, error)
        return None
    return _build_limit_confirmation(username, amount, td, label, jira_ticket)


# ── Interaction gateway (button callbacks) ────────────────────────────────────

def _handle_interact_gateway(event: dict[str, Any]) -> dict[str, Any]:
    """Verify signature on button callback, ACK, self-invoke async."""
    raw_body, headers = _decode_request(event)
    if not _verify_slack_signature(
        headers.get("x-slack-signature", ""),
        headers.get("x-slack-request-timestamp", ""),
        raw_body,
    ):
        logger.warning("Invalid Slack signature on interact")
        return {"statusCode": 403, "body": ""}

    return _dispatch_interact(raw_body)


def _decode_request(event: dict[str, Any]) -> tuple[str, dict[str, str]]:
    """Decode raw body and normalise headers from an API Gateway event."""
    raw_body = event.get("body", "") or ""
    if event.get("isBase64Encoded"):
        raw_body = base64.b64decode(raw_body).decode("utf-8")
    headers = {k.lower(): v for k, v in (event.get("headers") or {}).items()}
    return raw_body, headers


def _dispatch_interact(raw_body: str) -> dict[str, Any]:
    """Parse the interaction payload and fire async self-invoke."""
    params = parse_qs(raw_body)
    payload_raw = params.get("payload", [""])[0]
    try:
        payload = json.loads(payload_raw)
    except Exception:
        logger.exception("Failed to parse interaction payload")
        return {"statusCode": 400, "body": ""}

    actions = payload.get("actions", [])
    if not actions:
        return _ack()

    action = actions[0]
    try:
        _lambda_client.invoke(
            FunctionName=os.environ.get("AWS_LAMBDA_FUNCTION_NAME", ""),
            InvocationType="Event",
            Payload=json.dumps({
                "mode": "interact_async",
                "action_id": action.get("action_id"),
                "value": action.get("value", ""),
                "caller_slack_id": payload.get("user", {}).get("id", ""),
                "channel_id": payload.get("channel", {}).get("id", ""),
                "response_url": payload.get("response_url", ""),
            }).encode(),
        )
        result = _ack()
    except Exception:
        logger.exception("Failed to self-invoke interact async")
        result = _ephemeral(
            "There was a problem dispatching that action. Please try again."
        )
    return result


def _handle_interact_async(event: dict[str, Any]) -> dict[str, Any]:
    """Execute confirmed admin action."""
    logger.info(
        "interact_async received: action_id=%s caller=%s channel=%s response_url_present=%s",
        event.get("action_id"),
        event.get("caller_slack_id"),
        event.get("channel_id"),
        bool(event.get("response_url")),
    )
    try:
        action_id = event["action_id"]
        value = event["value"]
        caller_slack_id = event["caller_slack_id"]
        channel_id = event.get("channel_id", "")
        response_url = event.get("response_url", "")
    except KeyError as exc:
        logger.exception(
            "Malformed interact_async payload: missing key %s — action_id=%s caller=%s",
            exc,
            event.get("action_id"),
            event.get("caller_slack_id"),
        )
        return {"statusCode": 200}

    _dispatch_confirmed_action(action_id, value, caller_slack_id, channel_id, response_url)
    return {"statusCode": 200}


def _dispatch_confirmed_action(
    action_id: str | None, value: str, caller_slack_id: str, channel_id: str, response_url: str
) -> None:
    """Validate and execute a confirmed button action."""
    if action_id == "cancel_action" or value == "cancel":
        # The cancel ACK is already posted by the interaction gateway; nothing more to do.
        logger.info("cancel_action received from %s — no-op (already ACKed by the interaction gateway)", caller_slack_id)
        return

    if not _is_admin(caller_slack_id):
        _post_result(
            "That action is reserved for administrators.",
            response_url, channel_id, caller_slack_id,
        )
        return

    _run_validated_action(value, response_url, channel_id, caller_slack_id)


def _run_validated_action(value: str, response_url: str, channel_id: str, caller_slack_id: str) -> None:
    """Parse, validate and run the action payload."""
    try:
        data = json.loads(value)
    except Exception:
        logger.exception("Failed to parse action value")
        _post_result("Something went wrong. Please try again.", response_url, channel_id, caller_slack_id)
        return

    action = data.get("action")
    username = data.get("username", "")
    if not _VALID_USERNAME.match(username):
        logger.error("Rejecting interact_async: invalid username %r (action=%s)", username, action)
        _post_result(f"Invalid username: `{username}`. Action rejected.", response_url, channel_id, caller_slack_id)
        return

    try:
        _execute_action(action, username, data, response_url, channel_id, caller_slack_id)
    except Exception:
        logger.exception("Error executing action %s for %s", action, username)
        _post_result(
            "There was a problem executing that action. Please try again.",
            response_url, channel_id, caller_slack_id,
        )


def _execute_action(
    action: str | None, username: str, data: dict[str, Any],
    response_url: str, channel_id: str, caller_slack_id: str
) -> None:
    """Execute a confirmed admin action and post the result."""
    if action == "block":
        until_iso = data.get("until_iso")
        label = data.get("label", "indefinitely")
        _apply_block(username, until_iso)
        _invoke_enforcement_lambda()
        logger.info("Blocked %s for %s by %s", username, label, caller_slack_id)
        _post_result(
            f"Done — *{username}* has been blocked from Bedrock for *{label}*. "
            f"The enforcement policies will be updated momentarily.",
            response_url, channel_id, caller_slack_id,
        )
    elif action == "unblock":
        _remove_block(username)
        _invoke_enforcement_lambda()
        logger.info("Unblocked %s by %s", username, caller_slack_id)
        _post_result(
            f"The block on *{username}* has been lifted. "
            f"Normal spend-based enforcement resumes on the next run (within 15 minutes).",
            response_url, channel_id, caller_slack_id,
        )
    elif action == "limit":
        amount = float(data["amount"])
        # Re-validate at execution time: the button `value` is client-controlled
        # JSON, so a tampered/replayed confirm could carry an amount the parse-time
        # check never saw — including nan/inf, which slip a naive ceiling check.
        amount_error = _limit_amount_error(amount)
        if amount_error:
            logger.error(
                "Rejecting invalid limit %r for %s at execution time (caller=%s)",
                amount, username, caller_slack_id,
            )
            _post_result(amount_error, response_url, channel_id, caller_slack_id)
            return
        expires_at = data.get("expires_at")
        duration_label = data.get("duration_label", "never")
        jira_ticket = data.get("jira_ticket")
        _set_limit(username, amount, caller_slack_id, expires_at, jira_ticket)
        logger.info(
            "Set limit for %s to $%.0f (expires: %s, ticket: %s) by %s",
            username, amount, expires_at or "never", jira_ticket or "none", caller_slack_id,
        )
        expiry_note = (
            f" This reverts to the ${DEFAULT_DAILY_LIMIT:.0f} default in *{duration_label}*."
            if expires_at else " This limit does not expire."
        )
        ticket_note = f" Jira ticket: *{jira_ticket}*." if jira_ticket else ""
        _post_result(
            f"Done — *{username}*'s daily limit has been set to *${amount:.0f}*."
            f"{expiry_note}{ticket_note} The change takes effect on the next run (within 15 minutes).",
            response_url, channel_id, caller_slack_id,
        )
    else:
        _post_result(
            f"Unrecognised action: `{action}`",
            response_url, channel_id, caller_slack_id,
        )
