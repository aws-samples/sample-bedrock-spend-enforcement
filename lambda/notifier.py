# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""
Bedrock spend notifications and /bedrock-spend slash command responses.

Sends one DM per tier transition (warn/t1/t2). Resolves SSO username to Slack
user ID via users.lookupByEmail (username@${SLACK_EMAIL_DOMAIN}).
"""

import logging
import os
import secrets

logger = logging.getLogger(__name__)

# No default: every deployment has a different corporate email domain, and a
# silently-wrong default would resolve every lookup to the wrong Slack workspace.
SLACK_EMAIL_DOMAIN = os.environ["SLACK_EMAIL_DOMAIN"]

# ── Tier copy ──────────────────────────────────────────────────────────────────
#
# Three variants per tier purely for a bit of message variety across repeated
# notifications — no substitution placeholder beyond ${spend}/${limit}.

_WARN_MESSAGES = [
    (
        "Your Bedrock spend is at *${spend}* today — about 70% of the ${limit} daily limit. "
        + "Claude Opus, Sonnet, and Haiku all remain available. This is just a heads-up."
    ),
    (
        "Heads-up: your Bedrock spend has reached *${spend}*, roughly 70% of today's ${limit} limit. "
        + "Claude Opus, Sonnet, and Haiku are still fully available."
    ),
    (
        "Your Bedrock usage has crossed 70% of the daily limit — *${spend}* of ${limit} so far. "
        + "No models have been restricted yet."
    ),
]

_T1_MESSAGES = [
    (
        "Your Bedrock spend has reached *${spend}*, crossing the 80% threshold. Claude Opus has "
        + "been disabled for the rest of the day. Claude Sonnet and Haiku remain available. "
        + "Access resets at 0400 UTC."
    ),
    (
        "At *${spend}* today, your Bedrock usage has hit the 80% threshold and Claude Opus is now "
        + "unavailable until the daily reset at 0400 UTC. Claude Sonnet and Haiku are unaffected."
    ),
    (
        "Claude Opus has been withdrawn for the remainder of the day — your spend reached *${spend}*. "
        + "Claude Sonnet and Haiku remain in service. The limit resets at 0400 UTC."
    ),
]

_T2_MESSAGES = [
    (
        "Your Bedrock spend has reached the daily limit of *${spend}*. Claude Opus and Sonnet have "
        + "both been disabled until the reset at 0400 UTC. Claude Haiku remains available."
    ),
    (
        "The daily Bedrock limit has been reached — *${spend}* today. Claude Opus and Sonnet are "
        + "unavailable for the rest of the day. Claude Haiku remains in service. Access resets at "
        + "0400 UTC."
    ),
    (
        "You've reached today's Bedrock limit (*${spend}*). Claude Opus and Sonnet are now disabled "
        + "until 0400 UTC. Claude Haiku is still available."
    ),
]

# ── Message selection ─────────────────────────────────────────────────────────

def _pick(messages: list[str], spend_usd: float, limit_usd: float) -> str:
    """Pick a random message and substitute spend/limit placeholders."""
    text = messages[secrets.randbelow(len(messages))]
    return text.replace("${spend}", f"${spend_usd:.2f}").replace("${limit}", f"${limit_usd:.0f}")


def spend_warning_text(spend_usd: float, limit_usd: float) -> str:
    """70% warning — all models still available."""
    return _pick(_WARN_MESSAGES, spend_usd, limit_usd)


def t1_blocked_text(spend_usd: float, limit_usd: float) -> str:
    """80% threshold — Opus withdrawn."""
    return _pick(_T1_MESSAGES, spend_usd, limit_usd)


def t2_blocked_text(spend_usd: float, limit_usd: float) -> str:
    """100% limit — Opus and Sonnet withdrawn."""
    return _pick(_T2_MESSAGES, spend_usd, limit_usd)


def slash_command_text(
    spend_usd: float, limit_usd: float, limit_expires_at: str | None = None,
) -> str:
    """Ephemeral /bedrock-spend response — content varies by current spend tier.

    limit_expires_at (ISO-8601 UTC), when given, appends a note about when the
    caller's custom daily limit reverts to the default.
    """
    t1 = limit_usd * 0.80
    pct = int(spend_usd / limit_usd * 100) if limit_usd else 0

    if spend_usd >= limit_usd:
        msg = (
            f"Your spend has reached the daily limit of ${limit_usd:.0f} — *${spend_usd:.2f}* in "
            f"total. Claude Opus and Sonnet are both unavailable until 0400 UTC. "
            f"Claude Haiku remains available."
        )
    elif spend_usd >= t1:
        msg = (
            f"Your spend stands at *${spend_usd:.2f}* — {pct}% of the ${limit_usd:.0f} daily "
            f"allowance. Claude Opus has been withdrawn for the day. Claude Sonnet and Haiku "
            f"remain available; Sonnet would follow Opus at ${limit_usd:.0f}. The account resets "
            f"at 0400 UTC."
        )
    elif spend_usd >= limit_usd * 0.70:
        msg = (
            f"Your spend stands at *${spend_usd:.2f}* — {pct}% of the ${limit_usd:.0f} daily "
            f"allowance. All models are available for now. Opus would be withdrawn at "
            f"${t1:.0f} and Sonnet at ${limit_usd:.0f}. Haiku is never restricted."
        )
    else:
        msg = (
            f"Your Bedrock spend stands at *${spend_usd:.2f}* — {pct}% of the ${limit_usd:.0f} "
            f"daily allowance. Claude Opus, Sonnet, and Haiku all remain available. "
            f"Nothing to report."
        )
    if limit_expires_at:
        msg += f" (This custom limit reverts to the default on {limit_expires_at[:10]}.)"
    return msg


# ── Slack DM / channel ────────────────────────────────────────────────────────

def _slack_client() -> "WebClient":  # type: ignore[name-defined]
    """Return an authenticated Slack WebClient.

    Wired with slack_sdk's built-in RateLimitErrorRetryHandler: on a 429, the
    SDK reads Slack's Retry-After header and sleeps that long before retrying,
    up to max_retry_count times. Capped at 2 (not the library default of
    unbounded backoff growth) so a sustained rate-limit doesn't eat the
    Lambda's timeout — callers are expected to leave a call uncached on
    failure and let the next scheduled run pick it back up.
    """
    from slack_sdk import WebClient
    from slack_sdk.http_retry.builtin_handlers import RateLimitErrorRetryHandler
    return WebClient(
        token=os.environ["SLACK_BOT_TOKEN"],
        retry_handlers=[RateLimitErrorRetryHandler(max_retry_count=2)],
    )


def _resolve_slack_user_id(username: str) -> str | None:
    """Resolve SSO username → Slack user ID via email lookup."""
    slack_id, _definite_not_found = resolve_slack_id_with_status(username)
    return slack_id


def resolve_slack_id_with_status(username: str) -> tuple[str | None, bool]:
    """Resolve SSO username → Slack user ID, distinguishing why a lookup failed.

    Returns (slack_id, is_definite_not_found). is_definite_not_found is True only
    when Slack explicitly reported no user matches that email (error
    "users_not_found") — a real negative, safe to cache. Any other failure
    (rate limit exhausted after retry, network error, unexpected exception)
    returns (None, False): "couldn't check right now", not "doesn't exist" —
    callers must not treat this as a confirmed-bad identity.
    """
    from slack_sdk.errors import SlackApiError

    email = f"{username}@{SLACK_EMAIL_DOMAIN}"
    try:
        resp = _slack_client().users_lookupByEmail(email=email)
        return resp["user"]["id"], False
    except SlackApiError as exc:
        error_code = exc.response.get("error") if exc.response else None
        logger.exception("Slack rejected email lookup for %s (%s): %s", username, email, error_code)
        return None, error_code == "users_not_found"
    except Exception:
        logger.exception("Unexpected error resolving Slack user for %s (%s)", username, email)
        return None, False


def send_dm(username: str, text: str) -> None:
    """Send a DM to an SSO username. Silently skips if user cannot be resolved."""
    from slack_sdk.errors import SlackApiError

    user_id = _resolve_slack_user_id(username)
    if not user_id:
        return
    try:
        _slack_client().chat_postMessage(channel=user_id, text=text)
        logger.info("Sent spend DM to %s (%s)", username, user_id)
    except SlackApiError as exc:
        logger.exception("Slack rejected DM to %s (%s): %s", username, user_id, exc.response.get("error"))
    except Exception:
        logger.exception("Unexpected error sending DM to %s (%s)", username, user_id)
