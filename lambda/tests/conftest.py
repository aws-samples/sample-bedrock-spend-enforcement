# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""Shared test setup for lambda/tests.

Two concerns are handled here, both needed before any test module can safely
`import handler`:

1. ATHENA_RESULTS_BUCKET and SLACK_EMAIL_DOMAIN are required environment
   variables (no hardcoded default — see handler.py and notifier.py). Set
   placeholders before those modules are imported so collection doesn't blow
   up with a KeyError.

2. handler.T1_POLICY_ARN / handler.T2_POLICY_ARN resolve the running AWS
   account via STS at import time (see handler._enforcement_account_id), so a
   reader can deploy this Lambda into their own account with zero extra
   config. Tests must never depend on — or accidentally call out to — a real
   AWS account, so boto3.client is patched just long enough for that one
   import to resolve deterministically to the standard example account ID,
   then restored to the real implementation for everything else.
"""
import os
import sys
from unittest.mock import MagicMock, patch

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

os.environ.setdefault("ATHENA_RESULTS_BUCKET", "s3://example-athena-results/")
os.environ.setdefault("SLACK_EMAIL_DOMAIN", "example.com")

import notifier  # noqa: F401,E402 # lgtm[py/unused-import]


def _fake_sts_client(service_name: str, *args: object, **kwargs: object) -> MagicMock:
    """Stand in for boto3.client during handler's module-level STS lookup."""
    if service_name == "sts":
        sts = MagicMock()
        sts.get_caller_identity.return_value = {"Account": "123456789012"}
        return sts
    raise AssertionError(f"unexpected boto3.client({service_name!r}) call during handler import")


with patch("boto3.client", side_effect=_fake_sts_client):
    import handler  # noqa: F401 # lgtm[py/unused-import]  (resolves T1_POLICY_ARN/T2_POLICY_ARN once, deterministically)
