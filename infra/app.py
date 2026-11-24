#!/usr/bin/env python3
"""CDK app for HOLD.

Deploy (requires AWS credentials and Docker for the local image asset):

    cd infra
    python -m pip install -r requirements.txt
    cdk bootstrap
    cdk deploy

This stack creates the AgentCore Runtime, the Bedrock Guardrail, the immutable
ledger bucket, the incident table, the notification topic and the human-plane
Cognito groups. It deliberately does not grant the runtime role any data-plane
permission: the agent reaches state only through the tool boundary.
"""

from __future__ import annotations

import aws_cdk as cdk

from hold_stack import HoldStack

app = cdk.App()
env = cdk.Environment(
    account=app.node.try_get_context("account") or None,
    region=app.node.try_get_context("region") or "us-east-1",
)

HoldStack(
    app,
    "HoldContainmentStack",
    env=env,
    description="HOLD containment agent: AgentCore Runtime, Guardrail, immutable ledger and human plane.",
)

app.synth()
