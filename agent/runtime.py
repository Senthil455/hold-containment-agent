"""Amazon Bedrock AgentCore Runtime entrypoint.

Deploy with the CDK stack in ``infra/`` (or ``agentcore configure`` against
this file). The container exposes the HTTP contract AgentCore expects; the
platform handles session routing, scaling, identity and invocation auth.

The entrypoint accepts::

    {"prompt": "What is the status of LOT-2291?"}

and returns the model's answer plus every tool verdict, the containment state
and the current ledger head. A refused tool is a successful invocation with a
DENY verdict; it is not an exception and it does not change state.
"""

from __future__ import annotations

import os
from typing import Any

from agent.service import HoldService

try:  # pragma: no cover - the import only exists inside the deployed runtime
    from bedrock_agentcore.runtime import BedrockAgentCoreApp
except ModuleNotFoundError as exc:  # pragma: no cover
    raise SystemExit(
        "bedrock-agentcore is not installed. "
        "Install agent/requirements.txt or run the demo with `python demo/server.py`."
    ) from exc


app = BedrockAgentCoreApp()
_service: HoldService | None = None


def service() -> HoldService:
    global _service
    if _service is None:
        _service = HoldService()
    return _service


# Fail closed at container start. A missing signing key must stop the runtime,
# not surface as a 500 on the first human-plane request.
service()


def _extract_prompt(payload: Any) -> str:
    if isinstance(payload, str):
        return payload
    if not isinstance(payload, dict):
        return ""
    for key in ("prompt", "input", "text", "message"):
        value = payload.get(key)
        if isinstance(value, str) and value.strip():
            return value
    return ""


@app.entrypoint
def invoke(payload: Any, context: Any = None) -> dict[str, Any]:
    prompt = _extract_prompt(payload)
    if not prompt.strip():
        return {
            "error": "Invalid input: send a JSON object with a non-empty 'prompt' string."
        }
    if len(prompt) > 6000:
        return {"error": "Input exceeds the 6000 character limit. Send the relevant excerpt."}

    result = service().ask(prompt)
    if context is not None:
        result["session_id"] = getattr(context, "session_id", None)
    return result


if __name__ == "__main__":  # pragma: no cover
    # AgentCore supplies the bind address and port.
    app.run()
