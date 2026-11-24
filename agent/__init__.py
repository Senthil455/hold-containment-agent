"""AgentCore entrypoint for HOLD.

The agent is deliberately thin. It can choose among already-scoped tools, but
every decision about what those tools are allowed to do is made outside the
model by the containment kernel in ``hold/``.
"""
