"""HOLD - a containment agent whose authority only ever tightens.

A food-safety recall agent built on Amazon Bedrock AgentCore. It can place
holds, widen a recall, notify affected accounts and escalate. It cannot release
product, narrow scope, delete a record or export data, and no amount of prompt
text changes that: the capability lives in the identity the agent runs as and in
a lattice check on the state transition, not in the model's instructions.
"""

__version__ = "1.0.0"
__all__ = ["__version__"]
