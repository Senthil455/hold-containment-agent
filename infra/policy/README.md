# Gateway policy set (optional outer layer)

These Cedar policies are the production form of the **POLICY** layer shown in
the console. They are intentionally kept out of `hold_stack.py`: a Gateway with
no registered tool-plane target is an empty control, and pretending otherwise
would weaken the argument.

When the containment tool plane is registered as an AgentCore Gateway target
named `ContainmentTools`, these policies authorise exactly the eleven agent
tools and explicitly forbid the ten human/admin effects. Cedar is default-deny
and forbid-wins, so the explicit forbids are a second, auditable statement of
the same boundary.

## Attach

Use the AgentCore CLI or the control-plane API:

```bash
agentcore add gateway --name HoldGateway --authorizer-type IAM
agentcore add policy-engine --name HoldPolicy --attach-to-gateways HoldGateway --attach-mode enforce
agentcore add policy --engine HoldPolicy --name deny-release --definition infra/policy/deny_release.cedar
agentcore add policy --engine HoldPolicy --name agent-allowlist --definition infra/policy/agent_allowlist.cedar
```

The action strings use the AgentCore convention
`<target-name>___<tool-name>`, for example
`ContainmentTools___trace_lot`. If the target is renamed, update the action
names with it; a mismatched name is a policy that silently matches nothing.

## What this layer does not do

It does not replace the kernel. A Cedar permit means "this principal may ask";
it does not mean the request is safe. The kernel still checks capability,
schema, scope, rate, the containment lattice and the human co-signature. The
stress suite deliberately phrases several attacks to pass the upstream layers so
that the inner boundary is the thing being tested.
