# Production readiness review

Reviewed: 2026-11-24/25. This is a functional and safety audit of the repository,
not a claim that the deployed AWS path has been exercised. The live path was not
available because no AWS credentials, CDK CLI or Docker daemon were present in the
review environment.

## Verified locally

| Check | Result |
|---|---|
| `python -m unittest discover -s tests -v` | 83 tests, OK |
| `python -m evals.run_stress --print` | 18/18 passed, 0 released, chain OK |
| `python scripts/smoke.py` | expected state, 19-entry chain, SMOKE OK |
| `python -m compileall -q hold agent evals demo infra tests config` | OK |
| `python -m build --wheel` + `python scripts/verify_wheel.py` | wheel contains runtime and guardrail config |
| Installed-wheel `hold.guardrail.load_config()` | resolves packaged `config/guardrail.json` |
| Demo API regression matrix | all checks passed |
| Agent capability denials | `release_hold`, `narrow_recall`, `approve_disposition`, `close_incident`, delete/export/external-write denied |
| Human co-signature edge cases | missing, replayed, expired, payload-mismatch and self-approval refused |
| Ledger tamper drill on an empty ledger | HTTP 200, no crash |

## Defects fixed in this pass

1. **Never-held lots could be released.** `release_hold` now requires every lot
   to be currently held. Never-held, already-released and dispositioned lots are
   refused with `NOT_HELD`.
2. **`approve_disposition(RELEASE)` did not release.** It now adds the lots to
   the released set and removes them from containment.
3. **Destroyed/reworked lots reported `SHIPPABLE`.** A new `DISPOSITIONED` lot
   state is recorded, surfaced in the status payload and rendered by the demo.
4. **`close_incident` claimed closure while containment was active.** Closure now
   requires no held or recalled lots, sets an explicit `closed` flag and is
   refused with `ACTIVE_CONTAINMENT` otherwise. A new hold reopens the incident.
5. **Empty-ledger tamper drill crashed the API.** The demo drill now handles an
   empty or single-entry ledger, and `_tamper_for_demo` bounds-checks its input.
6. **No default co-signature key in the deployed runtime.** `HoldService` now
   requires `HOLD_COSIGN_KEY` or `HOLD_COSIGN_KEY_SECRET_ARN` and refuses to
   start otherwise. The CDK stack generates a Secrets Manager secret and grants
   the runtime read-only access to it.
7. **Cross-region inference-profile ARN used the stack account.** System-defined
   profiles use an empty account segment; the IAM resource now matches that.
8. **`config/guardrail.json` was absent from an installed wheel.** `config` is
   now a package with the JSON as package data, and the loader resolves either
   the checkout or the installed package.
9. **Smoke and stress could pass with a broken prerequisite.** Smoke now asserts
   the expected final state and exits non-zero on mismatch. A stress case with a
   blocked prerequisite now fails instead of being counted as a pass.
10. **Container ran as root.** The image now runs as an unprivileged `hold` user
    and has a `.dockerignore`.

## Blocking gaps before production

These are not cosmetic. They are the difference between a strong local
demonstration and a system that can carry a real recall.

1. **State and ledger are in memory.** `AuthorityKernel` and `Ledger` are
   process-local. The CDK stack provisions DynamoDB and an S3 Object Lock bucket,
   but the runtime has no persistence code and deliberately no data-plane
   permission. A restart loses the incident, and two instances diverge. The
   audit trail is therefore not durable. The kernel and ledger are serialized
   within one process, but two tasks have independent state and independent
   cosign replay caches. Implement the DynamoDB conditional-write state store and
   the S3 WORM ledger writer, then grant the tool plane (not the model runtime)
   those permissions.
2. **The demo human console is unauthenticated.** `/api/human/action` accepts a
   request, mints its own co-signature and acts as the QA Director. It binds to
   loopback by default, but it must never be exposed. Production needs Cognito /
   OIDC authentication, WebAuthn approval, and token issuance outside the agent
   process. The deployed runtime now loads a generated HMAC key from Secrets
   Manager, so the public fallback is gone, but the signer is still symmetric;
   the documented asymmetric KMS signer with a verify-only runtime is not wired.
3. **Notifications and escalations are simulated.** `notify_customers` updates
   the containment state but does not publish to SNS. `escalate_incident` creates
   an in-memory task. The SNS topic exists, but no tool-plane service publishes
   to it and no queue receives escalations. Wire these before relying on the
   system to contact customers.
4. **The live AgentCore path is untested.** No AWS account was available, so
   `cdk deploy`, the live Bedrock Converse loop and the AgentCore runtime
   contract were not executed. `cdk synth` was executed locally with
   `aws-cdk-lib==2.278.0` and the template was inspected, but synthesis is not
   deployment: the IAM policy shape and the Secrets Manager wiring are not
   deployment-proven.
5. **Dependencies are not pinned.** `agent/requirements.txt` uses ranges and the
   base image is a floating tag. Produce a lockfile with hashes, pin the base
   image digest and scan the image before release.
6. **Only Python 3.14 was available locally.** CI targets 3.12. Run the suite on
   the exact production interpreter before release.
7. **Rate limiting and request state are per process.** The notification token
   bucket and pending release requests do not survive a restart and do not span
   instances. Move them to a shared store if the runtime scales beyond one task.
8. **No production observability.** There are no CloudWatch alarms, no ledger
   head publication, no dead-letter queue and no alert when the chain fails to
   verify. Add them before go-live.

## Recommendation

The containment kernel and its refusal paths are ready for a controlled pilot.
The system as a whole is **not yet production-ready** for a real recall until
items 1, 2 and 3 above are implemented and the live AWS path has been deployed
and exercised in a non-production account.
