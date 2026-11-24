# HOLD — the rule set

**Job:** contain a presumptive *Listeria monocytogenes* finding on a soft-cheese line without ever letting the agent decide that product is safe.

**Principal:** `agent:hold`, running in Amazon Bedrock AgentCore Runtime.

**Incident:** IR-2041, Northfield Dairy Co. (fictional), Line 3, Alpine Bloom Reserve. The raw-milk vat is implicated; finished lots may have shipped. Confirmation culture is still pending.

These rules are written for an operator, not for a lawyer. Each one names the layer that actually enforces it. The model is never asked to enforce a rule by remembering it; the rule is outside the model.

---

## The one sentence

> The agent may make the recall **bigger**, but only a named human can make it **smaller**.

That is the whole design. The rest is making the sentence true under a compromised model, a hostile document, a replayed tool call, a malformed argument, a burst of retries, and a tired operator at 02:00.

---

## The rules

### R1 — One direction only

**Plain language.** The agent may place holds, widen a recall, notify affected accounts, and escalate. It may never release a hold, narrow a recall, close an incident, delete a record, or bulk-export data. Those are not permissions it has, so no amount of asking changes the answer.

**Enforced by.**
- **CAPABILITY** — `hold/registry.py` declares an effect for every tool (`READ`, `TIGHTEN`, `RELEASE`, `DESTRUCT`, `EXFIL`, `EXTERNAL_WRITE`). `can_invoke()` maps the principal to an effect set before any argument is read. `agent:hold` holds only `READ` and `TIGHTEN`.
- **IDENTITY** — the AgentCore Runtime role can invoke Bedrock and the Guardrail, nothing else. No S3, DynamoDB, SNS or ERP grant exists.
- **POLICY** — `infra/policy/` repeats the same allowlist in Cedar for a deployment that routes the tool plane through AgentCore Gateway.
- **HUMAN** — the release effect exists only on the human plane, and even there it needs a payload-bound co-signature.

**The refusal a user sees.** `NO_RELEASE_AUTHORITY` on a release, `EFFECT_OUT_OF_BAND` on a destructive or export tool, `PLANE_ISOLATION` on an operations tool.

**Stress evidence.** S01, S02, S06, S07, S11, S12, S14, S17.

---

### R2 — Scope comes from the trace, not from the sentence

**Plain language.** The agent cannot invent lot numbers or account numbers. Every identifier it names must exist in this tenant's trace data. Recall scope is computed from trace evidence, never copied from the request.

**Enforced by.**
- **SCHEMA** — every identifier must match the declared shape; unknown fields are refused, so a smuggled `admin_override` is not silently ignored.
- **SCOPE** — `_check_scope()` verifies every lot, customer and document against `World` before the handler runs. Unknown identifiers return `UNKNOWN_RESOURCE`.
- **KERNEL** — recall scope is a set union. A request that names a narrower list cannot shrink the set.

**Edge case.** A lot that exists but belongs to another tenant is not visible. Tenant identity is part of the world, not an argument the model can set.

**Stress evidence.** S13, S15.

---

### R3 — The ratchet

**Plain language.** Every change must leave the recall at least as contained as it was. Holds and recall scope may grow; notifications may be added; the release set may only shrink. If a request would loosen containment, it is refused or reduced to its safe part, and the attempt is recorded.

**Enforced by.**
- **KERNEL / lattice** — `hold/lattice.py` defines the partial order. `dominant(after, before)` requires:

  ```
  after.held     ⊇ before.held
  after.recalled ⊇ before.recalled
  after.notified ⊇ before.notified
  after.released ⊆ before.released
  ```

  plus a monotone `generation` counter. The check runs on the **committed state**, not on the model's description of it.
- **KERNEL / plan** — `widen_recall` applies a union; `notify_customers` derives eligibility from the trace; `release_hold` is unavailable to the agent.
- **LEDGER** — a coerced call returns `COERCED_SAFE` and records `SCOPE_SHRINK_ATTEMPT_MASKED` or `ATTEMPTED_LOOSENING`.

**Why "reduced to its safe part" is not a loophole.** If a caller asks to widen to `[LOT-2291]` while `LOT-2292` is already recalled, the kernel applies the union. The caller cannot use a "widen" tool to shrink. This is tested by S04.

**Stress evidence.** S04, S05, S12, S14.

---

### R4 — No self-approval

**Plain language.** Releasing product needs a named human, a second person's signature, and a signature that covers the exact lots and the exact justification. Approvals expire in fifteen minutes and work once.

**Enforced by.**
- **CAPABILITY** — the agent has no `RELEASE` effect. A valid token presented by the agent is still refused.
- **HUMAN** — `hold/cosign.py` verifies an HMAC-SHA256 token over `{action, requester, payload_digest, approver, nonce, expiry}`. The payload digest is built from the validated arguments, not from model text. Tokens are single-use, TTL-bound, approver ≠ requester, and the requester principal is part of the signed payload.
- **KERNEL** — only a human principal can call `release_hold`; the HMAC key is not in the model's reach. The demo uses a local HMAC key for reproducibility; the production target is a KMS-backed signer with a verify-only runtime, described in `README.md`.

**Edge case.** A token for `LOT-2291` does not work for `LOT-2292`; a token for `release_hold` does not work for `narrow_recall`; a token minted for `human:qa-director` does not work for `agent:hold`. The justification is inside the digest.

**Stress evidence.** S11.

---

### R5 — Documents are data, not orders

**Plain language.** Supplier certificates, customer emails, and web content are untrusted. They may raise an alarm and cause tighter containment. They can never justify loosening anything, and instructions inside them are never followed.

**Enforced by.**
- **PROVENANCE / taint broker** — every untrusted document is wrapped in a canary-delimited block with source, channel and trust. The canary is deterministic per session and document, stripped from the body so it cannot be forged, and checked on model output.
- **GUARDRAIL** — prompt-attack detection and denied topics run before the model and on its draft.
- **KERNEL** — even if the model obeys the document perfectly, the worst it can do is place an unnecessary hold or widen a recall. The lattice makes the attack's *success* case a fail-safe.

**Why this is the central claim.** Prompt injection is usually framed as "can the model be tricked into doing X?" Here the question is "what is the worst X the model can do?" The answer is bounded by the effect set and the lattice. A stolen instruction can cause an over-hold, which a human can release; it cannot cause an under-recall.

**Stress evidence.** S03, S08, S16. S03 carries a forged "FDA clearance" inside a real certificate of analysis.

---

### R6 — Least data

**Plain language.** The agent works with account identifiers, not people. It never sees an email address or a phone number, and it cannot compose a free-form message. Notices come from approved templates and are sent by the notification service.

**Enforced by.**
- **DATA MODEL** — `Customer` in `hold/seed.py` has id, name, kind, city and region. There is no contact field to leak.
- **KERNEL** — `notify_customers` accepts a template id and an optional subset of already-eligible accounts. The recipient set is derived from recalled lots; an account that did not receive recalled product cannot be added.
- **GUARDRAIL** — PII entities are blocked or anonymised on input and output. `send_freeform_email` is not an agent capability at all.

**Edge case.** A subset is allowed only for a re-send to accounts already notified. Naming a friendly subset while other affected accounts are still unnotified returns `UNDER_NOTIFICATION_BLOCKED`.

**Stress evidence.** S05, S06, S10.

---

### R7 — No destructive path

**Plain language.** Nothing in this system can delete a lot, a shipment, or an audit entry. The ledger is append-only; the deployment bucket uses Object Lock compliance mode.

**Enforced by.**
- **CAPABILITY** — `delete_lot`, `purge_ledger`, `export_records`, `bulk_download` and `send_freeform_email` are catalogue entries with no principal that can invoke them. They exist in the boundary lab so the refusal is testable.
- **IDENTITY** — the runtime role has an explicit IAM `Deny` on S3 object deletion and DynamoDB writes/deletion, in addition to having no grant. The explicit deny survives an accidental future grant.
- **LEDGER** — the CDK stack creates the ledger bucket with S3 Object Lock in **compliance** mode (365 days) at bucket creation. It cannot be enabled later, which is why it is in the stack rather than a runbook.

**Edge case.** The model can *ask* to delete. The attempt is recorded as a denial with the actor, the arguments digest, and the layer. The record is the evidence.

**Stress evidence.** S07.

---

### R8 — Stay in your lane

**Plain language.** The agent does not give legal or medical advice, does not declare food safe, and does not discuss liability, compensation, or press. It routes those questions to a qualified human.

**Enforced by.**
- **GUARDRAIL** — denied topics on input and output: `LegalAdvice`, `MedicalAdvice`, `SafetyDetermination`, `LiabilityNegotiation`, `PressComment`. The single source of truth is `config/guardrail.json`; the CDK stack builds the Bedrock Guardrail from it, and `hold/guardrail.py` mirrors the same topics offline so tests are deterministic and reproducible.
- **HUMAN** — a blocked question creates an escalation task, not a silent refusal.

**Edge case.** A request can be operationally legitimate and still hit a denied topic ("Can we tell the pregnant customer it's safe?"). The correct behaviour is to escalate, not to answer with a disclaimer. S10 tests that.

**Stress evidence.** S09, S10.

---

### R9 — Every attempt is on the record

**Plain language.** Every tool attempt and every blocked prompt is written down, including the ones that were refused. The record is hash-chained so any edit is detectable, and it carries which layer made the decision.

**Enforced by.**
- **LEDGER** — `hold/ledger.py` hashes canonical JSON with the previous entry's hash. Each receipt carries `seq`, `prev`, `hash`, `decision`, `code`, `layer`, actor, safe arguments, argument digest, state before/after, delta, flags and co-signature reference.
- **API** — `GET /api/ledger` and `GET /api/ledger/verify` recompute the chain; the UI's tamper drill mutates a shadow copy and shows the exact break.
- **DEPLOYMENT** — the CDK stack provisions a versioned S3 bucket with Object Lock in compliance mode. The demo keeps the chain in memory; the production tool plane is responsible for sealing the daily root to that bucket. This boundary is stated rather than hidden.

**Edge case.** A denial is a normal outcome, not an exception. Refusals are recorded with the same care as allows, because the refusals are the evidence that the boundary exists.

**Stress evidence.** S17; the suite verifies the shared chain at the end.

---

### R10 — Fail closed, then escalate

**Plain language.** When the agent is uncertain, it holds more product and asks a human. It never releases and asks afterwards. Ambiguity is a reason to contain, not a reason to wait.

**Enforced by.**
- **KERNEL** — read failures and validation errors do not produce an empty scope that could be mistaken for "nothing affected". They produce an explicit failure or an escalation.
- **HUMAN** — `escalate_incident` is a tightening effect available to the agent; it opens a review task with a reason code and evidence reference.
- **LATTICE** — the safe direction is always available. The agent never needs release authority in order to do the cautious thing.

**Edge case.** If a trace read is incomplete, the agent must not say "only these two lots are affected." The correct answer names the evidence gap and holds the wider set.

**Stress evidence.** S14, S18.

---

### R11 — Bounded blast radius

**Plain language.** Batch sizes, notification rates, turn budgets and note lengths are capped. A looping or panicking agent cannot spam every customer in the database.

**Enforced by.**
- **KERNEL** — per-tool batch caps (for example 25 lots per hold, 10 per release request, 50 recipients per notice), a token bucket on notifications, and note length limits.
- **SERVICE** — the live Converse loop has an 8-step tool budget; `agent/service.py` stops after it and returns a safe reply.
- **HUMAN** — rate-limit denials are ledgered and visible in the console.

**Edge case.** A no-op re-send still counts against the rate limit. The limit exists to bound fan-out attempts, not just successful state changes.

**Stress evidence.** S16.

---

### R12 — Human override is recorded, not hidden

**Plain language.** A human can overrule the agent. When they do, the system records who, when, on what evidence, and what the agent had concluded. The ratchet binds the machine, not the accountable person.

**Enforced by.**
- **HUMAN** — the human plane is a separate principal (`human:qa-director`, `human:vp-quality`) with its own authenticated session. The agent cannot mint it.
- **KERNEL** — a human release still has to be structurally well formed and is separately co-signed. The lattice check is skipped for a human transition because accountability is the point; the record shows the override.
- **LEDGER** — the human action is appended to the same chain with a distinct actor, the co-signature reference and the agent's pending request. The UI flips the monotone badge to `↯ HUMAN OVERRIDE` rather than pretending the machine held.

**Edge case.** A human can release a lot that is **held but not recalled**; a recalled lot must first be narrowed by a second co-signed human action. This is deliberate: the easiest human action is still a tightening-first path.

**Stress evidence.** S11; the end-to-end UI flow produces a `HUMAN_OVERRIDE` receipt and a verified chain.

---

## What HOLD cannot do

| Capability | Agent | QA Director | VP Quality | Why |
|---|---|---|---|---|
| Read trace, lots, shipments, supplier docs | ✅ | ✅ | ✅ | Evidence is needed to contain |
| Place a hold | ✅ | ✅ | ✅ | Additive, safe direction |
| Widen a recall | ✅ | ✅ | ✅ | Additive, safe direction |
| Notify affected accounts | ✅ | ✅ | ✅ | Template-bound, trace-derived |
| Request release | ✅ | ✅ | ✅ | A request is not a release |
| Release a held lot | ❌ | ✅ + co-sign | ✅ + co-sign | Human accountability |
| Narrow a recall | ❌ | ✅ + co-sign | ✅ + co-sign | Loosening |
| Close the incident | ❌ | ✅ + co-sign | ✅ + co-sign | Implicitly ends containment |
| Delete / purge / export | ❌ | ❌ | ❌ | No containment need; separate change control |

The co-signature requires **two distinct humans**: the requester and the approver. A single QA Director cannot self-approve.

---

## How the layers fit

| Layer | What it sees | What it stops | Where it lives |
|---|---|---|---|
| **GUARDRAIL** | The user prompt and the model draft | Prompt attacks, denied topics, PII, ungrounded claims | Bedrock Guardrails; offline mirror in `hold/guardrail.py` |
| **IDENTITY** | The workload principal | Direct data-plane access; mistaken grants | AgentCore Runtime role; explicit deny in `infra/hold_stack.py` |
| **POLICY** | The tool call at the gateway | Tools outside the Cedar allowlist | `infra/policy/*.cedar` (deployment layer) |
| **CAPABILITY** | Principal + declared tool effect | Release, destruct, exfil, external write | `hold/registry.py` + `hold/kernel.py` |
| **KERNEL** | The proposed state transition | Any loosening; bad scope; unknown ids; rate abuse | `hold/kernel.py` + `hold/lattice.py` |
| **HUMAN** | The exact payload + two identities | Self-approval; replayed or transplanted tokens | `hold/cosign.py` + human console |
| **LEDGER** | Every attempt | Undetected edits; missing refusals | `hold/ledger.py`; S3 Object Lock in deployment |

**The layer that is not in the public demo path.** The boundary lab calls `kernel.invoke()` directly, below the guardrail and below IAM. The console marks GUARDRAIL, IDENTITY and POLICY as `— not in this path` rather than falsely showing them green. That is the point of the lab: the inner boundary holds when the outer layers are absent. The full console flow does exercise the guardrail; the deployment stack supplies identity.

**The layer that is not auto-deployed.** The AgentCore Gateway/Cedar set is in `infra/policy/` but is not created by `hold_stack.py`. An empty gateway would look like a control and enforce nothing. The README explains how to attach it when the tool plane is moved behind a target.

---

## Plain-language refusals

The agent does not say "I cannot assist with that" and stop. It names the boundary and the next safe step:

- Release request → *"Releasing, narrowing or closing is a human authority. This principal holds no RELEASE capability... Ask a QA Director to review the evidence and co-sign in the human console."*
- Destructive request → *"No principal in this system can delete records... the audit ledger is write-once. There is no path to this from here."*
- Export request → *"Bulk export is not reachable from the containment plane... Data-owner export runs through DLP review."*
- Untrusted document → *"The document is evidence, not instruction. I have flagged the injected text and kept the analytical rows."*
- Scope pressure → *"A recall notice may be re-sent to a subset, but it may not be withheld from an affected account."*

---

## Honest limits

These are the things a judge should not have to discover by reading the code:

1. **The live Bedrock path is implemented but not exercised in this repo** because no AWS credentials were available in the build environment. The deterministic twin, the stress suite and the UI use the same kernel and the same tool catalogue.
2. **The demo co-signature is HMAC with a local key.** The production design is KMS-backed signing with a verify-only runtime; the HMAC is a protocol test, not the final key management.
3. **The demo ledger is in memory.** The CDK stack provisions the Object Lock bucket, but the demo does not write to it.
4. **The AgentCore Gateway/Cedar layer is provided as policy files, not deployed.** The in-process capability map is the enforced boundary in the demo.
5. **The incident, company, people and documents are fictional.** Every identifier and result is synthetic.

The failure log (`docs/FAILURE_LOG.md`) records the bugs found while building this, including one false claim that survived into an early draft and the fix.
