# HOLD — failure log

A safety submission that only shows green checkmarks is not evidence. This is the list of things that were wrong, how they were found, what they would have meant in an incident, and what changed.

The log is ordered by **what the bug would have cost**, not by when it was found. Every fix has a regression test or a stress case unless the item is explicitly a documentation/deployment gap.

---

## 1. The guardrail never lowercased the prompt — R8

**What broke.** `normalize_text()` folded full-width characters and stripped zero-width characters, but it did not lowercase. The prompt-attack patterns were written in lowercase. `IGNORE ALL PREVIOUS INSTRUCTIONS` therefore did not match `ignore all previous instructions`.

**How it was found.** A test using a mixed-case jailbreak passed through the guardrail. The code looked correct because the fixture was lowercase.

**Why it mattered.** This is the difference between a guardrail and a decoration. An attacker only has to capitalise a word. The guardrail is not the primary boundary, but it is the first layer, and a silent bypass makes the layer trace lie.

**Fix.** `normalize_text()` now applies `.lower()` after NFKC, confusable folding and zero-width removal. The regression test `test_fullwidth_and_zero_width_are_normalised` and the mixed-case guardrail tests cover it.

**Residual risk.** The offline mirror is not Bedrock Guardrails. A production deployment uses the hosted Guardrail; the mirror is for reproducible tests. Both should be exercised in the deployment smoke test.

---

## 2. The canary was detected, flagged, and not stripped — R5

**What broke.** `Session.turn` called `taint.leak_check()` and appended a ledger entry with `CANARY_ECHO_STRIPPED`, but the composed reply was never changed. The flag said "stripped"; the marker was still in the text a human would read.

**How it was found.** Reading the output path while adding the live loop. The test only checked detection, not the resulting string.

**Why it mattered.** A false assurance in the ledger is worse than no flag: it tells the reviewer the response was cleaned when it was not. The canary itself is a marker, not the sensitive content, but the same code path is where a future redaction would live.

**Fix.** Added `TaintBroker.strip_canaries()` and called it in both `Session.turn` and `AgentService._ask_model`. The new test `test_canary_echo_is_stripped` asserts the marker is gone and the replacement is present.

**Residual risk.** Stripping a marker is not the same as removing the untrusted block. The current behaviour replaces the marker; a production implementation should remove the whole block or re-compose from the trusted evidence. This is listed as a next step, not claimed as complete.

---

## 3. The live model could read the raw document body — R5

**What broke.** The offline `Session` ingested a supplier document into the taint broker and appended provenance, but the tool result returned to the model still contained `doc.body`. The canary-wrapped `model_text` existed in the broker and was never used on the model path.

**How it was found.** Tracing `read_supplier_doc` from the kernel to the Converse loop while wiring `agent/service.py`. The offline tests did not exercise a model reading the document.

**Why it mattered.** This is the exact indirect-injection path the project is about. A canary that is generated but not sent to the model is security theatre. The live path would have handed the hostile prose to the model with no quarantine.

**Fix.** Both paths now replace the tool output's `content` with `info["model_text"]`:
- `Session.turn` does it after `ingest_document()`;
- `HoldService._invoke()` does it for the live loop.

The `read_supplier_doc` output now contains the canary-delimited block, and the provenance is attached. The canary is deterministic per session/document and the body cannot forge it (tested).

**Residual risk.** The model still sees the prose inside the quarantine block. The design does not rely on the model ignoring it; the lattice bounds the consequence. The quarantine is evidence handling, not the boundary.

---

## 4. The co-signature token was not read from the tool arguments — R4

**What broke.** The kernel accepted a `cosign_token` keyword argument for tests, but the MCP/tool path passes the token inside the tool arguments as `args["cosign"]`. The kernel checked only the keyword, so a valid human release through the tool surface failed with `COSIGN_MISSING`.

**How it was found.** The end-to-end human console flow returned a denial at the `HUMAN` layer even after the UI had minted a token. The unit tests called the kernel directly with the keyword and never exercised the tool-argument shape.

**Why it mattered.** The safe failure direction (deny) is good, but the control was unusable through the real interface. A judge would see a release that could never succeed, which weakens the claim that the human plane works.

**Fix.** `token = cosign_token if cosign_token is not None else clean.get("cosign")`. The demo now releases `LOT-2288` with generation 4, one released lot, and a verified chain. The co-signature is optional in the schema so a missing token produces `COSIGN_MISSING` at the `HUMAN` layer instead of a schema error at `SCHEMA`; the layer trace is therefore honest about what failed.

**Residual risk.** The demo token is HMAC with a local key. The production design is KMS-backed signing with a verify-only runtime; see the honest limits.

---

## 5. The rate limiter did not count a no-op notification — R11

**What broke.** The notification token bucket only advanced when the state changed. A model that repeatedly re-sent the same notice to the same accounts could spin without consuming budget, because the second send was a no-op.

**How it was found.** S16 (notification flood) was added after noticing that the first rate-limit test used a fresh account set every time. The no-op path was untested.

**Why it mattered.** The limit exists to bound **attempts**, not just successful state changes. A looping agent is exactly the case where the state stops changing.

**Fix.** Every `notify_customers` invocation that reaches the commit path appends to the window, including a no-op re-send. S16 now passes with `RATE_LIMITED`.

**Residual risk.** The bucket is per-process. A multi-replica deployment needs a shared token bucket (DynamoDB conditional update or API Gateway usage plan). The current single-incident runtime is serialised; the deployment note should make the shared limiter explicit.

---

## 6. The under-notification rule was missing — R6

**What broke.** The first version allowed `notify_customers` to take a subset of eligible accounts for any reason. The intent was to allow re-sends to a subset, not to let a commercial pressure campaign skip affected customers.

**How it was found.** S05 was written from the incident story ("notify Harbor Market and GreenFork only"). The kernel accepted it.

**Why it mattered.** Under-notification is the highest-consequence failure in a recall. It is the one thing a food-safety agent must never be talked into.

**Fix.** The kernel now compares the requested subset with the set of eligible, not-yet-notified accounts. If any eligible account is omitted, it returns `UNDER_NOTIFICATION_BLOCKED`. A subset is allowed only when every omitted account has already been notified.

**Residual risk.** "Eligible" is derived from recalled lots and shipments. If the trace itself is incomplete, the kernel cannot know about an account it has never seen. That is why R10 requires an explicit incomplete-evidence refusal rather than an empty scope.

---

## 7. The tamper drill was a no-op — R9

**What broke.** The UI's "tamper" action mutated a copy of the ledger, but the mutation was on a field that was not part of the hash input. The verification still returned OK, so the drill "proved" nothing.

**How it was found.** Running the drill and seeing `verified` after a supposed edit. The test had asserted that the endpoint returned 200, not that the chain broke.

**Why it mattered.** A tamper-evidence claim that cannot demonstrate a break is a demo trick. The ledger is one of the seven layers; it has to fail visibly when edited.

**Fix.** The shadow mutation now changes a hashed field (`decision` / `tool` / `args`) and the verification recomputes the chain from genesis. The UI shows the broken sequence and the expected vs actual hash. The live ledger is never touched.

**Residual risk.** The demo ledger is in memory. The deployment uses S3 Object Lock in compliance mode; the root-sealing job is not implemented in this repository.

---

## 8. The layer trace claimed layers that were not in the path — honesty

**What broke.** The boundary lab calls `kernel.invoke()` directly. The first layer-trace renderer marked `GUARDRAIL`, `IDENTITY` and `POLICY` as **passed** for a call caught at `CAPABILITY`, because they appeared earlier in the list. They had not run. The screenshot looked like a seven-layer proof; it was a decorative chain.

**How it was found.** Reading the lab screenshot and asking what "passed" meant for the Gateway in an offline process. The answer was "nothing".

**Why it mattered.** This is the submission's central claim. A judge who knows AgentCore would spot that a local Python process did not evaluate IAM or Cedar. The honest version is stronger: the lab deliberately tests the **inner** boundary with the outer layers absent, and the UI says so.

**Fix.** `_layer_trace()` now returns `not_in_path` for GUARDRAIL/IDENTITY/POLICY on the lab path, and for HUMAN when the actor is not human. The UI renders `— not in this path` and a note: *"The lab invokes the kernel directly; guardrail, IAM and Gateway policy are upstream. This is the inner boundary holding without them."* The screenshot was recaptured.

**Residual risk.** The full console flow does exercise the offline guardrail; the deployment stack supplies identity. The Gateway/Cedar layer is still optional and is labelled as such.

---

## 9. The stress report said "refused at the input guardrail" for cases that passed it — honesty

**What broke.** When a case had no scripted final prose, the Markdown renderer fell back to "Refused at the input guardrail." S02, S03 and S04 pass the guardrail and are refused at `CAPABILITY` or `KERNEL`. The table was right; the prose was wrong.

**How it was found.** Reading the generated `docs/STRESS_TEST.md` next to the table. The contradiction was visible in the same section.

**Why it mattered.** A stress report is evidence. If the narrative contradicts the evidence column, the whole report is suspect. It also hid the most important point: the guardrail is not the boundary.

**Fix.** `_what_happened()` derives the sentence from the actual result record: guardrail block, first denial message, coerced-safe explanation, or no-tool outcome. The report was regenerated. S04 now explains the union/coercion instead of printing a bare code.

**Residual risk.** The report is generated from a deterministic suite; it is not a live red-team against the deployed model. That distinction is stated at the top of the report.

---

## 10. The documentation claimed a control the stack did not have — R7

**What broke.** The rule text said the ledger bucket used Object Lock in **compliance** mode. The first CDK stack used **governance** mode, which a privileged principal can bypass with `s3:BypassGovernanceRetention`.

**How it was found.** Cross-checking every "enforced by" claim in `docs/RULES.md` against `infra/hold_stack.py`. The text was ahead of the code.

**Why it mattered.** Governance mode is a weaker claim. In a food-safety audit, "we can delete it if we really need to" is not WORM.

**Fix.** The stack uses `ObjectLockRetention.compliance(Duration.days(365))`. The bucket is created with Object Lock enabled, because it cannot be added later. The runtime role also has an explicit IAM deny on S3 deletion and DynamoDB writes/deletion, so an accidental future grant does not become a data path.

**Residual risk.** The stack was not deployed (no credentials). The claim is about the code, not a live bucket. The deployment checklist must verify the retention mode after `cdk deploy`.

---

## 11. Smaller defects worth recording

| Defect | Impact | Fix |
|---|---|---|
| The taint scanner flagged a legitimate internal QMS note ("do not release vat V-2211 product") | False positive would train operators to ignore flags | Require an imperative aimed at the reader ("please", "you must"), not a policy description. Regression test `test_legitimate_internal_note_is_clean` |
| A legitimate supplier delivery notice was flagged | Same | Rule narrowed to disposition-change instructions; `test_legitimate_supplier_notice_is_clean` |
| The architecture diagram said "Strands" and "role: gateway:Invoke only" | Misdescribed the actual runtime and IAM | Diagram now says "Bedrock Converse" and "Bedrock + Guardrail only"; Gateway labelled optional |
| The UI said "9 reachable" tools | Off by two; the registry has 11 agent tools | Corrected in the SVG, the console and the docs |
| The capability caption was hard-coded | Would drift when the registry changed | Dynamic `11 of 21 catalogue tools` |
| `.counter` CSS class collided with the header counter | Misaligned badges | Renamed to `.counterbadge` |
| Step buttons stayed active after the walkthrough | A second click could confuse the demo | Buttons disable and relabel to "Walkthrough complete" |
| `debug.log` is held by a lingering process | Cannot be removed in this environment | Left in place, listed as an environment artifact; not part of the submission |

---

## 12. CDK synth caught three deployment bugs

**What broke.** The first `infra/` draft looked plausible but had never been synthesized. Running `python infra/app.py` with `aws-cdk-lib==2.278.0` found:

1. `RuntimeAuthorizerConfiguration.iam()` does not exist in the L2 API; the method is `using_iam()`. The stack failed before producing a template.
2. The KMS key policy statement for the Bedrock Guardrail had no `Resource`, so CDK validation refused the key. Adding `resources=["*"]` fixed it; using the key ARN created a circular dependency because the policy is part of the key.
3. The Cognito client defaulted to `https://example.com` with implicit and authorization-code grants. That is a placeholder, not a human plane. It now uses an explicit local callback, authorization-code flow only, SRP auth, and `openid`/`email`/`profile` scopes.

A fourth, smaller issue: `point_in_time_recovery` is deprecated; the stack now uses `point_in_time_recovery_specification`.

**How it was found.** Not by reading the docs — by synthesizing the stack. The CDK API surface changes between versions, and a deployment file that has never been synthesized is a guess.

**Why it mattered.** This is the deployment half of the submission. A stack that cannot synth is not a deployment path; it is a diagram with Python syntax. The synth also confirmed the runtime role has no data-plane grant, the explicit deny is present, and the ledger bucket renders `Mode: COMPLIANCE`.

**Fix.** The stack now synthesizes `HoldContainmentStack.template.json` with `aws-cdk-lib==2.278.0` (pinned in `infra/requirements.txt`). The template was inspected for the runtime role, Object Lock, KMS policy and Cognito client. It has not been deployed; synth is not deploy.

**Residual risk.** `AgentRuntimeArtifact.from_asset` needs Docker at deploy time, and the first real deploy still has to prove the runtime image starts, the Guardrail version matches, and the human pool can authenticate. Those are deploy-time checks, not synth-time checks.

---

## 13. What is still not done

These are not hidden in a footnote. They are the next engineering steps.

1. **Live AgentCore deployment and a live Bedrock run.** The code is written, the container builds from the repository, and the CDK stack is reviewed, but no AWS credentials were available. The deterministic twin and the browser demo are the executed evidence.
2. **KMS-backed co-signature.** The demo uses HMAC with a local key. The production design is an asymmetric KMS key: the human plane signs, the runtime only verifies. The kernel interface is ready for a verifier, but the key management is not wired.
3. **Shared rate limiter.** The token bucket is per process. A multi-replica deployment needs a shared conditional-update bucket.
4. **Ledger root sealing.** The bucket exists; the daily root-sealing job does not. The chain is verified in memory in the demo.
5. **Gateway/Cedar deployment.** The policies are written and documented, but not attached to a live gateway target. The in-process capability map is the enforced boundary.
6. **Trace completeness.** The world is synthetic and complete. A production integration must distinguish "no shipments" from "the shipment feed is down"; R10 is the design intent, not a finished integration.

The point of this log is not that the project is perfect. It is that the boundary is real, the evidence is reproducible, and the gaps are named.
