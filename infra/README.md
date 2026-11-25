# HOLD infrastructure

The CDK app creates the deployment-shaped pieces of HOLD:

- **AgentCore Runtime** with the repository root as the container asset;
- **Bedrock Guardrail** built from `../config/guardrail.json`, with a pinned version;
- **KMS key** for the guardrail, table, topic and ledger bucket;
- **DynamoDB** incident table (PITR, stream, customer-managed key);
- **SNS** customer-notice topic (fixed templates, KMS);
- **S3** ledger bucket (versioned, Object Lock **compliance** mode, 365 days);
- **Secrets Manager** secret for the human-plane co-signature key;
- **Cognito** human pool with `qa_director` and `vp_quality` groups, MFA required.

The runtime role gets `bedrock:InvokeModel`, `bedrock:InvokeModelWithResponseStream`, `bedrock:ApplyGuardrail`, `bedrock:GetGuardrail`, logs, and read-only access to the one co-signature secret. It gets **no** S3, DynamoDB, SNS or ERP permission, plus an explicit deny on S3 deletion and DynamoDB writes/deletion. The tool plane is a separate credential boundary.

## Deploy

```bash
cd infra
python -m venv .venv
# Windows: .venv\Scripts\activate
# macOS/Linux: source .venv/bin/activate
python -m pip install -r requirements.txt
cdk synth
cdk bootstrap
cdk deploy
```

The stack has been synthesized with `aws-cdk-lib==2.278.0`; the generated template was inspected for the runtime role, Object Lock compliance mode, KMS policy and Cognito client. Synth is not deploy. Docker must be running for `AgentRuntimeArtifact.from_asset`; the first deploy builds the image from the repository `Dockerfile` and pushes it to the CDK asset repository.

After deploy, note the outputs:

```
HoldContainmentStack.RuntimeArn
HoldContainmentStack.GuardrailId
HoldContainmentStack.GuardrailVersion
HoldContainmentStack.LedgerBucketName
HoldContainmentStack.IncidentTableName
HoldContainmentStack.HumanUserPoolId
HoldContainmentStack.HumanClientId
```

## What this stack intentionally does not do

- **No AgentCore Gateway target.** A gateway with no registered target is an empty control. `policy/` contains the Cedar allowlist and explicit forbids for the deployment where the containment tool plane is registered as a Gateway target. See `policy/README.md`.
- **No human console hosting.** The demo console is local. A production human plane needs its own authenticated web app and a KMS-backed signer; the Cognito pool and groups are the identity foundation. The stack currently provisions a generated HMAC key in Secrets Manager for the runtime; that removes the public fallback but is not the asymmetric KMS signer target.
- **No ledger root-sealing job.** The bucket and retention mode are correct; the scheduled job that writes the daily root is a tool-plane responsibility.

## Verify after deploy

```bash
aws bedrock get-guardrail --guardrail-identifier <id>
aws s3api get-object-lock-configuration --bucket <ledger-bucket>
aws iam get-role --role-name <runtime-role>   # confirm no data-plane grants
```

The `GuardrailVersion` output must match `HOLD_GUARDRAIL_VERSION` in the runtime environment. A guardrail update without a new pinned version is a silent drift.

The runtime reads the co-signature key from the `CosignKey` secret through `HOLD_COSIGN_KEY_SECRET_ARN`. There is no fallback key: if the secret cannot be read, the runtime fails at start-up rather than accepting a known demo key.

## Cost / cleanup

The stack is sized for a demo: on-demand DynamoDB, a single small runtime, a guardrail and an S3 bucket. `cdk destroy` will not delete the retained KMS key, ledger bucket or Cognito pool because they are `RETAIN`. That is deliberate for audit evidence; clean them up manually only after exporting the ledger.
