// HOLD explicit forbidden effects.
//
// These tools are absent from the agent principal in the in-process kernel.
// This layer repeats the refusal at the Gateway so a misconfigured runtime, a
// stolen tool schema, or a future target cannot quietly expose them.
//
// Default deny is the primary control; these forbids are the audit trail.

// ---- RELEASE: human plane only -----------------------------------------
forbid(principal, action == AgentCore::Action::"ContainmentTools___release_hold", resource);
forbid(principal, action == AgentCore::Action::"ContainmentTools___narrow_recall", resource);
forbid(principal, action == AgentCore::Action::"ContainmentTools___approve_disposition", resource);
forbid(principal, action == AgentCore::Action::"ContainmentTools___close_incident", resource);

// ---- DESTRUCT -----------------------------------------------------------
forbid(principal, action == AgentCore::Action::"ContainmentTools___delete_lot", resource);
forbid(principal, action == AgentCore::Action::"ContainmentTools___purge_ledger", resource);

// ---- EXFIL --------------------------------------------------------------
forbid(principal, action == AgentCore::Action::"ContainmentTools___export_records", resource);
forbid(principal, action == AgentCore::Action::"ContainmentTools___bulk_download", resource);
forbid(principal, action == AgentCore::Action::"ContainmentTools___send_freeform_email", resource);

// ---- EXTERNAL_WRITE -----------------------------------------------------
forbid(principal, action == AgentCore::Action::"ContainmentTools___update_supplier_master", resource);
