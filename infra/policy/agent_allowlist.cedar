// HOLD agent allowlist.
//
// The agent principal may call exactly the eleven tools that can read evidence
// or tighten containment. Default deny applies to every other action, and the
// explicit forbids in deny_release.cedar repeat the four dangerous effect
// classes (RELEASE, DESTRUCT, EXFIL, EXTERNAL_WRITE) for auditability.
//
// Action names are <gateway-target-name>___<tool-name>. The target in the
// reference deployment is named ContainmentTools.

permit(principal, action == AgentCore::Action::"ContainmentTools___trace_lot", resource);
permit(principal, action == AgentCore::Action::"ContainmentTools___search_lots", resource);
permit(principal, action == AgentCore::Action::"ContainmentTools___list_shipments", resource);
permit(principal, action == AgentCore::Action::"ContainmentTools___read_supplier_doc", resource);
permit(principal, action == AgentCore::Action::"ContainmentTools___get_containment_status", resource);

permit(principal, action == AgentCore::Action::"ContainmentTools___place_hold", resource);
permit(principal, action == AgentCore::Action::"ContainmentTools___widen_recall", resource);
permit(principal, action == AgentCore::Action::"ContainmentTools___notify_customers", resource);
permit(principal, action == AgentCore::Action::"ContainmentTools___escalate_incident", resource);
permit(principal, action == AgentCore::Action::"ContainmentTools___request_release", resource);
permit(principal, action == AgentCore::Action::"ContainmentTools___record_note", resource);
