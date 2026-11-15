import random, asyncio
from app.models.schemas import LayerResult, LayerStatus, EvidenceType, Severity, ActivityItem
from app.services.data_store import store
from app.security.audit import append_audit_event
from app.security.trust_engine import apply_trust_delta
from app.core.clock import get_clock

# Track recent denials per agent for behavioral rules (R-M1, R-M2)
_recent_denials: dict[str, list[dict]] = {}

async def record_and_monitor(agent_id: str, tool_name: str, server_id: str, decision: str, args: dict, deny_reason: str | None = None) -> LayerResult:
    await asyncio.sleep(random.uniform(0.01, 0.02))
    now = get_clock().now()
    
    store.operation_count += 1
    if decision == "DENIED":
        store.blocked_count += 1
    
    severity = Severity.INFO if decision == "ALLOWED" else Severity.CRITICAL
    event_type = "TOOL_EXECUTION" if decision == "ALLOWED" else "AUTHORIZATION_DENY"
    
    evt = append_audit_event(
        event_type=event_type,
        severity=severity,
        actor_id=agent_id,
        tool_name=tool_name,
        server_id=server_id,
        decision=decision,
        summary=f"{tool_name} by {agent_id}: {decision}" + (f" ({deny_reason})" if deny_reason else ""),
        details={"args": args, "deny_reason": deny_reason}
    )
    
    # Activity feed entry
    store.activity.insert(0, ActivityItem(
        timestamp=now,
        event_type=event_type,
        summary=evt.summary,
        severity=severity
    ))
    # Keep activity feed bounded
    if len(store.activity) > 50:
        store.activity.pop()
    
    # Trust evidence adjustment
    if decision == "ALLOWED":
        apply_trust_delta(agent_id, 1.0, EvidenceType.OPERATION_ALLOWED_CLEAN, f"Clean execution of {tool_name}")
    else:
        # 1. Base penalty for unauthorized attempt
        apply_trust_delta(agent_id, -6.0, EvidenceType.UNAUTHORIZED_ATTEMPT, f"Denied operation: {tool_name} — {deny_reason}")
        
        # 2. Check behavioral rules (R-M1: Burst Denials, R-M2: Resource Enumeration)
        agent_denials = _recent_denials.setdefault(agent_id, [])
        agent_denials.append({"tool": tool_name, "args": args, "time": now})
        
        if len(agent_denials) >= 3:
            # Rule R-M1: Burst Denials (>=3 denials in window) -> -10 penalty
            apply_trust_delta(agent_id, -10.0, EvidenceType.BURST_DENIALS, "Rule R-M1 triggered: >=3 denied operations within window")
            # Rule R-M2: Resource Enumeration (>=3 distinct resources) -> -10 penalty
            distinct_resources = {str(d.get("args", {}).get("invoice_id", "")) for d in agent_denials if "invoice_id" in d.get("args", {})}
            if len(distinct_resources) >= 3:
                apply_trust_delta(agent_id, -10.0, EvidenceType.RESOURCE_ENUMERATION, "Rule R-M2 triggered: Resource enumeration pattern detected across multiple invoices")
            
            # Clear window after firing
            _recent_denials[agent_id] = []
    
    return LayerResult(
        layer=6,
        name="L6 Monitoring",
        status=LayerStatus.PASS,
        summary=f"Audit logged (seq={evt.seq}), entry hash chained, behavioral monitor evaluated",
        details={"event_id": evt.event_id, "seq": evt.seq, "decision": decision, "entry_hash": evt.entry_hash[:16] + "..."},
        duration_ms=round(random.uniform(8, 18), 2)
    )
