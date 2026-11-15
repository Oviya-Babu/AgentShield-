import uuid
from datetime import datetime, timezone
from app.models.schemas import AuditEvent, Severity
from app.services.data_store import store
from app.core.crypto import compute_entry_hash, canonical_json
from app.core.clock import get_clock

def append_audit_event(
    event_type: str,
    severity: Severity,
    actor_id: str = "",
    tool_name: str = "",
    server_id: str = "",
    decision: str = "",
    summary: str = "",
    details: dict = None
) -> AuditEvent:
    seq = len(store.audit_events) + 1
    prev_hash = store.audit_events[-1].entry_hash if store.audit_events else "0" * 64
    event_id = f"evt_{uuid.uuid4().hex[:12]}"
    ts = get_clock().now()

    event_dict = {
        "seq": seq,
        "event_id": event_id,
        "timestamp": ts.isoformat(),
        "event_type": event_type,
        "severity": severity.value,
        "actor_id": actor_id,
        "tool_name": tool_name,
        "server_id": server_id,
        "decision": decision,
        "summary": summary,
        "details": details or {}
    }
    entry_hash = compute_entry_hash(prev_hash, event_dict)

    evt = AuditEvent(
        seq=seq,
        event_id=event_id,
        timestamp=ts,
        event_type=event_type,
        severity=severity,
        actor_id=actor_id,
        tool_name=tool_name,
        server_id=server_id,
        decision=decision,
        summary=summary,
        details=details or {},
        prev_hash=prev_hash,
        entry_hash=entry_hash,
        origin="seeded" if seq <= 1 else "runtime"
    )
    store.audit_events.append(evt)
    return evt

def verify_audit_chain() -> dict:
    events = store.audit_events
    if not events:
        return {
            "valid": True,
            "total_events": 0,
            "verified_events": 0,
            "broken_at": None,
            "message": "Audit log is empty; genesis chain valid",
            "limitation": "A hash chain does not protect against an attacker who controls the logging system and signing keys."
        }

    prev_hash = "0" * 64
    for idx, evt in enumerate(events):
        event_dict = {
            "seq": evt.seq,
            "event_id": evt.event_id,
            "timestamp": evt.timestamp.isoformat() if evt.timestamp else "",
            "event_type": evt.event_type,
            "severity": evt.severity.value if hasattr(evt.severity, "value") else str(evt.severity),
            "actor_id": evt.actor_id,
            "tool_name": evt.tool_name,
            "server_id": evt.server_id,
            "decision": evt.decision,
            "summary": evt.summary,
            "details": evt.details
        }
        expected = compute_entry_hash(prev_hash, event_dict)
        if expected != evt.entry_hash:
            return {
                "valid": False,
                "total_events": len(events),
                "verified_events": idx,
                "broken_at": evt.seq,
                "message": f"Hash chain verification failed at sequence #{evt.seq}: stored entry hash does not match computed digest",
                "limitation": "A hash chain does not protect against an attacker who controls the logging system and signing keys."
            }
        prev_hash = evt.entry_hash

    return {
        "valid": True,
        "total_events": len(events),
        "verified_events": len(events),
        "broken_at": None,
        "message": f"Cryptographic integrity verified: all {len(events)} events form an unbroken SHA-256 hash chain",
        "limitation": "A hash chain does not protect against an attacker who controls the logging system and signing keys."
    }
