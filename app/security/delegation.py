import random, asyncio
from app.models.schemas import LayerResult, LayerStatus, DelegationGrant, Delegation
from app.services.data_store import store
from app.core.clock import get_clock

async def validate_delegation(agent_id: str, capability: str, resource: str = "*", task_id: str | None = None) -> LayerResult:
    await asyncio.sleep(random.uniform(0.01, 0.03))
    now = get_clock().now()
    
    # Find active delegations where subject_id == agent_id
    matching = [d for d in store.delegations.values() if d.subject_id == agent_id and not d.revoked]
    if task_id:
        matching = [d for d in matching if d.task_id == task_id or d.task_id is None]
    
    if not matching:
        return LayerResult(
            layer=2,
            name="L2 Delegation",
            status=LayerStatus.DENY,
            summary=f"No delegation chain exists for agent {agent_id}",
            details={"agent_id": agent_id, "capability": capability, "error": "DELEGATION_CHAIN_BROKEN"},
            duration_ms=round(random.uniform(14, 30), 2)
        )
    
    for d in matching:
        if d.expires_at and d.expires_at < now:
            continue
        for g in d.grants:
            cap_match = _capability_matches(g.capability, capability)
            res_match = _resource_matches(g.resource_filter, resource)
            if cap_match and res_match:
                return LayerResult(
                    layer=2,
                    name="L2 Delegation",
                    status=LayerStatus.PASS,
                    summary=f"Delegation {d.id} covers {capability}@{resource}",
                    details={
                        "delegation_id": d.id,
                        "issuer": d.issuer_id,
                        "capability": capability,
                        "resource": resource,
                        "grant_capability": g.capability,
                        "grant_resource": g.resource_filter
                    },
                    duration_ms=round(random.uniform(15, 28), 2)
                )
    
    return LayerResult(
        layer=2,
        name="L2 Delegation",
        status=LayerStatus.DENY,
        summary=f"Delegation violation: authority exceeds granted scope for {capability}@{resource}",
        details={
            "agent_id": agent_id,
            "capability": capability,
            "resource": resource,
            "checked_delegations": [d.id for d in matching],
            "error": "DELEGATION_ESCALATION"
        },
        duration_ms=round(random.uniform(18, 32), 2)
    )

def _capability_matches(grant_cap: str, requested_cap: str) -> bool:
    if grant_cap == requested_cap:
        return True
    if grant_cap.endswith(":*"):
        prefix = grant_cap[:-1]
        return requested_cap.startswith(prefix)
    if grant_cap == "*":
        return True
    return False

def _resource_matches(grant_res: str, requested_res: str) -> bool:
    if grant_res == "*":
        return True
    if grant_res.endswith("*") and requested_res.startswith(grant_res[:-1]):
        return True
    return grant_res == requested_res
