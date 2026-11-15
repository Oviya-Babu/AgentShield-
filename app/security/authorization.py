import random, asyncio
from app.models.schemas import LayerResult, LayerStatus, TrustState
from app.services.data_store import store

ROLE_CEILINGS = {
    "orchestrator": ["invoice:read", "file:read", "email:draft", "customer:read"],
    "researcher": ["invoice:read", "customer:read", "file:read"],
    "executor": ["email:draft", "email:send", "file:write"],
    "finance_analyst": ["invoice:read", "file:read", "email:draft"],
    "security_operator": ["*"],
}

async def check_authorization(agent_id: str, tool_name: str, args: dict, capability: str, resource: str = "*") -> LayerResult:
    await asyncio.sleep(random.uniform(0.01, 0.03))
    agent = store.agents.get(agent_id)
    if not agent:
        return LayerResult(layer=4, name="L4 Authorization", status=LayerStatus.DENY, summary=f"Agent {agent_id} not found", details={"error": "AUTHZ_UNKNOWN_AGENT"})
    
    # 1. Check role ceiling
    ceiling = ROLE_CEILINGS.get(agent.agent_type, [])
    if not _ceiling_allows(ceiling, capability):
        return LayerResult(
            layer=4,
            name="L4 Authorization",
            status=LayerStatus.DENY,
            summary=f"Role ceiling violation: {agent.agent_type} may not execute {capability}",
            details={"agent_type": agent.agent_type, "capability": capability, "ceiling": ceiling, "error": "AUTHZ_NO_CAPABILITY"},
            duration_ms=round(random.uniform(12, 24), 2)
        )
    
    # 2. Check sensitivity against agent trust state (R-09: HIGH sensitivity requires TRUSTED)
    tool_def = store.tools.get(tool_name)
    if tool_def and tool_def.risk_level.value == "HIGH" and agent.trust_state != TrustState.TRUSTED:
        return LayerResult(
            layer=4,
            name="L4 Authorization",
            status=LayerStatus.DENY,
            summary=f"High-sensitivity tool {tool_name} requires TRUSTED state (agent is {agent.trust_state.value})",
            details={"tool": tool_name, "sensitivity": "HIGH", "agent_trust_state": agent.trust_state.value, "error": "AUTHZ_TRUST_RESTRICTED"},
            duration_ms=round(random.uniform(10, 22), 2)
        )
    
    # 3. Check registered recipient for email tools (R-07)
    if tool_name in ("send_email_mock", "draft_email") and "to" in args:
        recipient_email = args["to"]
        rec = store.recipients.get(recipient_email)
        if not rec or not rec.registered:
            return LayerResult(
                layer=4,
                name="L4 Authorization",
                status=LayerStatus.DENY,
                summary=f"Recipient {recipient_email} is not in registered finance recipient list",
                details={"recipient": recipient_email, "registered": False, "tool": tool_name, "error": "AUTHZ_RECIPIENT_NOT_REGISTERED"},
                duration_ms=round(random.uniform(14, 26), 2)
            )
    
    # 4. Check specific invoice permissions if requested
    if tool_name == "get_invoice":
        inv_id = args.get("invoice_id", "")
        if resource != "*" and resource != inv_id and not resource.endswith("*"):
            return LayerResult(
                layer=4,
                name="L4 Authorization",
                status=LayerStatus.DENY,
                summary=f"Resource out of authority: access to {inv_id} not covered by grant {resource}",
                details={"requested_invoice": inv_id, "granted_resource": resource, "error": "AUTHZ_RESOURCE_NOT_GRANTED"},
                duration_ms=round(random.uniform(12, 25), 2)
            )

    return LayerResult(
        layer=4,
        name="L4 Authorization",
        status=LayerStatus.PASS,
        summary=f"Context-continuous authorization granted: {capability} on {resource}",
        details={"agent_id": agent_id, "capability": capability, "resource": resource, "policy_version": 3, "role_ceiling_ok": True},
        duration_ms=round(random.uniform(11, 24), 2)
    )

def _ceiling_allows(ceiling: list[str], capability: str) -> bool:
    for c in ceiling:
        if c == "*" or c == capability:
            return True
        if c.endswith(":*") and capability.startswith(c[:-1]):
            return True
    return False
