import random, asyncio, uuid
from datetime import datetime, timezone
from app.models.schemas import (LayerResult, LayerStatus, TrustState, TrustEvidence, EvidenceType)
from app.services.data_store import store
from app.core.clock import get_clock

def compute_trust_state(score: float) -> TrustState:
    if score >= 80:
        return TrustState.TRUSTED
    if score >= 60:
        return TrustState.RESTRICTED
    if score >= 30:
        return TrustState.SUSPICIOUS
    return TrustState.BLOCKED

def apply_trust_delta(entity_id: str, delta: float, evidence_type: EvidenceType, description: str = "") -> tuple[float, float, TrustState]:
    """Apply trust delta to agent or server. Returns (before, after, new_state)."""
    agent = store.agents.get(entity_id)
    server = store.servers.get(entity_id)
    entity = agent or server
    if not entity:
        return (0.0, 0.0, TrustState.BLOCKED)
    
    before = entity.trust_score
    after = max(0.0, min(100.0, before + delta))
    entity.trust_score = after
    new_state = compute_trust_state(after)
    entity.trust_state = new_state
    
    ev = TrustEvidence(
        id=f"tev_{uuid.uuid4().hex[:12]}",
        entity_id=entity_id,
        evidence_type=evidence_type,
        delta=delta,
        score_before=before,
        score_after=after,
        timestamp=get_clock().now(),
        description=description or f"{evidence_type.value}: delta={delta:+0.1f}"
    )
    store.trust_evidence.append(ev)
    return (before, after, new_state)

async def check_trust(agent_id: str, server_id: str) -> LayerResult:
    await asyncio.sleep(random.uniform(0.01, 0.03))
    agent = store.agents.get(agent_id)
    server = store.servers.get(server_id)
    if not agent:
        return LayerResult(
            layer=3,
            name="L3 Trust",
            status=LayerStatus.DENY,
            summary=f"Agent {agent_id} not found in trust store",
            details={"error": "TRUST_ENTITY_UNKNOWN"}
        )
    if not server:
        return LayerResult(
            layer=3,
            name="L3 Trust",
            status=LayerStatus.DENY,
            summary=f"MCP Server {server_id} not found in trust store",
            details={"error": "TRUST_ENTITY_UNKNOWN"}
        )
    
    # 1. Manifest integrity verification (PRD L3)
    if server.poisoned or (server.manifest_hash != server.original_manifest_hash):
        return LayerResult(
            layer=3,
            name="L3 Trust",
            status=LayerStatus.DENY,
            summary=f"MCP Server {server.name} manifest integrity mismatch (tool definition mutated)",
            details={
                "server_id": server_id,
                "poisoned": server.poisoned,
                "current_hash": server.manifest_hash,
                "original_hash": server.original_manifest_hash,
                "manifest_tampered": True,
                "diff": "DESCRIPTION_CHANGED: tool description altered without authorization",
                "error": "INTEGRITY_MISMATCH"
            },
            duration_ms=round(random.uniform(18, 35), 2)
        )
    
    # 2. Check agent trust state
    if agent.trust_state in (TrustState.SUSPICIOUS, TrustState.BLOCKED):
        return LayerResult(
            layer=3,
            name="L3 Trust",
            status=LayerStatus.DENY,
            summary=f"Agent {agent.name} trust state is {agent.trust_state.value} (score: {agent.trust_score:.1f}) — operations suspended",
            details={
                "agent_id": agent_id,
                "trust_score": agent.trust_score,
                "trust_state": agent.trust_state.value,
                "server_id": server_id,
                "error": "TRUST_STATE_DENY"
            },
            duration_ms=round(random.uniform(14, 26), 2)
        )
    
    # 3. Check server trust state
    if server.trust_state in (TrustState.SUSPICIOUS, TrustState.BLOCKED):
        return LayerResult(
            layer=3,
            name="L3 Trust",
            status=LayerStatus.DENY,
            summary=f"MCP Server {server.name} trust state is {server.trust_state.value} — quarantined",
            details={
                "server_id": server_id,
                "trust_score": server.trust_score,
                "trust_state": server.trust_state.value,
                "error": "TRUST_STATE_DENY"
            },
            duration_ms=round(random.uniform(15, 28), 2)
        )
    
    # 4. Agent in RESTRICTED status returns WARNING
    if agent.trust_state == TrustState.RESTRICTED:
        return LayerResult(
            layer=3,
            name="L3 Trust",
            status=LayerStatus.WARNING,
            summary=f"Agent {agent.name} is RESTRICTED (score: {agent.trust_score:.1f}). High-sensitivity operations blocked",
            details={
                "agent_trust_score": agent.trust_score,
                "agent_trust_state": "RESTRICTED",
                "server_trust_score": server.trust_score,
                "server_trust_state": server.trust_state.value
            },
            duration_ms=round(random.uniform(12, 24), 2)
        )
    
    return LayerResult(
        layer=3,
        name="L3 Trust",
        status=LayerStatus.PASS,
        summary=f"Trust verified: {agent.name} ({agent.trust_score:.0f}/{agent.trust_state.value}), {server.name} ({server.trust_score:.0f}/MATCH)",
        details={
            "agent_trust_score": agent.trust_score,
            "agent_trust_state": agent.trust_state.value,
            "server_trust_score": server.trust_score,
            "server_trust_state": server.trust_state.value,
            "manifest_status": "MATCH"
        },
        duration_ms=round(random.uniform(10, 22), 2)
    )
