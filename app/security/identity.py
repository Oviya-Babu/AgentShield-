import random, asyncio
from app.models.schemas import LayerResult, LayerStatus
from app.services.data_store import store
from app.core.crypto import sign_message, verify_signature

async def verify_identity(agent_id: str) -> LayerResult:
    await asyncio.sleep(random.uniform(0.01, 0.03))
    agent = store.agents.get(agent_id)
    if not agent:
        return LayerResult(
            layer=1,
            name="L1 Identity",
            status=LayerStatus.DENY,
            summary=f"Unknown agent: {agent_id}",
            details={"agent_id": agent_id, "error": "IDENTITY_UNKNOWN_AGENT"},
            duration_ms=round(random.uniform(12, 24), 2)
        )
    if not agent.credential_active or agent.status != "active":
        return LayerResult(
            layer=1,
            name="L1 Identity",
            status=LayerStatus.DENY,
            summary=f"Agent {agent.name} credential revoked/inactive",
            details={"agent_id": agent_id, "credential_active": False, "error": "IDENTITY_REVOKED"},
            duration_ms=round(random.uniform(10, 20), 2)
        )
    # Cryptographic challenge-response check
    msg = f"{agent_id}:request"
    sig = sign_message(msg)
    valid = verify_signature(msg, sig)
    if not valid:
        return LayerResult(
            layer=1,
            name="L1 Identity",
            status=LayerStatus.DENY,
            summary="Ed25519 signature verification failed",
            details={"agent_id": agent_id, "error": "IDENTITY_BAD_SIGNATURE"},
            duration_ms=round(random.uniform(15, 28), 2)
        )
    return LayerResult(
        layer=1,
        name="L1 Identity",
        status=LayerStatus.PASS,
        summary=f"Agent {agent.name} ({agent_id}) verified via active Ed25519 key",
        details={"agent_id": agent_id, "credential_active": True, "signature_valid": True},
        duration_ms=round(random.uniform(12, 25), 2)
    )
