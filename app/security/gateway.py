import uuid
from app.models.schemas import PipelineEvent, LayerResult, LayerStatus
from app.services.data_store import store
from app.core.clock import get_clock
from app.security.identity import verify_identity
from app.security.delegation import validate_delegation
from app.security.trust_engine import check_trust
from app.security.authorization import check_authorization
from app.security.execution_binding import mint_token, verify_and_execute
from app.security.monitor import record_and_monitor

TOOL_CAPABILITY_MAP = {
    "get_invoice": ("invoice:read", "srv_db"),
    "list_invoices": ("invoice:read", "srv_db"),
    "get_customer_record": ("customer:read", "srv_db"),
    "read_file": ("file:read", "srv_fs"),
    "list_files": ("file:read", "srv_fs"),
    "write_file": ("file:write", "srv_fs"),
    "draft_email": ("email:draft", "srv_email"),
    "send_email_mock": ("email:send", "srv_email"),
}

LAYER_METADATA = [
    (1, "L1 Identity"),
    (2, "L2 Delegation"),
    (3, "L3 Trust"),
    (4, "L4 Authorization"),
    (5, "L5 Execution Binding"),
    (6, "L6 Monitoring"),
]

def _make_skipped(layer_num: int, layer_name: str) -> LayerResult:
    return LayerResult(
        layer=layer_num,
        name=layer_name,
        status=LayerStatus.SKIPPED,
        summary="Evaluation skipped due to upstream security denial",
        details={},
        duration_ms=0.0
    )

async def process_tool_call(
    agent_id: str,
    tool_name: str,
    args: dict,
    resource: str | None = None,
    task_id: str | None = None,
    override_token_args: dict | None = None,
    override_replay: bool = False
) -> PipelineEvent:
    """Process a tool call through the 6-layer security pipeline."""
    op_id = f"op_{uuid.uuid4().hex[:12]}"
    cap, server_id = TOOL_CAPABILITY_MAP.get(tool_name, ("unknown", "unknown"))
    
    # Auto-derive resource if not provided
    if not resource:
        if tool_name == "get_invoice":
            resource = args.get("invoice_id", "*")
        elif tool_name in ("draft_email", "send_email_mock"):
            resource = args.get("to", "*")
        elif tool_name in ("read_file", "write_file"):
            resource = args.get("path", "*")
        elif tool_name == "get_customer_record":
            resource = args.get("customer_id", "*")
        else:
            resource = "*"

    event = PipelineEvent(
        operation_id=op_id,
        agent_id=agent_id,
        tool_name=tool_name,
        server_id=server_id,
        args=args,
        timestamp=get_clock().now()
    )

    # ── L1: Identity ──
    l1 = await verify_identity(agent_id)
    event.layer_results.append(l1)
    if l1.status == LayerStatus.DENY:
        event.decision = "DENIED"
        event.deny_reason = l1.summary
        # Skipped layers 2-5
        for num, name in LAYER_METADATA[1:5]:
            event.layer_results.append(_make_skipped(num, name))
        l6 = await record_and_monitor(agent_id, tool_name, server_id, "DENIED", args, l1.summary)
        event.layer_results.append(l6)
        return event

    # ── L2: Delegation ──
    l2 = await validate_delegation(agent_id, cap, resource, task_id)
    event.layer_results.append(l2)
    if l2.status == LayerStatus.DENY:
        event.decision = "DENIED"
        event.deny_reason = l2.summary
        # Skipped layers 3-5
        for num, name in LAYER_METADATA[2:5]:
            event.layer_results.append(_make_skipped(num, name))
        l6 = await record_and_monitor(agent_id, tool_name, server_id, "DENIED", args, l2.summary)
        event.layer_results.append(l6)
        return event

    # ── L3: Trust ──
    l3 = await check_trust(agent_id, server_id)
    event.layer_results.append(l3)
    if l3.status == LayerStatus.DENY:
        event.decision = "DENIED"
        event.deny_reason = l3.summary
        # Skipped layers 4-5
        for num, name in LAYER_METADATA[3:5]:
            event.layer_results.append(_make_skipped(num, name))
        l6 = await record_and_monitor(agent_id, tool_name, server_id, "DENIED", args, l3.summary)
        event.layer_results.append(l6)
        return event

    # ── L4: Authorization ──
    l4 = await check_authorization(agent_id, tool_name, args, cap, resource)
    event.layer_results.append(l4)
    if l4.status == LayerStatus.DENY:
        event.decision = "DENIED"
        event.deny_reason = l4.summary
        # Skipped layer 5
        event.layer_results.append(_make_skipped(5, "L5 Execution Binding"))
        l6 = await record_and_monitor(agent_id, tool_name, server_id, "DENIED", args, l4.summary)
        event.layer_results.append(l6)
        return event

    # ── L5: Execution Binding ──
    token_mint_args = override_token_args if override_token_args is not None else args
    token = mint_token(op_id, agent_id, tool_name, token_mint_args)
    if override_replay:
        token.used = True
        store.used_nonces.add(token.nonce)

    l5 = await verify_and_execute(token.token_id, agent_id, tool_name, args)
    event.layer_results.append(l5)
    if l5.status == LayerStatus.DENY:
        event.decision = "DENIED"
        event.deny_reason = l5.summary
        l6 = await record_and_monitor(agent_id, tool_name, server_id, "DENIED", args, l5.summary)
        event.layer_results.append(l6)
        return event

    event.tool_result = l5.details.get("tool_result")

    # ── L6: Monitoring (always runs) ──
    l6 = await record_and_monitor(agent_id, tool_name, server_id, "ALLOWED", args)
    event.layer_results.append(l6)

    event.decision = "ALLOWED"
    return event
