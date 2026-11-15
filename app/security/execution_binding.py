import random, asyncio, uuid
from app.models.schemas import LayerResult, LayerStatus, ExecutionToken
from app.services.data_store import store
from app.core.crypto import canonical_json, sha256_hex
from app.core.clock import get_clock

def mint_token(operation_id: str, agent_id: str, tool_name: str, args: dict) -> ExecutionToken:
    nonce = uuid.uuid4().hex
    args_hash = sha256_hex(canonical_json(args))
    token = ExecutionToken(
        token_id=f"tok_{uuid.uuid4().hex[:12]}",
        operation_id=operation_id,
        agent_id=agent_id,
        tool_name=tool_name,
        args_hash=args_hash,
        nonce=nonce,
        issued_at=get_clock().now(),
        used=False
    )
    store.tokens[token.token_id] = token
    return token

async def verify_and_execute(token_id: str, agent_id: str, tool_name: str, args: dict) -> LayerResult:
    await asyncio.sleep(random.uniform(0.01, 0.03))
    token = store.tokens.get(token_id)
    if not token:
        return LayerResult(
            layer=5,
            name="L5 Execution Binding",
            status=LayerStatus.DENY,
            summary="Execution token not found or invalid",
            details={"token_id": token_id, "error": "TOKEN_NOT_FOUND"}
        )
    
    # Nonce check (Replay prevention)
    if token.nonce in store.used_nonces or token.used:
        return LayerResult(
            layer=5,
            name="L5 Execution Binding",
            status=LayerStatus.DENY,
            summary="Single-use execution nonce already consumed — replay attack blocked",
            details={
                "token_id": token_id,
                "nonce": token.nonce,
                "error": "REPLAY_DETECTED"
            },
            duration_ms=round(random.uniform(14, 28), 2)
        )
    
    # Arguments hash check (Argument substitution prevention)
    current_hash = sha256_hex(canonical_json(args))
    if current_hash != token.args_hash:
        return LayerResult(
            layer=5,
            name="L5 Execution Binding",
            status=LayerStatus.DENY,
            summary="Cryptographic argument binding violation: submitted arguments differ from authorized token",
            details={
                "token_id": token_id,
                "expected_hash": token.args_hash,
                "actual_hash": current_hash,
                "error": "BINDING_ARGS_MISMATCH"
            },
            duration_ms=round(random.uniform(16, 30), 2)
        )
    
    # Tool/Agent match
    if token.agent_id != agent_id or token.tool_name != tool_name:
        return LayerResult(
            layer=5,
            name="L5 Execution Binding",
            status=LayerStatus.DENY,
            summary="Operation binding mismatch: agent or tool does not match token claims",
            details={"expected_agent": token.agent_id, "actual_agent": agent_id, "error": "BINDING_TOOL_MISMATCH"},
            duration_ms=round(random.uniform(12, 24), 2)
        )
    
    # Consume nonce
    token.used = True
    store.used_nonces.add(token.nonce)
    
    # Execute tool (simulated MCP execution)
    tool_result = _simulate_tool(tool_name, args)
    receipt_sig = sha256_hex(f"receipt:{token.operation_id}:{current_hash}")
    
    return LayerResult(
        layer=5,
        name="L5 Execution Binding",
        status=LayerStatus.PASS,
        summary=f"Execution bound: verified gateway token, consumed nonce, received signed receipt",
        details={
            "token_id": token_id,
            "nonce": token.nonce[:8] + "...",
            "args_hash_match": True,
            "receipt_signature": receipt_sig[:12] + "...",
            "tool_result": tool_result
        },
        duration_ms=round(random.uniform(20, 42), 2)
    )

def _simulate_tool(tool_name: str, args: dict):
    if tool_name == "get_invoice":
        inv_id = args.get("invoice_id", "")
        inv = store.invoices.get(inv_id)
        if inv:
            return {"invoice_id": inv.id, "customer": inv.customer, "amount_cents": inv.amount_cents, "currency": inv.currency, "status": inv.status}
        return {"error": f"Invoice {inv_id} not found in database"}
    if tool_name == "list_invoices":
        return {"invoices": [{"id": i.id, "customer": i.customer, "amount_cents": i.amount_cents, "status": i.status} for i in store.invoices.values()]}
    if tool_name == "draft_email":
        return {"draft_id": f"draft_{uuid.uuid4().hex[:8]}", "to": args.get("to",""), "subject": args.get("subject","Invoice Followup"), "status": "DRAFT_SAVED"}
    if tool_name == "send_email_mock":
        return {"message_id": f"msg_{uuid.uuid4().hex[:8]}", "to": args.get("to",""), "status": "MOCK_SENT"}
    if tool_name == "read_file":
        return {"path": args.get("path",""), "content": "Sample financial summary data from /sandbox/reports/q3_summary.txt"}
    if tool_name == "write_file":
        return {"path": args.get("path",""), "bytes_written": len(args.get("content","")), "status": "SUCCESS"}
    if tool_name == "list_files":
        return {"directory": args.get("dir","/sandbox"), "files": ["q3_summary.txt", "vendors.txt"]}
    if tool_name == "get_customer_record":
        return {"customer_id": args.get("customer_id",""), "name": "Acme Corp", "tier": "Enterprise", "email": "finance@example.test"}
    return {"status": "executed", "tool": tool_name}
