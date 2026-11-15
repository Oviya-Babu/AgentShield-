"""Seed data loader for AgentShield prototype."""

from __future__ import annotations
import uuid
from datetime import datetime, timezone, timedelta
from app.services.data_store import store
from app.models.schemas import (
    Principal, Agent, MCPServer, ToolDef, Delegation, DelegationGrant,
    Invoice, RegisteredRecipient, RiskLevel, TrustState, Severity
)
from app.security.audit import append_audit_event
from app.core.clock import get_clock


def seed_all():
    """Populate data store with PRD seeded entities."""
    store.reset()
    now = get_clock().now()

    # 1. Principals
    store.principals["usr_alice"] = Principal(
        id="usr_alice",
        name="Alice Finance",
        role="finance_analyst",
        status="active",
        scopes=["invoice:read", "email:draft", "file:read"],
        origin="seeded"
    )
    store.principals["usr_ops"] = Principal(
        id="usr_ops",
        name="Security Operator",
        role="security_operator",
        status="active",
        scopes=["*"],
        origin="seeded"
    )

    # 2. Agents
    store.agents["agt_planner"] = Agent(
        id="agt_planner",
        name="Planner",
        agent_type="orchestrator",
        status="active",
        trust_score=90.0,
        trust_state=TrustState.TRUSTED,
        credential_active=True,
        origin="seeded"
    )
    store.agents["agt_research"] = Agent(
        id="agt_research",
        name="Research",
        agent_type="researcher",
        status="active",
        trust_score=90.0,
        trust_state=TrustState.TRUSTED,
        credential_active=True,
        origin="seeded"
    )
    store.agents["agt_executor"] = Agent(
        id="agt_executor",
        name="Executor",
        agent_type="executor",
        status="active",
        trust_score=90.0,
        trust_state=TrustState.TRUSTED,
        credential_active=True,
        origin="seeded"
    )

    # 3. Tools
    t_get_invoice = ToolDef(
        name="get_invoice",
        description="Fetch invoice record by ID",
        risk_level=RiskLevel.MEDIUM,
        server_id="srv_db",
        parameters={"invoice_id": "string"}
    )
    t_list_invoices = ToolDef(
        name="list_invoices",
        description="List all invoices",
        risk_level=RiskLevel.LOW,
        server_id="srv_db",
        parameters={}
    )
    t_get_customer = ToolDef(
        name="get_customer_record",
        description="Fetch customer record",
        risk_level=RiskLevel.MEDIUM,
        server_id="srv_db",
        parameters={"customer_id": "string"}
    )
    t_read_file = ToolDef(
        name="read_file",
        description="Read file from sandbox",
        risk_level=RiskLevel.MEDIUM,
        server_id="srv_fs",
        parameters={"path": "string"}
    )
    t_list_files = ToolDef(
        name="list_files",
        description="List files in directory",
        risk_level=RiskLevel.LOW,
        server_id="srv_fs",
        parameters={"dir": "string"}
    )
    t_write_file = ToolDef(
        name="write_file",
        description="Write file to sandbox out",
        risk_level=RiskLevel.HIGH,
        server_id="srv_fs",
        parameters={"path": "string", "content": "string"}
    )
    t_draft_email = ToolDef(
        name="draft_email",
        description="Draft an email",
        risk_level=RiskLevel.LOW,
        server_id="srv_email",
        parameters={"to": "string", "subject": "string", "body": "string"}
    )
    t_send_email = ToolDef(
        name="send_email_mock",
        description="Send email via mock outbox",
        risk_level=RiskLevel.HIGH,
        server_id="srv_email",
        parameters={"to": "string", "subject": "string", "body": "string"}
    )

    for t in [t_get_invoice, t_list_invoices, t_get_customer, t_read_file, t_list_files, t_write_file, t_draft_email, t_send_email]:
        store.tools[t.name] = t

    # 4. MCP Servers
    store.servers["srv_db"] = MCPServer(
        id="srv_db",
        name="Database MCP",
        status="active",
        trust_score=95.0,
        trust_state=TrustState.TRUSTED,
        tools=[t_get_invoice, t_list_invoices, t_get_customer],
        manifest_hash="hash_srv_db_v1",
        manifest_description="Database MCP Server v1.0",
        original_manifest_hash="hash_srv_db_v1",
        original_manifest_description="Database MCP Server v1.0",
        poisoned=False,
        origin="seeded"
    )
    store.servers["srv_fs"] = MCPServer(
        id="srv_fs",
        name="Filesystem MCP",
        status="active",
        trust_score=95.0,
        trust_state=TrustState.TRUSTED,
        tools=[t_read_file, t_list_files, t_write_file],
        manifest_hash="hash_srv_fs_v1",
        manifest_description="Filesystem MCP Server v1.0",
        original_manifest_hash="hash_srv_fs_v1",
        original_manifest_description="Filesystem MCP Server v1.0",
        poisoned=False,
        origin="seeded"
    )
    store.servers["srv_email"] = MCPServer(
        id="srv_email",
        name="Email MCP",
        status="active",
        trust_score=95.0,
        trust_state=TrustState.TRUSTED,
        tools=[t_draft_email, t_send_email],
        manifest_hash="hash_srv_email_v1",
        manifest_description="Email MCP Server v1.0 (Mocked)",
        original_manifest_hash="hash_srv_email_v1",
        original_manifest_description="Email MCP Server v1.0 (Mocked)",
        poisoned=False,
        origin="seeded"
    )

    # 5. Invoices
    store.invoices["INV-1001"] = Invoice(id="INV-1001", customer="Acme Corp", amount_cents=125000, currency="USD", status="PENDING", due_date="2026-12-01")
    store.invoices["INV-1002"] = Invoice(id="INV-1002", customer="Beta Inc", amount_cents=84000, currency="USD", status="PAID", due_date="2026-11-20")
    store.invoices["INV-1003"] = Invoice(id="INV-1003", customer="Gamma LLC", amount_cents=312000, currency="USD", status="PENDING", due_date="2026-12-15")
    store.invoices["INV-1004"] = Invoice(id="INV-1004", customer="Delta Co", amount_cents=56000, currency="USD", status="OVERDUE", due_date="2026-11-01")
    store.invoices["INV-1005"] = Invoice(id="INV-1005", customer="Epsilon Ltd", amount_cents=99000, currency="USD", status="PAID", due_date="2026-11-25")

    # 6. Registered Recipients
    store.recipients["finance@example.test"] = RegisteredRecipient(email="finance@example.test", registered=True)
    store.recipients["attacker@evil.example"] = RegisteredRecipient(email="attacker@evil.example", registered=False)

    # 7. Delegations
    expires = now + timedelta(hours=24)
    d0 = Delegation(
        id="dlg_D0",
        issuer_id="usr_alice",
        subject_id="agt_planner",
        grants=[
            DelegationGrant(capability="invoice:read", resource_filter="INV-1001"),
            DelegationGrant(capability="email:draft", resource_filter="*")
        ],
        expires_at=expires,
        revoked=False,
        origin="seeded",
        created_at=now
    )
    d1 = Delegation(
        id="dlg_D1",
        issuer_id="agt_planner",
        subject_id="agt_research",
        grants=[
            DelegationGrant(capability="invoice:read", resource_filter="INV-1001")
        ],
        expires_at=expires,
        revoked=False,
        origin="seeded",
        created_at=now
    )
    d2 = Delegation(
        id="dlg_D2",
        issuer_id="agt_planner",
        subject_id="agt_executor",
        grants=[
            DelegationGrant(capability="email:draft", resource_filter="*")
        ],
        expires_at=expires,
        revoked=False,
        origin="seeded",
        created_at=now
    )
    store.delegations["dlg_D0"] = d0
    store.delegations["dlg_D1"] = d1
    store.delegations["dlg_D2"] = d2

    # 8. Genesis Audit Event
    append_audit_event(
        event_type="SYSTEM_INITIALIZED",
        severity=Severity.INFO,
        actor_id="system",
        tool_name="init",
        server_id="core",
        decision="PASS",
        summary="AgentShield security gateway initialized with seeded state",
        details={"version": "1.0.0", "origin": "seeded"}
    )
