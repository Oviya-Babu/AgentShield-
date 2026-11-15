"""In-memory data store for AgentShield prototype."""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from app.models.schemas import (
        Agent, MCPServer, Principal, ToolDef, Delegation,
        Invoice, RegisteredRecipient, AuditEvent, TrustEvidence,
        ExecutionToken, Workflow, AttackResult, ActivityItem,
    )


class DataStore:
    """Singleton in-memory store — reset by calling ``reset()``."""

    def __init__(self) -> None:
        self.reset()

    # ---- reset ---------------------------------------------------------
    def reset(self) -> None:
        self.principals: dict[str, Principal] = {}
        self.agents: dict[str, Agent] = {}
        self.servers: dict[str, MCPServer] = {}
        self.tools: dict[str, ToolDef] = {}
        self.delegations: dict[str, Delegation] = {}
        self.invoices: dict[str, Invoice] = {}
        self.recipients: dict[str, RegisteredRecipient] = {}

        self.audit_events: list[AuditEvent] = []
        self.trust_evidence: list[TrustEvidence] = []
        self.used_nonces: set[str] = set()
        self.tokens: dict[str, ExecutionToken] = {}

        self.workflows: dict[str, Workflow] = {}
        self.attack_results: list[AttackResult] = []
        self.activity: list[ActivityItem] = []

        self.operation_count: int = 0
        self.blocked_count: int = 0


store = DataStore()
