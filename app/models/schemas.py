"""Pydantic v2 models and enums for AgentShield."""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any, Optional

from pydantic import BaseModel, Field


# ── Enums ────────────────────────────────────────────────────────────────


class TrustState(str, Enum):
    TRUSTED = "TRUSTED"
    RESTRICTED = "RESTRICTED"
    SUSPICIOUS = "SUSPICIOUS"
    BLOCKED = "BLOCKED"


class LayerStatus(str, Enum):
    PASS = "PASS"
    DENY = "DENY"
    WARNING = "WARNING"
    SKIPPED = "SKIPPED"


class RiskLevel(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class Severity(str, Enum):
    INFO = "INFO"
    WARNING = "WARNING"
    CRITICAL = "CRITICAL"


class EvidenceType(str, Enum):
    OPERATION_ALLOWED_CLEAN = "OPERATION_ALLOWED_CLEAN"
    UNAUTHORIZED_ATTEMPT = "UNAUTHORIZED_ATTEMPT"
    DELEGATION_VIOLATION = "DELEGATION_VIOLATION"
    BINDING_VIOLATION = "BINDING_VIOLATION"
    BURST_DENIALS = "BURST_DENIALS"
    RESOURCE_ENUMERATION = "RESOURCE_ENUMERATION"
    MANIFEST_DESCRIPTION_CHANGED = "MANIFEST_DESCRIPTION_CHANGED"
    MANIFEST_RESTORED = "MANIFEST_RESTORED"
    TRUST_RESET = "TRUST_RESET"


# ── Core domain models ──────────────────────────────────────────────────


class Principal(BaseModel):
    id: str
    name: str
    role: str
    status: str = "active"
    scopes: list[str] = Field(default_factory=list)
    origin: str = "seeded"


class Agent(BaseModel):
    id: str
    name: str
    agent_type: str
    status: str = "active"
    trust_score: float = 90.0
    trust_state: TrustState = TrustState.TRUSTED
    credential_active: bool = True
    origin: str = "seeded"


class ToolDef(BaseModel):
    name: str
    description: str = ""
    risk_level: RiskLevel = RiskLevel.LOW
    server_id: str = ""
    parameters: dict[str, Any] = Field(default_factory=dict)


class MCPServer(BaseModel):
    id: str
    name: str
    status: str = "active"
    trust_score: float = 95.0
    trust_state: TrustState = TrustState.TRUSTED
    tools: list[ToolDef] = Field(default_factory=list)
    manifest_hash: str = ""
    manifest_description: str = ""
    original_manifest_hash: str = ""
    original_manifest_description: str = ""
    poisoned: bool = False
    origin: str = "seeded"


# ── Delegation models ───────────────────────────────────────────────────


class DelegationGrant(BaseModel):
    capability: str
    resource_filter: str = "*"


class Delegation(BaseModel):
    id: str
    issuer_id: str
    subject_id: str
    grants: list[DelegationGrant] = Field(default_factory=list)
    expires_at: Optional[datetime] = None
    revoked: bool = False
    origin: str = "seeded"
    created_at: Optional[datetime] = None
    task_id: Optional[str] = None


# ── Security pipeline models ────────────────────────────────────────────


class LayerResult(BaseModel):
    layer: int = 1
    name: str = ""
    status: LayerStatus = LayerStatus.PASS
    summary: str = ""
    details: dict[str, Any] = Field(default_factory=dict)
    duration_ms: float = 0.0


class PipelineEvent(BaseModel):
    operation_id: str
    agent_id: str
    tool_name: str
    server_id: str = ""
    args: dict[str, Any] = Field(default_factory=dict)
    decision: str = "ALLOW"
    layer_results: list[LayerResult] = Field(default_factory=list)
    deny_reason: Optional[str] = None
    timestamp: Optional[datetime] = None
    tool_result: Optional[Any] = None


class ExecutionToken(BaseModel):
    token_id: str
    operation_id: str
    agent_id: str
    tool_name: str
    args_hash: str = ""
    nonce: str = ""
    issued_at: Optional[datetime] = None
    used: bool = False


# ── Workflow models ─────────────────────────────────────────────────────


class WorkflowStep(BaseModel):
    step: int
    label: str = ""
    status: str = "pending"
    pipeline_event: Optional[PipelineEvent] = None


class Workflow(BaseModel):
    id: str
    workflow_type: str = "invoice"
    status: str = "pending"
    adversarial: bool = False
    steps: list[WorkflowStep] = Field(default_factory=list)
    delegations: list[Delegation] = Field(default_factory=list)
    created_at: Optional[datetime] = None


# ── Audit models ────────────────────────────────────────────────────────


class AuditEvent(BaseModel):
    seq: int
    event_id: str
    timestamp: Optional[datetime] = None
    event_type: str = ""
    severity: Severity = Severity.INFO
    actor_id: str = ""
    tool_name: str = ""
    server_id: str = ""
    decision: str = ""
    summary: str = ""
    details: dict[str, Any] = Field(default_factory=dict)
    prev_hash: str = ""
    entry_hash: str = ""
    origin: str = ""


class AuditVerifyResult(BaseModel):
    chain_length: int = 0
    valid: bool = True
    first_invalid_seq: Optional[int] = None
    recomputed_hashes: list[str] = Field(default_factory=list)


# ── Trust models ────────────────────────────────────────────────────────


class TrustEvidence(BaseModel):
    id: str
    entity_id: str
    evidence_type: EvidenceType
    delta: float = 0.0
    score_before: float = 0.0
    score_after: float = 0.0
    timestamp: Optional[datetime] = None
    description: str = ""


class TrustHistoryResponse(BaseModel):
    entity_id: str
    current_score: float = 0.0
    current_state: TrustState = TrustState.TRUSTED
    evidence: list[TrustEvidence] = Field(default_factory=list)


# ── Dashboard models ────────────────────────────────────────────────────


class DashboardOverview(BaseModel):
    total_agents: int = 0
    total_servers: int = 0
    trusted_count: int = 0
    restricted_count: int = 0
    suspicious_count: int = 0
    blocked_count: int = 0
    total_invocations: int = 0
    blocked_operations: int = 0
    alerts: int = 0


class ActivityItem(BaseModel):
    timestamp: Optional[datetime] = None
    event_type: str = ""
    summary: str = ""
    severity: Severity = Severity.INFO


# ── Attack simulation models ────────────────────────────────────────────


class AttackScenario(BaseModel):
    attack_type: str
    name: str = ""
    description: str = ""
    target_layer: str = ""


class AttackPathResult(BaseModel):
    mode: str = "protected"
    attack_succeeded: bool = False
    tool_executions: list[PipelineEvent] = Field(default_factory=list)
    detected: bool = True
    decision: str = "DENY"
    trust_before: Optional[float] = None
    trust_after: Optional[float] = None
    audit_event_ids: list[str] = Field(default_factory=list)


class AttackResult(BaseModel):
    id: str
    attack_type: str
    timestamp: Optional[datetime] = None
    protected: Optional[AttackPathResult] = None
    baseline: Optional[AttackPathResult] = None


class AttackRunRequest(BaseModel):
    mode: str = "both"


# ── Workflow request models ─────────────────────────────────────────────


class InvoiceWorkflowRequest(BaseModel):
    adversarial: bool = False
    step_delay_ms: int = 200


# ── Supplementary domain objects ────────────────────────────────────────


class Invoice(BaseModel):
    id: str
    customer: str
    amount_cents: int
    currency: str = "USD"
    status: str = "pending"
    due_date: Optional[str] = None


class RegisteredRecipient(BaseModel):
    email: str
    registered: bool = True
