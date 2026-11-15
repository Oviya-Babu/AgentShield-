# AgentShield: Dynamic Trust Verification and Context-Continuous Runtime Security Enforcement for Multi-Agent MCP Systems

**AgentShield** is a functional full-stack research prototype demonstrating that authenticating an AI agent once, or authorizing an earlier operation, must never be treated as permission for the next operation. Every protected tool invocation is re-verified at runtime across six security layers against the agent's identity, the delegation chain back to the original user, the current trust state of the agent and the MCP server, a per-operation authorization policy, and a cryptographic binding to the exact arguments that will execute.

---

## 🚀 Quick Start

### 1. Launch with One Click
Double-click `start.bat` or run:
```bash
# Terminal 1: Backend
cd backend
python -m uvicorn app.main:app --host 0.0.0.0 --port 8000

# Terminal 2: Frontend
cd frontend
npm run dev
```

- **SOC Security Dashboard**: [http://localhost:5173](http://localhost:5173)
- **FastAPI OpenAPI Interactive Docs**: [http://localhost:8000/docs](http://localhost:8000/docs)

---

## 🛡️ Six-Layer Security Architecture

1. **L1 Identity Verification**: Ed25519 cryptographic key signature check, credential active status verification, and session validation.
2. **L2 Delegation Chain Validation**: Authority must form a strict tree rooted at the original user (`usr_alice`), where child grants are strictly covered by parent authority (`child ⊆ parent`). Escalated grants are rejected before persistence.
3. **L3 Dynamic Trust Engine & Manifest Integrity**: Evidence-based trust scores (0–100) and discrete states (`TRUSTED`, `RESTRICTED`, `SUSPICIOUS`, `BLOCKED`). Live tools/list manifest hashing detects tool definition tampering or poisoning.
4. **L4 Context-Continuous Authorization**: Evaluates effective capability (`Principal Scopes ∩ Chain Grants ∩ Role Ceiling`), argument schemas, exact resource matches, and recipient registration.
5. **L5 Execution Binding**: Mints a single-use gateway-signed token bound to the SHA-256 hash of canonical arguments. Detects replay attacks via consumed nonces, and blocks argument substitution attacks.
6. **L6 Runtime Behavioral Monitoring & Tamper-Evident Audit**: Evaluates behavioral rules (sliding windows for burst denials and resource enumeration), logs append-only SHA-256 hash-chained audit events, and provides cryptographic integrity verification.

---

## 🧪 Demonstration Capabilities in the UI

1. **Security Operations Overview (`/`)**: Real-time telemetry, 8 SOC metrics, trust score trends, allowed vs. blocked operations, and live activity stream.
2. **Security Pipeline Stepper (`/pipeline`)**: Multi-agent invoice workflow with a vertical 6-stage stepper showing per-layer results (`PASS`, `DENY`, `WARNING`, `SKIPPED`), execution timings, and expandable token / receipt details.
3. **Attack Simulation Lab (`/attacks`)**: Empirical comparison between an unprotected baseline and AgentShield across 5 attack vectors:
   - *Privilege Escalation via Delegation*
   - *MCP Tool Poisoning / Manifest Tampering*
   - *Replay Attack with Captured Nonce*
   - *Cryptographic Argument Substitution*
   - *Compromised Agent Rapid Enumeration*
4. **Autonomous Agents (`/agents`)**: Agent trust scores, credential management, identity verification challenges, and trust evidence logs.
5. **MCP Servers (`/servers`)**: Tool inventories, live manifest hashes, simulated tool poisoning injection, and restore capabilities.
6. **Tamper-Evident Audit (`/audit`)**: Full audit log with prev_hash/entry_hash verification, search/filter, and a **Tamper Demo** button proving that controlled row tampering is detected by cryptographic verification.
7. **Delegation Explorer (`/delegation`)**: Visual representation of the delegation hierarchy and an interactive **Authorization What-If Tester (Dry Run)**.
