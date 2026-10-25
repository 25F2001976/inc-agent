# Public HTTPS Incident Agent (v2)

Autonomous incident diagnosis and remediation agent implementing the GA5 Incident Agent v2 specification:
- `POST /v2/incidents`
- `POST /v2/incidents/{runId}/receipts`
- `GET /v2/incidents/{runId}`
- OTLP trace generation with precise hierarchy (SERVER -> invoke_agent -> chat, execute_tool, join, approval_gate).
- Redaction of sensitive tokens and prompts.
- Atomic state transitions, conflict rejection (409), and idempotency replay.
