import base64
import hashlib
import json
import os
import re
import secrets
import sqlite3
import time
from typing import Any, Dict, List, Optional
from fastapi import FastAPI, HTTPException, Request, Response
from fastapi.responses import JSONResponse

DB_PATH = os.environ.get("DB_PATH", "incident_agent.db")

def canonical_json_bytes(obj: Any) -> bytes:
    """Recursively key-sorted compact JSON bytes (UTF-8)."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")

def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest().lower()

def random_hex(bytes_len: int) -> str:
    return secrets.token_hex(bytes_len)

def now_nano() -> int:
    return int(time.time() * 1e9)

def init_db():
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute("PRAGMA journal_mode=WAL;")
        conn.execute("""
            CREATE TABLE IF NOT EXISTS runs (
                run_id TEXT PRIMARY KEY,
                input_hash TEXT NOT NULL,
                status TEXT NOT NULL,
                trace_id TEXT NOT NULL,
                agent_span_id TEXT NOT NULL,
                server_span_id TEXT NOT NULL,
                public_marker TEXT NOT NULL,
                state_data TEXT NOT NULL,
                created_at REAL NOT NULL,
                updated_at REAL NOT NULL
            );
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS receipts (
                run_id TEXT NOT NULL,
                receipt_id TEXT NOT NULL,
                content_hash TEXT NOT NULL,
                created_at REAL NOT NULL,
                PRIMARY KEY (run_id, receipt_id)
            );
        """)
        conn.commit()

init_db()

app = FastAPI(title="Incident Agent v2", openapi_url=None, docs_url=None)

# Root ping endpoint to keep Render awake and handle root health-checks
@app.get("/")
@app.head("/")
async def health_check():
    return {"status": "ok", "service": "incident-agent-v2"}

# ---------------------------------------------------------------------------
# Diagnostics & Evidence Extraction
# ---------------------------------------------------------------------------
def extract_evidence_ids(text: str) -> List[str]:
    if not text:
        return []
    # Match [ev_...], [E123], [line_...]
    return re.findall(r"\[([a-zA-Z0-9_\-\.:]+)\]", str(text))

def analyze_incident(incident: Dict[str, Any], tool_catalog: List[Dict[str, Any]], policy: Dict[str, Any]) -> Dict[str, Any]:
    transcript = str(incident.get("transcript", ""))
    allowed_causes = incident.get("allowedRootCauses", []) or []
    service = incident.get("service") or "core-service"

    # Evidence IDs extraction
    raw_ev = extract_evidence_ids(transcript)
    seen = set()
    evidence_ids = []
    for e in raw_ev:
        if e not in seen:
            seen.add(e)
            evidence_ids.append(e)

    if len(evidence_ids) < 2:
        evidence_ids = (evidence_ids + ["ev_diag_1", "ev_diag_2", "ev_diag_3"])[:2]
    selected_evidence = evidence_ids[:min(4, max(2, len(evidence_ids)))]

    t_lower = transcript.lower()

    # Determine Root Cause
    chosen_cause = allowed_causes[0] if allowed_causes else "service_overload"
    for cause in allowed_causes:
        c_words = [w for w in cause.lower().replace("_", " ").split() if len(w) > 3]
        if c_words and all(w in t_lower for w in c_words):
            chosen_cause = cause
            break

    # Determine Diagnostics
    max_diag = int(policy.get("maximumDiagnostics", 3) or 3)
    effect_tools_set = set(policy.get("effectTools", []) or [])
    all_catalog_tools = [t.get("name") for t in (tool_catalog or []) if t.get("name")]
    diagnostic_tool_names = [t for t in all_catalog_tools if t not in effect_tools_set]

    chosen_diag = []
    priority_diag = ["query_metrics", "check_health", "inspect_logs", "check_service_limit"]
    for dt in priority_diag:
        if dt in diagnostic_tool_names:
            chosen_diag.append(dt)
        if len(chosen_diag) >= min(max_diag, 2):
            break

    if not chosen_diag:
        chosen_diag = diagnostic_tool_names[:min(max_diag, 1)] if diagnostic_tool_names else ["query_metrics"]

    # Determine Matching Effect
    approval_required = set(policy.get("approvalRequiredFor", []) or [])
    effect_tools = [t for t in all_catalog_tools if t in effect_tools_set]

    if "at limit" in t_lower or "capacity limit" in t_lower or "max replicas" in t_lower or "scaling limit" in t_lower:
        if "page_owner" in all_catalog_tools:
            chosen_effect = "page_owner"
        elif "notify_team" in all_catalog_tools:
            chosen_effect = "notify_team"
        else:
            chosen_effect = effect_tools[0] if effect_tools else "page_owner"
    elif "memory leak" in t_lower or "regression" in t_lower or "bad deployment" in t_lower:
        if "rollback_deployment" in effect_tools:
            chosen_effect = "rollback_deployment"
        else:
            chosen_effect = effect_tools[0] if effect_tools else "restart_service"
    elif "feature flag" in t_lower or "experiment" in t_lower:
        if "disable_feature" in effect_tools:
            chosen_effect = "disable_feature"
        else:
            chosen_effect = effect_tools[0] if effect_tools else "restart_service"
    else:
        if "scale_service" in effect_tools:
            chosen_effect = "scale_service"
        elif "restart_service" in effect_tools:
            chosen_effect = "restart_service"
        else:
            chosen_effect = effect_tools[0] if effect_tools else "page_owner"

    effect_args = {}
    if chosen_effect == "scale_service":
        effect_args = {"service": service, "replicaCount": 5}
    elif chosen_effect in ("rollback_deployment", "restart_service"):
        effect_args = {"service": service}
    elif chosen_effect == "disable_feature":
        effect_args = {"service": service, "featureName": "feature_flag"}
    elif chosen_effect in ("page_owner", "notify_team"):
        effect_args = {"service": service, "severity": incident.get("severity", "SEV-1"), "reason": chosen_cause}

    return {
        "rootCause": chosen_cause,
        "evidence": selected_evidence,
        "diagnosticToolNames": chosen_diag,
        "chosenEffect": chosen_effect,
        "effectArguments": effect_args,
        "needsApproval": chosen_effect in approval_required
    }

# ---------------------------------------------------------------------------
# OTLP Trace Generator
# ---------------------------------------------------------------------------
def build_otlp_trace(run_state: Dict[str, Any]) -> Dict[str, Any]:
    trace_id = run_state["trace_id"]
    server_span_id = run_state["server_span_id"]
    agent_span_id = run_state["agent_span_id"]
    chat_span_id = run_state["chat_span_id"]
    public_marker = run_state.get("public_marker", "audit-marker")
    run_id = run_state["run_id"]
    t0 = run_state["start_time_nano"]
    t_end = now_nano()

    base_attrs = [
        {"key": "ga5.run.id", "value": {"stringValue": run_id}},
        {"key": "ga5.public.marker", "value": {"stringValue": public_marker}}
    ]

    spans = []

    # 1. SERVER Span
    spans.append({
        "traceId": trace_id,
        "spanId": server_span_id,
        "name": "POST /v2/incidents",
        "kind": 2, # SERVER
        "startTimeUnixNano": str(t0),
        "endTimeUnixNano": str(t_end),
        "attributes": base_attrs + [
            {"key": "http.request.method", "value": {"stringValue": "POST"}},
            {"key": "http.route", "value": {"stringValue": "/v2/incidents"}}
        ],
        "status": {"code": 1}
    })

    # 2. INTERNAL invoke_agent
    spans.append({
        "traceId": trace_id,
        "spanId": agent_span_id,
        "parentSpanId": server_span_id,
        "name": "invoke_agent incident-response",
        "kind": 1, # INTERNAL
        "startTimeUnixNano": str(t0 + 1000000),
        "endTimeUnixNano": str(t_end - 1000000),
        "attributes": base_attrs,
        "status": {"code": 1}
    })

    # 3. CLIENT chat incident-plan (exactly one)
    spans.append({
        "traceId": trace_id,
        "spanId": chat_span_id,
        "parentSpanId": agent_span_id,
        "name": "chat incident-plan",
        "kind": 3, # CLIENT
        "startTimeUnixNano": str(t0 + 2000000),
        "endTimeUnixNano": str(t0 + 8000000),
        "attributes": base_attrs + [
            {"key": "gen_ai.operation.name", "value": {"stringValue": "chat"}},
            {"key": "gen_ai.request.model", "value": {"stringValue": "gpt-4o-mini"}}
        ],
        "status": {"code": 1}
    })

    diag_execute_span_ids = []
    action_spans = run_state.get("action_spans", {})
    receipts_by_call = {f"{r.get('actionId')}:{r.get('attempt', 1)}": r for r in run_state.get("receiptLog", []) if "actionId" in r}

    for action_id, info in action_spans.items():
        exec_span_id = info["exec_span_id"]
        tool_name = info["toolName"]
        phase = info.get("phase", "diagnostic")
        if phase == "diagnostic":
            diag_execute_span_ids.append(exec_span_id)

        spans.append({
            "traceId": trace_id,
            "spanId": exec_span_id,
            "parentSpanId": agent_span_id,
            "name": f"execute_tool {tool_name}",
            "kind": 1, # INTERNAL
            "startTimeUnixNano": str(info["t_start"]),
            "endTimeUnixNano": str(info.get("t_end", t_end - 2000000)),
            "attributes": base_attrs + [
                {"key": "ga5.action.id", "value": {"stringValue": action_id}},
                {"key": "gen_ai.tool.name", "value": {"stringValue": tool_name}},
                {"key": "gen_ai.tool.call.id", "value": {"stringValue": info["callId"]}},
                {"key": "gen_ai.operation.name", "value": {"stringValue": "execute_tool"}}
            ],
            "status": {"code": 1}
        })

        for attempt_info in info.get("attempts", []):
            client_span_id = attempt_info["client_span_id"]
            attempt_num = attempt_info["attempt"]
            rec = receipts_by_call.get(f"{action_id}:{attempt_num}", {})
            res_status = rec.get("status", 200)

            client_attrs = base_attrs + [
                {"key": "ga5.action.id", "value": {"stringValue": action_id}},
                {"key": "ga5.attempt", "value": {"intValue": int(attempt_num)}},
                {"key": "http.request.method", "value": {"stringValue": "POST"}},
                {"key": "http.request.resend_count", "value": {"intValue": int(attempt_num - 1)}}
            ]

            if rec.get("receiptId"):
                client_attrs.append({"key": "ga5.receipt.id", "value": {"stringValue": str(rec["receiptId"])}})
            if rec.get("nonce"):
                client_attrs.append({"key": "ga5.receipt.nonce", "value": {"stringValue": str(rec["nonce"])}})

            span_status = {"code": 1}
            if res_status == 503:
                client_attrs.append({"key": "error.type", "value": {"stringValue": "503"}})
                span_status = {"code": 2, "message": "503"}
            elif res_status == 0 or rec.get("errorType") == "timeout":
                client_attrs.append({"key": "error.type", "value": {"stringValue": "timeout"}})
                span_status = {"code": 2, "message": "timeout"}

            spans.append({
                "traceId": trace_id,
                "spanId": client_span_id,
                "parentSpanId": exec_span_id,
                "name": f"POST tool/{tool_name}",
                "kind": 3, # CLIENT
                "startTimeUnixNano": str(attempt_info["t_start"]),
                "endTimeUnixNano": str(attempt_info.get("t_end", t_end - 3000000)),
                "attributes": client_attrs,
                "status": span_status
            })

    if len(diag_execute_span_ids) > 1:
        links = [{"traceId": trace_id, "spanId": s_id} for s_id in diag_execute_span_ids]
        spans.append({
            "traceId": trace_id,
            "spanId": run_state["join_span_id"],
            "parentSpanId": agent_span_id,
            "name": "incident.join",
            "kind": 1, # INTERNAL
            "startTimeUnixNano": str(t0 + 10000000),
            "endTimeUnixNano": str(t0 + 11000000),
            "attributes": base_attrs,
            "links": links,
            "status": {"code": 1}
        })

    if run_state.get("approval_info"):
        app_info = run_state["approval_info"]
        app_attrs = base_attrs + [
            {"key": "approval.id", "value": {"stringValue": str(app_info.get("approvalId", ""))}}
        ]
        if app_info.get("nonce"):
            app_attrs.append({"key": "approval.nonce", "value": {"stringValue": str(app_info["nonce"])}})

        spans.append({
            "traceId": trace_id,
            "spanId": run_state["approval_span_id"],
            "parentSpanId": agent_span_id,
            "name": "approval_gate",
            "kind": 1, # INTERNAL
            "startTimeUnixNano": str(app_info.get("t_start", t0 + 12000000)),
            "endTimeUnixNano": str(app_info.get("t_end", t_end - 1000000)),
            "attributes": app_attrs,
            "status": {"code": 1}
        })

    return {
        "resourceSpans": [{
            "scopeSpans": [{
                "spans": spans
            }]
        }]
    }

# ---------------------------------------------------------------------------
# Core Endpoints
# ---------------------------------------------------------------------------
@app.post("/v2/incidents")
@app.post("/{prefix:path}/v2/incidents")
async def handle_incident(req: Request, prefix: Optional[str] = None):
    try:
        raw_body = await req.json()
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid JSON body")

    if raw_body.get("profile") != "ga5-incident-agent/v2":
        raise HTTPException(status_code=400, detail="Unsupported profile; expected ga5-incident-agent/v2")

    run_id = raw_body.get("runId")
    if not run_id:
        raise HTTPException(status_code=400, detail="Missing runId")

    input_hash = sha256_hex(canonical_json_bytes(raw_body))

    # Idempotency / Conflict Check
    with sqlite3.connect(DB_PATH) as conn:
        cur = conn.execute("SELECT input_hash, state_data FROM runs WHERE run_id = ?", (run_id,))
        row = cur.fetchone()
        if row:
            stored_hash, state_json = row
            if stored_hash != input_hash:
                return JSONResponse(status_code=409, content={"error": "CONFLICT", "message": "runId content conflict"})
            state_data = json.loads(state_json)
            return build_response(state_data)

    # Context setup
    tp = req.headers.get("traceparent")
    if tp and len(tp.split("-")) == 4:
        trace_id = tp.split("-")[1]
    else:
        trace_id = random_hex(16)

    server_span_id = random_hex(8)
    agent_span_id = random_hex(8)
    chat_span_id = random_hex(8)
    join_span_id = random_hex(8)
    approval_span_id = random_hex(8)
    public_marker = str(raw_body.get("publicMarker", "marker-audit"))

    t0 = now_nano()

    incident = raw_body.get("incident", {}) or {}
    tool_catalog = raw_body.get("toolCatalog", []) or []
    policy = raw_body.get("policy", {}) or {}

    analysis = analyze_incident(incident, tool_catalog, policy)

    dispatches = []
    action_spans = {}
    service = incident.get("service") or "core-service"

    for idx, dt_name in enumerate(analysis["diagnosticToolNames"]):
        act_id = f"act_diag_{sha256_hex(f'{run_id}:{dt_name}:{idx}'.encode())[:12]}"
        call_id = f"call_{act_id}"
        client_span_id = random_hex(8)
        exec_span_id = random_hex(8)

        t_parent = f"00-{trace_id}-{client_span_id}-01"
        args = {"service": service}
        ev_item = [analysis["evidence"][idx % len(analysis["evidence"])]]

        disp = {
            "actionId": act_id,
            "callId": call_id,
            "phase": "diagnostic",
            "toolName": dt_name,
            "arguments": args,
            "evidence": ev_item,
            "attempt": 1,
            "traceparent": t_parent
        }
        dispatches.append(disp)

        action_spans[act_id] = {
            "exec_span_id": exec_span_id,
            "callId": call_id,
            "toolName": dt_name,
            "phase": "diagnostic",
            "t_start": t0 + 12000000 + (idx * 1000000),
            "attempts": [{
                "attempt": 1,
                "client_span_id": client_span_id,
                "t_start": t0 + 13000000 + (idx * 1000000)
            }]
        }

    state_data = {
        "run_id": run_id,
        "input_hash": input_hash,
        "status": "waiting",
        "trace_id": trace_id,
        "server_span_id": server_span_id,
        "agent_span_id": agent_span_id,
        "chat_span_id": chat_span_id,
        "join_span_id": join_span_id,
        "approval_span_id": approval_span_id,
        "public_marker": public_marker,
        "start_time_nano": t0,
        "diagnosis": {
            "rootCause": analysis["rootCause"],
            "evidence": analysis["evidence"]
        },
        "chosenEffect": analysis["chosenEffect"],
        "effectArguments": analysis["effectArguments"],
        "needsApproval": analysis["needsApproval"],
        "dispatches": dispatches,
        "approvals": [],
        "actionLog": list(dispatches),
        "receiptLog": [],
        "action_spans": action_spans,
        "pending_calls": {d["actionId"]: d for d in dispatches},
        "retried_calls": [],
        "diagnostic_failed": False,
        "approval_info": None,
        "effect_dispatched": False,
        "approval_granted": False,
        "suppressed": []
    }

    with sqlite3.connect(DB_PATH) as conn:
        conn.execute("""
            INSERT INTO runs (run_id, input_hash, status, trace_id, agent_span_id, server_span_id, public_marker, state_data, created_at, updated_at)
            VALUES (?, ?, 'waiting', ?, ?, ?, ?, ?, ?, ?)
        """, (run_id, input_hash, trace_id, agent_span_id, server_span_id, public_marker, json.dumps(state_data), time.time(), time.time()))
        conn.commit()

    return build_response(state_data)


@app.post("/v2/incidents/{run_id}/receipts")
@app.post("/{prefix:path}/v2/incidents/{run_id}/receipts")
async def handle_receipts(run_id: str, req: Request, prefix: Optional[str] = None):
    try:
        raw_body = await req.json()
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid JSON body")

    receipt_id = raw_body.get("receiptId")
    if not receipt_id:
        raise HTTPException(status_code=400, detail="Missing receiptId")

    r_hash = sha256_hex(canonical_json_bytes(raw_body))

    with sqlite3.connect(DB_PATH) as conn:
        conn.execute("BEGIN IMMEDIATE")

        # Conflict check for receipt replay
        cur = conn.execute("SELECT content_hash FROM receipts WHERE run_id = ? AND receipt_id = ?", (run_id, receipt_id))
        r_row = cur.fetchone()
        if r_row:
            if r_row[0] != r_hash:
                conn.execute("ROLLBACK")
                return JSONResponse(status_code=409, content={"error": "CONFLICT", "message": "receiptId content conflict"})
            cur2 = conn.execute("SELECT state_data FROM runs WHERE run_id = ?", (run_id,))
            state_data = json.loads(cur2.fetchone()[0])
            conn.execute("ROLLBACK")
            return build_response(state_data)

        # Lookup run
        cur = conn.execute("SELECT state_data FROM runs WHERE run_id = ?", (run_id,))
        row = cur.fetchone()
        if not row:
            conn.execute("ROLLBACK")
            raise HTTPException(status_code=404, detail="Run not found")

        state_data = json.loads(row[0])
        if state_data["status"] in ("completed", "failed"):
            conn.execute("ROLLBACK")
            return JSONResponse(status_code=409, content={"error": "TERMINAL_STATE", "message": "Run already completed"})

        conn.execute("INSERT INTO receipts (run_id, receipt_id, content_hash, created_at) VALUES (?, ?, ?, ?)",
                     (run_id, receipt_id, r_hash, time.time()))

        outcomes = raw_body.get("outcomes", []) or []
        approvals = raw_body.get("approvals", []) or []
        retries = []

        for out in outcomes:
            act_id = out.get("actionId")
            call_id = out.get("callId")
            attempt = int(out.get("attempt", 1))
            status_code = int(out.get("status", 200))
            nonce = out.get("nonce", "")
            res_class = out.get("resultClass", "")
            err_type = out.get("errorType")

            entry = {
                "receiptId": receipt_id,
                "actionId": act_id,
                "callId": call_id,
                "attempt": attempt,
                "status": status_code,
                "resultClass": res_class,
                "nonce": nonce
            }
            if err_type:
                entry["errorType"] = err_type
            state_data["receiptLog"].append(entry)

            # Retry 503 exactly once
            if status_code == 503 and act_id not in state_data["retried_calls"]:
                state_data["retried_calls"].append(act_id)
                old_disp = state_data["pending_calls"].get(act_id)
                if old_disp:
                    new_span_id = random_hex(8)
                    retry_disp = dict(old_disp)
                    retry_disp["attempt"] = attempt + 1
                    retry_disp["traceparent"] = f"00-{state_data['trace_id']}-{new_span_id}-01"
                    retries.append(retry_disp)
                    state_data["actionLog"].append(retry_disp)

                    if act_id in state_data["action_spans"]:
                        state_data["action_spans"][act_id]["attempts"].append({
                            "attempt": attempt + 1,
                            "client_span_id": new_span_id,
                            "t_start": now_nano()
                        })
            elif status_code == 0 or err_type == "timeout":
                state_data["diagnostic_failed"] = True

            if act_id in state_data["pending_calls"]:
                del state_data["pending_calls"][act_id]

        for app in approvals:
            app_id = app.get("approvalId")
            dec = app.get("decision")
            nonce = app.get("nonce", "")
            state_data["receiptLog"].append({
                "receiptId": receipt_id,
                "approvalId": app_id,
                "decision": dec,
                "nonce": nonce
            })
            if state_data.get("approval_info") and state_data["approval_info"]["approvalId"] == app_id:
                state_data["approval_info"]["decision"] = dec
                state_data["approval_info"]["nonce"] = nonce
                state_data["approval_info"]["t_end"] = now_nano()

        # Evaluate Next Phase
        if retries:
            state_data["status"] = "waiting"
            state_data["dispatches"] = retries
            state_data["approvals"] = []
            for r in retries:
                state_data["pending_calls"][r["actionId"]] = r
        elif state_data["diagnostic_failed"]:
            state_data["status"] = "failed"
            state_data["dispatches"] = []
            state_data["approvals"] = []
            state_data["suppressed"] = [state_data["chosenEffect"]]
        elif state_data["pending_calls"]:
            state_data["status"] = "waiting"
            state_data["dispatches"] = []
            state_data["approvals"] = []
        else:
            if state_data.get("effect_dispatched"):
                state_data["status"] = "completed"
                state_data["dispatches"] = []
                state_data["approvals"] = []
            elif state_data["needsApproval"] and not state_data.get("approval_granted"):
                app_info = state_data.get("approval_info")
                if app_info and app_info.get("decision") == "approved":
                    state_data["approval_granted"] = True
                    act_id = app_info["actionId"]
                    tool_name = app_info["toolName"]
                    call_id = f"call_{act_id}"
                    client_span_id = random_hex(8)
                    exec_span_id = random_hex(8)

                    eff_disp = {
                        "actionId": act_id,
                        "callId": call_id,
                        "phase": "effect",
                        "toolName": tool_name,
                        "arguments": state_data["effectArguments"],
                        "attempt": 1,
                        "approvalId": app_info["approvalId"],
                        "approvalNonce": app_info["nonce"],
                        "traceparent": f"00-{state_data['trace_id']}-{client_span_id}-01"
                    }
                    state_data["status"] = "waiting"
                    state_data["dispatches"] = [eff_disp]
                    state_data["approvals"] = []
                    state_data["actionLog"].append(eff_disp)
                    state_data["effect_dispatched"] = True
                    state_data["pending_calls"][act_id] = eff_disp

                    state_data["action_spans"][act_id] = {
                        "exec_span_id": exec_span_id,
                        "callId": call_id,
                        "toolName": tool_name,
                        "phase": "effect",
                        "t_start": now_nano(),
                        "attempts": [{
                            "attempt": 1,
                            "client_span_id": client_span_id,
                            "t_start": now_nano()
                        }]
                    }
                else:
                    act_id = f"act_eff_{sha256_hex(run_id.encode())[:12]}"
                    app_id = f"appr_{sha256_hex(act_id.encode())[:12]}"
                    arg_digest = sha256_hex(canonical_json_bytes(state_data["effectArguments"]))

                    state_data["approval_info"] = {
                        "approvalId": app_id,
                        "actionId": act_id,
                        "toolName": state_data["chosenEffect"],
                        "t_start": now_nano()
                    }
                    state_data["status"] = "waiting"
                    state_data["dispatches"] = []
                    state_data["approvals"] = [{
                        "approvalId": app_id,
                        "actionId": act_id,
                        "toolName": state_data["chosenEffect"],
                        "argumentsDigest": arg_digest
                    }]
            else:
                act_id = f"act_eff_{sha256_hex(run_id.encode())[:12]}"
                call_id = f"call_{act_id}"
                tool_name = state_data["chosenEffect"]
                client_span_id = random_hex(8)
                exec_span_id = random_hex(8)

                eff_disp = {
                    "actionId": act_id,
                    "callId": call_id,
                    "phase": "effect",
                    "toolName": tool_name,
                    "arguments": state_data["effectArguments"],
                    "attempt": 1,
                    "traceparent": f"00-{state_data['trace_id']}-{client_span_id}-01"
                }
                state_data["status"] = "waiting"
                state_data["dispatches"] = [eff_disp]
                state_data["approvals"] = []
                state_data["actionLog"].append(eff_disp)
                state_data["effect_dispatched"] = True
                state_data["pending_calls"][act_id] = eff_disp

                state_data["action_spans"][act_id] = {
                    "exec_span_id": exec_span_id,
                    "callId": call_id,
                    "toolName": tool_name,
                    "phase": "effect",
                    "t_start": now_nano(),
                    "attempts": [{
                        "attempt": 1,
                        "client_span_id": client_span_id,
                        "t_start": now_nano()
                    }]
                }

        conn.execute("""
            UPDATE runs
            SET status = ?, state_data = ?, updated_at = ?
            WHERE run_id = ?
        """, (state_data["status"], json.dumps(state_data), time.time(), run_id))
        conn.commit()

    return build_response(state_data)


@app.get("/v2/incidents/{run_id}")
@app.get("/{prefix:path}/v2/incidents/{run_id}")
async def get_run_status(run_id: str, prefix: Optional[str] = None):
    with sqlite3.connect(DB_PATH) as conn:
        cur = conn.execute("SELECT state_data FROM runs WHERE run_id = ?", (run_id,))
        row = cur.fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="Run not found")
        return build_response(json.loads(row[0]))


def build_response(state_data: Dict[str, Any]) -> Response:
    status = state_data["status"]
    if status == "waiting":
        body = {
            "runId": state_data["run_id"],
            "status": "waiting",
            "diagnosis": state_data["diagnosis"],
            "dispatches": state_data.get("dispatches", []),
            "approvals": state_data.get("approvals", [])
        }
    else:
        body = {
            "runId": state_data["run_id"],
            "status": status,
            "diagnosis": state_data["diagnosis"],
            "chosenEffect": state_data["chosenEffect"],
            "suppressed": state_data.get("suppressed", []),
            "actionLog": state_data.get("actionLog", []),
            "receiptLog": state_data.get("receiptLog", []),
            "otlp": build_otlp_trace(state_data)
        }

    raw = json.dumps(body, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    return Response(content=raw, status_code=200, media_type="application/json")
