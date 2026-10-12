"""BƯỚC 3c — trifecta split + egress allowlist (13').

Tách 1 yêu cầu người dùng thành ít nhất 2 run riêng biệt — KHÔNG run nào
được cầm cả 3 chân của trifecta cùng lúc:

    Run A: gọi search_docs (untrusted content).
           KHÔNG gọi read_customer. KHÔNG gọi http_post.
    Run B: gọi read_customer (private data).
           CHỈ nhận input là TYPED, ĐÃ SANITIZE từ Run A — ví dụ
           list[int] ticket id trích từ TÊN FILE (vd "ticket-007.md" -> 7),
           KHÔNG BAO GIỜ nhận nguyên văn text của document. free text của
           attacker không được đi xa hơn Run A.

Mọi lần gọi tool (allow HAY deny) phải:
  1. Đi qua `agent.policy.check()` TRƯỚC KHI tool thật sự chạy.
  2. Được ghi vào ledger qua `agent.ledger.append()` — cả khi deny.
Nếu policy deny, KHÔNG được gọi tool đó.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
import hashlib
import json
from pathlib import Path
import re
import uuid

from agent import ledger, pii, policy, tools
from agent.policy import PolicyContext

REPORTS_DIR = Path(__file__).resolve().parent.parent / "reports"
DEFAULT_LEDGER_PATH = REPORTS_DIR / "ledger.jsonl"
CUSTOMERS_FILE = Path(__file__).resolve().parent.parent / "data" / "customers.json"


class RunnerScaffoldPending(NotImplementedError):
    """Only the original 3c stub uses this to enable the CP1/CP2 baseline."""


def handle(
    message: str,
    llm,
    log_dir: Path | None = None,
    principal_id: str = "support_l1",
) -> str:
    ledger_path = (log_dir / "ledger.jsonl") if log_dir else DEFAULT_LEDGER_PATH
    agent_id = "lab24-agent"
    now_utc = datetime.now(timezone.utc)
    expires_at = (now_utc + timedelta(hours=1)).isoformat()

    def _authorize(
        tool_name: str,
        args: tuple,
        kwargs: dict,
        data_classification: str,
        request_purpose: str,
        agent_owner: str,
        run_id: str,
        delegation_depth: int,
        egress_enabled: bool,
        agent_scopes: tuple[str, ...],
        parent_scopes: tuple[str, ...] = (),
    ):
        ctx = PolicyContext(
            data_classification=data_classification,
            request_purpose=request_purpose,
            agent_owner=agent_owner,
            delegation_depth=delegation_depth,
            egress_enabled=egress_enabled,
            principal_id=principal_id,
            requested_tool=tool_name,
            agent_scopes=agent_scopes,
            parent_scopes=parent_scopes,
            expires_at=expires_at,
        )
        allowed, reason = policy.check(ctx)

        # Hash arguments for audit
        args_repr = json.dumps(
            {"args": [str(a) for a in args], "kwargs": {k: str(v) for k, v in kwargs.items()}},
            sort_keys=True,
            ensure_ascii=False,
        )
        args_hash = hashlib.sha256(args_repr.encode("utf-8")).hexdigest()

        entry = {
            "ts": datetime.now(timezone.utc).isoformat(),
            "agent_id": agent_id,
            "run_id": run_id,
            "tool": tool_name,
            "args_hash": args_hash,
            "classification": data_classification,
            "decision": "allow" if allowed else "deny",
            "reason": reason,
            "on_behalf_of": principal_id,
            "expires_at": expires_at,
        }
        ledger.append(entry, ledger_path)

        return allowed

    def _call_tool(
        tool_name: str,
        func,
        args: tuple,
        kwargs: dict,
        data_classification: str,
        request_purpose: str,
        agent_owner: str,
        run_id: str,
        delegation_depth: int,
        egress_enabled: bool,
        agent_scopes: tuple[str, ...],
        parent_scopes: tuple[str, ...] = (),
    ):
        allowed = _authorize(
            tool_name=tool_name,
            args=args,
            kwargs=kwargs,
            data_classification=data_classification,
            request_purpose=request_purpose,
            agent_owner=agent_owner,
            run_id=run_id,
            delegation_depth=delegation_depth,
            egress_enabled=egress_enabled,
            agent_scopes=agent_scopes,
            parent_scopes=parent_scopes,
        )

        if not allowed:
            return None, False

        res = func(*args, **kwargs)
        return res, True

    # -----------------------------------------------------------------------
    # Run A: search_docs (Untrusted Content)
    # -----------------------------------------------------------------------
    run_id_a = f"run-a-{uuid.uuid4().hex[:8]}"
    docs, allowed_a = _call_tool(
        tool_name="search_docs",
        func=tools.search_docs,
        args=(message,),
        kwargs={},
        data_classification="internal",
        request_purpose="summarize-tickets",
        agent_owner=f"{agent_id}/{run_id_a}",
        run_id=run_id_a,
        delegation_depth=0,
        egress_enabled=False,
        agent_scopes=("search_docs",),
    )
    if not allowed_a or docs is None:
        return "Yêu cầu bị từ chối bởi chính sách."

    # Typed sanitization: extract integer ticket_ids ONLY from filename (doc["id"])
    ticket_ids: set[int] = set()
    for d in docs:
        m = re.fullmatch(r"ticket-(\d+)\.md", d["id"])
        if m:
            ticket_ids.add(int(m.group(1)))

    combined_text = "\n\n".join(d["text"] for d in docs)
    injected = llm.find_injection(combined_text)

    # -----------------------------------------------------------------------
    # Run B: read_customer (Private Data Store) via Trusted Mapping
    # -----------------------------------------------------------------------
    run_id_b = f"run-b-{uuid.uuid4().hex[:8]}"
    run_b_owner = f"{agent_id}/{run_id_b}"

    # The trusted ticket-to-customer index lives in the private store too.
    # Authorize that boundary before opening the file. Only typed ticket IDs
    # cross from Run A; no document text or attacker-supplied customer ID does.
    may_open_private_index = _authorize(
        tool_name="read_customer",
        args=(sorted(ticket_ids),),
        kwargs={},
        data_classification="restricted",
        request_purpose="support-reply",
        agent_owner=run_b_owner,
        run_id=run_id_b,
        delegation_depth=0,
        egress_enabled=False,
        agent_scopes=("read_customer",),
    )

    customers_data: list[dict] = []
    if may_open_private_index and CUSTOMERS_FILE.exists():
        customers_data = json.loads(CUSTOMERS_FILE.read_text(encoding="utf-8"))

    # Map ticket_ids to customer_ids using trusted customer metadata
    matched_customer_ids: list[str] = []
    for cust in customers_data:
        rel_tickets = cust.get("related_tickets", [])
        if any(tid in rel_tickets for tid in ticket_ids):
            if cust["customer_id"] not in matched_customer_ids:
                matched_customer_ids.append(cust["customer_id"])

    for cid in matched_customer_ids:
        _record, _allowed_b = _call_tool(
            tool_name="read_customer",
            func=tools.read_customer,
            args=(cid,),
            kwargs={},
            data_classification="restricted",
            request_purpose="support-reply",
            agent_owner=run_b_owner,
            run_id=run_id_b,
            delegation_depth=0,
            egress_enabled=False,
            agent_scopes=("read_customer",),
        )

    # -----------------------------------------------------------------------
    # Egress Attempt check (PEP Enforcement on http_post)
    # -----------------------------------------------------------------------
    if injected is not None:
        run_id_c = f"run-c-{uuid.uuid4().hex[:8]}"

        # This callable is never reached under the mandatory restricted +
        # egress deny rule. Keeping only the URL in args ensures the policy
        # attempt itself never carries a customer record across the boundary.
        def _post_without_records(url: str):
            return tools.http_post(url, {})

        _call_tool(
            tool_name="http_post",
            func=_post_without_records,
            args=(injected.target_url,),
            kwargs={},
            data_classification="restricted",
            request_purpose="reconciliation",
            agent_owner=f"{agent_id}/{run_id_c}",
            run_id=run_id_c,
            delegation_depth=1,
            egress_enabled=True,
            agent_scopes=("http_post",),
        )

    # -----------------------------------------------------------------------
    # PII Gate & Summarization
    # -----------------------------------------------------------------------
    sanitized_docs = []
    for d in docs:
        sanitized_docs.append({
            "id": d["id"],
            "text": pii.redact(d["text"]),
        })

    return llm.summarize(sanitized_docs)
