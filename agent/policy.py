"""BƯỚC 3b — PEP (Policy Enforcement Point) tại tool call (15').

Cổng chặn TRƯỚC KHI tool thật sự execute. Đọc CHECKPOINTS.md (§3b).

Interface bắt buộc (tests/test_policy.py và agent/runner.py gọi trực tiếp):

    check(context: PolicyContext) -> tuple[bool, str]
        Trả về (allow, reason).
        `reason` KHÔNG BAO GIỜ được để trống — cả khi allow=True và
        allow=False. Đây là evidence audit ở Bước 4 (rubric: "Audit
        completeness = 100%" — điều kiện trượt nếu có dòng thiếu reason).

PolicyContext — 5 input gốc và các input OBO cho lớp L3:

    data_classification: str   "public" | "internal" | "restricted"
    request_purpose: str       tự do, ví dụ "reconciliation", "support-reply"
    agent_owner: str            định danh agent/run gọi tool này
    delegation_depth: int       0 = gọi trực tiếp bởi user, >0 = agent gọi agent
    egress_enabled: bool        run hiện tại có được phép gọi network không
    principal_id: str           ID người ra lệnh từ data/principals.json
    requested_tool: str         tool sắp gọi
    agent_scopes: tuple[str]    quyền tối đa của agent
    parent_scopes: tuple[str]   quyền của agent cha khi delegation_depth > 0
    expires_at: str             ISO-8601 UTC; hết hạn phải deny

Rule TỐI THIỂU bắt buộc (không được viết yếu hơn rule này):

    classification == "restricted" and egress_enabled is True  ->  DENY

Checkpoint OBO: quyền hiệu lực = principal.allowed_tools ∩ agent_scopes,
và nếu depth > 0 thì còn giao với parent_scopes. Unknown principal, scope
thiếu, run hết hạn đều deny kèm reason. Principal là fixture mô phỏng,
không phải xác thực người dùng production.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import json
from pathlib import Path
from typing import Any

PRINCIPALS_FILE = Path(__file__).resolve().parent.parent / "data" / "principals.json"


def _load_principals() -> dict[str, dict[str, Any]]:
    """Load the simulated authority source, failing closed on bad data."""
    try:
        principals = json.loads(PRINCIPALS_FILE.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    return principals if isinstance(principals, dict) else {}


def _parse_utc_expiry(value: str) -> datetime | None:
    """Return an aware UTC datetime, or None for missing/invalid/non-UTC input."""
    if not value or not isinstance(value, str):
        return None
    try:
        # Python 3.10 does not accept the trailing ``Z`` in fromisoformat().
        normalized = value[:-1] + "+00:00" if value.endswith("Z") else value
        parsed = datetime.fromisoformat(normalized)
    except ValueError:
        return None
    if parsed.tzinfo is None or parsed.utcoffset() != timezone.utc.utcoffset(parsed):
        return None
    return parsed.astimezone(timezone.utc)


@dataclass(frozen=True)
class PolicyContext:
    data_classification: str
    request_purpose: str
    agent_owner: str
    delegation_depth: int
    egress_enabled: bool
    principal_id: str = ""
    requested_tool: str = ""
    agent_scopes: tuple[str, ...] = ()
    parent_scopes: tuple[str, ...] = ()
    expires_at: str = ""


def check(context: PolicyContext) -> tuple[bool, str]:
    # 1. Kiểm data_classification chỉ thuộc public, internal, restricted
    if context.data_classification not in ("public", "internal", "restricted"):
        return False, f"Invalid data classification '{context.data_classification}'"

    # 2. Rule tối thiểu: restricted + egress_enabled -> DENY (bất kể principal nào)
    if context.data_classification == "restricted" and context.egress_enabled:
        return False, "Egress is prohibited for restricted data (minimum PEP deny rule)"

    # 3. Các context còn lại phải là một tool request OBO đầy đủ.
    if context.delegation_depth < 0:
        return False, "Delegation depth cannot be negative"
    if not context.agent_owner or not context.agent_owner.strip():
        return False, "Agent owner is required"
    if not context.principal_id or not context.principal_id.strip():
        return False, "Principal identity is required"
    if not context.requested_tool or not context.requested_tool.strip():
        return False, "Requested tool is required"
    if not context.request_purpose or not context.request_purpose.strip():
        return False, "Request purpose is required"

    # 4. TTL bắt buộc, phải là ISO-8601 UTC và vẫn còn hiệu lực.
    exp_dt = _parse_utc_expiry(context.expires_at)
    if exp_dt is None:
        return False, "A valid UTC expiration time is required"
    if datetime.now(timezone.utc) >= exp_dt:
        return False, f"Authorization expired at {context.expires_at}"

    # 5. Kiểm danh tính principal từ data/principals.json
    principals = _load_principals()
    if context.principal_id not in principals:
        return False, f"Unknown principal '{context.principal_id}'"

    p_info = principals[context.principal_id]
    if not isinstance(p_info, dict):
        return False, f"Invalid authority record for principal '{context.principal_id}'"

    # 6. Mục đích phải nằm trong danh sách được uỷ quyền.
    allowed_purposes = p_info.get("purposes", [])
    if not isinstance(allowed_purposes, list) or context.request_purpose not in allowed_purposes:
        return False, f"Purpose '{context.request_purpose}' not allowed for principal '{context.principal_id}'"

    # 7. Quyền hiệu lực là giao principal ∩ agent (∩ parent nếu delegated).
    allowed_tools = p_info.get("allowed_tools", [])
    principal_tools = set(allowed_tools) if isinstance(allowed_tools, list) else set()
    if context.requested_tool not in principal_tools:
        return False, f"Tool '{context.requested_tool}' not in allowed tools for principal '{context.principal_id}'"

    if not context.agent_scopes or context.requested_tool not in context.agent_scopes:
        return False, f"Tool '{context.requested_tool}' not in agent scopes"

    if context.delegation_depth > 0:
        if not context.parent_scopes or context.requested_tool not in context.parent_scopes:
            return False, f"Tool '{context.requested_tool}' exceeds parent scopes at delegation depth {context.delegation_depth}"

    return True, f"Access granted for principal '{context.principal_id}' to tool '{context.requested_tool or 'none'}'"
