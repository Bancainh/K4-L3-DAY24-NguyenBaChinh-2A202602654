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

import json
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path


_PRINCIPALS_PATH = Path(__file__).resolve().parent.parent / "data" / "principals.json"
_CLASSIFICATIONS = {"public", "internal", "restricted"}


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
    # This mandatory data/egress rule is evaluated first and stands even
    # when legacy callers do not yet supply OBO fields.
    if context.data_classification == "restricted" and context.egress_enabled:
        return False, "restricted data cannot be used in an egress-enabled call"

    if context.data_classification not in _CLASSIFICATIONS:
        return False, f"unknown data classification: {context.data_classification!r}"
    if context.delegation_depth < 0:
        return False, "delegation_depth cannot be negative"
    if not context.principal_id:
        return False, "missing on-behalf-of principal"
    if not context.requested_tool:
        return False, "missing requested tool"

    try:
        principals = json.loads(_PRINCIPALS_PATH.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return False, "trusted principal registry is unavailable"
    principal = principals.get(context.principal_id)
    if not isinstance(principal, dict):
        return False, f"unknown principal: {context.principal_id}"

    if not context.expires_at:
        return False, "missing delegation expiry"
    try:
        expiry = datetime.fromisoformat(context.expires_at.replace("Z", "+00:00"))
        if expiry.tzinfo is None:
            return False, "delegation expiry must include a timezone"
        if expiry.astimezone(timezone.utc) <= datetime.now(timezone.utc):
            return False, "delegation has expired"
    except ValueError:
        return False, "delegation expiry is not valid ISO-8601"

    purposes = set(principal.get("purposes", []))
    if context.request_purpose not in purposes:
        return False, f"purpose {context.request_purpose!r} is not allowed for principal"

    allowed_tools = set(principal.get("allowed_tools", []))
    effective_tools = allowed_tools.intersection(context.agent_scopes)
    if context.delegation_depth > 0:
        effective_tools.intersection_update(context.parent_scopes)
    if context.requested_tool not in effective_tools:
        return False, f"tool {context.requested_tool!r} is outside effective OBO scope"

    return True, (
        f"principal {context.principal_id!r} may use {context.requested_tool!r} "
        f"for purpose {context.request_purpose!r}"
    )
