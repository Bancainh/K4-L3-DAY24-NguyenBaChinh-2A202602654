"""BƯỚC 3a — PII gate TRƯỚC KHI vào context/store (12').

Đọc CHECKPOINTS.md (§3a) trước khi bắt đầu: Presidio không có tiếng Việt
sẵn (AnalyzerEngine() mặc định chỉ hỗ trợ "en"). Đường an toàn cho 2h là
regex recognizer + deny-list cho PERSON — coi spaCy/transformers NER là
stretch goal, KHÔNG bắt buộc.

Interface bắt buộc (tests/test_pii.py gọi trực tiếp 2 hàm này):

    detect(text: str) -> list[dict]
        Mỗi entity: {"type": str, "start": int, "end": int}
        `type` là một trong: "VN_CCCD", "VN_PHONE", "VN_BANK_ACCOUNT", "EMAIL"
        `start`/`end` là offset ký tự trong `text` (offset đầu bao gồm,
        offset cuối KHÔNG bao gồm — giống slice Python text[start:end]).
        Format này khớp với tests/vn_pii_testset.jsonl.

    redact(text: str) -> str
        Trả về `text` sau khi mọi entity từ detect() bị thay bằng
        "[REDACTED_<TYPE>]". Phải xử lý overlap/thứ tự đúng khi có nhiều
        entity (gợi ý: thay từ cuối văn bản về đầu để offset không bị lệch).

Gợi ý định dạng (không bắt buộc đúng regex này, miễn đạt ngưỡng trên test
set ở tests/vn_pii_testset.jsonl):
    VN_CCCD          12 chữ số liên tiếp
    VN_PHONE         0 + 9-10 chữ số, có thể có dấu cách/gạch ngang
    VN_BANK_ACCOUNT  8-16 chữ số liên tiếp, thường đi kèm "STK"/"số tài khoản"
    EMAIL            dạng chuẩn local@domain.tld

Đo bằng: pytest tests/test_pii.py -v -s   (in ra precision/recall)
"""
from __future__ import annotations

import re


_EMAIL_RE = re.compile(r"(?<![\w.+-])[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}(?![\w-])", re.I)
_CCCD_CONTEXT_RE = re.compile(r"\bCCCD\b[^0-9]{0,32}(\d{12})(?!\d)", re.I)
_BANK_CONTEXT_RE = re.compile(
    r"\b(?:STK|s[oố]\s*t[aà]i\s*kho[aả]n)\b[^0-9]{0,48}(\d{8,16})(?!\d)",
    re.I,
)
_PHONE_CONTEXT_RE = re.compile(
    r"\b(?:SĐT|SDT|s[oố]\s*(?:đi[eệ]n\s*tho[aạ]i|dt))\b"
    r"[^0-9]{0,80}(0(?:[ -]?\d){9,10})(?!\d)",
    re.I,
)
_GENERIC_CCCD_RE = re.compile(r"(?<!\d)\d{12}(?!\d)")
_GENERIC_PHONE_RE = re.compile(r"(?<!\d)0(?:[ -]?\d){9,10}(?!\d)")


def _add_entity(entities: list[dict], entity_type: str, start: int, end: int) -> None:
    """Add a non-overlapping entity, preserving the earlier contextual match."""
    if any(start < item["end"] and item["start"] < end for item in entities):
        return
    entities.append({"type": entity_type, "start": start, "end": end})


def _capture_group_entities(text: str, pattern: re.Pattern, entity_type: str,
                            entities: list[dict]) -> None:
    for match in pattern.finditer(text):
        start, end = match.span(1)
        _add_entity(entities, entity_type, start, end)


def detect(text: str) -> list[dict]:
    if not isinstance(text, str):
        raise TypeError("text must be a string")

    entities: list[dict] = []

    # Contextual patterns run first so a 12-digit bank account is not
    # misclassified as a CCCD by the conservative generic fallback.
    _capture_group_entities(text, _BANK_CONTEXT_RE, "VN_BANK_ACCOUNT", entities)
    _capture_group_entities(text, _CCCD_CONTEXT_RE, "VN_CCCD", entities)
    _capture_group_entities(text, _PHONE_CONTEXT_RE, "VN_PHONE", entities)

    for match in _EMAIL_RE.finditer(text):
        _add_entity(entities, "EMAIL", *match.span())
    for match in _GENERIC_CCCD_RE.finditer(text):
        _add_entity(entities, "VN_CCCD", *match.span())
    for match in _GENERIC_PHONE_RE.finditer(text):
        _add_entity(entities, "VN_PHONE", *match.span())

    return sorted(entities, key=lambda item: (item["start"], item["end"], item["type"]))


def redact(text: str) -> str:
    redacted = text
    for entity in sorted(detect(text), key=lambda item: item["start"], reverse=True):
        marker = f"[REDACTED_{entity['type']}]"
        redacted = redacted[:entity["start"]] + marker + redacted[entity["end"]:]
    return redacted
