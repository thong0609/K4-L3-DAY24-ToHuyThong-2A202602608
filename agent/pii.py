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


# ---------------------------------------------------------------------------
# Regex patterns
# ---------------------------------------------------------------------------

# EMAIL: standard format with word boundary to avoid capturing sentence punctuation
_EMAIL_RE = re.compile(r"\b([a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})\b")

# VN_BANK_ACCOUNT: 8-16 chữ số liên tiếp, đứng sau nhãn STK / số tài khoản
_BANK_LABELED_RE = re.compile(
    r"(?:STK|số\s+tài\s+khoản|stk)\s*[:\s]?\s*(\d{8,16})",
    re.IGNORECASE,
)

# VN_CCCD: đúng 12 chữ số liên tiếp, không có chữ số trước/sau
_CCCD_RE = re.compile(r"(?<!\d)(\d{12})(?!\d)")

# VN_PHONE: bắt đầu bằng 0, tiếp theo 8-10 chữ số (tổng 9-11 ký tự số),
# cho phép dấu cách/gạch giữa các nhóm
_PHONE_RE = re.compile(
    r"(?<!\d)(0\d{1,2}[-\s]?\d{3,4}[-\s]?\d{3,4})(?!\d)"
)


def detect(text: str) -> list[dict]:
    """Phát hiện PII trong text, trả về list entity với type/start/end."""
    entities: list[dict] = []
    claimed: list[tuple[int, int]] = []  # (start, end)

    def _overlaps_claimed(s: int, e: int) -> bool:
        for cs, ce in claimed:
            if s < ce and cs < e:
                return True
        return False

    # 1) EMAIL — ưu tiên bắt trước, word boundary chuẩn
    for m in _EMAIL_RE.finditer(text):
        s, e = m.start(1), m.end(1)
        if not _overlaps_claimed(s, e):
            entities.append({"type": "EMAIL", "start": s, "end": e})
            claimed.append((s, e))

    # 2) VN_BANK_ACCOUNT — có nhãn STK/số tài khoản (phải trước CCCD vì STK 12 số không phải CCCD)
    for m in _BANK_LABELED_RE.finditer(text):
        s, e = m.start(1), m.end(1)
        if not _overlaps_claimed(s, e):
            entities.append({"type": "VN_BANK_ACCOUNT", "start": s, "end": e})
            claimed.append((s, e))

    # 3) VN_CCCD — 12 số liên tiếp (phải trước PHONE để không bị nuốt bởi 0xxx)
    for m in _CCCD_RE.finditer(text):
        s, e = m.start(1), m.end(1)
        if not _overlaps_claimed(s, e):
            entities.append({"type": "VN_CCCD", "start": s, "end": e})
            claimed.append((s, e))

    # 4) VN_PHONE — bắt đầu 0, 9-10 chữ số
    for m in _PHONE_RE.finditer(text):
        raw = m.group(1)
        digits = re.sub(r"[\s\-]", "", raw)
        if 9 <= len(digits) <= 11:
            s, e = m.start(1), m.end(1)
            if not _overlaps_claimed(s, e):
                entities.append({"type": "VN_PHONE", "start": s, "end": e})
                claimed.append((s, e))

    # Sắp xếp theo vị trí trong văn bản
    entities.sort(key=lambda x: x["start"])
    return entities


def redact(text: str) -> str:
    """Thay thế mọi entity PII bằng [REDACTED_<TYPE>].

    Thay từ cuối về đầu để offset không bị lệch sau mỗi lần thay.
    """
    entities = detect(text)
    entities_sorted = sorted(entities, key=lambda x: x["start"], reverse=True)
    result = text
    for ent in entities_sorted:
        placeholder = f"[REDACTED_{ent['type']}]"
        result = result[: ent["start"]] + placeholder + result[ent["end"] :]
    return result
