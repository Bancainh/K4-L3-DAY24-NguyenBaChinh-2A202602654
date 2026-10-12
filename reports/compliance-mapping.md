# Compliance mapping — checkpoint 5

Đã đối chiếu tên, cơ quan ban hành và hiệu lực trên cổng văn bản chính thức:
[Luật 91/2025/QH15](https://vanban.chinhphu.vn/?docid=214590&pageid=27160),
[Nghị định 356/2025/NĐ-CP](https://chinhphu.vn/?docid=216387&pageid=27160),
[Luật 134/2025/QH15](https://vanban.chinhphu.vn/?classid=1&docid=216334&pageid=27160),
và [OWASP Agentic Top 10](https://genai.owasp.org/2025/12/09/owasp-top-10-for-agentic-applications-the-benchmark-for-agentic-security-in-the-age-of-autonomous-ai/).
Mapping dưới đây ở mức mục tiêu/control; chưa khẳng định đáp ứng điều khoản
pháp lý cụ thể.

| Nguồn / yêu cầu | Control đã làm | Evidence file:dòng | Giới hạn |
|---|---|---|---|
| Luật 91/2025/QH15 — bảo vệ dữ liệu cá nhân | Nhận diện/redact PII; phân loại restricted; mục đích và principal; chặn egress; audit | `agent/pii.py:65`, `agent/policy.py:61`, `reports/ledger.jsonl:23` | Dữ liệu và principal đều synthetic; không có quy trình chủ thể dữ liệu hay vận hành production. |
| NĐ 356/2025/NĐ-CP — biện pháp thi hành Luật BVDLCN | DPIA-lite, giới hạn mục đích, least privilege, TTL và hash-chain evidence | `reports/dpia-lite.md:1`, `agent/policy.py:83`, `agent/ledger.py:62` | Chưa phải hồ sơ đánh giá tác động pháp lý hoàn chỉnh; hash chain thiếu external anchor. |
| Luật AI 134/2025/QH15 — quản trị hệ thống AI | Tách trust boundary, kiểm soát hành động OBO, log lý do mọi quyết định, kiểm thử adversarial | `agent/runner.py:146`, `tests/test_obo.py`, `tests/test_injection.py` | Mock deterministic, không đánh giá model production, chất lượng, giám sát con người hay phân loại rủi ro pháp lý. |
| OWASP ASI01 — Agent Goal Hijack | Bốn lure + split: free text không quyết định customer ID; PEP chặn đích egress | `corpus/ticket-901.md`, `corpus/ticket-902.md`, `corpus/ticket-903.md`, `corpus/ticket-904.md`, `agent/runner.py:176-184` | Heuristic nhận diện chỉ để tạo evidence; containment chính nằm ở kiến trúc split. |
| OWASP ASI03 — Identity & Privilege Abuse | Principal registry, giao scope, delegation depth, purpose và TTL | `data/principals.json`, `agent/policy.py:71-107`, `tests/test_obo.py` | `--as` chỉ mô phỏng principal, không phải authentication production. |
| OWASP ASI04 — Agentic Supply Chain Vulnerabilities | Lock có hash, hook Gitleaks pin, quét history/HEAD, incident playbook | `requirements.lock`, `.pre-commit-config.yaml`, `reports/secrets-incident.md` | Không có SBOM, chữ ký artifact, provenance hoặc monitoring registry runtime. |

Mô phỏng kỹ thuật này không tự chứng minh tuân thủ pháp luật; cần legal review,
quy trình tổ chức và bằng chứng vận hành thực tế trước khi dùng production.
