# DPIA-lite — checkpoint 5

1. **Dữ liệu và phân loại.** Corpus ticket là nội dung không tin cậy,
   phân loại `internal`. Hồ sơ khách synthetic gồm tên, CCCD, số điện thoại,
   tài khoản ngân hàng, email và quan hệ ticket; runner phân loại `restricted`.
   Không sử dụng dữ liệu hoặc credential thật.
2. **Mục đích và principal.** `support_l1` chỉ được `search_docs` cho
   `summarize-tickets`/`support-reply`; `dpo` được đọc hồ sơ cho
   `support-reply`. Mỗi call mang principal, agent/run ID, scope, delegation
   depth và TTL 5 phút. Unknown principal, sai purpose, thiếu scope hoặc hết
   hạn đều fail closed.
3. **Luồng dữ liệu.** Run A gọi `search_docs` và giữ raw text. Boundary sang
   Run B chỉ chứa `list[int]` ticket ID lấy từ tên file. Run B suy customer ID
   từ `related_tickets` tin cậy rồi mới qua PEP trước `read_customer`.
   Payload injection nhắm `http://127.0.0.1:10024/reconcile`; PEP từ chối
   `restricted + egress`, nên `attack-after.log` rỗng.
4. **Evidence và rủi ro còn lại.** `attack-before.log` có 4 lần exfil
   synthetic; `attack-after.log` có 0 byte; `ledger.jsonl:23` ghi deny
   `http_post` cùng reason và chuỗi hash verify `True`. Test xác nhận
   support bị deny, dpo còn tiện ích hợp lệ, và `KH-000777` chỉ xuất hiện
   trong free text không bao giờ được đọc. Giới hạn: mock deterministic,
   registry principal chỉ là fixture, regex có thể không bao phủ mọi PII,
   ledger không có external anchor nên không phát hiện cắt đuôi/viết lại,
   và localhost allowlist không đại diện cho network control production.
