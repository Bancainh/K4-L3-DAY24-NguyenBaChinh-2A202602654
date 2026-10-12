# Baseline — checkpoint 1

1. Chưa. `agent/loop.py:27-47`, hàm `_naive_loop()`, chỉ nhận `message` và
   `llm`; nó không tạo `principal_id`, `agent_id`, `run_id`, TTL hay scope.
2. Không có PEP nào cho phép. `_naive_loop()` gọi thẳng
   `tools.http_post()` tại `agent/loop.py:44`. Allowlist localhost trong
   `agent/tools.py:68-84` chỉ giữ bài lab an toàn, không phải kiểm soát quyền.
3. `reports/attack-before.log:1-4` là bằng chứng bốn replay baseline đã gửi
   record synthetic `KH-000999` tới `/reconcile`, gồm CCCD, điện thoại,
   tài khoản ngân hàng và email tổng hợp.
