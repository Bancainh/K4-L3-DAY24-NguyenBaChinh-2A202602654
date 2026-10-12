# Secret giả trong lịch sử Git — checkpoint 4

- Scanner: Gitleaks `8.30.1`, tải từ release chính thức và chạy với
  `.gitleaks.toml`.
- Commit chứa token giả: `1bdd849922156c868a5ee9293d68f5b72e242d2c`
  (short SHA `1bdd849`).
- Quét lịch sử bằng `gitleaks git --config .gitleaks.toml --redact --verbose .`
  phát hiện đúng 1 finding trong `lab-fake-secret.txt:1`, rule
  `lab24-synthetic-token`; exit code 1 là kết quả dự kiến của bài tập.
- Quét HEAD bằng `gitleaks dir --config .gitleaks.toml --redact --verbose .`
  không phát hiện leak, exit code 0. `pre-commit run --all-files` cũng pass.
- Token có tiền tố `LAB24-DEMO` là dữ liệu giả, vô hiệu. Nếu là credential
  thật phải thu hồi/rotate ngay tại nhà cung cấp, điều tra phạm vi sử dụng,
  thay secret ở mọi consumer và theo dõi dấu hiệu lạm dụng.
- Xoá file khỏi HEAD không xoá bản sao trong lịch sử Git và không làm token
  hết hiệu lực. Pin dependency/hook giúp giảm rủi ro supply chain về sau,
  nhưng không thể thay thế rotate một credential đã lộ.
