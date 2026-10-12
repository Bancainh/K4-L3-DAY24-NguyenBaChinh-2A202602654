# Verification — 12/10/2026

- OS / Python / Gitleaks: Windows; Python 3.11; Gitleaks 8.30.1.
- `python -m pytest tests/ -q`: 33 passed.
- PII: precision 1.000, recall 1.000 (118/118 true positives).
- `python -m agent.check_lure corpus/ticket-90*.md`: 4/4 lure sẵn sàng.
- `pre-commit run --all-files`: Passed (`gitleaks-system`, rev v8.30.1).
- `pip install --require-hashes -r requirements.lock`: Passed.
- History scan: 1 expected synthetic finding at commit `1bdd849`; HEAD scan clean.
- `attack-before.log`: 4 dòng synthetic exfil; `attack-after.log`: 0 byte.
- Ledger verify: `True`; dòng cuối là `http_post` deny với reason.
- Các lỗi còn lại: không có lỗi test. Windows native không phải môi trường
  pilot theo README; kết quả này cần được TA tái chạy trên WSL2/Linux/macOS.
