# Verification — Báo cáo kiểm định kỹ thuật

**Tác giả:** Tô Huy Thông — 2A202602608
**Ngày:** 2026-10-12

---

## 1. Môi trường kiểm định
- **Hệ điều hành:** Windows
- **Python:** 3.10.0
- **Gitleaks:** v8.30.1

---

## 2. Kết quả kiểm định PII Gate (CP3a)
- **Lệnh chạy:**
  ```bash
  python -m pytest tests/test_pii.py -v -s --basetemp=.pytest_tmp
  ```
- **Số liệu đo lường:**
  - `gold`: 118
  - `pred`: 118
  - `tp`: 118
  - `precision`: 1.000 (100%)
  - `recall`: 1.000 (100%)
  - **Đánh giá theo RUBRIC.md:** Đạt thang điểm tối đa (Band >95% = 10đ).

- **Giới hạn của bộ nhận diện Regex:**
  1. **Phụ thuộc vào mẫu định dạng tĩnh:** Hoạt động tối ưu trên các mẫu số có cấu trúc cố định (CCCD 12 số, email dạng phổ biến, SĐT đầu 0). Khi gặp các định dạng số quốc tế hoặc biến thể viết tắt tự do, độ tin cậy suy giảm.
  2. **Nhạy cảm với ngữ cảnh nhận diện:** Số tài khoản ngân hàng (8–16 số) phụ thuộc vào nhãn ngữ cảnh (`STK`, `số tài khoản`). Nếu khách hàng ghi số tài khoản trần không nhãn trong văn bản tự nhiên, regex khó phân biệt với các mã số đơn hàng/mã hóa đơn.
  3. **Không nhận dạng được thực thể ngữ nghĩa sâu (Deep Semantic / Named Entities):** Regex không thể nhận dạng tên người (`PERSON`) trong tiếng Việt nếu không có mô hình học máy ngôn ngữ (NER/Transformers) hoặc bảng từ điển chuyên dụng.

---

## 3. Policy và OBO (CP3b/CP3c)
- **Lệnh policy:** `python -m pytest tests/test_policy.py -v --basetemp=.pytest_tmp`
  - Kết quả: `4 passed`; có cả allow và deny, trong đó `restricted + egress` luôn bị chặn.
- **Lệnh OBO:** `python -m pytest tests/test_obo.py -v --basetemp=.pytest_tmp`
  - Kết quả: `5 passed`; `support_l1` bị deny khi đọc hồ sơ restricted, `dpo` được allow cho `support-reply`; delegation, TTL và ledger đều được kiểm tra.

---

## 4. Split, injection và ledger (CP3d/CP3e)
- `python -m pytest tests/test_split.py -v --basetemp=.pytest_tmp`: `1 passed`; `KH-000777` không bị đọc từ free text và khách liên quan hợp lệ vẫn được đọc.
- `python -m pytest tests/test_injection.py -v --basetemp=.pytest_tmp`: `8 passed`, không có SKIP (4 lure × 2 principal).
- `python -m pytest tests/test_ledger.py -v --basetemp=.pytest_tmp`: `3 passed`; hash chain hợp lệ và phát hiện được sửa dòng.
- Chạy bằng chứng: `python -m agent.loop --mock --as dpo "Tổng hợp các ticket còn mở tuần này"`.
- Kiểm tra `verify(Path('reports/ledger.jsonl'))`: `True`.
- Ledger có `http_post`, `decision=deny`, `on_behalf_of=dpo` và `reason="Egress is prohibited for restricted data (minimum PEP deny rule)"`.
- Ledger chỉ lưu `args_hash`; không có các trường hồ sơ thô `cccd`, `phone` hoặc `bank_account`.

---

## 5. Supply chain (CP4)
- `gitleaks version`: lệnh trần không chạy vì executable chưa nằm trong `PATH`; `.\gitleaks.exe version` trả `8.30.1`.
- `.\gitleaks.exe git --config .gitleaks.toml --redact --verbose .`: exit `1` mong đợi; 4 commit, 1 finding đã redact tại commit `1bdd849`, file `lab-fake-secret.txt`, rule `lab24-synthetic-token`.
- `.\gitleaks.exe dir --config .gitleaks.toml --redact .`: exit `0`, không có finding; không cần chỉnh allowlist `.venv/`.
- Ban đầu thiếu `pip-tools` và `pre-commit`; đã cài `pip-tools 7.6.2`, `pre-commit 4.6.2`, sinh `requirements.lock` và cài bằng `python -m pip install --require-hashes -r requirements.lock` thành công.
- Install trong Python global có cảnh báo conflict tồn tại sẵn: `datasets 5.0.0` yêu cầu `fsspec<=2026.4.0` nhưng môi trường có `fsspec 2026.9.0`; đây không phải dependency trong `requirements.txt`/lock của lab.
- `python -m pre_commit install`: đã cài hook tại `.git/hooks/pre-commit`.
- Thêm thư mục repo vào `PATH` của phiên chạy để hook tìm thấy binary local; `python -m pre_commit run --all-files`: `Detect hardcoded secrets ... Passed`.
- `python -m pytest tests/test_supply_chain.py -v --basetemp=.pytest_tmp`: lần đầu `2 passed, 1 failed` vì incident note còn trống; sau khi viết báo cáo: `3 passed`.

---

## 6. Replay sau containment (CP5)
- Trước replay: `PYTHONIOENCODING=utf-8`, `python sink/sink.py --reset`, sau đó chạy sink tại `127.0.0.1:10024`.
- `python -m agent.loop --mock --as dpo "Tổng hợp các ticket còn mở tuần này"`: hoàn tất, tổng hợp 45 ticket.
- Chép `reports/sink.log` thành `reports/attack-after.log`: `0` byte, `0` dòng.
- `reports/attack-before.log`: `1196` byte, `4` dòng chứa POST synthetic của `KH-000999`; `reports/attack-after.log`: rỗng.
- Ledger sau replay: `72` dòng; có `3` dòng `http_post=deny`. Dòng mới nhất có `on_behalf_of=dpo` và reason `Egress is prohibited for restricted data (minimum PEP deny rule)`.
- `python -c "from agent.ledger import verify; from pathlib import Path; print(verify(Path('reports/ledger.jsonl')))"`: `True`.
- Lỗi đã gặp: PowerShell `cp1258` không in được một số ký tự tiếng Việt từ CLI; đặt `$env:PYTHONIOENCODING='utf-8'` khắc phục, không ảnh hưởng quyết định policy hay nội dung ledger.

---

## 7. Kết quả kiểm định cuối
- `python -m pytest tests/ -q --basetemp=.pytest_tmp`: `33 passed in 4.58s`, `0 failed`, `0 skipped`.
- Số SKIP: `0`; cả 4 lure đã có file và được replay dưới 2 principal.
- `python -m pre_commit run --all-files`: `Detect hardcoded secrets ... Passed`.
- Quét working tree cuối bằng Gitleaks: exit `0`, không có finding.
- `attack-after.log`: `0` byte.
- Ledger verify: `True`.
