# DPIA-lite — mô tả học tập

1. **Dữ liệu nào và phân loại gì?** Ticket trong `corpus/` là nội dung `internal`, có thể chứa chỉ thị không tin cậy và PII viết trong text. Hồ sơ khách giả trong `data/customers.json` gồm customer ID, tên, CCCD, điện thoại, tài khoản ngân hàng, email và ticket liên quan; runner coi hồ sơ là `restricted`. Toàn bộ dữ liệu của lab là synthetic.

2. **Ai xử lý và vì mục đích nào?** `support_l1` chỉ được `search_docs` để `summarize-tickets`; không được mở private store. `dpo` được `search_docs` và `read_customer`, trong đó việc đọc hồ sơ ở luồng này dùng purpose `support-reply`. `data/principals.json` chỉ mô phỏng authority source, còn `--as` không xác thực người đang dùng máy.

3. **Dữ liệu đi qua đâu?** Run A gọi `search_docs`, phát hiện lure và lấy `list[int]` từ tên đúng dạng `ticket-N.md`; text không đi sang Run B. Nội dung ticket được PII gate che trước khi tóm tắt. Sau policy gate, Run B dùng ticket ID tra `related_tickets` trong private store và kiểm policy lần nữa trước mỗi `read_customer`. Lượt egress riêng chỉ mang URL tới policy; `http_post` nếu được gọi cũng chỉ trỏ được vào sink `127.0.0.1:10024`. Mỗi quyết định tool được ghi vào JSONL ledger bằng `args_hash`, không ghi hồ sơ thô.

4. **Đã chặn/cho phép gì và còn giới hạn gì?** `support_l1` bị deny khi đọc hồ sơ; `dpo` vẫn đọc khách thật sự liên quan. Mọi `restricted + egress` bị deny, nên replay 4 lure × 2 principal không đưa PII tới sink và `attack-after.log` là 0 byte. Giới hạn: mock LLM/regex không bao phủ ngôn ngữ tự nhiên tùy ý; quyền và TTL là fixture chứ không phải IAM thật; hash chain không phát hiện xóa dòng cuối hoặc viết lại toàn chuỗi nếu thiếu external anchor; sink chỉ là localhost; chưa có mã hóa, retention/deletion workflow, concurrency protection, chữ ký số, SIEM, DLP hoặc kiểm soát mạng production.

Tài liệu này phục vụ bài lab, không phải hồ sơ đánh giá tác động xử lý dữ liệu cá nhân hay ý kiến pháp lý chính thức.
