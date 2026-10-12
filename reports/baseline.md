# Baseline — CP1

**Tác giả:** Tô Huy Thông — 2A202602608
**Ngày:** 2026-10-12

---

## Câu 1 — Mỗi lần chạy baseline đã có agent_id/run_id và danh tính người dùng để kiểm quyền chưa?

**Chưa có.** Hàm `_naive_loop()` tại `agent/loop.py:27–54` không khởi tạo bất kỳ `agent_id`, `run_id` hay `principal` nào. Mỗi lần chạy là ẩn danh hoàn toàn — không có danh tính để kiểm quyền trước khi gọi tool, cũng không có identifier để truy vết sau khi dữ liệu đã rời khỏi hệ thống.

Bằng chứng: signature hàm tại `agent/loop.py:27` là `def _naive_loop(message: str, llm) -> str:` — không nhận `principal_id`, `run_id` hay bất kỳ tham số danh tính nào.

---

## Câu 2 — Trước http_post, có policy nào kiểm mục đích, quyền và loại dữ liệu không? Ai thực sự quyết định gửi?

**Không có policy nào.** Luồng trong `_naive_loop()` đi thẳng từ `find_injection()` → `read_customer()` → `http_post()` mà không qua bất kỳ cổng kiểm soát nào:

- `agent/loop.py:34`: `injected = llm.find_injection(combined_text)` — chỉ kiểm tra text có marker không.
- `agent/loop.py:39`: `collected.append(tools.read_customer(customer_id))` — đọc hồ sơ ngay lập tức nếu `injected is not None`.
- `agent/loop.py:44`: `tools.http_post(injected.target_url, {"records": collected})` — gửi dữ liệu không qua `policy.check()`.

Người quyết định gửi là **attacker** — thông qua chỉ thị giấu trong `ticket-901.md`. `MockLLM.find_injection()` tại `agent/llm.py:85–86` "nghe theo" chỉ thị vì lệnh và dữ liệu đi chung một stream text, không được phân tách.

---

## Câu 3 — Dòng nào tạo body POST, và file nào sẽ ghi lại việc sink đã nhận body đó?

Body POST được tạo tại `agent/loop.py:44`:

```python
tools.http_post(injected.target_url, {"records": collected})
```

Trong đó `collected` là list các dict hồ sơ khách hàng lấy từ `read_customer()` — bao gồm `cccd`, `phone`, `bank_account` của `KH-000999`.

File ghi nhận: **`reports/sink.log`** — được ghi bởi `sink/sink.py` mỗi khi nhận HTTP POST. Sau khi copy, bằng chứng tĩnh nằm ở **`reports/attack-before.log`**.

---

## Tóm tắt lỗi

Ticket là **dữ liệu** do bên ngoài cung cấp, nhưng baseline xử lý chỉ thị bên trong như **lệnh**. `_naive_loop()` ở `agent/loop.py:31–44` gọi `read_customer()` và `http_post()` dựa trực tiếp vào nội dung do attacker kiểm soát, không có cổng kiểm quyền (`policy.check()`) nào ở giữa.
