# Báo cáo token giả trong lịch sử Git

## Công cụ và phạm vi

- Scanner: Gitleaks `8.30.1`, cấu hình `.gitleaks.toml` với default rules và rule lab `lab24-synthetic-token`.
- Binary local `gitleaks.exe` được dùng vì lệnh `gitleaks` chưa có trong `PATH` của PowerShell. Không thay đổi rule và không bỏ qua repo.
- Quét lịch sử: `.\gitleaks.exe git --config .gitleaks.toml --redact --verbose .`.
- Quét working tree: `.\gitleaks.exe dir --config .gitleaks.toml --redact .`.

## Kết quả

- Lịch sử Git: exit code `1` như dự kiến; quét 4 commit và phát hiện đúng 1 finding đã redact.
- Finding: commit `1bdd849922156c868a5ee9293d68f5b72e242d2c` (viết tắt `1bdd849`), file `lab-fake-secret.txt`, dòng 1, rule `lab24-synthetic-token`.
- Working tree hiện tại: exit code `0`, không có finding. Không xuất hiện false positive trong `.venv/`, vì vậy không thêm allowlist.
- Token là dữ liệu synthetic, cố ý vô hiệu; báo cáo không sao chép giá trị token.

## Ứng phó nếu đây là credential thật

Phải thu hồi hoặc rotate credential tại dịch vụ đã cấp token trước, xác định phạm vi và thời gian lộ, kiểm audit log để tìm dấu hiệu sử dụng sai, vô hiệu session/credential dẫn xuất nếu có, rồi xử lý các bản sao trong lịch sử Git, cache CI, artifact, fork và mirror. Sau đó quét lại và thông báo theo quy trình incident response của tổ chức.

Xóa file khỏi HEAD hoặc pin dependency không làm credential đã lộ tự mất hiệu lực: bản cũ vẫn tồn tại trong lịch sử và các bản sao, còn pin dependency chỉ kiểm soát phiên bản gói chứ không thu hồi bí mật. Vì vậy rotate/thu hồi ở bên cấp credential là bước bắt buộc.
