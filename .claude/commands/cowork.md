---
description: Chạy vòng cowork Opus → Fable → Sonnet cho một yêu cầu
argument-hint: <mô tả tính năng / bug / vấn đề>
---

Yêu cầu của người dùng:

$ARGUMENTS

Thực hiện vòng cowork đúng theo quy trình trong `CLAUDE.md`:

1. Đọc `.vibe/PLAN.md`, `.vibe/CHALLENGES.md`, `.vibe/LOG.md` nếu đã có, để nối tiếp công việc cũ thay vì làm lại từ đầu.
2. Bước 0–1: hiểu yêu cầu, đọc code liên quan, viết/cập nhật PLAN.md.
3. Bước 2–3: gọi `fable-critic` phản biện plan (Gate 1), rồi tự quyết từng finding và ghi vào CHALLENGES.md.
4. Trước khi giao Sonnet, gửi người dùng một tóm tắt ngắn: plan, các Blocker/Major đã xử lý thế nào, câu hỏi cần họ quyết (nếu có).
   - Có câu hỏi thì chờ trả lời.
   - Không có câu hỏi thì tiếp tục luôn.
5. Bước 4–6: giao từng task cho `sonnet-coder`, tự kiểm chứng bằng lệnh thật, gọi Gate 2 theo quy tắc.
6. Bước 7: đóng vòng, cập nhật `.vibe/`, báo cáo kết quả. Không commit nếu người dùng chưa yêu cầu.
