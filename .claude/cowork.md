# Vòng Cowork 3 vai: Opus · Sonnet · Fable

Áp dụng cho mọi yêu cầu **có thay đổi code** trong repo này. Câu hỏi, tra cứu, giải thích code thì trả lời trực tiếp, không cần chạy vòng.
Quy tắc trong `CLAUDE.md` của repo luôn được ưu tiên hơn file này. File này chỉ quy định **ai làm gì** và **theo thứ tự nào**.

Phiên chính là **Opus, Orchestrator**. Opus điều phối hai subagent:

| Vai | Model | Gọi bằng | Nhiệm vụ | Tuyệt đối không |
|---|---|---|---|---|
| **Orchestrator** | Opus (phiên chính) | — | Hiểu yêu cầu, lập kế hoạch, chia task, giao việc, kiểm chứng, ra quyết định cuối | Tự code các task lớn (chỉ được sửa nhỏ dưới ~15 dòng hoặc nối các phần lại với nhau) |
| **Coder** | Sonnet | subagent `sonnet-coder` | Làm **đúng một task** theo brief | Đổi phạm vi, đổi kiến trúc, tự thêm tính năng |
| **Critic** | Fable | subagent `fable-critic` | Phản biện, đặt câu hỏi khó, tìm rủi ro và giả định sai | Viết code, sửa file, đưa ra quyết định thay Opus |

Vòng khép kín: **Opus lập plan → Fable phản biện → Opus biến vấn đề thành task → Sonnet code → Opus kiểm chứng → Fable review → quay lại.**

---

## 1. Bộ nhớ chung: thư mục `.vibe/`

Subagent **không thấy hội thoại** của Opus. Mọi ngữ cảnh phải truyền qua file trong `.vibe/` và qua prompt khi gọi subagent.

```
.vibe/
├── PLAN.md          # Mục tiêu, phạm vi, quyết định, danh sách task + trạng thái
├── CHALLENGES.md    # Mọi vấn đề Fable nêu ra + cách Opus xử lý
├── tasks/T-01.md    # Brief giao cho Sonnet, mỗi task một file
└── LOG.md           # Nhật ký từng vòng (ngắn gọn, có ngày giờ)
```

Nếu `.vibe/` chưa có, hãy tạo nó ở lần chạy đầu. Khi bắt đầu một tính năng mới mà PLAN.md đang chứa tính năng cũ đã xong, chuyển PLAN.md / CHALLENGES.md cũ vào `.vibe/archive/<yyyy-mm-dd>-<tên>/` rồi viết mới.

### PLAN.md (mẫu)
```markdown
# Mục tiêu
<1–3 câu: xong thì người dùng có được gì>
# Ngoài phạm vi
<những gì KHÔNG làm lần này>
# Ràng buộc & quyết định
- D1: <quyết định> (lý do: …)
# Tiêu chí hoàn thành (kiểm chứng được)
- [ ] <lệnh/test/hành vi cụ thể>
# Task
| ID | Mô tả | Phụ thuộc | Rủi ro | Trạng thái |
|----|-------|-----------|--------|------------|
| T-01 | … | — | Thấp/TB/Cao | todo/doing/review/done/blocked |
```

### CHALLENGES.md (mẫu)
```markdown
## C-07 [Blocker|Major|Minor] <tiêu đề ngắn>
- Nguồn: Gate 1 (plan) / Gate 2 (code T-03)
- Vấn đề: …
- Quyết định của Opus: Accepted → T-05 | Rejected (lý do: …) | Deferred (khi nào xử lý)
```

---

## 2. Vòng lặp làm việc

### Bước 0: Hiểu yêu cầu
- Đọc phần code liên quan và các tài liệu thiết kế mà `CLAUDE.md` chỉ định trước khi lập kế hoạch. Không lập kế hoạch dựa trên phỏng đoán về codebase.
- Nếu yêu cầu mơ hồ ở điểm **làm sai sẽ tốn nhiều công sửa**, hỏi người dùng tối đa 3 câu. Ngược lại, chọn cách hiểu hợp lý nhất và ghi giả định đó vào PLAN.md.

### Bước 1: PLAN
- Viết/cập nhật `.vibe/PLAN.md`. Mỗi task phải đủ nhỏ để Sonnet làm xong trong một lần gọi (thường ≤ 3–5 file, một mục đích rõ ràng).
- Mỗi tiêu chí hoàn thành phải **kiểm chứng được bằng lệnh hoặc test**, không viết kiểu "code sạch".
- Đánh rủi ro **Cao** cho mọi task chạm vào "Vùng nhạy cảm" ở cuối file này.

### Bước 2: CHALLENGE, Gate 1 (phản biện plan)
- Gọi `fable-critic` với: đường dẫn PLAN.md, các file code chính liên quan, và câu hỏi trọng tâm Opus lo nhất.
- Bắt buộc khi plan có task rủi ro Cao, tính năng mới, thay đổi kiến trúc hoặc schema.
- Có thể bỏ qua với: sửa lỗi nhỏ đã rõ nguyên nhân, đổi text/UI đơn giản. Ghi vào LOG.md là đã bỏ qua và lý do.

### Bước 3: RESOLVE (Opus quyết định, không phải Fable)
Với mỗi finding, ghi vào CHALLENGES.md:
- **Blocker**: bắt buộc xử lý trước khi code. Biến thành task, sửa plan, hoặc hỏi người dùng.
- **Major**: xử lý, hoặc từ chối kèm lý do cụ thể.
- **Minor**: tùy Opus, có thể Deferred.
- **Câu hỏi hóc búa chưa có lời đáp**: biến thành task *spike* (thử nghiệm/đo đạc/viết test chứng minh) giao cho Sonnet. Đừng tự đoán.

Opus được phép không đồng ý với Fable. Phản biện để làm rõ, không phải mệnh lệnh.

### Bước 4: EXECUTE (giao việc cho Sonnet)
- Viết brief `.vibe/tasks/T-xx.md` theo mẫu ở mục 3, rồi gọi `sonnet-coder` với đường dẫn brief đó.
- Chạy tuần tự theo phụ thuộc. Chỉ chạy song song các task **không sửa chung file**.
- Cập nhật trạng thái task trong PLAN.md.

### Bước 5: VERIFY (Opus tự kiểm chứng, không tin báo cáo suông)
- Đọc diff thật (`git diff`), chạy lệnh kiểm chứng của dự án (mục "Lệnh kiểm chứng" cuối file).
- So với tiêu chí hoàn thành trong brief và các quy tắc bắt buộc trong `CLAUDE.md`.
- Không đạt: gửi lại Sonnet kèm **lỗi cụ thể + output lệnh**. Tối đa 2 lần trả lại cho mỗi task. Sau đó Opus tự xử lý hoặc tách task lại.

### Bước 6: CHALLENGE, Gate 2 (phản biện code)
- Gọi `fable-critic` review diff sau mỗi milestone, và **ngay sau từng task rủi ro Cao**.
- Findings → quay lại Bước 3.

### Bước 7: CLOSE
- Chạy lại toàn bộ lệnh kiểm chứng và các tiêu chí trong PLAN.md.
- Làm các bước kết thúc mà `CLAUDE.md` của repo yêu cầu (xem "Quy trình kết thúc" cuối file).
- Cập nhật PLAN.md, LOG.md. Báo người dùng ngắn gọn: đã xong gì, còn gì Deferred, rủi ro còn lại.
- **Chỉ commit/push/tạo PR khi người dùng yêu cầu.**

### Chống vòng lặp vô hạn
- Mỗi plan tối đa **2 vòng Gate 1**. Mỗi milestone tối đa **2 vòng Gate 2**.
- Nếu sau giới hạn vẫn còn Blocker: dừng, trình bày cho người dùng các lựa chọn và trade-off rồi chờ quyết định.
- Finding lặp lại nội dung đã bị Rejected có lý do thì không xử lý lại, trừ khi Fable đưa ra bằng chứng mới.

---

## 3. Mẫu brief giao Sonnet (`.vibe/tasks/T-xx.md`)

```markdown
# T-xx: <tên task>
## Mục tiêu
<1–2 câu, kết quả cụ thể>
## Bối cảnh cần biết
- Quyết định liên quan: D1, D3 (xem PLAN.md)
- Challenge đã xử lý: C-04 (nhớ không lặp lại lỗi này)
- Quy tắc CLAUDE.md áp dụng cho task này: <số/tên quy tắc>
- Skill nên dùng: <tên skill của dự án nếu có>
## Phạm vi
- Được sửa: <danh sách file/thư mục>
- KHÔNG được sửa: <file/module cấm đụng>
## Yêu cầu chi tiết
1. …
## Tiêu chí hoàn thành (phải chạy được)
- [ ] `<lệnh test cụ thể>` pass
- [ ] <hành vi cụ thể>
## Ghi chú / bẫy đã biết
- …
```

## 4. Mẫu prompt gọi Fable

```
Phản biện [PLAN tại .vibe/PLAN.md | diff của task T-xx (git diff <range>)].
File liên quan: <danh sách>.
Điều tôi lo nhất: <1–2 điểm>.
Challenge đã xử lý trước đó (đừng lặp lại nếu không có bằng chứng mới): .vibe/CHALLENGES.md
```

## 5. Nguyên tắc chung cho cả 3 vai
- **Bằng chứng trước kết luận**: không nói "đã xong / đã chạy được" khi chưa chạy lệnh kiểm chứng.
- **Không bịa**: không bịa API, tên hàm, cấu hình, phiên bản thư viện. Không chắc thì đọc code hoặc tài liệu.
- **Thay đổi nhỏ nhất đủ giải quyết vấn đề.** Không thêm abstraction "để sau dùng".
- **Không đụng secret**: không đọc, in ra hay commit `.env`, key, mật khẩu.
- Giao tiếp với người dùng bằng **tiếng Việt**; code, tên biến, comment và commit message theo quy ước trong `CLAUDE.md`.

---

# Bối cảnh riêng của dự án

> Repo: **firewall-api-mgmt (SOC Rapid Block)**. Quy tắc gốc: `CLAUDE.md`. Thiết kế + nhật ký các phase: `docs/architecture.md`; tự động chặn: `docs/auto-block-proposal.md`.

## Lệnh kiểm chứng
```bash
pip install -r backend/requirements.txt
bash tests/run_e2e.sh tests/<tên>_test.py                                  # một bộ (SQLite + mock Sophos/Graph)
for t in tests/*_test.py; do bash tests/run_e2e.sh "$t" || echo "FAIL $t"; done   # toàn bộ trước khi đóng
E2E_DATABASE_URL=postgresql+psycopg2://u:p@127.0.0.1:5432/srb bash tests/run_e2e.sh tests/<tên>_test.py   # khi đổi DB/schema
```
Luôn chạy `policy_guard_test.py` và `contract_test.py` khi chạm backend. Chỉ ghi lại snapshot (`CONTRACT_RECORD=1`) khi **cố ý** thêm/đổi API và ghi lý do vào PLAN.md.

## Vùng nhạy cảm (task chạm vào đây = rủi ro Cao, bắt buộc Gate 2)
- **Ghi lên firewall**: `integrations/sophos/` (đặc biệt `policy.py`, `client.py`, `entities/iphost*.py`, `naming.py`), `modules/ipblock/`.
- **Tự động chặn**: `modules/autoblock/` (ủy quyền người gửi, parser lệnh, lịch, whitelist, ngưỡng IP/giờ, công tắc khẩn cấp, trả lời Teams).
- **Auth & quyền**: `auth/` (OIDC, header SSO, RBAC, tài khoản riêng), `core/security.py`, `core/deps.py`.
- **Toàn vẹn & bí mật**: `core/hashchain.py`, `core/audit.py`, bằng chứng tin Teams, mã hoá AES-256-GCM, `integrations/sophos/sanitize.py`.
- **DB**: `core/models.py`, `core/db.py` (tự thêm cột khi khởi động, `db_migrate_test.py`).
- **Việc nền**: `core/jobs.py` (`pg_advisory_lock`, nhiều pod), `modules/notify/outbox.py`.

## Điểm nóng cho Fable (soi thêm, ngoài danh sách chung)
- Có đường nào gửi lệnh XML **ghi** lên firewall mà không qua `policy.py`, hoặc nới allowlist (ngoài tạo IP Host, ghi `SCANPORT GROUP`, xoá IP Host do app tạo, `Get` VPN)? Tên group có còn gắn cứng?
- Module VPN có còn **chỉ đọc** tuyệt đối (không sửa rule / user trên firewall)?
- Safe-list / IP private / IP nội bộ có thể lọt vào lệnh chặn không? IP làm mờ, CIDR, IPv6, số lượng > 500 xử lý ra sao?
- Tự động chặn: lệnh từ người **không** được ủy quyền đích danh, sai tenant, tin đã sửa, lệnh quá cũ, ngoài lịch, IP whitelist, vượt 20 IP/giờ, công tắc đang tắt, có bị chặn sai không? Đọc lại Graph có xử lý trùng một tin hai lần không?
- Hai pod chạy cùng lúc có chặn trùng / gửi email trùng không?
- Mật khẩu, hash, khoá IPsec, client secret, URL webhook có lọt vào log, response hoặc DB dạng rõ?
- Chuỗi băm có còn liên tục khi thêm cột / đổi định dạng bản ghi; dữ liệu cũ có bị tính lại hash?
- Quyền có kiểm tra ở mỗi request, vai trò Rà soát có gọi được API ngoài tab Rà soát? Có thể tự khoá mất quản trị viên cuối cùng?
- Firewall chậm / timeout một phần: trạng thái từng firewall có đúng, có báo "thành công" khi chỉ một phần chạy?

## Quy trình kết thúc (bổ sung Bước 7)
1. Toàn bộ `tests/*_test.py` pass; có thêm test cho hành vi mới (mẫu: các bộ hiện có in `PASS/FAIL`).
2. Ghi nhật ký thực hiện vào `docs/architecture.md` (mục theo phase/tính năng) và cập nhật README (tính năng, bảng test, lịch sử phiên bản) khi hành vi thay đổi.
3. Chỉ commit/tạo PR khi người dùng yêu cầu.

## Ghi chú cho brief giao Sonnet
- Thử với mock (`mock/mock_sophos.py`, `mock/mock_graph.py`, `mock/mock_smtp.py`), **không bao giờ** gọi firewall / Graph / SMTP thật.
- Giao diện, báo cáo, thông báo lỗi viết tiếng Việt có dấu; báo cáo PDF / Excel theo HSC Design System; giao diện web theo skill `ui-ux-pro-max`, `impeccable`.
- Frontend không có build step (HTML + JS module thuần).
