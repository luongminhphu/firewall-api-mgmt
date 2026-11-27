# SOC Rapid Block — Kiến trúc: hiện trạng, kiến trúc đích, kế hoạch chuyển đổi

> Trạng thái: **ĐÃ DUYỆT** (18/11/2026) — quyết định ở §9. **Phase 1–5 + rà soát định kỳ xong** (§10–§15). Việc tiếp theo: đối chiếu parser với mẫu thật từ `tools/sophos_sample.py`.
> Áp dụng cho: v1.7.0 (commit `88e54eb` trên `main`).
> Phạm vi: (A) tái cấu trúc backend + frontend **không đổi hành vi**; (B) module VPN (B1 tài khoản, B2 thời hạn qua firewall rule).

---

## 0. Tóm tắt cho người duyệt

| Hạng mục | Đề xuất | Cần anh quyết |
|---|---|---|
| Lưới an toàn | Bước 1.0 thêm **contract test** chụp lại danh sách route + hình dạng response hiện tại, chạy sau mỗi commit | — |
| Backend | Tách `main.py` (1 141 dòng, 38 route) thành `core/ auth/ integrations/sophos/ modules/*`, 9 commit nhỏ; module cũ giữ lại dạng **shim re-export** đến khi test chuyển xong | Duyệt cấu trúc §3 |
| Pydantic | Schema vào/ra riêng, nhưng **lỗi validate vẫn trả 400 + thông điệp tiếng Việt như cũ** (không để FastAPI trả 422) | Duyệt §3.4 |
| Hardening | `integrations/sophos/policy.py` thành **điểm chặn duy nhất**: mọi XML gửi firewall được phân tích (thao tác + entity) trước khi gửi, ngoài allowlist → chặn + audit `policy_violation` | — |
| Frontend | ES modules thuần (`<script type="module">`), không build; tách 7 trang + 6 component, mỗi trang một commit, có smoke test Playwright | — |
| VPN | Entity đã **xác minh trên tài liệu SFOS 22.0** (§5.1). Chỉ đọc. Bảng DB mới (thêm, không sửa bảng cũ) | Phiên bản SFOS thật; mẫu XML thật (§8) |
| Thông báo | Bảng `email_outbox` idempotent + worker gửi SMTP | SMTP relay, người nhận (§8) |

---

## 1. Hiện trạng

### 1.1 Triển khai

```
Trình duyệt ──► Entra App Proxy (MFA) ──► K8s NodePort ──► Pod app (uvicorn, 1 replica) ──► PostgreSQL (StatefulSet)
                                                              │
                                                              └─► Sophos XML API https://<fw>:4444/webconsole/APIController
```

- Image dựng bởi GitHub Actions → GHCR; `deploy/k8s/base` + overlay `prod` (cấu hình site ở `local-config.yaml`).
- **1 replica** là ràng buộc ngầm: `service.fw_lock` (khóa ghi theo firewall), `jobs._events`, `group_cache._locks` đều nằm trong bộ nhớ tiến trình.

### 1.2 Backend (`backend/app`, ~4 000 dòng)

| File | Dòng | Vai trò thực tế | Vấn đề |
|---|---|---|---|
| `main.py` | 1 141 | 38 route + helper auth (principal/require) + login/OIDC/header + firewall CRUD + block/unblock + audit/changes CSV + branding + users + static | Gom mọi tầng; `payload: dict` ở mọi route (mass-assignment chặn thủ công từng trường); `@app.on_event` đã deprecated |
| `service.py` | ~560 | Block/unblock, test kết nối, `audit()`, `resolve_hosts`, `fw_lock` | Trộn nghiệp vụ + truy cập DB + gọi firewall |
| `sophos.py` | ~420 | Client XML API + dựng XML IPHost/IPHostGroup + kiểm tra group cố định | Chính sách nằm rải rác (đây + `policy.py` + `main.locked_group`) |
| `group_cache.py` | 335 | Cache SCANPORT GROUP, bộ lập lịch (thread), quét lite/full | Bộ lập lịch riêng; khóa mềm `refreshing_since` |
| `changelog.py` | 265 | Nhật ký thay đổi + hash chain + drift + truy vấn batch | Hash chain gắn chặt bảng `group_changes` → không tái dùng được cho VPN |
| `jobs.py` | ~160 | Công việc nền v1.7 (ThreadPool, bảng `jobs`) | Không có khóa liên pod |
| `auth.py` / `users.py` / `crypto.py` | 266 / 165 / 103 | OIDC + header SSO; user nội bộ + chống dò mật khẩu; AES-GCM + token HMAC | `crypto.py` gộp 2 việc khác nhau (mã hóa credential và session token) |
| `db.py` | ~310 | Engine, 9 model, `_migrate()` thủ công | Migration ad-hoc (ALTER khi khởi động) |
| `policy.py`, `ipparse.py`, `config.py` | nhỏ | Group cố định, bóc IP, cấu hình env | — |

**Luồng phân quyền hiện tại**: token HMAC trong header `X-Auth-Token` (frontend giữ trong `localStorage`), mỗi request đọc lại quyền từ DB (`principal`). Không dùng cookie phiên nên **không có bề mặt CSRF** cho API; riêng `/api/audit.csv` và `/api/changes.csv` nhận token qua **query string** (lọt vào log proxy) — ghi nhận là nợ kỹ thuật, **không sửa trong phase refactor** vì đổi hành vi (xem §7).

**Ghi nhận thêm (giữ nguyên trong phase 1, đưa vào backlog):**
- CORS `allow_origins=["*"]` — vô hại với token header nhưng nên giới hạn.
- `/api/audit?q=` lọc **sau** `LIMIT` (tìm kiếm chỉ trong N dòng mới nhất).
- Không có log có cấu trúc; lỗi chỉ `log.exception` dạng text.

### 1.3 Frontend (`frontend/`, không build)

- `app.js` 1 599 dòng, một IIFE: utils → login/SSO → branding → tabs → firewalls → nguồn IP → block → IP Host Group + cache → audit → users/phân quyền → changes → khởi động.
- `index.html` 6 tab (`data-tab`/`data-panel`), CSS: `hsc-tokens.css` (token màu HSC, sáng/tối) + `styles.css` + `fonts.css` (Inter tự host).
- Trạng thái dùng chung trong một object `state`; render bằng template string + `esc()`.

### 1.4 Test

- 11 kịch bản E2E dạng script (`tests/*_test.py`, in `PASS/FAIL`) chạy qua `tests/run_e2e.sh`: dựng mock Sophos (HTTPS tự ký) + app trên SQLite.
- `mock/mock_sophos.py`: IPHost, IPHostGroup, Set add/update (nhiều entity + `transactionid`), Remove; mô phỏng chậm.
- Không có test đơn vị thuần, không có test UI tự động trong repo.

---

## 2. Nguyên tắc chuyển đổi

1. **Không đổi hành vi** ở phase 1–2: cùng API path, method, mã HTTP, khóa JSON, thông điệp lỗi, cùng bảng DB.
2. **Mỗi bước một commit**, toàn bộ test (11 kịch bản cũ + contract test mới) xanh sau mỗi commit; commit không xanh thì không đẩy.
3. **Strangler**: module mới viết ở vị trí mới; vị trí cũ (`app/service.py`, `app/sophos.py`, `app/db.py`, `app/crypto.py`…) giữ lại dạng **re-export** cho tới bước cuối, để test và import cũ vẫn chạy. Xóa shim là một commit riêng.
4. Router mỏng → service (nghiệp vụ, không biết HTTP) → repository (SQLAlchemy) / integration (firewall).
5. Không đổi schema DB ở phase 1–2. Phase 3+ chỉ **thêm** bảng/cột (không đổi/xóa cột cũ).
6. Hardening không nới: `SCANPORT GROUP` gắn cứng; mọi thao tác lên firewall đi qua một điểm kiểm soát.

---

## 3. Kiến trúc đích — Backend

### 3.1 Cây thư mục

```
backend/app/
  main.py                    # tạo app, lifespan, middleware, mount router, static — < 120 dòng
  core/
    config.py                # Settings (giữ nguyên tên biến môi trường)
    db.py                    # engine, SessionLocal, Base, get_session, init_db + _migrate (giữ nguyên)
    models.py                # các model hiện có (tách khỏi db.py, không đổi bảng/cột)
    security.py              # encrypt/decrypt credential (AES-GCM) + issue/verify token — tách từ crypto.py
    audit.py                 # audit() + repository AuditLog
    hashchain.py             # chuỗi băm dùng chung: append(table, payload) / verify(table)
    jobs.py                  # công việc nền + bộ lập lịch chung + khóa phân tán (pg_try_advisory_lock)
    errors.py                # AppError(status, message) + handler giữ định dạng {"detail": "..."}
    logging.py               # log JSON có cấu trúc (ts, level, logger, msg, request_id, actor, fw)
    deps.py                  # client_ip_of, selected_firewalls, get_fw (dùng chung các router)
  auth/
    rbac.py                  # ROLE_RANK, role_at_least, principal, require("operator"/"admin")
    local.py                 # /api/login (tài khoản app + mật khẩu chung break-glass)
    oidc.py                  # Entra OIDC (PKCE, JWKS, state/nonce) — từ auth.py
    header_sso.py            # header SSO qua App Proxy (TRUSTED_PROXY_CIDRS)
    users/                   # router + service + repository + schemas (/api/users, /api/me/password)
    router.py                # /api/auth/*, /api/config
  integrations/sophos/
    client.py                # SophosClient: kết nối keep-alive, _post, đăng nhập, mã lỗi, batch transactionid
    xml.py                   # dựng/parse XML, escape, as_list
    entities/
      iphost.py  iphostgroup.py              # đang dùng
      firewallrule.py  firewallrulegroup.py  # VPN B2 (chỉ đọc)
      user.py  usergroup.py  schedule.py     # VPN B1/B2 (chỉ đọc)
      sslvpn.py  ipsec.py                    # VPN B1 (chỉ đọc)
    policy.py                # ALLOWLIST thao tác + guard trong client — nơi DUY NHẤT quyết định
  modules/
    firewalls/   router.py service.py repository.py schemas.py   # CRUD, test kết nối
    ipblock/     router.py service.py parse.py group_cache.py changelog.py schemas.py
    audit/       router.py (/api/audit, /api/audit.csv)
    branding/    router.py service.py
    vpn/         accounts/  rules/  notify/   (phase 3–5)
```

### 3.2 Phụ thuộc giữa các tầng

```
router (FastAPI, schema I/O, RBAC) ──► service (nghiệp vụ thuần) ──► repository (DB)
                                                   └────────────────► integrations/sophos (qua policy guard)
core/* được mọi tầng dùng; modules/* KHÔNG import chéo router của nhau (chỉ service public).
```

Quy tắc kiểm tra tự động (thêm vào contract test): `modules/*/service.py` không import `fastapi`; chỉ `integrations/sophos/client.py` được import `httpx` tới firewall.

### 3.3 Policy — điểm chặn duy nhất

`integrations/sophos/policy.py` khai báo **allowlist cứng trong mã nguồn**:

| Entity | Get | Set add | Set update | Remove | Ràng buộc thêm |
|---|---|---|---|---|---|
| `IPHost` | ✔ | ✔ | ✘ | ✔ | Remove chỉ object do app tạo (`is_app_owned`) — giữ như hiện tại |
| `IPHostGroup` | ✔ (chỉ `SCANPORT GROUP` khi trả về) | ✘ | ✔ | ✘ | Name phải = `SCANPORT GROUP` |
| `FirewallRule`, `FirewallRuleGroup` | ✔ | ✘ | ✘ | ✘ | Group đọc phải thuộc `VPN_RULE_GROUPS_ALLOWED = ("VPN",)` |
| `User`, `UserGroup`, `Schedule`, `SSLVPNPolicy`, `VPNIPSecConnection` | ✔ | ✘ | ✘ | ✘ | Kết quả đi qua bộ lọc trường (§5.3) |
| Mọi entity khác | ✘ | ✘ | ✘ | ✘ | — |

Cơ chế: `SophosClient._post(inner_xml)` **parse lại** XML sắp gửi (thao tác `Get|Set@operation|Remove` × entity × `Name`) và gọi `policy.check()` trước khi mở kết nối. Vi phạm → `PolicyViolation` → service ghi `audit(action="policy_violation", result="denied")` → HTTP 403. Nhờ parse chính payload thật, kể cả lỗi lập trình (dựng nhầm XML) cũng bị chặn. Tên Rule Group VPN cấu hình được (`VPN_RULE_GROUPS`), nhưng giá trị ngoài `VPN_RULE_GROUPS_ALLOWED` bị bỏ qua và ghi cảnh báo khi khởi động.

### 3.4 Schema Pydantic mà không đổi hành vi

- Mỗi route có `XxxIn` (chỉ khai báo trường được nhận, `extra="ignore"`) và `XxxOut` (`response_model`, khóa y hệt hiện tại).
- Kiểu khai báo **khoan dung** như code hiện tại (vd `port: int | str | None`), kiểm tra nghiệp vụ vẫn trong service để giữ đúng thông điệp.
- Handler `RequestValidationError` → **HTTP 400 `{"detail": "<thông điệp tiếng Việt>"}`** (thay vì 422 dạng list), vì frontend hiển thị `data.detail` dạng chuỗi.
- Contract test so sánh response trước/sau trên cùng kịch bản.

### 3.5 Công việc nền & khóa phân tán (`core/jobs.py`)

- Gộp 3 cơ chế hiện có (thread lập lịch group cache, `jobs.py` v1.7, `_scan_wait`) vào một API: `submit()`, `wait()`, `every(name, interval, fn)`.
- Khóa: PostgreSQL `pg_try_advisory_lock(hashtext(key))` cho tác vụ định kỳ (sync VPN, quét cache, gửi email) và khóa ghi theo firewall; SQLite (test) dùng khóa trong tiến trình. Đây là thay đổi **nội bộ**, giúp chạy được >1 replica sau này; với 1 replica hành vi không đổi.

### 3.6 Logging có cấu trúc

JSON một dòng: `ts, level, logger, msg, request_id, actor, path, status, ms, fw_id, job_id`. Middleware gán `request_id` (nhận `X-Request-ID` từ App Proxy nếu có). **Không bao giờ log** body request, mật khẩu, token, XML gửi firewall (chứa `<Login>`). Bật bằng `LOG_FORMAT=json` (mặc định `text` để không đổi log hiện tại trong phase 1).

---

## 4. Kiến trúc đích — Frontend

```
frontend/
  index.html               # giữ markup hiện tại; <script type="module" src="js/main.js">
  hsc-tokens.css styles.css fonts.css assets/   # giữ nguyên
  js/
    main.js                # khởi động: đăng nhập/SSO → config → mount trang
    api.js                 # fetch + ApiError + thông điệp gateway + runJob (đã có ở v1.7)
    session.js             # token (localStorage fallback RAM), logout, SSO tự động
    router.js              # tab ↔ location.hash (#block, #groups…), back/forward
    store.js               # state dùng chung + subscribe() đơn giản
    util.js                # esc, fmtTime, debounce, sleep
    components/
      table.js badge.js modal.js toast.js filterbar.js pagination.js progress.js
    pages/
      block.js groups.js firewalls.js changes.js audit.js users.js vpn.js
```

- Không framework, không bundler: trình duyệt nạp ES module trực tiếp; middleware `_static_no_cache` hiện có đã áp dụng cho `.js` → không lo cache cũ khi deploy.
- `router.js` thêm deep link `#tab` (hiện tại tab không có trong URL) — đây là cải tiến UX duy nhất được phép trong phase 2, vì không đổi hành vi hiện có (mở `/` vẫn vào tab Chặn nhanh).
- Giữ: tiếng Việt, sáng/tối, mobile, các `id` DOM (để smoke test và người dùng quen thao tác).
- Kiểm chứng: thêm `tests/ui_smoke_test.js` (Playwright có sẵn trong môi trường CI/dev) — đăng nhập, mỗi tab render không lỗi console, chặn thử dry-run.

---

## 5. Module VPN

### 5.1 Entity Sophos — đã xác minh

Nguồn: tài liệu API chính thức **Sophos Firewall 22.0** (`docs.sophos.com/nsg/sophos-firewall/22.0/api/`), đọc trực tiếp các trang Add/Edit (khối *Sample Configuration*). Firewall HSC chạy **SFOS 22.0 MR3** — khớp bản tài liệu.

| Mục đích | Tag XML | Trang tài liệu | Trường dùng |
|---|---|---|---|
| Rule tường lửa | `FirewallRule` | PROTECT › Firewall › SecurityPolicy › *Add firewall rule / Edit firewall rule* | `Name` (≤60 ký tự, không dấu phẩy), `Description`, `Status` (Enable/Disable), `IPFamily`, `Position`, `PolicyType` (User/Network/HTTPBased), `UserPolicy`/`NetworkPolicy` › `Action`, `LogTraffic`, `SourceZones/Zone`, `SourceNetworks/Network`, `Services/Service`, `Schedule`, `DestinationZones/Zone`, `DestinationNetworks/Network`, `MatchIdentity`, `Identity/Member` (user/group) |
| Rule Group | `FirewallRuleGroup` | PROTECT › Firewall › FirewallGroup | `Name`, `Description`, `SecurityPolicyList/SecurityPolicy` (**tên các rule thuộc group**), `SourceZones`, `DestinationZones`, `Policytype` |
| Lịch | `Schedule` | SYSTEM › Profiles › Schedule | `Name`, `Type` (**Recurring/OneTime**), `ScheduleDetails/StartDate`, `ScheduleDetails/EndDate` (dạng `2011-03-14 15:38:07`, chỉ có với OneTime) |
| Tài khoản | `User` | CONFIGURE › Authentication › Users | `Username`, `Name`, `UserType`, `EmailList/EmailID`, `Group`, `Description`, `SSLVPNPolicy`, `Status` (active/deactive, chỉ đọc) — **có cả `Password`, `PasswordHash`** |
| Nhóm | `UserGroup` | CONFIGURE › Authentication › Groups | `GroupDetail/Name`, `GroupType`, `SSLVPNPolicy`, `GroupMembers/UserName` |
| SSL VPN remote access | `SSLVPNPolicy` | CONFIGURE › VPN › SSLVPNPolicy | `TunnelPolicy/Name`, `PolicyMembers/Member`, `PermittedNetworkResourcesIPv4/Resource` |
| IPsec remote access | `VPNIPSecConnection` | CONFIGURE › VPN › IPSECConnection | `Configuration/Name`, `ConnectionType` (=RemoteAccess), `Policy` … — **có `PresharedKey`** |

**Điểm chưa có trong tài liệu, phải xác minh trên dữ liệu thật trước khi code parser** (xem §8):
1. `FirewallRule` **không có trường ID số** trong schema — khóa nhận diện dự kiến là `Name` (duy nhất trên firewall) + thứ tự trong `SecurityPolicyList`.
2. `##ALL_SSLVPN_RW` nằm ở `SourceNetworks/Network` hay `Identity/Member`.
3. `<Get><FirewallRule>` có hỗ trợ `<Filter>` theo tên không; nếu không, đọc toàn bộ rồi lọc theo `SecurityPolicyList` (chạy nền, timeout riêng như quét IP Host).

### 5.2 B1 — Tài khoản VPN (chỉ đọc)

Bảng mới `vpn_accounts`:

| Cột | Ghi chú |
|---|---|
| `id`, `firewall_id` | `UNIQUE(firewall_id, username)` |
| `username`, `display_name`, `user_type`, `email`, `groups` (JSON), `sslvpn_policy`, `status` | chỉ các trường trong allowlist |
| `has_sslvpn`, `has_ipsec` | suy từ SSLVPNPolicy/VPNIPSecConnection |
| `first_seen_at`, `last_seen_at`, `removed_at` | mất khỏi firewall → set `removed_at`, **không xóa**; xuất hiện lại → `removed_at = NULL` |

Sync: `core/jobs.every("vpn-accounts", VPN_SYNC_MINUTES)` + nút "Đồng bộ" (operator). API: `GET /api/vpn/accounts` (viewer), `POST /api/vpn/sync` (operator, trả job như v1.7).

### 5.3 Bộ lọc trường bí mật

- **Allowlist** theo entity (chỉ giữ các trường liệt kê ở §5.1), áp ngay sau khi parse XML, **trước** khi ghi DB/log/trả API.
- Lưới an toàn thứ hai: hàm `assert_no_secret(obj)` từ chối (log cảnh báo, bỏ bản ghi) nếu còn khóa khớp `/pass|secret|key|otp|token|hash|psk/i`.
- Log/exception từ client không bao giờ chứa body phản hồi thô.

### 5.4 B2 — Thời hạn truy cập qua firewall rule

**Đọc**: `FirewallRuleGroup` có `Name ∈ VPN_RULE_GROUPS` → danh sách tên rule → `FirewallRule` tương ứng → `Schedule` được tham chiếu.

Bảng mới `vpn_rules` (khóa `firewall_id, rule_name`): position, enabled, action, policy_type, src_zones/networks/identity, dst_zones/networks, services, schedule_name, log_traffic, description (JSON cho danh sách), `schedule_end`, `name_date`, `expiry_date`, `expiry_source` (`schedule|name|none`), `expiry_mismatch`, `team`, `user_code`, `account_ids` (JSON), `content_hash`, `first_seen_at`, `last_seen_at`, `removed_at`.

**Parser tên rule** (`modules/vpn/rules/naming.py`, hàm thuần, test đầy đủ):

```
<tên> := [TEAM " - "] [USERCODE] [" -"]? ["expire"]? [DATE]
DATE  := d{1,2} / d{1,2} / d{4}   (dd/mm/yyyy, cũng chấp nhận - . làm dấu phân cách)
```

| Ví dụ | team | user_code | name_date |
|---|---|---|---|
| `THAM.NQ expire 23/04/2027` | — | THAM.NQ | 2027-04-23 |
| `RMS RESEARCH - CHAU.NB expire 19/10/2027` | RMS RESEARCH | CHAU.NB | 2027-10-19 |
| `RMS RESEARCH - NHAN.NDT 30/06/2027` | RMS RESEARCH | NHAN.NDT | 2027-06-30 |
| `HR team testing HRIS - expire 31/12/2026` | HR team testing HRIS | — | 2026-12-31 |
| `VPN - RMS RESEARCH GROUP access Factset Server` | VPN | — | — (`none`) |
| `ABC expire 31/02/2027` | — | — | lỗi → trạng thái *Không đọc được tên* |

- `user_code` = token dạng `CHỮ.CHỮ` (in hoa, có dấu chấm). Ngày **luôn hiểu là dd/mm** (quy ước HSC); ngày không hợp lệ → không đoán.
- **Ưu tiên**: Schedule `OneTime` có `EndDate` → `expiry_source=schedule`; nếu không → ngày trong tên (`name`); không có → `none`. Cả hai có và khác ngày → `expiry_mismatch = true` (badge *Lệch thời hạn*).
- Hạn tính **hết ngày** theo giờ Việt Nam (23:59:59 Asia/Ho_Chi_Minh).

**Liên kết rule ↔ tài khoản**: `Identity/Member` khớp `vpn_accounts.username` (không phân biệt hoa/thường; member là group → mở rộng qua `UserGroup`); dự phòng: `user_code` khớp phần trước `@` của username/email.

**Trạng thái** (tính khi đọc, không lưu — phụ thuộc ngày hôm nay; ngưỡng `vpn.expiring_days` mặc định 30):

| Trạng thái | Điều kiện (kiểm theo thứ tự) |
|---|---|
| Không đọc được tên | có chữ "expire"/chuỗi giống ngày nhưng parse lỗi, và không có schedule |
| User không còn / bị disabled | liên kết được tài khoản nhưng `removed_at` ≠ NULL hoặc `status = deactive` |
| Đã hết hạn nhưng rule vẫn bật | `expiry_date < hôm nay` và `enabled` |
| Sắp hết hạn | `0 ≤ expiry_date − hôm nay ≤ ngưỡng` |
| Còn hạn | `expiry_date − hôm nay > ngưỡng` |
| Không có hạn | `expiry_source = none` |

(Rule đã hết hạn và **đã tắt** → *Còn hạn* không áp dụng; hiển thị *Đã hết hạn (đã tắt)* ở bộ lọc phụ.) Một rule có thể mang thêm cờ *Lệch thời hạn*.

**Lịch sử**: mỗi lần sync so với `content_hash` lần trước → sự kiện `rule_added | rule_removed | expiry_changed | destination_changed | identity_changed | status_changed` ghi vào bảng `vpn_rule_changes` qua `core/hashchain` (chuỗi riêng, verify như `group_changes`).

**Dashboard (tab "VPN")**: thẻ đếm theo trạng thái → bảng lọc (team, trạng thái, firewall, khoảng ngày hết hạn, ô tìm) → panel chi tiết rule (nguồn/đích/dịch vụ/schedule, lịch sử) → xuất CSV "danh sách cần xử lý". **Không có nút sửa/tắt/xóa rule.**

API (đề xuất): `GET /api/vpn/rules`, `GET /api/vpn/rules/{fw_id}/{name}`, `GET /api/vpn/summary`, `GET /api/vpn/rules.csv`, `GET /api/vpn/changes`, `POST /api/vpn/sync` (operator), `GET|PUT /api/vpn/settings` (admin).

### 5.5 Thông báo email (phase 5)

- Bảng `email_outbox`: `dedupe_key UNIQUE`, `to`, `subject`, `body`, `status` (pending/sent/failed), `attempts`, `next_attempt_at`, `sent_at`, `last_error`.
- Idempotent: `dedupe_key = f"{kind}:{fw_id}:{rule}:{expiry_date}:{bucket}"`, bucket = mốc nhắc (30/14/7/1 ngày) → chạy sync nhiều lần không gửi trùng; đổi hạn → khóa mới.
- Loại: *sắp hết hạn* (đại diện team + Infra), *đã hết hạn nhưng vẫn bật* (Infra, nhắc hằng tuần).
- Worker gửi SMTP (`core/jobs.every`, khóa advisory), retry lùi dần; nội dung không chứa dữ liệu ngoài tên rule, user_code, ngày, đích.
- Cấu hình (admin): ngưỡng, mốc nhắc, email Infra, bảng `vpn_team_contacts(team, emails)` — **nhập tay** trong app.
- **SMTP cấu hình trên giao diện** (tab *Cài đặt › SMTP*, chỉ admin): host, cổng, bảo mật (`none|starttls|ssl`), tài khoản, mật khẩu, địa chỉ gửi, tên hiển thị, nút **Gửi thử**. Lưu ở `app_settings` (khóa `smtp.*`); mật khẩu mã hóa AES-GCM bằng `MASTER_KEY` như credential firewall, API **không bao giờ trả lại** mật khẩu (chỉ `has_password`). Mọi thay đổi ghi audit `settings_cud`. Pod cần được mở mạng tới SMTP relay.

### 5.6 Phân quyền VPN

| Vai trò | Quyền |
|---|---|
| viewer (Readonly) | xem tài khoản, rule, dashboard, lịch sử, xuất CSV |
| operator (Write) | + `POST /api/vpn/sync` |
| admin | + `PUT /api/vpn/settings`, người nhận, đại diện team |

---

## 6. Kế hoạch chuyển đổi

Mỗi dòng = 1 commit; cột "Kiểm chứng" là điều kiện để đẩy.

### Phase 1 — Backend (không đổi hành vi)

| # | Bước | Kiểm chứng |
|---|---|---|
| 1.0 | `tests/contract_test.py`: danh sách 38 route (method+path), khóa JSON của response mẫu mỗi nhóm, mã lỗi chính (400/401/403/404) | 11 kịch bản cũ + contract xanh |
| 1.1 | `core/` (config, db+models, security, audit, errors, deps) + shim ở vị trí cũ | như trên |
| 1.2 | `core/hashchain.py`, `changelog.py` dùng lại (hash cũ verify y hệt) | + `changes/verify` OK trên DB có sẵn dữ liệu |
| 1.3 | `integrations/sophos/` (client, xml, entities iphost/iphostgroup) + **policy guard** trong `_post` | + test mới: Set/Remove ngoài allowlist bị chặn + audit |
| 1.4 | `auth/` (rbac, local, oidc, header_sso, users) + router | oidc/sso/users tests |
| 1.5 | `modules/firewalls/` + schemas + handler 400 | contract |
| 1.6 | `modules/ipblock/` (parse, service block/unblock, group_cache, changelog router, jobs router) | iphostgroup/slow/many_ip/group_cache tests |
| 1.7 | `modules/audit`, `modules/branding` | contract |
| 1.8 | `core/jobs.py` hợp nhất lập lịch + advisory lock; `main.py` dùng lifespan, < 120 dòng | toàn bộ |
| 1.9 | `core/logging.py` (`LOG_FORMAT=json` tùy chọn), chuyển test sang import mới, **xóa shim** | toàn bộ |

### Phase 2 — Frontend

| # | Bước |
|---|---|
| 2.0 | `tests/ui_smoke_test.js` (Playwright) chạy trên `app.js` hiện tại |
| 2.1 | Chuyển sang `<script type="module">`, tách `util/api/session/store` |
| 2.2 | `router.js` (hash) + components (toast, badge, table, modal, filterbar, pagination, progress) |
| 2.3–2.8 | Mỗi trang một commit: block → groups → firewalls → changes → audit → users |
| 2.9 | Xóa `app.js` cũ |

### Phase 3 — VPN B1 · Phase 4 — VPN B2 + dashboard · Phase 5 — Email

Bước đầu phase 3: công cụ **`tools/sophos_sample.py`** (chỉ đọc) — admin chạy với tài khoản API read-only, công cụ gửi `<Get>` các entity ở §5.1, **che** mật khẩu/hash/khóa/email/IP và tên người (thay bằng mã giả nhất quán), ghi ra file XML để gửi lại; mock được dựng theo mẫu này. Trong lúc chờ mẫu thật, mock dựng theo tài liệu 22.0 và parser phải chịu được biến thể. Mỗi phase: mock Sophos mở rộng trước (User/UserGroup/Schedule/FirewallRule/FirewallRuleGroup "VPN" với các rule mẫu ở §5.4, có trường bí mật giả để test lọc) → model/migration thêm bảng → integration → service + test thuần → router → UI.

**Test bắt buộc** (theo yêu cầu): parser tên rule (đủ mẫu + mẫu lỗi), ưu tiên schedule > tên, phân loại trạng thái theo ngày (tham số `today`), mọi Set/Remove lên `FirewallRule`/`User` bị chặn kèm audit `policy_violation`, không lộ trường bí mật (DB, log, API), mock có Rule Group "VPN".

---

## 7. Rủi ro & ngoài phạm vi

| Rủi ro | Giảm thiểu |
|---|---|
| Refactor làm lệch response | Contract test bước 1.0; shim; commit nhỏ |
| 422 thay 400 khi dùng Pydantic | Handler §3.4 + contract test |
| Đọc FirewallRule chậm (nhiều rule) | Chạy nền, timeout riêng `VPN_SCAN_TIMEOUT`, chỉ rule trong group |
| Tên rule không theo quy ước | Trạng thái *Không đọc được tên* + CSV để Infra chuẩn hóa dần; không đoán ngày |
| Lộ bí mật từ User/IPsec | Allowlist + assert lần 2 + test |
| Nhiều replica | Advisory lock (§3.5) — vẫn khuyến nghị 1 replica tới khi khóa ghi theo firewall chuyển sang PG |

**Không làm trong các phase này** (backlog): token CSV qua query string → link tải ký ngắn hạn; giới hạn CORS; audit search trên DB; Alembic; tự động tắt/sửa rule (cấm theo yêu cầu); rà soát định kỳ ISO 27001 (xây trên B1+B2 sau).

---

## 8. Câu hỏi cần anh trả lời trước khi code

1. **Phiên bản SFOS** đang chạy trên các firewall (tài liệu đã đối chiếu: 22.0).
2. **Mẫu XML thật đã che thông tin** (chạy bằng tài khoản API chỉ đọc): `<Get><FirewallRuleGroup>` của group "VPN", 3–5 `<FirewallRule>` trong đó (có rule gắn Schedule), 1 `<Schedule>` OneTime, 1 `<User>` (xóa Password/PasswordHash). Dùng để dựng mock đúng thực tế và chốt 3 điểm ở cuối §5.1.
3. **SMTP relay** cho thông báo (host/port, có cần đăng nhập không, địa chỉ gửi) — cần mở mạng từ pod.
4. **Đại diện team**: nhập tay trong app (đề xuất) hay lấy từ nhóm AD/Entra?
5. Duyệt các quyết định: cấu trúc §3.1, xử lý 400 §3.4, `LOG_FORMAT` mặc định `text`, deep link tab §4, quy ước ngày **dd/mm** §5.4.

---

## 9. Quyết định đã duyệt (18/11/2026)

| # | Câu hỏi | Quyết định |
|---|---|---|
| 1 | Phiên bản SFOS | 22.0 MR3 |
| 2 | Mẫu XML thật | Chưa có cách lấy → app cung cấp `tools/sophos_sample.py` (chỉ đọc, tự che dữ liệu) ở đầu phase 3 |
| 3 | SMTP | Cấu hình trên giao diện, mục **Cài đặt** (admin), mật khẩu mã hóa, có gửi thử |
| 4 | Đại diện team | Nhập tay trong app |
| 5 | Cấu trúc §3.1, lỗi 400 §3.4, `LOG_FORMAT` mặc định `text`, deep link tab §4, ngày dd/mm §5.4 | Duyệt |

---

## 10. Nhật ký thực hiện phase 1

| Bước | Kết quả | Ghi chú |
|---|---|---|
| 1.0 | `tests/contract_test.py` + snapshot | 42 route, 53 response; mục mới được ghi bằng code cũ rồi so với code mới |
| 1.1 | `core/` | shim ở vị trí cũ tới 1.9 |
| 1.2 | `core/hashchain.py` | chuỗi do code cũ ghi verify khớp bằng code mới |
| 1.3 | `integrations/sophos/` + policy guard | `tests/policy_guard_test.py` (35 kiểm tra, không gửi gì khi bị chặn) |
| 1.4 | `auth/` | 3 test OIDC chỉ đổi đường dẫn import |
| 1.5 | `modules/firewalls/` + `core/errors.py` | lỗi validate → 400 chuỗi tiếng Việt; trường lạ bị bỏ qua |
| 1.6 | `modules/ipblock/` | `tests/imports_test.py` bắt import hỏng trong thân hàm |
| 1.7 | `modules/audit`, `modules/branding` | regex SVG/chữ ký file đối chiếu giống hệt |
| 1.8 | `core/jobs.py` (lock + every), lifespan | `tests/jobs_lock_test.py` mô phỏng 2 pod trên PostgreSQL |
| 1.9 | `core/logging.py`, xóa shim | `tests/logging_test.py`; `main.py` còn ~110 dòng |

Toàn bộ test chạy được trên SQLite và PostgreSQL 16 (`E2E_DATABASE_URL`). Khác biệt hành vi có chủ đích duy nhất:
lỗi validate body trả **400** (trước là 422 của FastAPI — frontend chưa từng gửi body sai kiểu), và response có thêm
header `X-Request-ID`.

---

## 11. Nhật ký thực hiện phase 2 (frontend)

| Bước | Kết quả |
|---|---|
| 2.0 | `tests/ui_smoke.cjs` (Playwright, trình duyệt thật) — xanh với `app.js` cũ trước khi tách; phát hiện lỗi thông báo "Đã thêm firewall" bị ẩn → sửa ở commit `fix(ui)` riêng |
| 2.1 | `app.js` → `js/main.js` (`<script type="module">`) + `util.js`, `store.js`, `api.js`, `components/toast.js`; `tests/frontend_lint_test.py` (ESLint no-undef / no-unused-vars) |
| 2.2 | `router.js` (deep link `#tab`, Back/Forward, ARIA tablist) + `components/{badge,progress,table}.js` |
| 2.3–2.9 | `pages/{audit,changes,users,groups,firewalls,block,branding}.js`, `session.js`; trang không import lẫn nhau mà dùng bus `store.on/emit` (`firewalls`, `cache-refresh`); `main.js` chỉ còn ghép nối (~120 dòng) |

Cấu trúc:

```
frontend/js/
  main.js        boot sau đăng nhập, router, phân quyền giao diện, sáng/tối, trình tự đăng nhập lúc mở trang
  session.js     form mật khẩu, SSO Microsoft, header SSO, Thoát
  api.js  store.js  router.js  util.js
  components/    badge, progress, table, toast
  pages/         block, groups, firewalls, changes, audit, users, branding
```

`components/modal|filterbar|pagination` **chưa tạo** vì giao diện hiện tại chưa cần (tránh mã chết) — sẽ thêm cùng
dashboard VPN ở phase 4. Smoke UI: 37 kiểm tra (mọi tab, chặn/bỏ chặn, logo, router, viewer, điện thoại 390px).

---

## 12. Nhật ký thực hiện phase 3 (VPN B1 — tài khoản, chỉ đọc)

| Bước | Kết quả |
|---|---|
| 3.0 | `policy.py` mở **chỉ `Get`** cho User, UserGroup, SSLVPNPolicy, VPNIPSecConnection, Schedule, FirewallRule, FirewallRuleGroup (group ∈ `VPN_RULE_GROUPS_ALLOWED`); `integrations/sophos/sanitize.py` (allowlist trường + `assert_no_secret`); mock có Rule Group "VPN" theo mẫu tên thực tế + trường bí mật giả |
| 3.1 | `tools/sophos_sample.py` — lấy mẫu thật, che bí mật / email / mã người (nhất quán giữa User ↔ identity ↔ tên rule) / họ tên / IP / MAC |
| 3.2 | Bảng `vpn_accounts` (unique firewall + username, `removed_at` không xóa), `vpn_sync`; `POST /api/vpn/sync` (operator, công việc nền), `GET /api/vpn/accounts` (viewer); đồng bộ định kỳ `VPN_SYNC_MINUTES` qua `core.jobs.every` (một pod/vòng); audit `vpn_sync` |
| 3.3 | Tab **VPN** (`pages/vpn.js`): trạng thái đồng bộ, bộ lọc, thống kê, bảng; sửa lỗi `[hidden]` bị `.btn` ghi đè |

Quy tắc tính quyền (hàm thuần `compute_access`): **SSL VPN** = user có SSL VPN policy riêng, hoặc thuộc nhóm có
policy, hoặc user/nhóm là thành viên tunnel policy; **IPsec** = user/nhóm trong `AllowedUser` của kết nối
`RemoteAccess` (SiteToSite không tính). Cần đối chiếu lại khi có mẫu thật từ `tools/sophos_sample.py`.

---

## 13. Nhật ký thực hiện phase 4 (VPN B2 — thời hạn qua firewall rule, chỉ đọc)

| Bước | Kết quả |
|---|---|
| 4.0 | `modules/vpn/expiry.py` (hàm thuần): `parse_rule_name`, `determine_expiry` (Schedule OneTime > tên, cờ lệch), `classify(today, threshold)`; `tests/vpn_expiry_test.py` (36 kiểm tra: đủ các mẫu tên thực tế + mẫu lỗi) |
| 4.1 | Đọc FirewallRuleGroup / FirewallRule / Schedule qua allowlist; bảng `vpn_rules` (khóa firewall + tên rule — API không có ID số), `vpn_rule_changes` (chuỗi băm); API `/api/vpn/rules` (+`as_of`), `/rules/{id}`, `/rules.csv`, `/changes`, `/changes/verify`, `/settings`; `tests/vpn_rules_test.py` (46 kiểm tra) |
| 4.2 | Dashboard (thẻ trạng thái bấm để lọc, bộ lọc, bảng phân trang, chi tiết rule dạng dialog, lịch sử), tab Cài đặt; `components/modal.js`, `components/pagination.js` |

Quyết định chi tiết:
- **Khóa rule = tên** (Sophos không trả ID số); đổi tên = "rule bị xóa" + "rule mới" trong lịch sử.
- **Lần đồng bộ đầu** ghi một sự kiện `baseline` (không ghi hàng trăm sự kiện "rule mới").
- **Team**: phần trước " - " (bỏ tiền tố "VPN - "); không có " - " thì phần chữ trước "GROUP"/"access".
- **User không còn / bị khóa**: mọi tài khoản liên kết đã bị xóa khỏi firewall hoặc Deactive, hoặc identity là user
  không tồn tại — chỉ kết luận khi đã đồng bộ tài khoản của firewall đó.
- Trạng thái tính khi đọc (không lưu) → không bao giờ "cũ"; `as_of` cho phép xem trước tương lai.
- CSV mặc định gồm: sắp hết hạn, hết hạn còn bật, user không còn, không đọc được tên, lệch thời hạn.

---

## 14. Nhật ký thực hiện phase 5 (thông báo email)

| Bước | Kết quả |
|---|---|
| 5.0–5.1 | `modules/notify/` — `smtp.py` (cấu hình trên giao diện, mật khẩu mã hóa, không trả về; chặn header injection; gửi thử), `planner.py` (hàm thuần: mốc nhắc, người nhận, dedupe_key), `outbox.py` (bảng `email_outbox`, retry lùi dần, SMTP tắt → nằm chờ), `router.py`; bảng `vpn_team_contacts`; `mock/mock_smtp.py`; `tests/notify_test.py` (35 kiểm tra) |
| 5.2 | Tab Cài đặt: SMTP + gửi thử, thông báo, đại diện team, hàng đợi email + Chạy ngay |

Quy tắc gửi:
- **Sắp hết hạn**: mốc hiện tại = mốc nhỏ nhất ≥ số ngày còn lại; `dedupe_key = vpn_expiring:<fw>:<rule>:<ngày hạn>:<mốc>`
  → mỗi mốc một lần, app ngừng vài ngày thì chỉ gửi mốc hiện tại, đổi hạn → nhắc lại. Người nhận: đại diện team của
  rule (khớp tên team không phân biệt hoa/thường) + email Infra.
- **Hết hạn nhưng vẫn bật**: chỉ Infra, `dedupe_key` theo tuần ISO → nhắc mỗi tuần tới khi rule được tắt/gia hạn.
- Thư có header `Auto-Submitted: auto-generated`; nội dung không có dữ liệu bí mật; app vẫn **không** sửa rule.
- Thử lại: 5 phút × 2^(n−1), tối đa 6 giờ, 8 lần → `failed`. Lập kế hoạch + gửi chạy định kỳ (`NOTIFY_INTERVAL_SECONDS`,
  mỗi vòng một pod qua `pg_try_advisory_lock`).

---

## 15. Rà soát quyền truy cập VPN định kỳ (ISO/IEC 27001:2022 — A.5.18 Access rights, A.8.2, A.5.15)

Quyết định (18/11/2026): **đại diện team** rà soát (đăng nhập Microsoft), **hằng quý**, phạm vi **rule VPN + tài khoản
mồ côi**. App vẫn **chỉ đọc** firewall: "Thu hồi" tạo danh sách cho Infra xử lý, không tự tắt rule.

**Đợt rà soát (campaign)** — bảng `review_campaigns`: tên ("Rà soát VPN Q4/2026"), khóa kỳ `2026-Q4` (UNIQUE → tự mở
không trùng), hạn hoàn thành (mặc định 14 ngày), mở/đóng, người mở/đóng.
- Tự mở ngày đầu quý (giờ VN, `core.jobs.every`, một pod/vòng) nếu bật; admin cũng mở tay được.
- Khi mở: **chụp ảnh** dữ liệu tại thời điểm đó vào `review_items` (không đổi theo đồng bộ sau này — bằng chứng audit):
  - mỗi rule trong Rule Group VPN (đích, dịch vụ, identity, tài khoản liên kết, hạn, trạng thái hạn);
  - mỗi **tài khoản mồ côi**: có quyền SSL VPN/IPsec, còn trên firewall, nhưng không gắn rule VPN nào → Infra.
- Phạm vi người rà soát: rule có team và team có đại diện (`vpn_team_contacts`) → đại diện team đó; còn lại
  (không team, team chưa có đại diện, tài khoản mồ côi) → **Infra** (quản trị viên).

**Quyết định từng mục**: `keep` (còn cần) · `revoke` (thu hồi) · `change` (cần điều chỉnh) — `revoke`/`change` bắt
buộc ghi lý do. Mỗi quyết định ghi vào `review_decisions` nối **chuỗi băm** (`core/hashchain`) — sửa/xóa sẽ lộ.
Quản trị viên quyết định thay được (ghi rõ "Infra quyết định thay").

**Vai trò `reviewer`** (mới, thấp nhất): người đăng nhập Microsoft mà email nằm trong danh sách đại diện team và chưa
là người dùng app → được vào app với vai trò `reviewer`, **chỉ** gọi được `/api/review/my*` + `/api/config`
(chặn tập trung ở `auth/rbac.principal`, mọi API khác 403). Người dùng app sẵn có (viewer/operator/admin) là đại
diện team thì rà soát được team mình trong tab Rà soát.

**Thông báo** (dùng outbox phase 5, idempotent): mở đợt → email mỗi đại diện (số mục cần rà soát + link);
còn ≤ 3 ngày → nhắc mục chưa quyết định; quá hạn → báo Infra danh sách team chưa xong.

**Đóng đợt** (admin): mục chưa quyết định ghi "Không phản hồi" (để leo thang). Xuất **CSV bằng chứng** (mọi mục,
quyết định, người, thời điểm, lý do, mã băm) và **CSV cần thu hồi / điều chỉnh** cho Infra.

### 15.1 Nhật ký thực hiện

| Bước | Kết quả |
|---|---|
| R.1 | `modules/review/` (service + router), 3 bảng, vai trò `reviewer` (chặn tập trung ở `auth/rbac.principal`, `ROLES` thêm `reviewer` để `issue_token` không đổi thành viewer), `APP_BASE_URL`; `tests/review_test.py` (36 kiểm tra) |
| R.2 | Tab Rà soát (thẻ từng quyền + quyết định + lý do, tiến độ; quản lý đợt, tiến độ theo team, CSV, kiểm tra chuỗi băm), thẻ cấu hình trong Cài đặt; smoke UI cho admin + reviewer |

Chi tiết: chỉ một đợt mở cùng lúc; tự mở chỉ khi đã có dữ liệu VPN và trong 15 ngày đầu quý (triển khai giữa quý không mở
bất ngờ); quyết định sửa được tới khi đóng đợt (mỗi lần sửa thêm một dòng nhật ký).

---

## 16. Tự động chặn IP từ group chat Teams (v2.2)

**Vấn đề.** SOC giám sát 24/7, nhưng Infra không trực đêm, nên lệnh chặn từ SOC nằm chờ tới sáng. Đề xuất đầy đủ
(chấm điểm TI, ba mức xử lý) ở `docs/auto-block-proposal.md`. Anh **chọn phương án đơn giản hơn** (18/11/2026), mô tả dưới đây.

**Luồng xử lý.** Module `modules/autoblock/`:

| Bước | Chi tiết |
|---|---|
| Đọc | `graph.py`: token client-credentials, đọc `GET /chats/{chat_id}/messages` (mới → cũ, dừng ở mốc đã đọc). Chu kỳ: quản trị viên chọn trong tab Cài đặt (60–3600 giây, mặc định `AUTOBLOCK_POLL_SECONDS`=300). Bộ lập lịch kiểm tra mỗi 30 giây, mốc `last_poll_at` lưu DB → đúng cả khi nhiều pod |
| Lọc tin | Chỉ tin tạo **sau** lúc bật / đổi Chat ID (`start_at`). Bỏ qua: tin của người ngoài danh sách tài khoản SOC (Object ID Entra) · tin **đã sửa** (`lastEditedDateTime`) · tin đã xóa · tin hệ thống. `msg_id` UNIQUE → không xử lý lại |
| Cú pháp | `parser.py`: một dòng đúng `ĐỀ XUẤT CỦA SOC: BLOCK IP <ip>`, **IN HOA**, phân biệt hoa/thường, chỉ IPv4 đơn (/32). Chuẩn hóa NFC + `&nbsp;` |
| Kiểm tra IP | Safe-list / IP nội bộ → `invalid` (như chặn tay). IP đang có yêu cầu hoạt động → `duplicate` |
| Quyết định | **Whitelist** (HSC / Akamai / Đối tác / danh sách thêm) → chờ, **chỉ quản trị viên Approve**, không tính ngưỡng · công tắc khẩn cấp TẮT → chờ · ngoài khung giờ (mặc định 18:00–08:00, tắt = 24/7) → chờ · ngưỡng đã ngắt hoặc vượt N IP/giờ (mặc định 20) → **ngắt** + email nhóm Admin, chờ · còn lại → **tự chặn** |
| Chặn | Gọi `ipblock.service.block_on_firewall` qua `core.jobs` (job nền, song song theo firewall, policy guard, `SCANPORT GROUP`, lịch sử hash chain). Tác nhân `autoblock`, nguồn `teams-auto` |
| Trả lời | `reply.py`: chặn thành công → `INFRA ĐÃ BLOCK <ip> THEO YÊU CẦU LÚC dd/mm/yyyy HH:MM:SS` (giờ VN, lúc chặn xong) qua **Teams Workflows** webhook. Graph không cho app gửi tin vào chat bằng quyền ứng dụng (chỉ `Teamwork.Migrate.All`). Lỗi → thử lại mỗi chu kỳ, tối đa 5 lần |
| Lịch | `window_reason`: tắt = 24/7 · ngày lễ (danh sách khoảng ngày, cả ngày) · T7/CN cả ngày (tùy chọn) · ngoài giờ ngày thường (`window_start`–`window_end`, qua đêm). `off_hours_span` gộp các khoảng liền nhau thành **ca ngoài giờ** (vd 18:00 T6 → 08:00 T2) cho danh sách ca và email báo cáo |
| Thông báo | Email nhóm Admin: vượt ngưỡng (gửi ngay), có lệnh chờ duyệt, báo cáo **khi kết thúc mỗi ca ngoài giờ** |

**Bảng mới:**
- `autoblock_messages`: tin đã đọc; chỉ lưu nội dung tin của tài khoản SOC.
- `autoblock_requests`: vòng đời từng lệnh (`mode` auto/pending, `status`, whitelist, kết quả từng firewall, trả lời Teams).
- `autoblock_events`: nhật ký **chuỗi băm**.

Cấu hình nằm trong `app_settings['autoblock.settings']`; client secret và URL webhook được mã hóa bằng `MASTER_KEY`, không bao giờ trả ra API.

**Quyền:**

| Vai trò | Được phép |
|---|---|
| viewer | Xem |
| operator | Approve (trừ IP whitelist), từ chối, gỡ chặn (từng IP / cả ca đêm), **TẮT** công tắc |
| admin | Cấu hình, **BẬT** lại công tắc, mở lại ngưỡng, Approve IP whitelist, đọc ngay, gửi thử |

### 16.1 Nhật ký thực hiện

| Bước | Kết quả |
|---|---|
| A.1 | `modules/autoblock/` (parser, graph, settings, service, router, reply), 3 bảng, `mock/mock_graph.py` (Graph + Entra token + Workflows giả lập), `tests/autoblock_test.py` |
| A.2 | Yêu cầu bổ sung trong lúc làm: chu kỳ 5 phút và chỉnh trên giao diện; whitelist + Approve chỉ quản trị viên; trả lời vào group chat |
| A.2b | Lịch tự chặn chỉnh trên giao diện: ngoài giờ ngày thường, cả ngày cuối tuần, ngày lễ (khoảng ngày), nút "Tự chặn cả ngày hôm nay" |
| A.3 | Tab **Tự động chặn** (thẻ trạng thái, chờ duyệt, ca đêm + gỡ tất cả, tất cả lệnh, kiểm tra chuỗi băm) + thẻ cấu hình trong Cài đặt; smoke UI admin + viewer + điện thoại |

Lỗi phát hiện khi tự kiểm tra:
- Lưu lần đầu vừa đổi Chat ID vừa bật → trạng thái ghi hai lần trong một phiên DB, gây INSERT trùng khóa. Sửa: `flush` sau mỗi lần lưu.
- Danh sách ca đêm so giờ VN với cột UTC → trống trên SQLite. Sửa: đổi mốc sang UTC trước khi truy vấn.

---

## 17. Giao diện v2.2 (thiết kế lại theo UI UX Pro Max)

Anh yêu cầu thiết kế lại tự do, không ràng buộc HSC Design System.

| Hạng mục | Quyết định |
|---|---|
| Phong cách | *Data-Dense Dashboard* (gợi ý của skill cho dashboard vận hành): bảng, thẻ KPI, lưới gọn, tối là mặc định |
| Màu | `frontend/theme.css`. Xanh dương cho thao tác chính (`--primary` #2563eb, chữ trắng 5.2:1), hổ phách cho cảnh báo. Mọi cặp chữ/nền ≥ 4.5:1 ở cả hai chế độ (đã đo) |
| Chữ | Fira Sans (giao diện, đủ dấu tiếng Việt) + Fira Code (IP, CIDR, XML), tự host woff2, giấy phép OFL. Bỏ Inter và `hsc-tokens.css` |
| Bố cục | Menu trái theo nhóm (Vận hành · Giám sát · VPN & tuân thủ · Quản trị). Dưới 960px là ngăn kéo (nút ☰, Esc, bấm nền để đóng). Thanh trên hiện tiêu đề trang |
| Cân đối | Lưới cột bằng nhau, thẻ cùng hàng cao bằng nhau (`align-items: stretch`). Thẻ trạng thái chia đều (VPN 4 × 2; điện thoại 2 cột, thẻ lẻ cuối trải hết hàng). Bảng cùng padding / chiều cao dòng, tiêu đề dính, cột thao tác căn phải, chữ số `tabular-nums` |
| Tooltip | `js/components/tips.js` gắn nút ⓘ cạnh nhãn của khoảng 60 mục cấu hình. Nội dung tập trung trong `HELP`. Một popup `role="tooltip"` dùng chung, mở khi rê chuột / focus / chạm, Esc để đóng, tự căn trong màn hình |
| Truy cập | Vùng chạm ≥ 40px trên điện thoại, font 16px cho ô nhập (iOS không zoom), focus luôn nhìn thấy, `prefers-reduced-motion` |

Giữ nguyên toàn bộ id / `data-*` mà JS và test dùng. Router vẫn dùng `.tab[data-tab]`. Smoke test chỉ đổi helper mở menu trên điện thoại và thêm kiểm tra tooltip.

---

## 18. Báo cáo chặn IP (v2.2)

**Yêu cầu (18/11/2026):**
- Kỳ báo cáo: 7 / 14 / 30 ngày, hoặc **chọn trên lịch**.
- Nội dung: danh sách IP bị chặn, phương thức (con người / tự động), thời gian thực hiện.
- Định dạng: **PDF + Excel**, mở đầu bằng **Executive Summary**, sau đó là chi tiết.
- Trình bày: **màu và font HSC Design System**, **logo ở header**.
- Gửi email qua SMTP đã cấu hình.

**Module `modules/reports/`:**

| Thành phần | Vai trò |
|---|---|
| `data.py` | `resolve` kỳ báo cáo (mốc nhanh hoặc khoảng ngày; giờ VN; tối đa 366 ngày). `build` lấy số liệu từ `group_changes` (`add` = lượt chặn; `remove` / `drift_remove` về sau = đã gỡ) và `autoblock_requests` / `autoblock_messages` (thời gian SOC gửi → chặn xong). `executive` sinh câu tổng quan, nhận định, cần lưu ý — chỉ từ số liệu, không đoán |
| Phương thức | `auto` khi tác nhân là `autoblock`. Còn lại là `manual`, gồm Approve lệnh SOC (vì con người quyết định) |
| `pdf.py` | reportlab, A4 ngang. Header là dải cover HSC (#0058AF / #00468C) với logo trong ô trắng. Trang 1 là Executive Summary, các trang sau là chi tiết (biểu đồ cột chồng, bảng). `CondPageBreak` để tiêu đề không đứng một mình cuối trang; chân trang "Trang x/y" |
| `xlsx.py` | openpyxl: sheet Executive Summary (có logo) → Theo ngày (biểu đồ) → Danh sách IP → Chi tiết lượt chặn → Người thực hiện. Font Inter, tiêu đề bảng #00468C, cột thời gian kiểu datetime, có bộ lọc |
| `logo.py` | Dùng logo đã tải lên (PNG / JPG / WebP → PNG). SVG hoặc chưa có logo → biểu tượng khiên mặc định vẽ bằng Pillow |
| `fonts/` | Inter / Inter Display tĩnh (Regular, SemiBold, Bold) tạo từ Inter variable chính thức bằng fontTools, sửa bảng tên để PDF nhúng không trùng tên; giấy phép OFL |
| `router.py` | `GET /api/reports/summary`, `blocks.pdf`, `blocks.xlsx` (viewer; tải qua `?token=`), `POST /api/reports/email` (Write; SMTP phải cấu hình và đang bật; tối đa 20 người nhận). Audit `report_export` / `report_email` |

`notify/smtp.send` nhận thêm `attachments`. Thư viện mới: `openpyxl`, `reportlab`, `Pillow` (đã ghim phiên bản).
Test: `tests/reports_test.py` kiểm tra số liệu, kỳ trên lịch, PDF (văn bản, logo, tiếng Việt), Excel (sheet, font, kiểu ngày), email đính kèm, phân quyền.

---

## 19. Rà soát cơ chế đọc tin Teams — thời điểm lệnh BLOCK IP, không đọc lại lịch sử

| Trước | Sau |
|---|---|
| Graph `orderby=createdDateTime desc`, app tự lọc phía mình và dừng khi gặp tin cũ hơn mốc. Mỗi chu kỳ vẫn nhận ít nhất một trang 50 tin | **Lọc phía Graph**: `$filter=lastModifiedDateTime gt <mốc>` + `$orderby=lastModifiedDateTime desc`. Chu kỳ không có tin mới thì Graph **trả 0 tin**. Tenant không nhận bộ lọc (400) thì tự quay về cách cũ (`server_filter=false` trên trạng thái) |
| Mốc đọc = `createdDateTime` lớn nhất, đọc chồng 10 phút | Mốc đọc = **`lastModifiedDateTime` lớn nhất do Graph trả** (giờ máy chủ Microsoft, định dạng mili giây), không dùng đồng hồ máy app. Đọc chồng `AUTOBLOCK_OVERLAP_SECONDS` (mặc định 120 giây) cho độ trễ nhất quán; `msg_id` UNIQUE chống xử lý lặp |
| Khung giờ tự chặn tính theo lúc app đọc tin | **Thời điểm lệnh = `createdDateTime` của tin SOC**, lưu ở `autoblock_requests.requested_at`. Khung giờ / lịch và danh sách ca ngoài giờ tính theo lúc SOC gửi (vd lệnh gửi 07:58, đọc lúc 08:02 vẫn tự chặn) |
| Lệnh gửi nhiều giờ trước (app ngừng, mất mạng) vẫn tự chặn khi app chạy lại | **Lệnh cũ** (trễ quá `stale_minutes`, mặc định 30, tối thiểu gấp đôi chu kỳ đọc) → **chờ duyệt**, lý do ghi rõ giờ gửi và số phút trễ |
| Tối đa 5 trang (250 tin), đọc mới → cũ: vượt quá thì mất tin cũ **không báo** | Tối đa 20 trang (1.000 tin). Còn tin chưa đọc thì `last_truncated` + cảnh báo trên tab; lệnh trễ thì rơi vào nhánh "lệnh cũ" |

Các bảo đảm giữ nguyên:
- Tin gửi trước lúc bật hoặc đổi Chat ID (`start_at`) không bao giờ được xử lý, kể cả khi sau đó bị sửa hay thả cảm xúc. Thao tác đó làm đổi `lastModifiedDateTime` nên Graph trả lại tin, nhưng app bỏ qua theo `createdDateTime`.
- Tin đã xử lý mà sau đó bị sửa hay thả cảm xúc cũng không bị xử lý lại (kiểm tra `msg_id`).

Test (`tests/autoblock_test.py`): Graph được gọi với bộ lọc · chu kỳ không có tin mới trả 0 tin · tin bị "chạm" không xử lý lại · tenant từ chối `$filter` thì tự quay về cách cũ · lệnh trễ 45 phút thì chờ duyệt · khung giờ tính theo lúc SOC gửi.

---

## 20. Bằng chứng (snapshot) tin BLOCK IP — kể cả khi người gửi xóa tin

**Yêu cầu:** SOC gửi lệnh, app đã chặn, sau đó người dùng xóa tin trên Teams. Cần bằng chứng về thời điểm và nội dung lệnh.

**Bản chụp lúc nhận:** bảng `autoblock_evidence`.
- Mọi tin có dòng lệnh đều được chụp, kể cả tin bị bỏ qua vì người lạ hay tin đã sửa.
- Bản chụp được **commit trước khi chặn**.
- Lưu: nguyên văn đối tượng `chatMessage` của Graph (`raw_json`, JSON chuẩn hóa) và **SHA-256** của nó; nội dung văn bản; các dòng lệnh; Message ID / Chat ID; người gửi (tên, Object ID, `userIdentityType`); `createdDateTime` / `lastModifiedDateTime` của Microsoft; giờ app chụp.
- Các bản chụp **nối chuỗi băm** (kể cả nội dung văn bản): sửa trực tiếp trong DB → `GET /api/autoblock/verify` báo đứt.

**Theo dõi sau xử lý:**
- Graph trả lại tin đã xử lý khi `lastModifiedDateTime` đổi.
- Tin bị xóa (`deletedDateTime`) hoặc bị sửa (`lastEditedDateTime`) → ghi `autoblock_messages.deleted_at` / `edited_at` (giờ Microsoft) và `*_seen_at` (lúc app phát hiện), kèm sự kiện chuỗi băm `msg_deleted_after` / `msg_edited_after`.
- **Bản chụp gốc không đổi**, kết quả chặn không đổi.

**API / giao diện:**
- `GET /api/autoblock/requests/{id}/evidence` (viewer): bản chụp + trạng thái tin hiện tại trên Teams + kết quả kiểm tra toàn vẹn.
- `GET …/evidence.json?token=`: file bằng chứng tải về, gồm `graph_message_raw` nguyên văn. Kiểm chứng độc lập: `SHA-256(graph_message_raw) = evidence.sha256`. Ghi audit `evidence_export`.
- Tab Tự động chặn › Tất cả lệnh › nút **Bằng chứng**.

Test: gửi → chặn → xóa → bản chụp còn nguyên, có mốc xóa · gửi → sửa · file JSON tự kiểm SHA-256 · lệnh của người lạ cũng được chụp · sửa nội dung bản chụp trong DB thì bị phát hiện.

---

## 21. Team SOC trực 24/7 — ai được gửi lệnh

**Bối cảnh (18/11/2026):**
- Group chat thuộc tenant HSC.
- Thành viên SOC là tài khoản **external** của nhà cung cấp dịch vụ SOC Managed Service, nhiều người, xoay ca.
- Khai báo từng Object ID không theo kịp việc đổi ca.

**Ba cách tin cậy** (khớp một là đủ; class `Trust` trong `autoblock/service.py`):

| Cách | Cấu hình | Cơ chế |
|---|---|---|
| ~~Tenant của đơn vị SOC~~ *(đã bỏ — xem cập nhật cuối mục)* | `soc_tenants` | So `from.user.tenantId` của tin (Graph). Kết hợp việc HSC kiểm soát thành viên group chat thành allowlist hiệu quả: thêm hay gỡ người khỏi chat là đủ. **Tenant HSC (trùng Tenant ID của App registration) bị từ chối** ở bước lưu và cả bước kiểm tra, để nhân viên HSC trong chat không kích hoạt được lệnh |
| Nhóm Entra | `soc_groups` | `GET /groups/{id}/transitiveMembers/microsoft.graph.user` (`GroupMember.Read.All`). Cache trong state (dùng chung các pod), đọc lại mỗi 30 phút, và đọc lại ngay khi gặp người gửi lạ nếu cache cũ hơn 5 phút. Đọc lỗi thì giữ danh sách cũ và báo `group_error`. Không áp dụng được cho tài khoản external (không có trong danh bạ HSC) |
| Tài khoản riêng lẻ | `soc_senders` | Object ID |

**Ghi nhận:**
- `autoblock_messages.sender_tenant` / `trusted_by`.
- `autoblock_evidence.sender_tenant` / `trusted_by` (nằm trong chuỗi băm).
- Ghi chú của lệnh ("SOC: Tenant …").
- Sự kiện `ignored_sender` ghi tenant người gửi.

**Giao diện:** *Cài đặt › Người được gửi lệnh* có ba khối. *Kiểm tra kết nối* liệt kê người gửi gần đây chưa được tin cậy, kèm tenant và nhãn External / HSC, với nút **"+ Tin cậy tenant này"** (chỉ có ở người external) và **"+ Chỉ tài khoản này"**.

Test: thành viên MSSP chưa khai báo thì bỏ qua → khai báo tenant → người mới vào ca gửi lệnh được chặn · nhân viên HSC trong chat thì bỏ qua · khai báo tenant HSC → 400 · nhóm Entra: thành viên được chặn, người vừa thêm vào nhóm được nhận nhờ đọc lại, đọc nhóm 403 thì giữ danh sách cũ · bằng chứng ghi tenant và cách tin cậy.

**Cập nhật (18/11/2026), thành viên HSC được ủy quyền.** Team IT Security của HSC (cùng tenant HSC) có quyền gửi lệnh.
Không cần cơ chế mới: thứ tự kiểm tra là tài khoản riêng lẻ → nhóm Entra → tenant. Chặn tenant HSC chỉ áp dụng cho cách
"tin cậy *cả tenant*", nên thành viên HSC khai báo đích danh hoặc nằm trong nhóm `IT-Security` vẫn được nhận.

- Giao diện ghi rõ cách khai báo, và có nút "+ Cho phép tài khoản HSC này".
- Test khóa hành vi: thành viên IT Security (tài khoản hoặc nhóm) được tự chặn; nhân viên HSC khác bị bỏ qua.

**Cập nhật (18/11/2026), bỏ tin cậy theo cả tenant.** Đối tác SOC (vd HPT) có thể có người khác trong group chat
(account manager, kỹ thuật…), nên tin cậy cả tenant là quá rộng. Thay đổi:

- `soc_tenants` bị bỏ. Chỉ còn hai cách: **tài khoản được ủy quyền** (`soc_senders`, mỗi mục `{id, name, tenant}`) và
  **nhóm Entra**. Mục có `tenant` thì `from.user.tenantId` của tin phải khớp.
- API nhận `soc_tenants` → 400. Cấu hình cũ có `soc_tenants` được đọc thành `legacy_tenants` (không còn hiệu lực) để giao
  diện hiện cảnh báo; `dismiss_legacy_tenants` xóa cảnh báo.
- *Kiểm tra kết nối* đọc thêm `GET /chats/{id}/members` (`ChatMember.Read.Chat` / `ChatMember.Read.All`, tùy chọn) để
  liệt kê thành viên chat kèm tenant và email, nút **+ Ủy quyền** cạnh từng người. Thiếu quyền → `members_error`, quay về
  danh sách người gửi gần đây.
- Sự kiện `ignored_sender` ghi "chưa được ủy quyền (… hoặc sai tenant)".

Test: người khác của cùng tenant đối tác bị bỏ qua · đúng Object ID nhưng sai tenant bị bỏ qua · danh sách thành viên chat
đánh dấu ai đã được ủy quyền · thiếu quyền đọc thành viên vẫn kiểm tra kết nối được · cấu hình cũ `soc_tenants` không còn
hiệu lực và hiện cảnh báo.

---

## 22. Đánh giá tổng thể & M1 hiệu suất / toàn vẹn (v2.2.1, 27/11/2026)

Đánh giá đầy đủ và lộ trình (liên kết tính năng, tính năng cho IT Infrastructure Manager): [`roadmap-infra.md`](roadmap-infra.md).

| Việc | Thay đổi | Test |
|---|---|---|
| Chuỗi băm liên pod | `hashchain.append` thêm `pg_advisory_xact_lock(hashtext('chain:<bảng>'))` trên chính session (không tốn thêm kết nối, nhả khi commit/rollback); lỗi giữa chừng thì rollback ngay. Chờ khoá không giới hạn: ưu tiên không mất bản ghi. Quy ước: flush thay đổi khác trước, gọi `append` sau, không gọi firewall giữa hai bước | `hashchain_multiproc_test.py`: 4 tiến trình × 50 dòng trên PostgreSQL; code cũ gãy chuỗi, code mới liền |
| Tìm Audit | Lọc `q` trong SQL **trước** `LIMIT` (`icontains(autoescape=True)`: `%` và `_` là ký tự thường); index `ix_audit_logs_action`, tạo cả cho DB cũ khi khởi động | `audit_search_test.py`, `db_migrate_test.py` |
| VPN `list_rules` | Dựng chỉ mục tài khoản theo firewall một lần (nhóm / username / mã user), kết quả và thứ tự giống bản cũ | `vpn_rules_perf_test.py`: 1,3 s → 0,01 s |
| Vận hành | `GZipMiddleware` (≥ 1 KB, mức 5); dọn `jobs` mỗi 6 giờ (trước chỉ chạy lúc khởi động); `DB_POOL_SIZE` / `DB_MAX_OVERFLOW`; huy hiệu menu ngừng poll khi tab ẩn | `ops_test.py` |
| Kiểm thử | `tests/run_all.sh`: lấy biến môi trường riêng từ dòng `# Chạy:` của từng bộ, chờ cổng được nhả giữa các bộ (vòng lặp cũ báo FAIL giả) | toàn bộ |

Không đổi API (contract snapshot giữ nguyên), không nới `policy.py`. Hoãn: chạy song song các lượt quét định kỳ, parse cache
một lần (xem roadmap §3).

## 23. Trang Tổng quan (v2.3.0, 27/11/2026)

Roadmap L1. **Chỉ frontend** (`frontend/js/pages/overview.js`), không API mới (contract snapshot giữ nguyên).

- Nguồn: `/api/group-cache`, `/api/autoblock/status`, `/api/vpn/rules`, `/api/review/campaigns`, `/api/changes?type=drift&from=<VN−6>`,
  `/api/reports/summary?days=7`, và `/api/notify/outbox?status=failed&limit=1000` (chỉ quản trị viên gọi; lọc 7 ngày, chỉ đếm theo loại,
  không hiện người nhận / tiêu đề). Gọi song song `Promise.allSettled`; mỗi nguồn lỗi, 403, hoặc trả dữ liệu không phải JSON (trang đăng nhập
  của proxy) chỉ làm hỏng thẻ của nó. Đang tải thì không gọi chồng.
- Sức khoẻ firewall lấy từ trạng thái quét cache (tín hiệu sống); `last_status` chỉ là phụ vì chỉ cập nhật khi bấm Kiểm tra hoặc chặn / bỏ chặn.
- Tự động chặn: `enabled` = bộ đọc Teams, `auto_enabled` = công tắc khẩn cấp (TẮT → Cảnh báo); bộ đọc đứng quá 3 chu kỳ → Cảnh báo.
- Router: tab mặc định theo vai trò (`setDefaultTab`: quản trị viên → `overview`, còn lại → `block`); hash rỗng / không hợp lệ, kể cả khi bấm
  Back, về tab mặc định; bỏ qua khi chưa đăng nhập. Vai trò Rà soát không thấy tab này (API vẫn chặn bằng `REVIEWER_PATHS`).
- Test: `ui_smoke.cjs` +23 khẳng định (route giả lập trạng thái có vấn đề, API 500, response HTML, Back, chống gọi chồng, Readonly không gọi outbox, 390px).
- Hoãn: `last_checked` trên thẻ Firewall; deep link có tham số (L2); `GET /api/overview/counts` cho huy hiệu menu (L6).
