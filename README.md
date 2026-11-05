# SOC Rapid Block — mini app chặn IP nhanh trên nhiều Sophos Firewall

Mini app HTML5 + FastAPI giúp team SOC/NOC dán thẳng đoạn chat Teams (hoặc CSV/nhập tay),
bóc IP tự động và đẩy vào **IP Host Group** trên **nhiều Sophos Firewall** cùng lúc qua XML API —
thao tác được từ điện thoại trong ngày nghỉ lễ Tết.

**Mới ở v1.5.2** — Sửa lỗi đăng nhập Microsoft: endpoint Entra ID đúng chuẩn v2.0 (`/oauth2/v2.0/authorize`, `/oauth2/v2.0/token`,
`/discovery/v2.0/keys`; bản cũ gọi sai đường dẫn → 404). Định danh theo `oid` bất biến, chặn tài khoản khách, không dùng claim `email`,
id_token không có `amr` không còn bị từ chối nhầm. Test mới `tests/entra_review_test.py` đối chiếu endpoint với discovery thật của Microsoft.

**Mới ở v1.5.1** — SSO một lần qua Entra Application Proxy: app tự nhận phiên Microsoft vừa xác thực (không hiện màn hình
đăng nhập, không chọn tài khoản, không MFA lần 2). Cấu hình site chuyển sang `deploy/k8s/overlays/prod/local-config.yaml`
(không bị `git pull`/`kubectl apply` ghi đè). Từ nay triển khai bằng `kubectl apply -k deploy/k8s/overlays/prod/`.

**Mới ở v1.5.0** — tab **Người dùng** (chỉ Quản trị viên): thêm / sửa / xóa người dùng, quyền **Write** hoặc **Readonly**,
cờ Quản trị viên, khóa tài khoản, đặt lại mật khẩu; người dùng tự đổi mật khẩu. Khóa / hạ quyền / xóa có hiệu lực ngay.

**Mới ở v1.4.0** — tên IP Host = chính địa chỉ IP/CIDR (`45.138.12.16`, `185.220.101.0/24`) thay cho `SOC_BLOCK_45_138_12_16`.
Object kiểu cũ đã có trong group vẫn được nhận ra (không tạo trùng), bỏ chặn/xóa bình thường. Nếu trên firewall đã có object
trùng tên IP nhưng trỏ tới địa chỉ khác, app báo lỗi và không dùng object đó.

**Mới ở v1.3.0** — chỉ thao tác trên IP Host Group cố định **`SCANPORT GROUP`**; payload IPHostGroup đúng mẫu Sophos (Name → IPFamily → Description → HostList), xem trước XML khi chạy thử.

**Mới ở v1.2.0**
- Truy cập từ Internet qua **Microsoft Entra Application Proxy** + **MFA tài khoản AD**, không mở port inbound,
  không public app — xem [`docs/entra-app-proxy.md`](docs/entra-app-proxy.md).
- Đăng nhập **Microsoft OIDC** (PKCE, kiểm tra chữ ký/tenant/nonce) và phân quyền theo **App Role**: Quản trị / Vận hành / Chỉ xem.
- Tab **Lịch sử thay đổi**: ghi tường minh từng IP được thêm/bớt khỏi Object Group (ai, lúc nào, lý do, số object trước → sau),
  **phát hiện thay đổi làm trực tiếp trên firewall**, chuỗi băm SHA-256 chống sửa log, xuất CSV.

---

## 1. Kiến trúc

```
Trình duyệt (HTML5, mobile-friendly)
        │  REST /api/*
        ▼
FastAPI backend  ──►  PostgreSQL (firewall + credential mã hóa AES-256-GCM + audit log)
        │
        │  HTTPS POST reqxml=<Request>…</Request>
        ▼
https://<firewall>:4444/webconsole/APIController   (Sophos Firewall XML API)
```

Trình duyệt **không** gọi thẳng firewall được (CORS + chứng chỉ self-signed), nên backend đóng vai proxy
và cũng là nơi giữ credential + ghi audit.

Cách chặn: với mỗi IP/CIDR, app tạo **IP Host** có tên chính là địa chỉ đó — vd `45.138.12.16`, `185.220.101.0/24` (`Set operation="add"`),
sau đó ghi lại toàn bộ `<HostList>` của group trong **một** lệnh (Sophos không hỗ trợ thêm/bớt từng phần tử của IPHostGroup —
[tài liệu IPHostGroup](https://docs.sophos.com/nsg/sophos-firewall/22.0/api/SYSTEM/Host%20and%20Services/IPHostGroup/operations/AddIpHostGroup&EditIpHostGroup.html)).

---

## 2. Yêu cầu phía firewall (làm 1 lần cho mỗi firewall)

Theo [hướng dẫn cấu hình API của Sophos](https://docs.sophos.com/nsg/sophos-firewall/20.0/Help/en-us/webhelp/onlinehelp/AdministratorHelp/BackupAndFirmware/API/APIConfiguration/):

1. **Bật API**: `System ▸ Backup & firmware ▸ API` → tick **Enable API configuration**.
2. **Allowed IP**: thêm IP của máy chủ chạy mini app vào danh sách Allowed IP (nếu thiếu → API trả mã **534**).
3. **Tài khoản API**: tạo admin riêng (vd `apiadmin`) có quyền sửa **Hosts and services**; nên giới hạn login theo IP
   ([khuyến nghị hardening](https://www.avanet.com/en/kb/sophos-firewall-api-zugriff-absichern/)).
4. **Cổng**: cổng XML API = cổng HTTPS của Admin Console (`System ▸ Administration ▸ Admin settings`), mặc định **4444**.
5. **Tạo group + rule chặn**: tạo IP Host Group tên chính xác **`SCANPORT GROUP`** (IP version **IPv4**) rồi tạo
   **firewall rule Drop** với Source zone WAN, Source networks = group đó, đặt **lên trên cùng**. Mini app chỉ đổ IP
   vào group này — không có rule thì IP vẫn không bị chặn. App **không tự tạo group**: nếu thiếu, app báo lỗi rõ ràng.
6. **Giới hạn quyền tài khoản API** (khuyến nghị): profile admin chỉ có quyền đọc/ghi **Hosts and services**, không có quyền
   firewall rule, network, system.

Mã trạng thái hay gặp: `200/202` OK · `502` object trùng tên · `503` trùng tham số ·
`526` không tồn tại · `532` chưa bật API · `534` IP nguồn chưa được cho phép · `599` thiếu quyền.

---

## 3. Triển khai

Hai lựa chọn: **Docker Compose** (một máy chủ, đơn giản nhất) hoặc **KubeSphere/Kubernetes** (dùng ảnh dựng sẵn trên GHCR — xem `deploy/k8s/kubesphere/README.md`).

### 3.1 Docker Compose

```bash
git clone <repo> sophos-blocker && cd sophos-blocker
cp .env.example .env

# sinh khóa
openssl rand -hex 32   # dán vào MASTER_KEY
openssl rand -hex 32   # dán vào SESSION_SECRET
# đổi APP_PASSWORD và POSTGRES_PASSWORD

docker compose up -d --build
docker compose logs -f app
```

Mở `http://<ip-server>:8080` → đăng nhập bằng `APP_PASSWORD`.

**Quan trọng**: `MASTER_KEY` dùng để mã hóa mật khẩu firewall trong DB. Mất key = phải nhập lại mật khẩu
cho toàn bộ firewall. Sao lưu key ở nơi an toàn (KeePass/vault), không commit `.env`.

### Biến môi trường chính

| Biến | Ý nghĩa |
|---|---|
| `MASTER_KEY` | Khóa mã hóa credential (bắt buộc, ≥16 ký tự) |
| `APP_PASSWORD` | Mật khẩu đăng nhập mini app |
| `SESSION_SECRET` | Khóa ký session; bỏ trống = sinh mới mỗi lần restart |
| `SESSION_TTL_HOURS` | Thời hạn phiên (mặc định 8h) |
| `HOST_PREFIX` | Chỉ để nhận diện object kiểu cũ do app tạo trước v1.4.0 (mặc định `SOC_BLOCK_`). Object mới luôn đặt tên = IP/CIDR |
| `SAFE_LIST` | Dải **không bao giờ** được chặn (dải nội bộ, VPN, đối tác) |
| `ALLOW_PRIVATE` | Cho phép chặn IP private (mặc định `false`) |
| `API_TIMEOUT` | Timeout gọi firewall, giây (mặc định 30) |
| `AUTH_MODES` | `local` (mật khẩu chung), `oidc` (Microsoft Entra ID + MFA), `header` (header SSO từ App Proxy); kết hợp bằng dấu phẩy |
| `LOCAL_ROLE` | Vai trò cấp cho đăng nhập mật khẩu chung (mặc định `admin`) |
| `OIDC_TENANT_ID` / `OIDC_CLIENT_ID` / `OIDC_CLIENT_SECRET` | Thông tin App registration trên Entra ID |
| `OIDC_REDIRECT_URI` | `<External URL>/api/auth/oidc/callback` |
| `OIDC_REQUIRE_MFA_CLAIM` | `true` = từ chối token có claim `amr` nhưng thiếu `mfa` (id_token v2.0 thường không có `amr`; MFA do Conditional Access bảo đảm) |
| `OIDC_ALLOW_GUESTS` | `false` (mặc định) = từ chối tài khoản khách B2B |
| `OIDC_AUTO_LOGIN` / `OIDC_PROMPT` / `OIDC_DOMAIN_HINT` | SSO một lần: tự chuyển sang Microsoft (mặc định `true`), `prompt` để trống = dùng lại phiên App Proxy, gợi ý domain (vd `hsc.com.vn`) |
| `ROLE_ADMIN` / `ROLE_OPERATOR` / `ROLE_VIEWER` | Giá trị App Role (mặc định `SRB.Admin` / `SRB.Operator` / `SRB.Viewer`) |
| `TRUSTED_PROXY_CIDRS` | IP connector được tin header SSO (chỉ dùng với `header`) |
| `HEADER_USER` / `HEADER_NAME` | Tên header danh tính (mặc định `X-SRB-UPN` / `X-SRB-NAME`) |
| `HEADER_ADMINS` / `HEADER_OPERATORS` / `HEADER_DEFAULT_ROLE` | Phân quyền theo UPN khi dùng header SSO |
| `SHARED_PASSWORD_LOGIN` | `true` (mặc định) = vẫn cho đăng nhập bằng mật khẩu chung `APP_PASSWORD` làm đường khẩn cấp; `false` = chỉ tài khoản riêng / Microsoft |
| `USERS_STRICT` | `true` = đăng nhập Microsoft chỉ chấp nhận người có trong tab Người dùng (bỏ qua App Role) |
| `PASSWORD_MIN_LENGTH` | Độ dài tối thiểu mật khẩu người dùng (mặc định 10, bắt buộc có chữ và số) |
| `LOGIN_MAX_FAILS` / `LOGIN_LOCK_MINUTES` | Sai mật khẩu N lần thì khóa tạm M phút (mặc định 5 lần / 10 phút) |

### Khuyến nghị vận hành

- **Không** phơi trực tiếp ra Internet. Truy cập từ xa dịp lễ: dùng Entra Application Proxy + Conditional Access MFA
  và `AUTH_MODES=oidc` ([hướng dẫn](docs/entra-app-proxy.md)), hoặc VPN.
- Sao lưu volume `pgdata` (chứa firewall + audit log).
- Cập nhật `SAFE_LIST` với dải IP văn phòng, VPN, đối tác để tránh tự chặn nhầm.

---

### 3.2 KubeSphere / Kubernetes

Manifests nằm ở `deploy/k8s/base/` (Namespace + ConfigMap + Secret mẫu + Postgres StatefulSet + Deployment + NodePort Service + NetworkPolicy). Image build tự động qua GitHub Actions và đẩy lên `ghcr.io/luongminhphu/firewall-api-mgmt`.

Quick start:

```bash
kubectl create namespace sophos-blocker
kubectl -n sophos-blocker create secret generic soc-rapid-block-secrets \
  --from-literal=MASTER_KEY=$(openssl rand -hex 32) \
  --from-literal=SESSION_SECRET=$(openssl rand -hex 32) \
  --from-literal=APP_PASSWORD='DoiMatKhauNay@2026' \
  --from-literal=POSTGRES_PASSWORD=$(openssl rand -hex 24)
kubectl apply -k deploy/k8s/base/
```

Truy cập `http://<node-ip>:30988`. Xem hướng dẫn đầy đủ (imagePullSecret cho GHCR private, cách import qua UI KubeSphere, upgrade/rollback, sao lưu Postgres) trong [`deploy/k8s/kubesphere/README.md`](deploy/k8s/kubesphere/README.md).

## 4. Sử dụng

**Tab Chặn nhanh**
1. Chọn nguồn: **Dán từ Teams** (app tự bóc IPv4/CIDR, hiểu cả dạng làm mờ `1.2.3[.]4`, `1.2.3(.)4`, `1.2.3[dot]4`),
   **Nhập tay**, hoặc **CSV/TXT** (kéo-thả file).
2. Tick các firewall đích (có thể chọn tất cả) và điền lý do/ticket. IP Host Group đích luôn là **`SCANPORT GROUP`**
   (hiển thị khóa, không sửa được).
3. Tick **Chạy thử (dry-run)** để xem trước sẽ tạo gì mà không ghi lên firewall.
4. Bấm **Chặn ngay** → xem kết quả từng IP trên từng firewall (đã thêm / đã có / lỗi + mã Sophos).

**Tab IP Host Group** — xem và tìm kiếm thành viên `SCANPORT GROUP` trên từng firewall, tick để **bỏ chặn**
(tùy chọn xóa luôn IP Host object — chỉ áp dụng cho object do app tạo: tên trùng đúng địa chỉ của object, hoặc tên kiểu cũ `SOC_BLOCK_*`).

**Payload IPHostGroup** — kết quả chặn (kể cả chạy thử) hiển thị đúng XML gửi lên firewall theo mẫu
[Add/Edit IP Host Group của Sophos](https://docs.sophos.com/nsg/sophos-firewall/22.0/api/SYSTEM/Host%20and%20Services/IPHostGroup/operations/AddIpHostGroup&EditIpHostGroup.html):

```xml
<Set operation="update">
  <IPHostGroup>
    <Name>SCANPORT GROUP</Name>
    <IPFamily>IPv4</IPFamily>
    <Description>(giữ nguyên mô tả hiện có trên firewall)</Description>
    <HostList>
      <Host>45.138.12.16</Host>
      <Host>185.220.101.0/24</Host>
    </HostList>
  </IPHostGroup>
</Set>
```

`<Host>` là **tên IP Host** (tối đa 60 ký tự, không dấu phẩy) — app tạo IP Host tên = IP/CIDR (vd `45.138.12.16`) trước, sau đó ghi lại
toàn bộ `HostList` (danh sách cũ + mới) vì Sophos không có lệnh thêm/bớt từng phần tử. `Description` và `IPFamily`
hiện có của group được giữ nguyên.

**Tab Firewall** — thêm/sửa/xóa firewall, **Kiểm tra** từng cái hoặc **Kiểm tra tất cả**.

**Tab Lịch sử thay đổi** — dòng thời gian mọi thay đổi thành viên Object Group:
- Mỗi lần chặn/bỏ chặn là một thẻ: thời gian, người thực hiện (UPN + tên AD), phương thức xác thực, firewall › group,
  `+N / −N`, số object **trước → sau**, lý do/ticket, nguồn (Teams/nhập tay/CSV), IP client; bên dưới liệt kê từng dòng
  `+ IP  object` (đỏ = đưa vào group chặn) và `− IP  object` (xanh = gỡ khỏi group).
- **Thay đổi ngoài app**: mỗi khi app đọc group (xem group, trước khi chặn/bỏ chặn, hoặc bấm **Đồng bộ & dò thay đổi ngoài app**),
  app so với ảnh chụp lần trước; nếu ai đó sửa trực tiếp trên WebAdmin, thay đổi được ghi thành thẻ màu cam
  "Thay đổi ngoài app". Lần đầu thấy một group sẽ ghi "Bắt đầu theo dõi" (baseline).
- Lọc theo firewall, group, loại (thêm/bớt/ngoài app), người thực hiện, khoảng ngày; ô tìm IP trả về toàn bộ lô có IP đó
  — trả lời nhanh câu hỏi "IP này bị chặn bởi ai, khi nào, vì sao, đã gỡ chưa".
- **Kiểm tra toàn vẹn log**: mỗi bản ghi chứa SHA-256 của bản ghi trước (hash chain); sửa/xóa trực tiếp trong DB sẽ bị phát hiện.
- **Xuất CSV** (UTF-8 BOM, giờ Việt Nam) để đính kèm báo cáo sự cố.

**Phân quyền** (theo App Role Entra hoặc cấu hình header):

| Vai trò | Xem group / log / lịch sử | Chặn, bỏ chặn, kiểm tra, đồng bộ | Thêm/sửa/xóa firewall |
|---|---|---|---|
| Chỉ xem (`SRB.Viewer`) | ✓ | — | — |
| Vận hành (`SRB.Operator`) | ✓ | ✓ | — |
| Quản trị (`SRB.Admin`) | ✓ | ✓ | ✓ |

**Tab Người dùng** (chỉ Quản trị viên) — quản lý tài khoản của app:

| Quyền | Xem group / lịch sử / audit | Chặn, bỏ chặn, kiểm tra, đồng bộ | Quản lý firewall + người dùng |
|---|---|---|---|
| Readonly | ✓ | — | — |
| Write | ✓ | ✓ | — |
| Write + Quản trị viên | ✓ | ✓ | ✓ |

- **Loại đăng nhập**: *Mật khẩu riêng* (tên + mật khẩu, băm PBKDF2-SHA256 310.000 vòng) hoặc *Microsoft (Entra ID)*
  (tên đăng nhập = UPN, đăng nhập qua MFA, app không giữ mật khẩu).
- Người dùng Microsoft có trong danh sách → dùng quyền đặt trong app; không có → dùng App Role Entra (hoặc bị từ chối nếu
  `USERS_STRICT=true`).
- Quyền được kiểm tra lại ở **mỗi request**: khóa, hạ quyền hay xóa người dùng có hiệu lực ngay, không chờ hết phiên.
- Chống tự khóa: không tự bỏ quyền quản trị / tự khóa / tự xóa chính mình; luôn phải còn ít nhất một Quản trị viên đang hoạt động.
- Mật khẩu chung `APP_PASSWORD` không dùng được để mạo danh tài khoản đã có trong danh sách. Sau khi đã tạo đủ tài khoản
  quản trị, nên đặt `SHARED_PASSWORD_LOGIN=false`.
- Mọi thao tác ghi audit `user_mgmt` (ai tạo/sửa/xóa ai, đổi gì), đăng nhập thành công/thất bại ghi audit `login`.

**Tab Audit log** — toàn bộ thao tác (ai, lúc nào, IP nào, firewall nào, kết quả, lý do), lọc + **Xuất CSV**.

### Cơ chế an toàn

**Hardening — group cố định `SCANPORT GROUP`** (từ v1.3.0):
- Tên group được **gắn cứng trong mã nguồn** (`backend/app/policy.py`), không đọc từ biến môi trường/ConfigMap, không nhận
  từ giao diện. Muốn đổi phải sửa mã, review, build lại image.
- Mọi API nhận tham số group (`/api/block`, `/api/unblock`, `/api/firewalls/*/group-members`, `/api/changes`,
  `/api/changes/sync`, tạo/sửa firewall) **từ chối HTTP 403** nếu group khác `SCANPORT GROUP` (so khớp chính xác,
  phân biệt hoa/thường) và ghi audit `policy_violation`.
- Lớp client Sophos kiểm tra lần nữa (phòng thủ nhiều lớp): chỉ `Set operation="update"` cho `SCANPORT GROUP`,
  không có hàm tạo group, chỉ xóa IP Host do app tạo (tên = địa chỉ thực của object, hoặc tiền tố cũ `SOC_BLOCK_`), chỉ liệt kê `SCANPORT GROUP`.
- Group không phải IPv4 trên firewall → từ chối, không ghi.

- Safe-list + chặn IP private (tùy chọn) để tránh tự khóa hệ thống.
- Tối đa 500 IP mỗi lần đẩy; hộp thoại xác nhận trước khi chặn/bỏ chặn.
- Mật khẩu firewall mã hóa AES-256-GCM, không bao giờ trả về client.
- Mọi thao tác đều được ghi audit kèm IP người thao tác; thay đổi thành viên group ghi vào lịch sử có hash chain.
- Đăng nhập Microsoft: Authorization Code + PKCE, kiểm tra chữ ký JWKS, issuer, audience, tenant, nonce, App Role.

---

## 5. Chưa gọi được API? Kiểm tra 3 điểm

1. **Đã bật API configuration** trên firewall chưa (lỗi `532`).
2. **IP máy chủ mini app** đã nằm trong Allowed IP list chưa (lỗi `534`).
3. **Cổng** có đúng cổng HTTPS Admin Console không (thường 4444, không phải 443) và tài khoản API có quyền
   Hosts and services không (lỗi `599`).

---

## 6. Phát triển & kiểm thử cục bộ

Có sẵn firewall giả lập để test không cần thiết bị thật:

```bash
python mock/mock_sophos.py --port 4444        # user apiadmin / Sophos@123

export MASTER_KEY=$(openssl rand -hex 32) APP_PASSWORD=socadmin \
       DATABASE_URL=sqlite:////tmp/sb.db
python -m uvicorn app.main:app --app-dir backend --port 8080
```

Thêm firewall `127.0.0.1:4444` trong tab Firewall để chạy thử toàn bộ luồng.
API docs: `http://localhost:8080/api/docs`.

Bộ kiểm thử hồi quy (mock firewall kiểm tra chặt thứ tự thẻ XML IPHostGroup):

```bash
bash tests/run_e2e.sh                              # SSO, RBAC, chặn/bỏ chặn, lịch sử thay đổi, hash chain
bash tests/run_e2e.sh tests/iphostgroup_test.py    # payload IPHostGroup + hardening SCANPORT GROUP
cd backend && PYTHONPATH=. python3 ../tests/sso_once_test.py && PYTHONPATH=. python3 ../tests/entra_review_test.py && cd ..   # SSO / Entra
bash tests/run_e2e.sh tests/users_test.py          # quản lý người dùng, quyền Write/Readonly, khóa/xóa tức thì
bash tests/run_e2e.sh tests/object_naming_test.py    # tên IP Host = IP/CIDR, tương thích object SOC_BLOCK_* cũ
cd backend && PYTHONPATH=. python3 ../tests/oidc_flow_test.py
```

---

## 7. Cấu trúc thư mục

```
backend/app/config.py    cấu hình từ biến môi trường
backend/app/crypto.py    mã hóa AES-256-GCM + token phiên HMAC (kèm vai trò)
backend/app/policy.py    chính sách hardening: group cố định SCANPORT GROUP
backend/app/users.py     quản lý người dùng: băm mật khẩu, quyền Write/Readonly, chống dò mật khẩu
backend/app/auth.py      đăng nhập Microsoft Entra ID (OIDC + PKCE) và header SSO App Proxy
backend/app/changelog.py lịch sử thay đổi group: hash chain, snapshot, phát hiện thay đổi ngoài app
backend/app/db.py        model Firewall, AuditLog, GroupChange, GroupSnapshot (SQLAlchemy)
backend/app/ipparse.py   bóc & kiểm tra IP/CIDR, safe-list
backend/app/sophos.py    client XML API Sophos
backend/app/service.py   luồng block/unblock/test + ghi audit
backend/app/main.py      REST API + phục vụ frontend tĩnh
frontend/                giao diện HTML5 (không framework)
mock/mock_sophos.py      firewall Sophos giả lập để kiểm thử
```

---

## 8. Nguồn tham khảo

- [Sophos Firewall API documentation](https://docs.sophos.com/nsg/sophos-firewall/22.0/api/apicontentpage.html)
- [Cấu hình API trên Sophos Firewall](https://docs.sophos.com/nsg/sophos-firewall/20.0/Help/en-us/webhelp/onlinehelp/AdministratorHelp/BackupAndFirmware/API/APIConfiguration/)
- [IPHost — Add/Edit](https://docs.sophos.com/nsg/sophos-firewall/22.0/api/system/host%20and%20services/iphost/operations/AddIPHost&EditIPHost.html)
- [IPHostGroup — Add/Edit](https://docs.sophos.com/nsg/sophos-firewall/22.0/api/SYSTEM/Host%20and%20Services/IPHostGroup/operations/AddIpHostGroup&EditIpHostGroup.html)
- [Bảo vệ truy cập API Sophos (Avanet)](https://www.avanet.com/en/kb/sophos-firewall-api-zugriff-absichern/)
- [Microsoft Entra Application Proxy — tổng quan](https://learn.microsoft.com/entra/identity/app-proxy/overview-what-is-app-proxy)
- [Header-based SSO với App Proxy](https://learn.microsoft.com/entra/identity/app-proxy/application-proxy-configure-single-sign-on-with-headers)
- [Bảo mật App Proxy](https://www.learn.microsoft.com/en-za/entra/identity/app-proxy/application-proxy-security)
