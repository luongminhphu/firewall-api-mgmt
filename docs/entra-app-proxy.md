# Truy cập SOC Rapid Block từ Internet qua Microsoft Entra Application Proxy + MFA

Mục tiêu: người trực SOC/NOC mở app từ laptop/điện thoại ở nhà (kể cả ngày lễ, Tết), đăng nhập bằng
tài khoản AD công ty + MFA, **mà không mở bất kỳ port inbound nào** trên firewall và không public app.

## 1. Kiến trúc

```
 Người trực (Internet)
        │ HTTPS  https://soc-rapid-block-<tenant>.msappproxy.net  (hoặc soc-block.hsc.com.vn)
        ▼
 ┌───────────────────────────────┐
 │ Microsoft Entra ID            │  ① Pre-authentication: đăng nhập AD
 │  + Conditional Access         │  ② Bắt buộc MFA, (tùy chọn) thiết bị compliant / quốc gia VN
 └──────────────┬────────────────┘
                ▼
 ┌───────────────────────────────┐
 │ Application Proxy (cloud MS)  │  chỉ chuyển request đã xác thực
 └──────────────┬────────────────┘
                ▲  kết nối OUTBOUND 443/80 do connector chủ động mở (không có inbound)
 ───────────────┼─────────────── Sophos Firewall biên ─────────────────────
                │
 ┌──────────────┴────────────────┐      HTTP nội bộ       ┌─────────────────────────┐
 │ Private Network Connector     │ ─────────────────────▶ │ KubeSphere NodePort     │
 │ (Windows Server trong LAN)    │  http://<node>:30988    │ soc-rapid-block :30988  │
 └───────────────────────────────┘                         └───────────┬─────────────┘
                                                                       ▼
                                                    ③ App tự xác thực lại bằng OIDC (token Entra,
                                                       kiểm tra chữ ký, tenant, App Role, nonce)
                                                    ④ Ghi audit + lịch sử thay đổi theo UPN thật
```

Lý do an toàn:

- Connector chỉ cần kết nối **outbound**, không phải mở port inbound hay đặt app vào DMZ
  ([Microsoft Learn — App Proxy overview](https://learn.microsoft.com/entra/identity/app-proxy/overview-what-is-app-proxy),
  [App Proxy security](https://www.learn.microsoft.com/en-za/entra/identity/app-proxy/application-proxy-security)).
- Với Pre-authentication = Microsoft Entra ID, request chưa đăng nhập bị chặn ngay ở cloud, chưa chạm tới mạng nội bộ.
- MFA được ép bằng Conditional Access gắn vào chính enterprise app này.
- App **không tin mù quáng** lớp ngoài: chế độ `oidc` tự xác minh id_token của Entra (chữ ký JWKS, `iss`,
  `aud`, `tid`, `nonce`, PKCE S256) và phân quyền theo App Role. Nếu ai đó vào thẳng NodePort trong LAN cũng
  vẫn phải đăng nhập Microsoft.

Yêu cầu license: Application Proxy cần Microsoft Entra ID P1 hoặc P2
([FAQ App Proxy](https://learn.microsoft.com/en-us/entra/identity/app-proxy/application-proxy-faq)) — M365 E3/E5/Business Premium đã bao gồm P1.

## 2. Chuẩn bị Connector (làm 1 lần)

1. Chuẩn bị 1–2 máy Windows Server 2016+ trong LAN (nên 2 máy để HA), truy cập được `http://<node-ip>:30988`.
2. Entra admin center → **Global Secure Access → Connect → Connectors** (hoặc Identity → Applications →
   Enterprise applications → Application proxy) → **Download connector service**, cài và đăng nhập bằng tài khoản
   Application Administrator.
3. Trên Sophos Firewall biên: cho phép connector đi **outbound TCP 443 và 80** tới các domain của Microsoft
   (`*.msappproxy.net`, `*.servicebus.windows.net`, `login.microsoftonline.com`, CRL/OCSP…) — danh sách đầy đủ
   theo [hướng dẫn cấu hình connector](https://www.learn.microsoft.com/da-dk/entra/global-secure-access/how-to-configure-connectors)
   và [connector qua proxy](https://learn.microsoft.com/en-us/entra/identity/app-proxy/application-proxy-configure-connectors-with-proxy-servers).
   **Không** mở bất kỳ rule inbound/NAT nào.
4. Gom connector vào 1 **Connector group** riêng, ví dụ `SOC-Tools`.

## 3. Publish app qua Application Proxy

Entra admin center → Enterprise applications → **New application → Add an on-premises application**:

| Trường | Giá trị |
| --- | --- |
| Name | `SOC Rapid Block` |
| Internal URL | `http://<IP node KubeSphere>:30988/` (nên dùng VIP/DNS nội bộ trỏ tới nhiều node) |
| External URL | `https://soc-rapid-block-<tenant>.msappproxy.net/` hoặc domain riêng `https://soc-block.hsc.com.vn/` (cần upload chứng chỉ) |
| Pre Authentication | **Microsoft Entra ID** (bắt buộc — không chọn Passthrough) |
| Connector Group | `SOC-Tools` |
| Translate URLs in headers | Yes (mặc định) |
| Translate URLs in application body | No |
| Backend application timeout | Default |

Sau đó: **Users and groups** → gán nhóm AD của SOC/NOC (ví dụ `GRP-SOC-Oncall`). Bật
**Assignment required = Yes** ở Properties để người ngoài nhóm không vào được.

## 4. Bắt buộc MFA bằng Conditional Access

Protection → Conditional Access → **New policy** `CA-SOC-RapidBlock-MFA`:

- Users: nhóm `GRP-SOC-Oncall` (loại trừ tài khoản break-glass).
- Target resources: app `SOC Rapid Block`.
- Conditions (khuyến nghị): Locations → chặn ngoài Việt Nam hoặc chỉ cho phép quốc gia cần thiết.
- Grant: **Require multifactor authentication** (hoặc Authentication strength = Phishing-resistant MFA),
  tùy chọn thêm **Require device to be marked as compliant**.
- Session: Sign-in frequency 8 giờ (khớp `SESSION_TTL_HOURS`).
- Bật policy ở chế độ **Report-only** 1–2 ngày, kiểm tra Sign-in logs rồi chuyển **On**.

## 5. Cho app tự xác thực bằng OIDC + App Role (khuyến nghị)

### 5.1 App registration

App registrations → chọn đúng app `SOC Rapid Block` vừa tạo ở bước 3 (App Proxy đã tự tạo registration), hoặc tạo mới:

1. **Authentication → Add a platform → Web**, Redirect URI:
   `https://<External URL>/api/auth/oidc/callback`
   (ví dụ `https://soc-rapid-block-hsc.msappproxy.net/api/auth/oidc/callback`). Không cần bật implicit/hybrid flow.
2. **Certificates & secrets → New client secret** (hạn 12 tháng, đặt lịch nhắc gia hạn). Copy *Value*.
3. **App roles → Create app role** (Allowed member types: Users/Groups):

   | Display name | Value | Quyền trong app |
   | --- | --- | --- |
   | SOC Rapid Block Admin | `SRB.Admin` | Toàn quyền: thêm/sửa/xóa firewall, chặn/bỏ chặn |
   | SOC Rapid Block Operator | `SRB.Operator` | Chặn/bỏ chặn IP, kiểm tra kết nối, đồng bộ lịch sử |
   | SOC Rapid Block Viewer | `SRB.Viewer` | Chỉ xem group, audit log, lịch sử thay đổi |

4. Enterprise applications → `SOC Rapid Block` → **Users and groups** → gán role cho từng nhóm
   (ví dụ `GRP-SOC-Oncall` = Operator, `GRP-Infra-Admin` = Admin). Người không có role sẽ bị từ chối đăng nhập.
5. Ghi lại **Directory (tenant) ID** và **Application (client) ID** ở trang Overview.

### 5.2 Cấu hình trên cluster (overlay `prod`, từ v1.5.1)

Cấu hình riêng của site nằm trong `deploy/k8s/overlays/prod/local-config.yaml` — file này **không có trong Git**, nên
`git pull` + `kubectl apply` không còn ghi đè `AUTH_MODES` về `local` như khi apply thẳng `base/`.

```bash
cd ~/firewall-api-mgmt
NS=sophos-blocker
# 1) Client secret vào Secret hiện có (giữ nguyên các khóa khác)
kubectl -n $NS patch secret soc-rapid-block-secrets --type merge \
  -p '{"stringData":{"OIDC_CLIENT_SECRET":"<client-secret-value>"}}'

# 2) Cấu hình site (làm 1 lần), điền tenant ID, client ID, External URL
cp deploy/k8s/overlays/prod/local-config.example.yaml deploy/k8s/overlays/prod/local-config.yaml
vi deploy/k8s/overlays/prod/local-config.yaml

# 3) Triển khai / nâng cấp từ nay luôn dùng overlay
kubectl apply -k deploy/k8s/overlays/prod/
kubectl -n $NS rollout restart deploy/soc-rapid-block-app
```

### 5.3 SSO đúng một lần, đúng tài khoản

Luồng khi đã cấu hình đúng:

```
Mở External URL ─▶ App Proxy pre-auth (đăng nhập + MFA — lần DUY NHẤT)
                ─▶ app chưa có phiên ─▶ tự chuyển /api/auth/oidc/login (không prompt, có login_hint/domain_hint)
                ─▶ Entra thấy phiên vừa đăng nhập ─▶ trả code ngay, không hỏi gì ─▶ app xác minh id_token
                ─▶ ghép UPN với tab Người dùng ─▶ vào thẳng màn hình chính, đúng quyền Write/Readonly
```

Điều kiện để không bị hỏi lần hai:

1. **Dùng chính app registration mà App Proxy đã tạo** (cùng Client ID với enterprise app đang publish) cho OIDC.
   Conditional Access/MFA áp lên một app duy nhất; phiên Entra từ bước pre-auth được dùng lại.
2. `OIDC_PROMPT` để trống (mặc định). `select_account` buộc hiện bảng chọn tài khoản, `login` buộc nhập lại mật khẩu
   ([Microsoft Learn — tham số prompt](https://learn.microsoft.com/en-us/entra/identity-platform/v2-protocols-oidc)).
3. App gửi `login_hint` = UPN lần đăng nhập trước và `domain_hint` → Entra chọn đúng tài khoản khi trình duyệt có nhiều
   tài khoản Microsoft.

Đảm bảo **đúng tài khoản được phân quyền**:

- Enterprise app → **Properties → Assignment required = Yes**, chỉ gán nhóm SOC/Infra → người ngoài danh sách bị chặn ngay
  ở App Proxy.
- Tab **Người dùng**: thêm từng người với loại **Microsoft (Entra ID)**, tên đăng nhập = UPN (vd `phu.luong@hsc.com.vn`),
  chọn Write/Readonly. Đặt `USERS_STRICT=true` để chỉ người có trong danh sách mới vào app (App Role không còn đủ).
- `OIDC_REQUIRE_MFA_CLAIM=true` → app từ chối token không có MFA.
- Nút **Thoát** chỉ thoát app; app không tự đăng nhập lại cho tới khi bấm nút Microsoft (tránh vòng lặp trên máy dùng chung).
  Muốn thoát hẳn Microsoft: đóng trình duyệt hoặc đăng xuất tại myaccount.microsoft.com.
- Đăng nhập mật khẩu chỉ còn là liên kết nhỏ "Đăng nhập bằng mật khẩu (khẩn cấp)"; khi ổn định đặt `AUTH_MODES=oidc`
  hoặc `SHARED_PASSWORD_LOGIN=false`.

Pod app cần đi ra `https://login.microsoftonline.com` (lấy JWKS và đổi code lấy token). Nếu cluster bắt buộc
egress qua proxy, đặt thêm biến `HTTPS_PROXY`/`NO_PROXY` cho Deployment.

Kiểm tra: mở External URL bằng cửa sổ ẩn danh → Microsoft đăng nhập + MFA **một lần** → app hiện "Đang đăng nhập bằng
tài khoản Microsoft…" trong tích tắc → vào thẳng màn hình chính, góc phải hiện UPN + quyền. Khi đã chạy ổn định, đổi `AUTH_MODES` thành `oidc` để **tắt hẳn mật khẩu chung**.

> Nếu tenant dùng MFA qua Conditional Access, claim `amr` thường đã có `mfa`; có thể bật
> `OIDC_REQUIRE_MFA_CLAIM=true` để app từ chối token không có MFA (phòng trường hợp CA bị tắt nhầm).

## 6. Phương án thay thế: Header-based SSO

Nếu không muốn tạo client secret, có thể để App Proxy gắn header danh tính
([Microsoft Learn — header-based SSO](https://learn.microsoft.com/entra/identity/app-proxy/application-proxy-configure-single-sign-on-with-headers)):

1. Enterprise app → **Single sign-on → Header-based** → thêm header:
   - `X-SRB-UPN` = `user.userprincipalname`
   - `X-SRB-NAME` = `user.displayname`
2. ConfigMap: `AUTH_MODES=header`, `TRUSTED_PROXY_CIDRS=<IP connector>/32,...`,
   `HEADER_ADMINS=...`, `HEADER_OPERATORS=...` (danh sách UPN, phân cách dấu phẩy), `HEADER_DEFAULT_ROLE=viewer`.
3. App chỉ tin header khi **IP TCP thực** của kết nối nằm trong `TRUSTED_PROXY_CIDRS`. NodePort mặc định
   (`externalTrafficPolicy: Cluster`) sẽ SNAT địa chỉ nguồn thành IP node → cần đặt
   `externalTrafficPolicy: Local` cho Service và trỏ Internal URL vào đúng node có pod, nếu không header SSO sẽ bị từ chối.

Vì ràng buộc mạng trên và vì header có thể bị giả nếu cấu hình sai CIDR, **khuyến nghị dùng chế độ `oidc`**.

## 7. Siết mạng nội bộ (khuyến nghị)

- Trên Sophos Firewall nội bộ: chỉ cho phép `connector IPs` và dải máy SOC trong LAN truy cập `node:30988`.
- Hoặc dùng Calico NetworkPolicy `ipBlock` cho pod app (cần `externalTrafficPolicy: Local` để giữ IP nguồn).
- Không tạo NAT/Virtual host public cho port 30988.

## 8. Checklist go-live

- [ ] Connector Active (2 máy), outbound 443/80 OK, không có rule inbound.
- [ ] Enterprise app: Pre-auth = Entra ID, Assignment required = Yes, đã gán nhóm.
- [ ] Conditional Access MFA = On, đã test bằng 1 tài khoản ngoài mạng công ty (4G).
- [ ] App roles đã gán; tài khoản không có role bị từ chối với thông báo tiếng Việt.
- [ ] `AUTH_MODES=oidc` (đã tắt mật khẩu chung), client secret có lịch gia hạn.
- [ ] Tab **Lịch sử thay đổi** hiển thị đúng UPN người thao tác; nút **Kiểm tra toàn vẹn log** báo khớp.
