# SOC Rapid Block — quản lý chặn IP & quyền VPN trên nhiều Sophos Firewall

Mini app HTML5 + FastAPI cho team SOC/NOC/Infra:

- **Chặn IP nhanh.** Dán thẳng đoạn chat Teams (hoặc CSV, hoặc nhập tay). App tự bóc IP rồi đẩy vào IP Host Group
  `SCANPORT GROUP` trên **nhiều Sophos Firewall cùng lúc** qua XML API. Dùng được trên điện thoại.
- **Tự động chặn ban đêm từ Teams.** App đọc group chat với SOC. Khi SOC gửi `ĐỀ XUẤT CỦA SOC: BLOCK IP <ip>`, app tự chặn
  IP đó, có whitelist, giới hạn số lượng và công tắc khẩn cấp, rồi trả lời `INFRA ĐÃ BLOCK <ip> THEO YÊU CẦU LÚC <thời điểm>`.
- **Theo dõi quyền VPN (chỉ đọc).** Theo dõi tài khoản VPN và thời hạn truy cập (firewall rule trong Rule Group `VPN`),
  nhắc hạn qua email, và **rà soát quyền định kỳ theo ISO/IEC 27001**. App **không bao giờ sửa** rule hay user trên firewall.

Phiên bản hiện tại: **v2.2.0**. Lịch sử thay đổi ở [mục 9](#9-lịch-sử-phiên-bản); thiết kế chi tiết ở [`docs/architecture.md`](docs/architecture.md).

**Mục lục**

1. [Tính năng](#1-tính-năng)
2. [Kiến trúc](#2-kiến-trúc)
3. [Chuẩn bị phía firewall](#3-chuẩn-bị-phía-firewall-làm-1-lần-cho-mỗi-firewall)
4. [Cài đặt](#4-cài-đặt): [Docker Compose](#41-docker-compose) · [**Rancher (RKE2 / K3s)**](#42-rancher-rke2--k3s) · [KubeSphere](#43-kubesphere) · [Biến môi trường](#44-biến-môi-trường)
5. [Hướng dẫn sử dụng](#5-hướng-dẫn-sử-dụng)
6. [Phân quyền & cơ chế an toàn](#6-phân-quyền--cơ-chế-an-toàn)
7. [Xử lý sự cố](#7-xử-lý-sự-cố)
8. [Phát triển & kiểm thử](#8-phát-triển--kiểm-thử)
9. [Lịch sử phiên bản](#9-lịch-sử-phiên-bản)
10. [Nguồn tham khảo](#10-nguồn-tham-khảo)

---

## 1. Tính năng

| Nhóm | Tính năng |
|---|---|
| **Chặn IP** | Bóc IPv4/CIDR từ chat Teams, kể cả dạng làm mờ (`1.2.3[.]4`, `1.2.3(.)4`, `1.2.3[dot]4`), từ CSV/TXT kéo-thả, hoặc nhập tay · Chặn trên nhiều firewall cùng lúc · Chạy thử (dry-run) và xem trước XML · Safe-list và chặn IP private để tránh tự khóa · Tối đa 500 IP/lần |
| **Tự động chặn từ Teams** | Đọc group chat qua Microsoft Graph theo chu kỳ (mặc định 5 phút, chỉnh trên giao diện) · Chỉ nhận đúng dòng `ĐỀ XUẤT CỦA SOC: BLOCK IP <ip>` (IN HOA) của **tài khoản SOC** trong danh sách; **tin đã sửa bị bỏ qua** · **Whitelist** HSC / Akamai / Đối tác → chờ quản trị viên **Approve** · Khung giờ tự chặn (mặc định 18:00–08:00) · Tối đa **20 IP/giờ**, vượt thì ngắt, chuyển chờ duyệt và báo nhóm Admin · **Công tắc tắt khẩn cấp** · Danh sách **ca đêm** + gỡ một chạm · Trả lời kết quả vào group chat |
| **Không còn lỗi 504** | Mỗi firewall chỉ cần 3 lệnh trên 1 kết nối, nhờ gộp lệnh tạo IP Host · Các firewall chạy song song · Quá `JOB_SYNC_WAIT` giây thì chuyển sang **công việc nền**, giao diện hiện tiến độ từng firewall |
| **IP Host Group** | Xem thành viên `SCANPORT GROUP` tức thì từ cache trong PostgreSQL · Quét lại nền · Bỏ chặn và xóa IP Host do app tạo |
| **Báo cáo** | Thống kê IP bị chặn theo **phương thức** (thủ công / tự động) và **thời gian thực hiện**, kỳ 7 / 14 / 30 ngày hoặc **chọn trên lịch** · **Executive Summary** (tổng quan, nhận định, cần lưu ý) rồi tới chi tiết · xuất **PDF** (A4, theo HSC Design System: font Inter, màu HSC, logo ở header) và **Excel** (nhiều sheet, lọc được) · **gửi email** qua SMTP đã cấu hình |
| **Lịch sử thay đổi** | Ghi từng IP thêm/bớt (ai, lúc nào, lý do/ticket, số object trước → sau) · **Phát hiện sửa trực tiếp trên WebAdmin** · Chuỗi băm SHA-256 chống sửa log · Xuất CSV |
| **VPN — tài khoản** | Danh sách tài khoản có quyền SSL VPN / IPsec remote access trên từng firewall (nhóm, trạng thái khóa). Tài khoản đã bị xóa khỏi firewall vẫn được giữ lại để rà soát · Đồng bộ định kỳ và đồng bộ tay |
| **VPN — thời hạn** | Đọc rule trong Rule Group `VPN`. Lấy hạn từ Schedule (OneTime), nếu không có thì bóc từ tên rule · Dashboard: *Sắp hết hạn, Hết hạn nhưng vẫn bật, User không còn / bị khóa, Không đọc được tên, Lệch thời hạn, Không có hạn, Còn hạn* · Lịch sử thay đổi rule nối chuỗi băm · **CSV danh sách cần xử lý** |
| **Thông báo email** | Cấu hình **SMTP trên giao diện** (STARTTLS / SSL / relay) · Nhắc trước hạn (mặc định 30/14/7/1 ngày) tới đại diện team + Infra · Báo Infra hằng tuần các rule đã hết hạn mà vẫn bật · Outbox chống gửi trùng, tự thử lại khi gửi lỗi |
| **Rà soát ISO 27001** | Đợt rà soát **hằng quý** (tự mở hoặc mở tay) gồm rule VPN và tài khoản mồ côi · **Đại diện team** quyết định *Còn cần / Thu hồi / Cần điều chỉnh* · Nhật ký quyết định nối chuỗi băm · **CSV bằng chứng** cho auditor + **CSV cần thu hồi** cho Infra |
| **Đăng nhập & quyền** | Microsoft Entra ID (OIDC + PKCE, MFA qua Conditional Access, SSO một lần qua App Proxy) · Header SSO · Tài khoản riêng · Vai trò *Rà soát / Readonly / Write / Quản trị viên* |
| **Giao diện** | Console vận hành kiểu Data-Dense Dashboard: menu trái theo nhóm (ngăn kéo trên điện thoại) · bảng / thẻ cân cột, chữ số đều độ rộng · tối / sáng · Fira Sans + Fira Code tự host · **tooltip ⓘ hướng dẫn** ở mọi mục cấu hình · logo tùy chỉnh |
| **Vận hành** | Audit log đầy đủ · Log JSON có `request_id` · Khóa phân tán `pg_advisory_lock` (nhiều pod không chạy trùng) |

---

## 2. Kiến trúc

```
Trình duyệt (HTML5, mobile-friendly)
        │  REST /api/*   (qua Entra App Proxy / Ingress / NodePort)
        ▼
FastAPI backend ──► PostgreSQL 16 (firewall + credential mã hóa AES-256-GCM, audit, lịch sử,
        │                          cache group, dữ liệu VPN, outbox email, rà soát)
        ├──► SMTP (thông báo)
        │  HTTPS POST reqxml=<Request>…</Request>
        ▼
https://<firewall>:4444/webconsole/APIController   (Sophos Firewall XML API, SFOS 22)
```

Trình duyệt **không** gọi thẳng firewall được (CORS và chứng chỉ self-signed). Vì vậy backend đóng vai proxy, đồng thời
là nơi giữ credential và ghi audit. Mọi lệnh XML gửi lên firewall đều phải qua **một điểm kiểm soát duy nhất**,
`integrations/sophos/policy.py`. Ngoài các thao tác dưới đây, mọi lệnh ghi đều bị chặn và ghi audit `policy_violation`:

- ghi IP Host;
- ghi `SCANPORT GROUP`;
- chỉ đọc (`Get`) đối với User / Group / FirewallRule / VPN.

**Cách chặn:** với mỗi IP/CIDR, app tạo một **IP Host** có tên chính là địa chỉ đó (vd `45.138.12.16`,
`185.220.101.0/24`), rồi ghi lại toàn bộ `<HostList>` của group trong **một** lệnh. Lý do: Sophos không hỗ trợ thêm/bớt
từng phần tử của IPHostGroup ([tài liệu IPHostGroup](https://docs.sophos.com/nsg/sophos-firewall/22.0/api/SYSTEM/Host%20and%20Services/IPHostGroup/operations/AddIpHostGroup&EditIpHostGroup.html)).

```
backend/app/
  main.py                 tạo app, lifespan (bộ lập lịch), middleware, mount router, phục vụ frontend
  core/                   config, db + models, security, audit, hashchain, jobs (công việc nền + khóa + lập lịch),
                          errors, logging
  auth/                   rbac (vai trò), router (đăng nhập), oidc (Entra), header_sso, users/
  integrations/sophos/    client XML API, xmlutil, naming, sanitize (lọc trường bí mật),
                          entities/ (iphost, iphostgroup, vpn), policy.py
  modules/
    firewalls/  ipblock/  audit/  branding/
    vpn/        accounts, expiry (bóc hạn), rules, sync, settings
    notify/     smtp, planner (lập kế hoạch nhắc), outbox (hàng đợi gửi)
    review/     đợt rà soát, quyết định, CSV bằng chứng
    autoblock/  đọc group chat Teams (graph), parser cú pháp, quyết định tự chặn / chờ duyệt, reply (Teams Workflows)
    reports/    số liệu báo cáo (data), Executive Summary, PDF (reportlab), Excel (openpyxl), logo, font Inter nhúng
frontend/                 ES module thuần, không build: js/main.js + js/pages/* (từng tab) + js/components/*
                          (tips.js: nội dung tooltip hướng dẫn) · theme.css (token màu) · styles.css · fonts.css
deploy/k8s/               base/ · overlays/prod/ · overlays/rancher/ · kubesphere/
mock/                     firewall Sophos giả lập (kèm dữ liệu VPN) + SMTP giả lập + Microsoft Graph / Workflows giả lập
tools/sophos_sample.py    lấy mẫu cấu hình VPN thật (chỉ đọc, che dữ liệu)
```

---

## 3. Chuẩn bị phía firewall (làm 1 lần cho mỗi firewall)

Các bước dưới đây theo [hướng dẫn cấu hình API của Sophos](https://docs.sophos.com/nsg/sophos-firewall/20.0/Help/en-us/webhelp/onlinehelp/AdministratorHelp/BackupAndFirmware/API/APIConfiguration/):

1. **Bật API.** Vào `System ▸ Backup & firmware ▸ API` và tick **Enable API configuration**.
2. **Allowed IP.** Thêm IP mà app dùng để đi ra firewall vào danh sách Allowed IP. Nếu thiếu, API trả mã **534**.
   - Trên Kubernetes, đó là IP của **node** nơi pod chạy (SNAT), hoặc IP egress/NAT của cụm.
   - Nếu không cố định được node, khai báo IP của tất cả các node.
3. **Tài khoản API.** Tạo admin riêng (vd `apiadmin`) với profile tối thiểu:
   - **Hosts and services:** đọc + ghi (để chặn/bỏ chặn).
   - **Firewall rules, Users/Authentication, Schedule, VPN:** **chỉ đọc** (chỉ cần nếu dùng module VPN).
   - Không cấp quyền network, system hay ghi rule.
   - Nên giới hạn login theo IP ([khuyến nghị hardening](https://www.avanet.com/en/kb/sophos-firewall-api-zugriff-absichern/)).
4. **Cổng.** Cổng XML API trùng cổng HTTPS của Admin Console (`System ▸ Administration ▸ Admin settings`), mặc định **4444**.
5. **Group và rule chặn.**
   - Tạo IP Host Group tên chính xác **`SCANPORT GROUP`** (IP version **IPv4**).
   - Tạo **firewall rule Drop**: Source zone WAN, Source networks = group đó, đặt **lên trên cùng**.
   - App chỉ đổ IP vào group này; nếu không có rule thì IP vẫn không bị chặn.
   - App **không tự tạo group**. Nếu thiếu group, app báo lỗi rõ ràng.
6. **Rule VPN** (nếu dùng module VPN). Đặt các rule cấp quyền VPN trong Rule Group **`VPN`**. Hạn truy cập được đọc theo thứ tự:
   - ngày kết thúc của **Schedule OneTime** gắn với rule;
   - nếu không có Schedule, ngày `dd/mm/yyyy` trong **tên rule** (vd `RMS RESEARCH - NHAN.NDT 30/06/2027`, `THAM.NQ expire 23/04/2027`).

Mã trạng thái hay gặp: `200/202` OK · `502` object trùng tên · `503` trùng tham số · `526` không tồn tại ·
`532` chưa bật API · `534` IP nguồn chưa được cho phép · `599` thiếu quyền.

---

## 4. Cài đặt

Image dựng sẵn được GitHub Actions đẩy lên `ghcr.io/luongminhphu/firewall-api-mgmt` (chỉ `linux/amd64`). Các tag:

- `latest` và `main`: mỗi lần push lên main;
- `2.2.0` và `2.2`: khi gắn tag `v2.2.0`;
- `sha-xxxxxxx`: theo commit.

Bảng trong app tự tạo khi khởi động, nên **không cần chạy migrate**.

> **`MASTER_KEY`** mã hóa mật khẩu firewall và mật khẩu SMTP trong DB. Mất key thì phải nhập lại toàn bộ mật khẩu.
> Sao lưu key ở nơi an toàn (KeePass/Vault) và **không commit** key vào Git.

### 4.1 Docker Compose

Dùng cho một máy chủ đơn, đơn giản nhất.

```bash
git clone https://github.com/luongminhphu/firewall-api-mgmt.git sophos-blocker && cd sophos-blocker
cp .env.example .env
openssl rand -hex 32   # dán vào MASTER_KEY
openssl rand -hex 32   # dán vào SESSION_SECRET
# đổi APP_PASSWORD và POSTGRES_PASSWORD trong .env
docker compose up -d --build
docker compose logs -f app
```

Mở `http://<ip-server>:8080` và đăng nhập bằng `APP_PASSWORD`. Bước tiếp theo: [5. Hướng dẫn sử dụng](#5-hướng-dẫn-sử-dụng).

### 4.2 Rancher (RKE2 / K3s)

Phần này áp dụng cho cụm do Rancher quản lý (RKE2 khuyến nghị, hoặc K3s). Manifest dùng Kustomize theo ba lớp:

| Thư mục | Nội dung |
|---|---|
| `deploy/k8s/base/` | Namespace `sophos-blocker` · ConfigMap · PostgreSQL 16 StatefulSet + PVC 5Gi · Deployment app (1 replica, `runAsNonRoot`) · Service NodePort `30988` · NetworkPolicy (DB chỉ nhận kết nối từ app) |
| `deploy/k8s/overlays/prod/` | Cấu hình riêng của site (Entra, quản lý người dùng…) trong `local-config.yaml`. File này **không có trong Git**, nên `git pull` không ghi đè |
| `deploy/k8s/overlays/rancher/` | Dựng trên `prod`, thêm **Ingress** (ingress-nginx), mẫu gắn **Rancher Project**, ghim tag image, và NetworkPolicy egress (tùy chọn) |

#### Bước 0 — Yêu cầu

- Cụm RKE2/K3s đã import vào Rancher, có **StorageClass** cho PVC của Postgres. RKE2 + Longhorn là mặc định của manifest;
  K3s thường dùng `local-path`.
- Có `kubectl` trỏ vào cụm: Rancher UI ▸ cluster ▸ **Download KubeConfig** (hoặc **Kubectl Shell** ngay trên trình duyệt),
  rồi `export KUBECONFIG=~/Downloads/<cluster>.yaml`. `kubectl` từ 1.21 trở lên đã có sẵn `-k` (Kustomize).
- Node ra được firewall qua cổng `4444`, ra máy chủ SMTP, và ra `login.microsoftonline.com:443` nếu dùng Entra.

#### Bước 1 — Lấy mã nguồn và chọn StorageClass

```bash
git clone https://github.com/luongminhphu/firewall-api-mgmt.git && cd firewall-api-mgmt
kubectl get storageclass
```

Sửa `storageClassName` trong `deploy/k8s/base/postgres.yaml` (mặc định `longhorn`) cho khớp với cụm, vd `local-path` trên K3s.
**Phải sửa trước lần cài đầu tiên**, vì `volumeClaimTemplates` của StatefulSet không sửa được sau khi đã tạo.

#### Bước 2 — Namespace và imagePullSecret (nếu package GHCR để private)

```bash
kubectl create namespace sophos-blocker
```

```bash
kubectl -n sophos-blocker create secret docker-registry ghcr-pull \
  --docker-server=ghcr.io --docker-username=<github-user> \
  --docker-password=<PAT có quyền read:packages>
```

Package để public thì bỏ qua lệnh thứ hai. Deployment vẫn khai báo `ghcr-pull`; secret không tồn tại chỉ sinh cảnh báo,
không làm hỏng việc pull image.

Có thể làm bằng giao diện thay cho dòng lệnh:

- **Namespace:** Rancher UI ▸ cluster ▸ **Projects/Namespaces** ▸ *Create Namespace* trong project mong muốn.
- **Registry secret:** **Storage ▸ Secrets ▸ Create ▸ Registry**, chọn namespace `sophos-blocker`, đặt tên `ghcr-pull`.

#### Bước 3 — Secret của app (không commit)

```bash
kubectl -n sophos-blocker create secret generic soc-rapid-block-secrets \
  --from-literal=MASTER_KEY=$(openssl rand -hex 32) \
  --from-literal=SESSION_SECRET=$(openssl rand -hex 32) \
  --from-literal=APP_PASSWORD='DoiMatKhauNay@2026' \
  --from-literal=POSTGRES_PASSWORD=$(openssl rand -hex 24) \
  --from-literal=OIDC_CLIENT_SECRET='<client-secret-Entra>' \
  --dry-run=client -o yaml | kubectl apply -f -
```

Sau khi tạo, lưu lại `MASTER_KEY` bằng lệnh dưới. **Không đổi `POSTGRES_PASSWORD`** sau khi DB đã khởi tạo, vì Postgres
chỉ đọc biến này ở lần chạy đầu tiên.

```bash
kubectl -n sophos-blocker get secret soc-rapid-block-secrets -o jsonpath='{.data.MASTER_KEY}' | base64 -d
```

#### Bước 4 — Cấu hình site

```bash
cp deploy/k8s/overlays/prod/local-config.example.yaml deploy/k8s/overlays/prod/local-config.yaml
```

Sửa `local-config.yaml`; file chỉ cần chứa các khóa khác với `base/configmap.yaml`. Các khóa thường cần chỉnh:

- `AUTH_MODES`;
- `OIDC_TENANT_ID` / `OIDC_CLIENT_ID` / `OIDC_REDIRECT_URI` (= `<URL ngoài>/api/auth/oidc/callback`);
- `APP_BASE_URL` (URL người dùng mở, dùng làm link trong email);
- `SAFE_LIST` (bổ sung dải văn phòng, VPN, đối tác).

Chưa dùng Entra thì đặt `AUTH_MODES: "local"`.

#### Bước 5 — Ingress và Project (overlay `rancher`)

Sửa `deploy/k8s/overlays/rancher/ingress.yaml`:

- **`host`:** tên miền nội bộ, hoặc tên miền mà Entra App Proxy connector trỏ tới.
- **TLS:** cert-manager, hoặc tạo bằng `kubectl -n sophos-blocker create secret tls soc-rapid-block-tls --cert=… --key=…`.
- **Timeout:** đã đặt `proxy-read-timeout` / `proxy-send-timeout` = 120s. Giá trị này phải **lớn hơn** `JOB_SYNC_WAIT` (20s)
  và `GROUP_CACHE_REFRESH_WAIT` (8s); nếu nhỏ hơn, request chặn IP sẽ bị ingress cắt thành 504.
- **Kích thước body:** `proxy-body-size` = 5m, để tải được logo và file CSV.

Trong `deploy/k8s/overlays/rancher/kustomization.yaml`, bỏ comment các khối cần dùng:

- **Gắn Project:** điền `field.cattle.io/projectId: "c-xxxxx:p-yyyyy"` để namespace nằm trong project Rancher, hưởng quyền
  và quota của project. Lấy ID ở Rancher UI ▸ Projects/Namespaces ▸ ⋮ của project ▸ *View in API*.
- **Ghim tag image:** `ghcr.io/luongminhphu/firewall-api-mgmt:2.2.0`, thay cho `latest`. Khuyến nghị cho môi trường thật.
- **`networkpolicy-egress.yaml`:** chỉ bật **sau khi** đã sửa CIDR của firewall và SMTP trong file. Có tác dụng với CNI
  Canal/Calico/Cilium (RKE2 mặc định dùng Canal).

> **K3s dùng Traefik** thay cho ingress-nginx. Đổi `ingressClassName: traefik` và bỏ các annotation `nginx.ingress…`.
> Timeout đọc mặc định của Traefik v3 là 60s, vẫn lớn hơn `JOB_SYNC_WAIT`.
> Không muốn dùng Ingress thì xóa `ingress.yaml` khỏi kustomization và truy cập qua NodePort `30988`.

#### Bước 6 — Triển khai

```bash
kubectl kustomize deploy/k8s/overlays/rancher/ | less          # xem trước manifest
kubectl apply -k deploy/k8s/overlays/rancher/
kubectl -n sophos-blocker rollout status statefulset/soc-rapid-block-db
kubectl -n sophos-blocker rollout status deployment/soc-rapid-block-app
kubectl -n sophos-blocker get pods,svc,ingress,pvc
```

Kiểm tra:

- Mở `https://<host>` (qua Ingress) hoặc `http://<node-ip>:30988` (qua NodePort).
- `curl -s https://<host>/api/health` phải trả `{"status": "ok", …, "version": "2.1.0"}`.
- Đăng nhập bằng `APP_PASSWORD`, rồi tạo ngay tài khoản Quản trị viên trong tab **Người dùng**.

Có thể làm bằng giao diện thay cho dòng lệnh: Rancher UI ▸ cluster ▸ **Import YAML** (nút ⬆ trên thanh trên cùng).
Dán kết quả của `kubectl kustomize deploy/k8s/overlays/rancher/`, chọn namespace mặc định `sophos-blocker`, bấm *Import*.
Theo dõi pod ở **Workloads ▸ Deployments / StatefulSets**; xem log bằng ⋮ ▸ *View Logs*.

#### Bước 7 — Truy cập từ Internet (Entra Application Proxy + MFA)

Cài connector trong mạng nội bộ. Internal URL trỏ tới host của Ingress, hoặc `http://<node-ip>:30988`.
Các bước chi tiết ở [`docs/entra-app-proxy.md`](docs/entra-app-proxy.md). Lưu ý:

- **Timeout:** timeout back-end của App Proxy khoảng 85s, vẫn lớn hơn `JOB_SYNC_WAIT`. Không cần chỉnh.
- **Header SSO** (`AUTH_MODES` có `header`): `TRUSTED_PROXY_CIDRS` phải khai báo IP mà **app nhìn thấy**.
  - Đi qua Ingress: đó là IP pod của ingress-nginx, tức dải pod CIDR của cụm.
  - Đi qua NodePort: là IP node.
  - Vì vậy, với Kubernetes nên dùng `oidc`.

#### Vận hành trên Rancher

| Việc | Lệnh / thao tác |
|---|---|
| **Nâng cấp** | Đổi tag image trong overlay, rồi chạy lại `kubectl apply -k deploy/k8s/overlays/rancher/`. Nếu vẫn dùng `latest`: `kubectl -n sophos-blocker rollout restart deploy/soc-rapid-block-app` (`imagePullPolicy: Always`). Hoặc trên UI: Deployment ▸ ⋮ ▸ *Redeploy* |
| **Rollback** | `kubectl -n sophos-blocker rollout undo deploy/soc-rapid-block-app`, hoặc ghim lại tag cũ. Schema chỉ **thêm** bảng/cột, nên bản cũ vẫn chạy được trên DB mới |
| **Xem log** | `kubectl -n sophos-blocker logs deploy/soc-rapid-block-app -f`. Đặt `LOG_FORMAT=json` để đẩy vào Loki/ELK qua Rancher Logging |
| **Số replica** | Giữ `replicas: 1` là đủ. Chạy 2 replica cũng an toàn: các bộ lập lịch (đồng bộ VPN, email, rà soát, cache) dùng `pg_advisory_lock`, nên mỗi vòng chỉ một pod chạy. **Postgres luôn 1 replica** |
| **Sao lưu DB** | `kubectl -n sophos-blocker exec soc-rapid-block-db-0 -- pg_dump -U sophos -Fc sophos_blocker > srb-$(date +%F).dump`. Nên kết hợp snapshot/backup Longhorn của PVC `pgdata-soc-rapid-block-db-0` |
| **Khôi phục** | `kubectl -n sophos-blocker exec -i soc-rapid-block-db-0 -- pg_restore -U sophos -d sophos_blocker --clean < srb-….dump`, với **cùng `MASTER_KEY`** |
| **GitOps (Fleet)** | Rancher ▸ **Continuous Delivery** ▸ Git Repos ▸ Add, path `deploy/k8s/overlays/rancher`. Vì `local-config.yaml` không có trong Git, hãy dùng repo/nhánh cấu hình riêng của site, hoặc tạo ConfigMap patch thủ công |
| **Gỡ cài đặt** | `kubectl delete -k deploy/k8s/overlays/rancher/`. PVC không tự xóa; xóa hẳn dữ liệu bằng `kubectl -n sophos-blocker delete pvc -l app.kubernetes.io/name=soc-rapid-block-db` |

> **Pod Security Admission (PSA).** Nếu cụm áp mức `restricted` cho mọi namespace, gắn nhãn namespace ở mức `baseline`:
> `kubectl label ns sophos-blocker pod-security.kubernetes.io/enforce=baseline`. Lý do: Postgres chạy bằng user của image,
> và cả hai pod chưa khai báo `seccompProfile`. Pod app đã chạy non-root và `drop: ALL`.

### 4.3 KubeSphere

Dùng chung manifest `base/` và `overlays/prod/`. Hướng dẫn riêng (import qua UI KubeSphere, workspace `soc`) ở
[`deploy/k8s/kubesphere/README.md`](deploy/k8s/kubesphere/README.md). Lệnh triển khai: `kubectl apply -k deploy/k8s/overlays/prod/`.

### 4.4 Biến môi trường

Đặt trong `.env` (Compose) hoặc trong ConfigMap / `local-config.yaml` / Secret (Kubernetes). Những mục có ghi *tab Cài đặt*
chỉ là giá trị ban đầu; quản trị viên chỉnh lại trên giao diện.

| Biến | Ý nghĩa |
|---|---|
| `MASTER_KEY` | Khóa mã hóa credential firewall/SMTP (bắt buộc, ≥16 ký tự). **Secret** |
| `APP_PASSWORD` | Mật khẩu chung để đăng nhập lần đầu / khẩn cấp. **Secret** |
| `SESSION_SECRET` | Khóa ký phiên; để trống thì mỗi lần restart sinh khóa mới (mọi người phải đăng nhập lại). **Secret** |
| `POSTGRES_PASSWORD` / `OIDC_CLIENT_SECRET` | Mật khẩu DB / client secret của Entra. **Secret** |
| `DATABASE_URL` | Chuỗi kết nối PostgreSQL (manifest k8s đã tự ghép) |
| `SESSION_TTL_HOURS` | Thời hạn phiên (mặc định 8 giờ) |
| `APP_BASE_URL` | Địa chỉ app mà người dùng mở (qua App Proxy/Ingress), dùng cho link trong email thông báo và rà soát |
| `SAFE_LIST` | Dải **không bao giờ** được chặn (dải nội bộ, VPN, đối tác) |
| `ALLOW_PRIVATE` | Cho phép chặn IP private (mặc định `false`) |
| `HOST_PREFIX` | Chỉ để nhận diện object kiểu cũ do app tạo trước v1.4.0 (mặc định `SOC_BLOCK_`). Object mới luôn đặt tên = IP/CIDR |
| `API_TIMEOUT` / `API_CONNECT_TIMEOUT` | Timeout gọi firewall / timeout kết nối TCP+TLS (mặc định 30 / 10 giây) |
| `SOPHOS_BATCH_SIZE` | Số IP Host gộp trong một lệnh tạo object (mặc định 50; `1` = tạo từng object như bản cũ) |
| `FW_PARALLEL` | Số firewall xử lý song song khi chặn/bỏ chặn (mặc định 4) |
| `JOB_SYNC_WAIT` | Request chặn/bỏ chặn/đồng bộ chờ tối đa N giây (mặc định 20), sau đó trả mã công việc và chạy nền. Phải **nhỏ hơn** timeout của App Proxy (~85s) và Ingress |
| `GROUP_CACHE_TTL_MINUTES` | Chu kỳ quét đầy đủ IP Host Group (mặc định 1440 = 24 giờ) |
| `GROUP_CACHE_DAILY_AT` | Giờ quét đầy đủ hằng ngày, HH:MM giờ VN (mặc định 02:00; để trống thì tắt) |
| `GROUP_CACHE_REFRESH_WAIT` | Số giây nút "Quét lại" chờ trước khi chuyển sang chạy nền (mặc định 8) |
| `GROUP_CACHE_MIN_REFRESH_SECONDS` | Khoảng cách tối thiểu giữa hai lần bấm "Quét lại" (mặc định 5) |
| `GROUP_CACHE_ERROR_RETRY_MINUTES` | Thời gian chờ trước khi quét lại sau lỗi (mặc định 30 phút) |
| `GROUP_CACHE_WARMUP` | `true` = quét mọi firewall khi app khởi động |
| `GROUP_SCAN_TIMEOUT` | Timeout riêng cho quét đầy đủ IP Host trên firewall có nhiều object (mặc định 180 giây) |
| `HOST_LOOKUP_LIMIT` | Số object tối đa tra cứu từng cái theo tên trước khi đọc toàn bộ (mặc định 25) |
| `VPN_SYNC_MINUTES` | Chu kỳ đồng bộ tài khoản và rule VPN, tính bằng phút (mặc định 360; `0` = chỉ đồng bộ tay) |
| `VPN_SCAN_TIMEOUT` | Timeout đọc User / Group / rule / chính sách VPN trên firewall (mặc định 180 giây) |
| `VPN_RULE_GROUPS` | Rule Group cần đọc (mặc định `VPN`); chỉ nhận giá trị nằm trong whitelist của mã nguồn. *Tab Cài đặt* |
| `VPN_EXPIRING_DAYS` | Ngưỡng "Sắp hết hạn" (mặc định 30 ngày). *Tab Cài đặt* |
| `NOTIFY_INTERVAL_SECONDS` | Chu kỳ lập kế hoạch nhắc hạn và gửi hàng đợi email (mặc định 300 giây; `0` = tắt chạy định kỳ, nút *Chạy ngay* vẫn dùng được). SMTP và người nhận: *tab Cài đặt* |
| `SMTP_TIMEOUT` | Timeout kết nối / gửi SMTP (mặc định 15 giây) |
| `AUTH_MODES` | `local` (mật khẩu chung), `oidc` (Microsoft Entra ID + MFA), `header` (header SSO từ App Proxy); kết hợp bằng dấu phẩy |
| `LOCAL_ROLE` | Vai trò cấp cho đăng nhập bằng mật khẩu chung (mặc định `admin`) |
| `OIDC_TENANT_ID` / `OIDC_CLIENT_ID` | Thông tin App registration trên Entra ID |
| `OIDC_REDIRECT_URI` | `<External URL>/api/auth/oidc/callback` |
| `OIDC_AUTO_LOGIN` / `OIDC_PROMPT` / `OIDC_DOMAIN_HINT` | SSO một lần: tự chuyển sang Microsoft (mặc định `true`); `prompt` để trống = dùng lại phiên App Proxy; gợi ý domain (vd `hsc.com.vn`) |
| `OIDC_REQUIRE_MFA_CLAIM` | `true` = từ chối token có claim `amr` nhưng thiếu `mfa` |
| `OIDC_ALLOW_GUESTS` | `false` (mặc định) = từ chối tài khoản khách B2B |
| `ROLE_ADMIN` / `ROLE_OPERATOR` / `ROLE_VIEWER` | Giá trị App Role (mặc định `SRB.Admin` / `SRB.Operator` / `SRB.Viewer`) |
| `TRUSTED_PROXY_CIDRS` | IP connector được tin header SSO (chỉ dùng với `header`) |
| `HEADER_USER` / `HEADER_NAME` | Tên header chứa danh tính (mặc định `X-SRB-UPN` / `X-SRB-NAME`) |
| `HEADER_ADMINS` / `HEADER_OPERATORS` / `HEADER_DEFAULT_ROLE` | Phân quyền theo UPN khi dùng header SSO |
| `SHARED_PASSWORD_LOGIN` | `true` (mặc định) = vẫn cho đăng nhập bằng `APP_PASSWORD` làm đường khẩn cấp; `false` = chỉ tài khoản riêng / Microsoft |
| `USERS_STRICT` | `true` = đăng nhập Microsoft chỉ chấp nhận người có trong tab Người dùng (bỏ qua App Role) |
| `PASSWORD_MIN_LENGTH` | Độ dài tối thiểu mật khẩu người dùng (mặc định 10, bắt buộc có chữ và số) |
| `LOGIN_MAX_FAILS` / `LOGIN_LOCK_MINUTES` | Sai mật khẩu N lần thì khóa tạm M phút (mặc định 5 lần / 10 phút) |
| `LOGO_MAX_KB` | Dung lượng tối đa của logo tải lên (mặc định 300) |
| `AUTOBLOCK_POLL_SECONDS` | Chu kỳ đọc group chat Teams **mặc định ban đầu** (giây, 300 = 5 phút); quản trị viên chỉnh lại trong tab Cài đặt (1–60 phút). `0` = tắt hẳn bộ đọc. Kết nối Graph, tài khoản SOC, whitelist, webhook trả lời: *tab Cài đặt* |
| `LOG_FORMAT` / `LOG_LEVEL` | `text` (mặc định) hoặc `json` (một dòng, có `request_id`, không bao giờ ghi mật khẩu/token) / mức log |

---

## 5. Hướng dẫn sử dụng

### 5.1 Bắt đầu nhanh (quản trị viên)

> Mỗi mục cấu hình có nút **ⓘ** cạnh tên. Rê chuột, bấm Tab hoặc chạm vào để xem hướng dẫn: điền gì, lấy ở đâu, ví dụ.

1. Đăng nhập lần đầu bằng `APP_PASSWORD`, hoặc bằng Microsoft nếu đã cấu hình Entra.
2. Tab **Người dùng**:
   - Tạo tài khoản cho từng người, chọn quyền **Readonly** / **Write** / **Write + Quản trị viên**.
   - Loại tài khoản: *Mật khẩu riêng* hoặc *Microsoft* (tên đăng nhập = UPN).
   - Tải **logo** nếu muốn.
   - Khi đã có ít nhất một quản trị viên đăng nhập được, đặt `SHARED_PASSWORD_LOGIN=false`.
3. Tab **Firewall**: thêm từng firewall (tên, host/IP, cổng 4444, tài khoản API), rồi bấm **Kiểm tra** hoặc **Kiểm tra tất cả**.
4. Tab **Cài đặt** (nếu dùng VPN và email):
   - cấu hình SMTP, rồi bấm **Gửi thử**;
   - nhập địa chỉ **Infra** nhận thông báo;
   - nhập **đại diện từng team** (tên team giống phần đầu tên rule, vd `RMS RESEARCH`).
5. Tab **Cài đặt › Tự động chặn từ Teams** (nếu dùng): làm theo [mục 5.9](#59-tab-tự-động-chặn-từ-teams).
6. Tab **VPN**: bấm **Đồng bộ ngay** cho lần đầu. Sau đó app tự đồng bộ theo chu kỳ `VPN_SYNC_MINUTES`.

### 5.2 Tab Chặn nhanh

1. Chọn nguồn IP:
   - **Dán từ Teams:** app tự bóc IPv4/CIDR, kể cả dạng làm mờ.
   - **Nhập tay.**
   - **CSV/TXT:** kéo-thả file.
2. Tick các firewall đích (có thể chọn tất cả) và điền lý do / số ticket. Group đích luôn là **`SCANPORT GROUP`**
   (hiển thị khóa, không sửa được).
3. Tick **Chạy thử (dry-run)** để xem trước sẽ tạo gì, kèm XML IPHostGroup đúng mẫu Sophos, mà không ghi lên firewall.
4. Bấm **Chặn ngay** và xác nhận.
   - Thanh tiến độ hiện trạng thái từng firewall; firewall nào xong thì kết quả hiện trước.
   - Phần tổng kết cho biết *đã thêm / đã có / lỗi*, kèm mã Sophos khi có lỗi.
   - Nếu lâu hơn `JOB_SYNC_WAIT`, việc chặn tiếp tục chạy nền, giao diện vẫn theo dõi được, và **không bị lỗi 504**.

<details><summary>Payload IPHostGroup gửi lên firewall</summary>

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

- `<Host>` là **tên IP Host** (tối đa 60 ký tự, không có dấu phẩy).
- App tạo IP Host trước (gộp tối đa `SOPHOS_BATCH_SIZE` object trong một lệnh `<Set>`), rồi ghi lại toàn bộ `HostList`
  (danh sách cũ + mới).
- `Description` và `IPFamily` hiện có của group được giữ nguyên.

</details>

### 5.3 Tab IP Host Group

- Xem và tìm thành viên `SCANPORT GROUP` trên từng firewall. Dữ liệu lấy từ cache nên hiện ngay; thẻ tổng quan cho biết
  số IP, thời điểm quét gần nhất và trạng thái.
- **Quét lại** đọc trực tiếp từ firewall. Nếu chậm, việc quét chuyển sang chạy nền.
- Tick IP rồi bấm **Bỏ chặn**. Có tùy chọn xóa luôn IP Host object, chỉ áp dụng cho object do app tạo.

### 5.4 Tab Firewall

Thêm, sửa, xóa firewall (chỉ quản trị viên). Bấm **Kiểm tra** để thử đăng nhập API và kiểm tra group `SCANPORT GROUP`.
Mật khẩu được mã hóa và không bao giờ hiển thị lại.

### 5.5 Tab Lịch sử thay đổi

Đây là dòng thời gian của mọi thay đổi thành viên group.

- **Thẻ chặn/bỏ chặn:** mỗi lần chặn hoặc bỏ chặn là một thẻ, gồm:
  - người thực hiện (UPN + tên AD) và phương thức đăng nhập;
  - firewall › group và `+N / −N`, số object **trước → sau**;
  - lý do, nguồn và IP client;
  - danh sách từng dòng `+ IP` (đỏ: vào group chặn) / `− IP` (xanh: gỡ khỏi group).
- **Thay đổi ngoài app** (thẻ màu cam): mỗi lần đọc group, app so với ảnh chụp lần trước. Nếu ai đó sửa trực tiếp trên
  WebAdmin, thay đổi sẽ được ghi lại. Bấm **Đồng bộ & dò thay đổi ngoài app** để kiểm tra ngay.
- **Lọc:** theo firewall, loại thay đổi, người thực hiện, khoảng ngày. Ô tìm IP trả lời nhanh câu hỏi
  *"IP này bị chặn bởi ai, khi nào, vì sao, đã gỡ chưa"*.
- **Kiểm tra toàn vẹn log:** xác minh chuỗi băm. **Xuất CSV** (UTF-8 BOM, giờ VN) để đính kèm báo cáo sự cố.

### 5.6 Tab VPN (chỉ đọc)

- **Dashboard.** Các thẻ đếm theo trạng thái hạn:

  | Trạng thái | Ý nghĩa |
  |---|---|
  | **Sắp hết hạn** | Còn ≤ N ngày |
  | **Hết hạn nhưng vẫn bật** | Cần Infra tắt rule |
  | **User không còn / bị khóa** | Tài khoản gắn rule không còn trên firewall hoặc đang bị khóa |
  | **Không đọc được tên** | Không có Schedule và tên rule không chứa ngày hợp lệ |
  | **Lệch thời hạn** | Schedule và tên rule ghi hai ngày khác nhau |
  | **Không có hạn** | Rule không có thông tin hạn |
  | **Còn hạn** | Còn hạn bình thường |

  Bấm vào một thẻ để lọc theo trạng thái đó.
- **Danh sách rule.** Lọc theo firewall / team / khoảng ngày / từ khóa, hoặc *xem tại ngày* (vd "đến 31/12 thì những gì hết hạn").
  Bấm vào một rule để xem chi tiết (nguồn, identity, đích, dịch vụ, schedule) và **lịch sử** (rule mới, bị xóa, đổi hạn,
  đổi đích, đổi người dùng, bật/tắt).
- **Tài khoản VPN.** Danh sách người có quyền SSL VPN / IPsec, nhóm và trạng thái khóa. Tài khoản đã bị xóa khỏi firewall
  vẫn được giữ, có đánh dấu, để phục vụ rà soát.
- **Xuất CSV cần xử lý.** Danh sách gửi Infra để tắt hoặc gia hạn rule. App **không tự tắt, sửa hay xóa** bất kỳ rule nào.
- **Đồng bộ ngay** cần quyền Write.

### 5.7 Tab Rà soát (ISO/IEC 27001:2022 A.5.18)

**Quản trị viên:**

- **Mở đợt.**
  - App tự mở đợt trong 15 ngày đầu quý, nếu đã bật tùy chọn và đã có dữ liệu VPN. Quản trị viên cũng mở tay được.
  - Khi mở, app **chụp ảnh** mọi rule VPN và **tài khoản mồ côi** (có quyền VPN nhưng không gắn rule nào) tại thời điểm đó.
- **Phân công.** Rule thuộc team đã có đại diện được giao cho đại diện đó. Phần còn lại (không thuộc team nào, team chưa có
  đại diện, tài khoản mồ côi) giao cho **Infra**.
- **Theo dõi.** Xem tiến độ từng team. Quản trị viên quyết định thay được; quyết định đó ghi rõ "Infra quyết định thay".
  App tự gửi email khi mở đợt, nhắc trước hạn và báo Infra khi quá hạn.
- **Đóng đợt.** Mục chưa có quyết định được ghi "Không phản hồi".
- **Xuất báo cáo.** Tải **CSV bằng chứng** cho auditor (mọi mục, quyết định, người, thời điểm, lý do, mã băm) và
  **CSV cần thu hồi / điều chỉnh** để Infra xử lý trên firewall.
- **Kiểm tra toàn vẹn** chuỗi băm của nhật ký quyết định.

**Đại diện team:**

1. Mở link trong email và đăng nhập bằng Microsoft. Không cần được tạo tài khoản trong app: người có email nằm trong danh
   sách đại diện sẽ vào với vai trò **Rà soát**, chỉ thấy tab Rà soát và chỉ thấy mục của team mình.
2. Với từng quyền, chọn **Còn cần**, **Thu hồi** hoặc **Cần điều chỉnh**. *Thu hồi* và *Cần điều chỉnh* bắt buộc ghi lý do.
   Có thể đổi quyết định cho tới khi đợt đóng.

### 5.8 Tab Cài đặt (quản trị viên)

- **SMTP:**
  - máy chủ, cổng, kiểu bảo mật (STARTTLS / SSL / không), kiểm tra chứng chỉ TLS;
  - tài khoản (mật khẩu mã hóa, không hiển thị lại) và địa chỉ gửi;
  - nút **Gửi thử**.
- **Thông báo:** bật/tắt; các mốc nhắc trước hạn (mặc định 30/14/7/1 ngày); email Infra; **đại diện từng team**.
- **Hàng đợi email:** trạng thái từng thư (chờ / đã gửi / lỗi, số lần thử) và nút **Chạy ngay**.
  - SMTP lỗi thì thư được thử lại, lùi dần tới 6 giờ, tối đa 8 lần.
  - SMTP đang tắt thì thư nằm chờ.
  - Mỗi mốc nhắc chỉ gửi **một lần**; nếu hạn rule thay đổi thì app nhắc lại.
- **VPN:** ngưỡng "sắp hết hạn", Rule Group được đọc.
- **Rà soát:** tự mở hằng quý, số ngày hạn hoàn thành, số ngày nhắc trước hạn.
- **Tự động chặn từ Teams:** kết nối Graph, tài khoản SOC, whitelist, trả lời vào group chat, khung giờ, ngưỡng, chu kỳ
  đọc, email nhóm Admin, firewall đích. Xem [mục 5.9](#59-tab-tự-động-chặn-từ-teams).

### 5.8a Tab Báo cáo

1. **Chọn kỳ báo cáo:** **7 / 14 / 30 ngày** gần nhất, hoặc **Chọn trên lịch** (từ ngày → đến ngày, tối đa 366 ngày, giờ Việt Nam).
2. **Executive Summary:**
   - câu tổng quan: số IP bị chặn, thủ công / tự động, tỷ lệ tự động;
   - 6 thẻ chỉ số, trong đó có thời gian từ lúc SOC gửi lệnh tới lúc chặn xong;
   - **nhận định nổi bật**: ngày cao điểm, trung bình IP/ngày, lệnh SOC, người chặn nhiều nhất;
   - **cần lưu ý / hành động**: lệnh còn chờ duyệt, đề xuất chặn IP thuộc whitelist, lệnh lỗi hoặc sai cú pháp.
3. **Chi tiết:**
   - biểu đồ IP bị chặn theo ngày (thủ công / tự động);
   - bảng người / tác nhân thực hiện;
   - danh sách IP: thời gian thực hiện, phương thức, người / kênh, firewall, trạng thái (đang chặn / đã gỡ), lý do.
4. **Tải PDF:** bản trình lãnh đạo, A4 ngang theo **HSC Design System** (font Inter / Inter Display, màu navy #0B2D5C /
   brand #2681FF / brand-deep #00468C).
   - **Logo ở header** là logo tải ở tab Người dùng; chưa có logo hoặc logo SVG thì dùng biểu tượng mặc định.
   - Trang 1 là Executive Summary, các trang sau là chi tiết.
5. **Tải Excel:** các sheet *Executive Summary · Theo ngày* (kèm biểu đồ) *· Danh sách IP · Chi tiết lượt chặn · Người thực hiện*.
   Cột thời gian là kiểu ngày giờ thật, có bộ lọc.
6. **Gửi email** (quyền Write trở lên):
   - nhập người nhận (tối đa 20), chọn đính kèm PDF / Excel, ghi chú đầu thư.
   - Thư đi qua **máy chủ SMTP đã cấu hình** ở tab Cài đặt (phải đang bật); nội dung thư là Executive Summary.

**Phương thức chặn:**
- **Tự động**: app tự chặn từ lệnh SOC.
- **Thủ công**: con người thao tác, gồm chặn tay (dán Teams / nhập tay / CSV) **và** Approve lệnh SOC chờ duyệt.

Mọi lần tải và gửi đều ghi audit (`report_export` / `report_email`).

### 5.9 Tab Tự động chặn (từ Teams)

**Quy ước với SOC.** Muốn app tự chặn, SOC thêm **một dòng riêng, viết IN HOA** vào tin nhắn trong group chat:

```
ĐỀ XUẤT CỦA SOC: BLOCK IP 195.178.110.102
```

App nhận lệnh theo các quy tắc sau:

- **Khớp chính xác.** Chữ thường hay viết hoa đầu câu (`Đề xuất của SOC: block ip …`) đều không được nhận, kể cả khi lệnh
  lẫn trong một câu dài. Một tin có thể chứa nhiều dòng lệnh.
- **Chỉ IPv4 đơn.** CIDR, dải, IPv6 hay tên miền không được tự chặn; dòng đó bị ghi "Không hợp lệ".
- **Sửa tin = bỏ qua.** Tin **đã sửa** không được xử lý. Gõ nhầm thì SOC gửi tin mới.
- **Chỉ tài khoản SOC.** Tin của người ngoài danh sách tài khoản SOC bị bỏ qua và ghi vào nhật ký.
- **Chặn trên mọi firewall đích.** Sau khi chặn xong, app trả lời vào group chat:
  `INFRA ĐÃ BLOCK 195.178.110.102 THEO YÊU CẦU LÚC 18/11/2026 23:42:10`.

**Cách app xử lý từng lệnh** (theo thứ tự):

| Điều kiện | Kết quả |
|---|---|
| IP nội bộ / thuộc `SAFE_LIST` | Không hợp lệ, không chặn |
| IP đang có yêu cầu đang chặn / chờ | Trùng, bỏ qua |
| IP thuộc **whitelist** (HSC / Akamai / Đối tác…) | **Chờ duyệt**, chỉ **quản trị viên** bấm **Approve** được; không tính vào ngưỡng |
| **Công tắc khẩn cấp** đang TẮT | Chờ duyệt |
| **Ngoài lịch tự chặn**, tức giờ hành chính khi Infra có mặt | Chờ duyệt |
| Đã **vượt ngưỡng** N IP/giờ (mặc định 20) | **Ngắt**: lệnh này và mọi lệnh sau chờ duyệt, email cảnh báo nhóm Admin ngay. Quản trị viên bấm **Mở lại** |
| Còn lại | **Tự chặn** ngay |

**Lịch tự chặn** (tab Cài đặt, quản trị viên chỉnh):

| Loại ngày | Tự chặn |
|---|---|
| Ngày thường | Ngoài giờ, mặc định **18:00 → 08:00** sáng hôm sau (giờ bắt đầu/kết thúc chỉnh được) |
| Thứ 7, Chủ nhật | **Cả ngày** (tùy chọn, mặc định bật) |
| Ngày lễ rơi vào ngày thường | **Cả ngày**, theo danh sách ngày lễ (một ngày hoặc cả đợt, vd Tết) |
| Nghỉ đột xuất | Nút **Tự chặn cả ngày hôm nay** trên tab Tự động chặn |
| Bỏ tick "Chỉ tự chặn theo lịch" | 24/7 |

Các khoảng liền nhau được gộp thành **một ca ngoài giờ**. Ví dụ: 18:00 thứ 6 → 08:00 thứ 2, hoặc cả kỳ nghỉ lễ nối cuối tuần.

**Trên tab:**

- **Thẻ trạng thái:** công tắc, số IP đã tự chặn trong 60 phút / ngưỡng, khung giờ, số lệnh chờ duyệt, lần đọc Teams gần nhất.
- **Tắt khẩn cấp:** người có quyền Write tắt được ngay; chỉ quản trị viên bật lại.
- **Chờ duyệt:** **Approve** để chặn ngay (chọn nhiều mục được), hoặc **Từ chối**. Mục thuộc whitelist có nhãn
  *Whitelist · Akamai: 23.32.0.0/11*.
- **Ca ngoài giờ:** các IP app đã tự chặn trong ca gần nhất (đêm / cuối tuần / ngày lễ). Khi vào ca, rà lại và bấm **Gỡ chặn**
  từng IP hoặc **Gỡ tất cả IP của ca**. Khi ca kết thúc (vd 08:00, hoặc 08:00 thứ 2), app email danh sách cho nhóm Admin.
- **Tất cả lệnh:** lọc theo trạng thái, kết quả trên từng firewall, *Đã báo Teams* / *Chưa báo Teams*.
  Nút **Kiểm tra toàn vẹn nhật ký** xác minh chuỗi băm.

**Cấu hình một lần** (tab Cài đặt › Tự động chặn từ Teams, quản trị viên):

1. **App registration** trên Entra ID (nên tách riêng với app đăng nhập):
   - Tạo client secret.
   - Cấp quyền đọc group chat, theo một trong hai cách:
     - **`ChatMessage.Read.Chat`** (resource-specific consent, chỉ cho đúng group chat đó; khuyến nghị): đóng gói app
       thành Teams app có khai báo quyền này rồi thêm vào group chat.
     - **`Chat.Read.All`** (Application, cần admin consent): đọc được mọi chat trong tenant, nên kém an toàn hơn.
   - Nhập Tenant ID, Client ID, Client secret.
2. **Chat ID:** mở group chat trên Teams web, sao chép phần `19:…@thread.v2` trên thanh địa chỉ.
3. Bấm **Kiểm tra kết nối**. App liệt kê người gửi gần đây; bấm **+ tên** để thêm **tài khoản SOC** (định danh bằng Object ID).
4. **Whitelist:** dán dải IP public của HSC, dải Akamai (Origin IP ACL / SiteShield) và IP đối tác, mỗi dòng một IP/CIDR.
   Có thể thêm danh sách khác.
5. **Trả lời vào group chat:**
   - Microsoft Graph không cho app gửi tin vào chat bằng quyền ứng dụng, nên dùng **Teams Workflows**.
   - Trong group chat chọn **… › Workflows › "Post to a chat when a webhook request is received"**, rồi sao chép URL webhook.
   - Dán URL vào app, bấm **Gửi thử**. Tin được đăng dưới tên *Workflows*.
6. Đặt lịch tự chặn (ngoài giờ ngày thường, cuối tuần, ngày lễ), ngưỡng IP/giờ, chu kỳ đọc (1–60 phút), email nhóm Admin, firewall đích. Tick **Bật** rồi bấm **Lưu**.
   App chỉ xử lý tin gửi **sau** lúc bật.

> Mạng: pod cần ra được `login.microsoftonline.com`, `graph.microsoft.com` và host của webhook Workflows
> (`*.logic.azure.com` hoặc `*.api.powerplatform.com`) qua cổng 443.

### 5.10 Tab Audit log

Ghi toàn bộ thao tác: ai, lúc nào, IP nào, firewall nào, kết quả, lý do. Có thể lọc và **Xuất CSV**. Các loại sự kiện đặc biệt:

- `policy_violation`: một lệnh bị chính sách chặn;
- `login`: đăng nhập thành công/thất bại;
- `user_mgmt`: thay đổi người dùng.

---

## 6. Phân quyền & cơ chế an toàn

| Quyền | Rà soát | Readonly (`SRB.Viewer`) | Write (`SRB.Operator`) | Quản trị viên (`SRB.Admin`) |
|---|---|---|---|---|
| Rà soát mục của team mình | ✓ | ✓ (nếu là đại diện) | ✓ (nếu là đại diện) | ✓ |
| Xem group / lịch sử / audit / VPN, xuất CSV | — | ✓ | ✓ | ✓ |
| Chặn, bỏ chặn, kiểm tra, quét lại, đồng bộ VPN | — | — | ✓ | ✓ |
| Tự động chặn: xem trạng thái / danh sách | — | ✓ | ✓ | ✓ |
| Tự động chặn: Approve, từ chối, gỡ chặn, **tắt** khẩn cấp | — | — | ✓ | ✓ |
| Tự động chặn: **Approve IP thuộc whitelist**, bật lại công tắc, mở lại sau khi vượt ngưỡng, cấu hình | — | — | — | ✓ |
| Firewall, người dùng, logo, Cài đặt (SMTP, VPN, rà soát), mở/đóng đợt rà soát | — | — | — | ✓ |

**Quyền và đăng nhập:**

- Quyền được kiểm tra lại ở **mỗi request**: khóa, hạ quyền hay xóa người dùng có hiệu lực ngay. Gỡ người khỏi danh sách
  đại diện team thì họ mất vai trò Rà soát ngay.
- Vai trò **Rà soát** chỉ gọi được API của tab Rà soát; mọi API khác trả 403. Việc chặn nằm ở một chỗ (`auth/rbac.py`).
- **Chống tự khóa:** không thể tự bỏ quyền quản trị, tự khóa hay tự xóa chính mình; luôn phải còn ít nhất một quản trị viên
  đang hoạt động.
- Mật khẩu riêng được băm PBKDF2-SHA256 (310.000 vòng). Sai nhiều lần thì bị khóa tạm.
- Đăng nhập Microsoft dùng Authorization Code + PKCE, và kiểm tra chữ ký JWKS, issuer, audience, tenant, nonce, App Role.
- Mật khẩu chung `APP_PASSWORD` không dùng được để mạo danh tài khoản đã có trong danh sách.

**Hardening phía firewall:**

- Tên group **`SCANPORT GROUP` được gắn cứng trong mã nguồn**: không đọc từ biến môi trường, không nhận từ giao diện.
  API nhận group khác sẽ trả HTTP 403 và ghi audit `policy_violation`. Muốn đổi tên phải sửa mã, review và build lại image.
- Mọi lệnh XML gửi lên firewall đều được `policy.py` phân tích trước khi gửi. Chỉ cho phép:
  - tạo IP Host;
  - ghi `SCANPORT GROUP`;
  - xóa IP Host do app tạo (tên = địa chỉ của object, hoặc có tiền tố cũ `SOC_BLOCK_`);
  - `Get` đối với dữ liệu VPN.

  Mọi lệnh ghi FirewallRule / User / Group / Schedule đều bị chặn.
- Rule Group được đọc chỉ nhận giá trị trong whitelist của mã nguồn (`VPN`).
- Mật khẩu, hash và khóa IPsec trong phản hồi của firewall bị loại theo **allowlist trường**, trước khi lưu, ghi log hay
  trả về API.

**An toàn dữ liệu và thao tác:**

- Mật khẩu firewall/SMTP được mã hóa AES-256-GCM và không bao giờ trả về client.
- Safe-list và chặn IP private giúp tránh tự khóa. Mỗi lần đẩy tối đa 500 IP, có hộp thoại xác nhận trước khi chặn/bỏ chặn.
- Lịch sử thay đổi group, lịch sử rule VPN và quyết định rà soát đều nối **chuỗi băm SHA-256**: sửa hay xóa trực tiếp trong
  DB sẽ bị phát hiện.

---

## 7. Xử lý sự cố

| Triệu chứng | Kiểm tra |
|---|---|
| Firewall trả `532` / `534` / `599` | Chưa bật API · IP đi ra của app (trên k8s là IP **node**) chưa có trong Allowed IP · tài khoản API thiếu quyền (Hosts and services; đọc rule/user nếu dùng VPN) |
| Kết nối firewall bị timeout | Cổng đúng là cổng HTTPS Admin Console (thường 4444, không phải 443)? NetworkPolicy egress có chặn không? Thử `kubectl -n sophos-blocker exec deploy/soc-rapid-block-app -- python -c "import socket;socket.create_connection(('<fw>',4444),5)"` |
| Lỗi 504 qua Ingress | Timeout của Ingress phải > `JOB_SYNC_WAIT`; xem annotation trong `overlays/rancher/ingress.yaml` |
| Pod app `CrashLoopBackOff` | `kubectl logs`: thiếu `MASTER_KEY`, hoặc DB chưa sẵn sàng hay sai `POSTGRES_PASSWORD` |
| Pod Postgres `Pending` | PVC chưa bound: `storageClassName` không khớp cụm (`kubectl get sc`) |
| `ErrImagePull` | Package GHCR private mà chưa có secret `ghcr-pull`, hoặc PAT hết hạn |
| Đăng nhập Microsoft lỗi | `OIDC_REDIRECT_URI` phải trùng **chính xác** Redirect URI trên App registration; pod phải ra được `login.microsoftonline.com` |
| Không nhận được email | Tab Cài đặt ▸ Hàng đợi email: xem lỗi của từng thư; bấm **Gửi thử**; kiểm tra egress tới SMTP và `APP_BASE_URL` |
| Tự động chặn: "Đọc Teams lỗi … 403" | App registration chưa được cấp `ChatMessage.Read.Chat` cho group chat (hoặc `Chat.Read.All` chưa admin consent) |
| Tự động chặn: SOC gửi lệnh nhưng app không chặn | Dòng lệnh phải đúng `ĐỀ XUẤT CỦA SOC: BLOCK IP <ip>` IN HOA, đứng riêng một dòng · người gửi có trong danh sách tài khoản SOC · tin không bị sửa · xem lý do trong *Tất cả lệnh* (chờ duyệt, whitelist, ngoài giờ, vượt ngưỡng) |
| Tự động chặn: "Chưa báo Teams" | URL webhook Workflows sai hoặc workflow bị tắt; pod chưa ra được `*.logic.azure.com`. App tự thử lại tối đa 5 lần |
| VPN báo "Không đọc được tên" | Tên rule cần có ngày dạng `dd/mm/yyyy`, hoặc rule gắn Schedule OneTime. App không đoán ngày sai định dạng |

---

## 8. Phát triển & kiểm thử

Chạy với firewall giả lập (không cần thiết bị thật):

```bash
python mock/mock_sophos.py --port 4444        # user apiadmin / Sophos@123, kèm dữ liệu VPN mẫu
export MASTER_KEY=$(openssl rand -hex 32) APP_PASSWORD=socadmin DATABASE_URL=sqlite:////tmp/sb.db
python -m uvicorn app.main:app --app-dir backend --port 8080
```

Sau đó thêm firewall `127.0.0.1:4444` trong tab Firewall. API docs có ở `http://localhost:8080/api/docs`.

Kiểm thử hồi quy:

```bash
bash tests/run_e2e.sh                                   # luồng chính: SSO, RBAC, chặn/bỏ chặn, lịch sử, hash chain
bash tests/run_e2e.sh tests/<tên>_test.py               # một bộ: vpn_rules, notify, review, users, contract, policy_guard…
E2E_DATABASE_URL=postgresql+psycopg2://u:p@127.0.0.1:5432/srb bash tests/run_e2e.sh tests/review_test.py   # trên PostgreSQL
```

Một số test bảo vệ quan trọng:

- `tests/contract_test.py` khóa danh sách API và hình dạng response.
- `tests/policy_guard_test.py` bảo đảm không lệnh ghi nào lọt lên firewall ngoài allowlist.
- `tests/ui_smoke.cjs` chạy Playwright trên toàn bộ các tab.

Lấy mẫu cấu hình VPN thật để phát triển (chỉ đọc, đã che dữ liệu):
`SOPHOS_PASSWORD=… python tools/sophos_sample.py --host <fw> --user <api> --insecure --out sophos-sample`.

---

## 9. Lịch sử phiên bản

| Phiên bản | Nội dung chính |
|---|---|
| **2.2.0** | **Báo cáo** PDF / Excel (Executive Summary, theo HSC Design System, logo, chọn kỳ trên lịch, gửi email qua SMTP). **Giao diện mới** (menu trái, bảng/thẻ cân đối, Fira Sans/Code, tooltip hướng dẫn cấu hình). Tự động chặn từ group chat Teams: cú pháp `ĐỀ XUẤT CỦA SOC: BLOCK IP <ip>`, tài khoản SOC, bỏ qua tin đã sửa, whitelist + Approve, lịch tự chặn (ngoài giờ ngày thường, cả ngày cuối tuần, ngày lễ, "cả ngày hôm nay"), ngưỡng 20 IP/giờ, công tắc khẩn cấp, danh sách ca đêm, trả lời `INFRA ĐÃ BLOCK …` qua Teams Workflows |
| **2.1.0** | Rà soát quyền VPN định kỳ theo ISO 27001 (tab Rà soát, vai trò Rà soát, CSV bằng chứng / cần thu hồi, chuỗi băm quyết định). Overlay Rancher |
| **2.0.0** | Thông báo email: cấu hình SMTP trên giao diện, nhắc trước hạn, báo hết hạn hằng tuần, outbox idempotent |
| **1.9.0** | VPN giai đoạn 2: thời hạn qua firewall rule (Schedule / tên rule), dashboard trạng thái, lịch sử rule, CSV cần xử lý |
| **1.8.0** | VPN giai đoạn 1: danh sách tài khoản VPN chỉ đọc, đồng bộ định kỳ, lọc trường bí mật, `tools/sophos_sample.py` |
| **1.7.x** | Sửa 504 khi chặn nhiều IP (gộp lệnh, song song, công việc nền). Tái cấu trúc backend/frontend theo module, log JSON, khóa phân tán |
| **1.6.x** | Cache IP Host Group trong PostgreSQL, quét nền, không còn timeout với firewall có nhiều object. HSC Design System, logo |
| **1.5.x** | Quản lý người dùng (Readonly / Write / Quản trị viên). SSO một lần qua Entra App Proxy, endpoint Entra v2.0 |
| **1.4.0** | Tên IP Host = IP/CIDR; vẫn nhận object `SOC_BLOCK_*` cũ |
| **1.3.0** | Hardening: chỉ thao tác `SCANPORT GROUP`; payload IPHostGroup đúng mẫu Sophos |
| **1.2.0** | Entra Application Proxy + MFA, OIDC + App Role, tab Lịch sử thay đổi có chuỗi băm |

Chi tiết từng bước và lý do thiết kế: [`docs/architecture.md`](docs/architecture.md).

---

## 10. Nguồn tham khảo

- [Sophos Firewall API documentation (SFOS 22.0)](https://docs.sophos.com/nsg/sophos-firewall/22.0/api/apicontentpage.html)
- [Cấu hình API trên Sophos Firewall](https://docs.sophos.com/nsg/sophos-firewall/20.0/Help/en-us/webhelp/onlinehelp/AdministratorHelp/BackupAndFirmware/API/APIConfiguration/)
- [IPHost — Add/Edit](https://docs.sophos.com/nsg/sophos-firewall/22.0/api/system/host%20and%20services/iphost/operations/AddIPHost&EditIPHost.html) ·
  [IPHostGroup — Add/Edit](https://docs.sophos.com/nsg/sophos-firewall/22.0/api/SYSTEM/Host%20and%20Services/IPHostGroup/operations/AddIpHostGroup&EditIpHostGroup.html)
- [Bảo vệ truy cập API Sophos (Avanet)](https://www.avanet.com/en/kb/sophos-firewall-api-zugriff-absichern/)
- [Rancher — Import YAML / kubectl](https://ranchermanager.docs.rancher.com/) · [RKE2 ingress-nginx](https://docs.rke2.io/networking/networking_services) ·
  [ingress-nginx annotations](https://kubernetes.github.io/ingress-nginx/user-guide/nginx-configuration/annotations/)
- [Microsoft Entra Application Proxy](https://learn.microsoft.com/entra/identity/app-proxy/overview-what-is-app-proxy) ·
  [Header-based SSO với App Proxy](https://learn.microsoft.com/entra/identity/app-proxy/application-proxy-configure-single-sign-on-with-headers)
