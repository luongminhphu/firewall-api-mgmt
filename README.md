# SOC Rapid Block — chặn IP, tự động chặn từ Teams & quản lý quyền VPN trên nhiều Sophos Firewall

Ứng dụng web (FastAPI + HTML5, không build) cho team SOC / NOC / Infra:

- **Chặn IP nhanh.** Dán thẳng đoạn chat Teams (hoặc CSV, hoặc nhập tay). App tự bóc IP và đẩy vào IP Host Group
  `SCANPORT GROUP` trên **nhiều Sophos Firewall cùng lúc** qua XML API. Dùng được trên điện thoại.
- **Tự động chặn từ Teams, kể cả ban đêm.** App đọc group chat với SOC. Khi SOC gửi dòng `ĐỀ XUẤT CỦA SOC: BLOCK IP <ip>`,
  app tự chặn theo lịch ngoài giờ, có whitelist, giới hạn số lượng và công tắc khẩn cấp. Xong thì app trả lời vào chat;
  bản chụp tin gốc được lưu làm bằng chứng, kể cả khi người gửi xóa tin sau đó.
- **Báo cáo cho lãnh đạo.** File PDF / Excel theo HSC Design System, mở đầu bằng Executive Summary, gửi được qua email.
- **Quản lý quyền VPN (chỉ đọc).** Theo dõi tài khoản và thời hạn VPN, nhắc hạn qua email, rà soát quyền định kỳ theo
  ISO/IEC 27001. App **không bao giờ sửa** rule hay user trên firewall.

Phiên bản: **v2.2.0** · Thiết kế chi tiết: [`docs/architecture.md`](docs/architecture.md) · Lịch sử: [mục 10](#10-lịch-sử-phiên-bản)

**Mục lục**

1. [Tính năng chính](#1-tính-năng-chính)
2. [Kiến trúc](#2-kiến-trúc)
3. [Chuẩn bị trước khi triển khai](#3-chuẩn-bị-trước-khi-triển-khai)
4. [Triển khai](#4-triển-khai) — [Docker Compose](#41-docker-compose) · [Rancher (RKE2 / K3s)](#42-rancher-rke2--k3s) · [KubeSphere](#43-kubesphere) · [Nâng cấp lên 2.2](#44-nâng-cấp-từ-bản-cũ-lên-22) · [Biến môi trường](#45-biến-môi-trường)
5. [Cài đặt ban đầu sau triển khai](#5-cài-đặt-ban-đầu-sau-triển-khai)
6. [Hướng dẫn sử dụng theo tab](#6-hướng-dẫn-sử-dụng-theo-tab)
7. [Phân quyền & cơ chế an toàn](#7-phân-quyền--cơ-chế-an-toàn)
8. [Xử lý sự cố](#8-xử-lý-sự-cố)
9. [Phát triển & kiểm thử](#9-phát-triển--kiểm-thử)
10. [Lịch sử phiên bản](#10-lịch-sử-phiên-bản)
11. [Nguồn tham khảo](#11-nguồn-tham-khảo)

---

## 1. Tính năng chính

### Vận hành chặn IP

| Tính năng | Mô tả |
|---|---|
| **Chặn nhanh** | Bóc IPv4/CIDR từ chat Teams, kể cả dạng làm mờ (`1.2.3[.]4`, `1.2.3(.)4`, `1.2.3[dot]4`), từ CSV/TXT kéo-thả hoặc nhập tay. Chặn trên nhiều firewall cùng lúc · chạy thử (dry-run) và xem trước XML · safe-list và chặn IP private để tránh tự khóa · tối đa 500 IP/lần |
| **Không lỗi 504** | Mỗi firewall chỉ cần 3 lệnh trên 1 kết nối HTTPS (gộp lệnh tạo IP Host), các firewall chạy song song. Quá `JOB_SYNC_WAIT` giây thì chuyển sang công việc nền; giao diện hiện tiến độ từng firewall |
| **IP Host Group** | Xem thành viên `SCANPORT GROUP` ngay từ cache PostgreSQL · quét lại nền · bỏ chặn, xóa IP Host do app tạo |
| **Lịch sử thay đổi** | Ghi từng IP thêm/bớt: ai, lúc nào, lý do/ticket, số object trước → sau · **phát hiện sửa trực tiếp trên WebAdmin** · chuỗi băm SHA-256 · xuất CSV |

### Tự động chặn từ group chat Teams

| Tính năng | Mô tả |
|---|---|
| **Lệnh của SOC** | Dòng riêng, viết IN HOA, khớp chính xác `ĐỀ XUẤT CỦA SOC: BLOCK IP <ip>` (chỉ IPv4 đơn); **tin đã sửa bị bỏ qua** |
| **Team SOC trực 24/7** | SOC là dịch vụ Managed Service của đối tác (vd HPT), thành viên là **tài khoản external** trong group chat của HSC. Chỉ **những người được ủy quyền đích danh** mới ra lệnh được — app **không** tin cậy cả tenant của đối tác (đối tác có thể có người khác trong chat). Ủy quyền từng **tài khoản** (gắn tenant, chọn nhanh từ danh sách thành viên group chat) hoặc qua **nhóm Entra**; thành viên HSC được ủy quyền (vd team IT Security) khai báo cùng cách. Người khác trong chat **không** gửi được lệnh |
| **Đọc tin hiệu quả** | Microsoft Graph, chu kỳ chỉnh trên giao diện (mặc định 5 phút). **Lọc phía Graph** theo `lastModifiedDateTime`, nên không đọc lại lịch sử; chu kỳ không có tin mới thì Graph trả 0 tin. Tin gửi trước lúc bật không bao giờ được xử lý |
| **Thời điểm lệnh** | Lấy theo giờ SOC gửi tin (`createdDateTime` của Microsoft), không theo lúc app đọc. Lệnh trễ quá ngưỡng (mặc định 30 phút) thì **chờ duyệt** |
| **Lịch tự chặn** | Ngày thường ngoài giờ (mặc định 18:00–08:00) · **cả ngày thứ 7, Chủ nhật** · **ngày lễ** (một ngày hoặc cả đợt) · nút "tự chặn cả ngày hôm nay" · hoặc 24/7. Giờ hành chính thì lệnh chờ duyệt |
| **Kiểm soát rủi ro** | **Whitelist** HSC / Akamai / đối tác: lệnh chờ, chỉ quản trị viên **Approve** · tối đa **20 IP/giờ**, vượt thì **ngắt** và báo nhóm Admin · **công tắc tắt khẩn cấp** · safe-list / IP nội bộ không bao giờ bị chặn |
| **Phản hồi & theo dõi** | Trả lời vào group chat `INFRA ĐÃ BLOCK <ip> THEO YÊU CẦU LÚC <thời điểm>` (qua Teams Workflows) · danh sách **ca ngoài giờ** để rà soát, gỡ một chạm · email báo cáo khi hết ca |
| **Bằng chứng** | **Chụp nguyên văn tin Teams ngay lúc nhận** (trước khi chặn): nội dung, người gửi, Message ID, giờ Microsoft, SHA-256, chuỗi băm. Tin bị **xóa / sửa** sau đó thì bản chụp vẫn còn, app ghi thêm mốc xóa/sửa · tải file JSON để kiểm chứng độc lập |

### Báo cáo

| Tính năng | Mô tả |
|---|---|
| **Kỳ báo cáo** | 7 / 14 / 30 ngày, hoặc **chọn trên lịch** (tối đa 366 ngày, giờ Việt Nam) |
| **Nội dung** | **Executive Summary** (tổng quan, 6 chỉ số, nhận định nổi bật, cần lưu ý) rồi tới chi tiết: theo ngày, phương thức **thủ công / tự động**, người thực hiện, thời gian từ lúc SOC gửi tới lúc chặn xong, danh sách IP kèm **thời gian thực hiện** và trạng thái hiện tại |
| **Định dạng** | **PDF** A4 theo HSC Design System (font Inter / Inter Display, màu HSC, **logo ở header**) · **Excel** nhiều sheet, cột ngày giờ thật, có bộ lọc |
| **Gửi email** | Qua máy chủ SMTP đã cấu hình, đính kèm PDF / Excel, nội dung thư là Executive Summary |

### VPN & tuân thủ (chỉ đọc firewall)

| Tính năng | Mô tả |
|---|---|
| **Tài khoản VPN** | Ai có quyền SSL VPN / IPsec trên từng firewall, nhóm, trạng thái khóa; tài khoản đã bị xóa vẫn được giữ để rà soát |
| **Thời hạn VPN** | Đọc rule trong Rule Group `VPN`. Hạn lấy từ Schedule OneTime, nếu không có thì từ tên rule · dashboard 7 trạng thái · lịch sử rule có chuỗi băm · CSV cần xử lý |
| **Nhắc hạn qua email** | SMTP cấu hình trên giao diện · nhắc trước hạn (30/14/7/1 ngày) tới đại diện team + Infra · báo hằng tuần rule hết hạn mà vẫn bật |
| **Rà soát ISO 27001** | Đợt rà soát hằng quý · đại diện team quyết định *Còn cần / Thu hồi / Cần điều chỉnh* · CSV bằng chứng cho auditor |

### Nền tảng

| Tính năng | Mô tả |
|---|---|
| **Đăng nhập & quyền** | Microsoft Entra ID (OIDC + PKCE, MFA qua Conditional Access, SSO một lần qua App Proxy) · header SSO · tài khoản riêng · vai trò *Rà soát / Readonly / Write / Quản trị viên* |
| **Tổng quan** | Một màn hình cho IT Infrastructure Manager: khối **Cần xử lý** (cầu dao tự động chặn đã ngắt, cache group lỗi, rule VPN hết hạn còn bật, rà soát quá hạn, lệnh chờ duyệt, sửa ngoài app 7 ngày, email lỗi 7 ngày…) xếp theo mức nghiêm trọng, cùng thẻ từng module; bấm để mở đúng tab. Trang mặc định của quản trị viên |
| **Giao diện** | Kiểu dashboard vận hành: menu trái theo nhóm (ngăn kéo trên điện thoại), bảng/thẻ cân cột, tối/sáng, **tooltip ⓘ hướng dẫn** ở mọi mục cấu hình |
| **Vận hành** | Audit log đầy đủ · log JSON có `request_id` · khóa phân tán `pg_advisory_lock` (chạy nhiều pod không trùng việc) · bảng tự tạo khi khởi động, không cần migrate |

---

## 2. Kiến trúc

```
                          Trình duyệt (HTML5, mobile-friendly)
                                   │ REST /api/*  (Entra App Proxy / Ingress / NodePort)
                                   ▼
 ┌──────────── FastAPI backend (1 image) ────────────┐        PostgreSQL 16
 │ chặn IP · cache · lịch sử · VPN · rà soát          │ ─────► firewall + credential (AES-256-GCM), audit,
 │ tự động chặn · báo cáo · thông báo · người dùng    │        lịch sử, cache, VPN, outbox email, rà soát,
 └──┬───────────────┬────────────────┬───────────────┘        lệnh tự động chặn + bằng chứng
    │ XML API       │ Graph (đọc)    │ webhook        │ SMTP
    ▼               ▼                ▼                ▼
 Sophos Firewall  graph.microsoft  Teams Workflows   máy chủ email
 :4444 (SFOS 22)  .com (chat SOC)  (trả lời chat)    (nhắc hạn, báo cáo)
```

- **Firewall.**
  - Trình duyệt không gọi thẳng firewall: backend làm proxy, giữ credential và ghi audit.
  - Mọi lệnh XML đều qua **một điểm kiểm soát duy nhất**, `integrations/sophos/policy.py`. Chỉ cho phép: ghi IP Host, ghi
    `SCANPORT GROUP`, và đọc (`Get`) dữ liệu VPN. Mọi lệnh ghi khác bị chặn và ghi audit `policy_violation`.
- **Cách chặn.** Mỗi IP/CIDR thành một **IP Host** có tên chính là địa chỉ đó (vd `45.138.12.16`). Sau đó app ghi lại
  toàn bộ `<HostList>` của group trong một lệnh, vì Sophos không cho thêm/bớt từng phần tử
  ([tài liệu IPHostGroup](https://docs.sophos.com/nsg/sophos-firewall/22.0/api/SYSTEM/Host%20and%20Services/IPHostGroup/operations/AddIpHostGroup&EditIpHostGroup.html)).
- **Teams.**
  - App **chỉ đọc** đúng một group chat qua Microsoft Graph.
  - Việc trả lời vào chat đi qua **Teams Workflows**, vì Graph không cho app gửi tin vào chat bằng quyền ứng dụng.

```
backend/app/
  main.py                 tạo app, bộ lập lịch (cache, VPN, email, rà soát, tự động chặn), mount router, phục vụ frontend
  core/                   config, db + models, security, audit, hashchain, jobs (công việc nền + khóa + lập lịch), logging
  auth/                   rbac (vai trò), router (đăng nhập), oidc (Entra), header_sso, users/
  integrations/sophos/    client XML API, entities/, sanitize (lọc trường bí mật), policy.py (điểm kiểm soát duy nhất)
  modules/
    firewalls/ ipblock/ audit/ branding/
    autoblock/            graph (đọc chat, lọc phía Graph) · parser (cú pháp) · settings (lịch, whitelist…)
                          service (quyết định tự chặn / chờ duyệt, bằng chứng) · reply (Teams Workflows)
    reports/              data (số liệu, Executive Summary) · pdf (reportlab) · xlsx (openpyxl) · logo · fonts/ (Inter)
    vpn/ notify/ review/
frontend/                 ES module thuần, không build: js/main.js + js/pages/* + js/components/* (tips.js = nội dung tooltip)
                          theme.css (token màu) · styles.css · fonts.css (Fira Sans / Fira Code tự host)
deploy/k8s/               base/ · overlays/prod/ · overlays/rancher/ · kubesphere/
mock/                     Sophos, SMTP, Microsoft Graph + Teams Workflows giả lập (kiểm thử không cần hệ thống thật)
tests/                    27 bộ kiểm thử end-to-end + smoke UI Playwright
```

---

## 3. Chuẩn bị trước khi triển khai

### 3.1 Phía Sophos Firewall (mỗi firewall một lần)

Theo [hướng dẫn cấu hình API của Sophos](https://docs.sophos.com/nsg/sophos-firewall/20.0/Help/en-us/webhelp/onlinehelp/AdministratorHelp/BackupAndFirmware/API/APIConfiguration/):

1. **Bật API.** Vào `System ▸ Backup & firmware ▸ API` và tick **Enable API configuration**.
2. **Allowed IP.** Thêm IP mà app dùng để đi ra firewall; thiếu thì API trả mã **534**.
   Trên Kubernetes, đó là IP của **node** (SNAT) hoặc IP egress/NAT của cụm; không cố định được node thì khai báo IP mọi node.
3. **Tài khoản API riêng** (vd `apiadmin`), cấp quyền tối thiểu:
   - *Hosts and services*: đọc + ghi.
   - *Firewall rules, Users/Authentication, Schedule, VPN*: **chỉ đọc**, và chỉ cần nếu dùng module VPN.
   - Không cấp quyền network, system hay ghi rule. Nên giới hạn đăng nhập theo IP
     ([khuyến nghị](https://www.avanet.com/en/kb/sophos-firewall-api-zugriff-absichern/)).
4. **Cổng.** Cổng XML API là cổng HTTPS của Admin Console (`System ▸ Administration ▸ Admin settings`), mặc định **4444**.
5. **Group và rule chặn.**
   - Tạo IP Host Group tên chính xác **`SCANPORT GROUP`** (IPv4).
   - Tạo **firewall rule Drop** với *Source zone = WAN*, *Source networks = SCANPORT GROUP*, đặt **lên trên cùng**.
   - App không tự tạo group; không có rule thì IP vào group cũng không bị chặn.
6. **Rule VPN** (nếu dùng module VPN): đặt trong Rule Group **`VPN`**. Hạn đọc từ Schedule OneTime; nếu không có thì từ
   ngày `dd/mm/yyyy` trong tên rule (vd `RMS RESEARCH - NHAN.NDT 30/06/2027`).

Mã lỗi hay gặp: `502` object trùng tên · `526` không tồn tại · `532` chưa bật API · `534` IP nguồn chưa được phép · `599` thiếu quyền.

### 3.2 Microsoft Entra ID & Teams

| Mục | Cần khi | Việc cần làm |
|---|---|---|
| **App đăng nhập (OIDC)** | Đăng nhập bằng tài khoản công ty + MFA | App registration kiểu Web, Redirect URI `<URL ngoài>/api/auth/oidc/callback`, App Role `SRB.Admin` / `SRB.Operator` / `SRB.Viewer`. Chi tiết, kèm Entra Application Proxy: [`docs/entra-app-proxy.md`](docs/entra-app-proxy.md) |
| **App đọc group chat** | Tự động chặn | App registration **riêng**, tạo *client secret*. Cấp quyền đọc chat theo **một** trong hai cách (bảng dưới). Ghi lại Tenant ID, Client ID, secret |
| **Nhóm Entra** *(tùy chọn)* | Thành viên HSC được ủy quyền (vd team IT Security), SOC nội bộ / khách B2B | Security group chứa những người được gửi lệnh (vd `IT-Security`); app đọc chat cần thêm quyền ứng dụng `GroupMember.Read.All`. Không dùng nhóm thì khai báo từng tài khoản |
| **Chat ID** | Tự động chặn | Mở group chat trên Teams web, sao chép phần `19:…@thread.v2` trên thanh địa chỉ |
| **Teams Workflows** | Trả lời `INFRA ĐÃ BLOCK …` vào chat | Teams mới không còn Workflows trong menu "…" của group chat. Mở app **Workflows** (thanh bên trái, hoặc **Apps › Workflows**) › **Create** › mẫu **"Send webhook alerts to a chat"** (bản cũ: *"Post to a chat when a webhook request is received"*) › **Post in: Group chat**, chọn đúng chat › sao chép **URL webhook**. Cũng tạo được ở make.powerautomate.com với cùng mẫu. Mở mạng ra host trong URL (thường `*.environment.api.powerplatform.com` hoặc `*.logic.azure.com`) |

Quyền đọc group chat cho app đọc chat (Microsoft Graph, quyền ứng dụng):

| Cách | Phạm vi | Ghi chú |
|---|---|---|
| **`ChatMessage.Read.Chat`** (resource-specific consent) — *khuyến nghị* | Chỉ đúng group chat đã cài app | Cần đóng gói app thành Teams app có khai báo quyền RSC và cài vào group chat ([hướng dẫn RSC](https://learn.microsoft.com/microsoftteams/platform/graph-api/rsc/resource-specific-consent)) |
| **`Chat.Read.All`** (Application) | Mọi chat trong tenant | Cần admin consent; đơn giản hơn nhưng phạm vi rộng — app vẫn chỉ đọc đúng Chat ID đã cấu hình |

*Tùy chọn:* thêm **`ChatMember.Read.Chat`** (RSC) hoặc **`ChatMember.Read.All`** để nút *Kiểm tra kết nối* liệt kê toàn bộ
thành viên group chat (kèm tenant, email) khi ủy quyền. Không có quyền này, app chỉ liệt kê người đã gửi tin gần đây.

### 3.3 Mạng & tài nguyên

| Chiều | Đích | Cổng | Dùng cho |
|---|---|---|---|
| Ra | IP quản trị từng firewall | 4444 (cổng Admin Console) | chặn IP, VPN |
| Ra | máy chủ SMTP / relay | 25 / 465 / 587 | nhắc hạn, báo cáo, cảnh báo |
| Ra | `login.microsoftonline.com` | 443 | đăng nhập Entra + token Graph |
| Ra | `graph.microsoft.com` | 443 | đọc group chat (tự động chặn) |
| Ra | host webhook Workflows (`*.logic.azure.com` / `*.api.powerplatform.com`) | 443 | trả lời vào group chat |
| Vào | người dùng → app | 8080 (Ingress / NodePort 30988 / App Proxy) | giao diện, API |

- **Tài nguyên** mặc định của pod app: 100m CPU / 192 MiB (request) → 1 CPU / 512 MiB (limit). Postgres có PVC 5 GiB.
  Như vậy đủ cho vài chục firewall và báo cáo dài tới 366 ngày.
- **`MASTER_KEY`** mã hóa mật khẩu firewall, mật khẩu SMTP, client secret Graph và URL webhook. **Mất key thì phải nhập lại
  toàn bộ** các thông tin này. Sao lưu key ở KeePass / Vault và không commit vào Git.

---

## 4. Triển khai

Image dựng sẵn do GitHub Actions đẩy lên `ghcr.io/luongminhphu/firewall-api-mgmt` (`linux/amd64`). Các tag:

- `latest` / `main`: mỗi lần push lên main;
- `2.2.0` / `2.2`: khi gắn tag `v2.2.0`;
- `sha-xxxxxxx`: theo commit.

Image đã gồm mọi thư viện (kể cả `openpyxl`, `reportlab`, `Pillow` cho báo cáo) và font nhúng. Bảng dữ liệu tự tạo khi app
khởi động, **không cần chạy migrate**.

### 4.1 Docker Compose

Dùng cho một máy chủ đơn.

```bash
git clone https://github.com/luongminhphu/firewall-api-mgmt.git sophos-blocker && cd sophos-blocker
cp .env.example .env
openssl rand -hex 32   # dán vào MASTER_KEY
openssl rand -hex 32   # dán vào SESSION_SECRET
# đổi APP_PASSWORD, POSTGRES_PASSWORD; đặt APP_BASE_URL = địa chỉ người dùng mở app
docker compose up -d --build
docker compose logs -f app
```

Mở `http://<ip-server>:8080`, đăng nhập bằng `APP_PASSWORD`, rồi làm tiếp [mục 5](#5-cài-đặt-ban-đầu-sau-triển-khai).

### 4.2 Rancher (RKE2 / K3s)

Manifest dùng Kustomize theo ba lớp:

| Thư mục | Nội dung |
|---|---|
| `deploy/k8s/base/` | Namespace `sophos-blocker` · ConfigMap · PostgreSQL 16 StatefulSet + PVC 5 GiB · Deployment app (1 replica, `runAsNonRoot`) · Service NodePort `30988` · NetworkPolicy (DB chỉ nhận kết nối từ app) |
| `deploy/k8s/overlays/prod/` | Cấu hình riêng của site trong `local-config.yaml`. File này **không có trong Git**, nên `git pull` không ghi đè |
| `deploy/k8s/overlays/rancher/` | Dựng trên `prod` · **Ingress** (ingress-nginx) · mẫu gắn Rancher Project · ghim tag image · NetworkPolicy egress (tùy chọn) |

**Bước 0 — Yêu cầu.**
- Cụm RKE2/K3s đã import vào Rancher, có **StorageClass** (manifest mặc định `longhorn`; K3s thường là `local-path`).
- Có `kubectl` trỏ vào cụm: Rancher UI ▸ cluster ▸ **Download KubeConfig**, hoặc dùng **Kubectl Shell** ngay trên trình duyệt.
- Mạng ra ngoài theo [mục 3.3](#33-mạng--tài-nguyên).

**Bước 1 — Mã nguồn và StorageClass.**

```bash
git clone https://github.com/luongminhphu/firewall-api-mgmt.git && cd firewall-api-mgmt
kubectl get storageclass
```

Sửa `storageClassName` trong `deploy/k8s/base/postgres.yaml` cho khớp cụm. **Phải sửa trước lần cài đầu**, vì
`volumeClaimTemplates` của StatefulSet không sửa được sau khi đã tạo.

**Bước 2 — Namespace và imagePullSecret** (chỉ cần khi package GHCR để private).

```bash
kubectl create namespace sophos-blocker
```

```bash
kubectl -n sophos-blocker create secret docker-registry ghcr-pull \
  --docker-server=ghcr.io --docker-username=<github-user> --docker-password=<PAT có quyền read:packages>
```

Có thể làm bằng giao diện: Rancher UI ▸ **Projects/Namespaces** ▸ *Create Namespace*, và **Storage ▸ Secrets ▸ Create ▸ Registry**
(tên `ghcr-pull`).

**Bước 3 — Secret của app** (không commit).

```bash
kubectl -n sophos-blocker create secret generic soc-rapid-block-secrets \
  --from-literal=MASTER_KEY=$(openssl rand -hex 32) \
  --from-literal=SESSION_SECRET=$(openssl rand -hex 32) \
  --from-literal=APP_PASSWORD='DoiMatKhauNay@2026' \
  --from-literal=POSTGRES_PASSWORD=$(openssl rand -hex 24) \
  --from-literal=OIDC_CLIENT_SECRET='<client-secret-app-đăng-nhập>' \
  --dry-run=client -o yaml | kubectl apply -f -
```

Lưu lại `MASTER_KEY` bằng lệnh dưới. **Không đổi `POSTGRES_PASSWORD`** sau khi DB đã khởi tạo, vì Postgres chỉ đọc biến
này ở lần chạy đầu. Client secret của app đọc chat và URL webhook Workflows **không** đặt ở đây; quản trị viên nhập trên
giao diện, app lưu mã hóa.

```bash
kubectl -n sophos-blocker get secret soc-rapid-block-secrets -o jsonpath='{.data.MASTER_KEY}' | base64 -d
```

**Bước 4 — Cấu hình site.**

```bash
cp deploy/k8s/overlays/prod/local-config.example.yaml deploy/k8s/overlays/prod/local-config.yaml
```

Trong `local-config.yaml`, chỉ ghi các khóa khác với `base/configmap.yaml`. Thường gồm:
- `AUTH_MODES`;
- `OIDC_TENANT_ID` / `OIDC_CLIENT_ID` / `OIDC_REDIRECT_URI`;
- **`APP_BASE_URL`** (dùng cho link trong email);
- `SAFE_LIST`;
- `AUTOBLOCK_POLL_SECONDS` (chu kỳ đọc Teams ban đầu).

Chưa dùng Entra thì đặt `AUTH_MODES: "local"`.

**Bước 5 — Ingress, Project, egress** (overlay `rancher`).

`deploy/k8s/overlays/rancher/ingress.yaml`:
- **`host` / TLS:** tên miền nội bộ, hoặc tên miền mà connector App Proxy trỏ tới; chứng chỉ qua cert-manager hoặc
  `kubectl create secret tls`.
- **Timeout:** đã đặt `proxy-read-timeout` / `proxy-send-timeout` = 120s. Giá trị này phải **lớn hơn** `JOB_SYNC_WAIT` (20s),
  nếu không request chặn IP bị cắt thành 504.
- **Kích thước body:** `proxy-body-size` = 5m, đủ cho logo và file CSV.

`deploy/k8s/overlays/rancher/kustomization.yaml`, bỏ comment các khối cần dùng:
- **Gắn Project:** `field.cattle.io/projectId: "c-xxxxx:p-yyyyy"` (lấy ở Rancher ▸ Projects/Namespaces ▸ ⋮ ▸ *View in API*).
- **Ghim tag image:** `ghcr.io/luongminhphu/firewall-api-mgmt:2.2.0` thay cho `latest`. Khuyến nghị cho môi trường thật.
- **`networkpolicy-egress.yaml`:** sửa CIDR firewall và SMTP trước khi bật. Policy đã mở 443 ra Internet (trừ dải nội bộ),
  đủ cho Entra, Graph và Workflows.

> **K3s dùng Traefik:** đổi `ingressClassName: traefik` và bỏ các annotation `nginx.ingress…`.
> Không muốn dùng Ingress thì xóa `ingress.yaml` khỏi kustomization và truy cập qua NodePort `30988`.

**Bước 6 — Triển khai.**

```bash
kubectl kustomize deploy/k8s/overlays/rancher/ | less        # xem trước
kubectl apply -k deploy/k8s/overlays/rancher/
kubectl -n sophos-blocker rollout status statefulset/soc-rapid-block-db
kubectl -n sophos-blocker rollout status deployment/soc-rapid-block-app
curl -s https://<host>/api/health     # {"status": "ok", "app": "SOC Rapid Block", "version": "2.2.0"}
```

Có thể làm bằng giao diện: Rancher ▸ **Import YAML**, dán kết quả `kubectl kustomize …`, chọn namespace `sophos-blocker`.

**Bước 7 — Truy cập từ Internet.** Dùng Entra Application Proxy + MFA: connector trỏ tới host Ingress hoặc
`http://<node-ip>:30988` ([`docs/entra-app-proxy.md`](docs/entra-app-proxy.md)). Với Kubernetes nên dùng `AUTH_MODES=oidc`
thay cho header SSO.

**Vận hành trên Rancher:**

| Việc | Lệnh / thao tác |
|---|---|
| Nâng cấp | Đổi tag image rồi chạy lại `kubectl apply -k deploy/k8s/overlays/rancher/`. Nếu dùng `latest`: `kubectl -n sophos-blocker rollout restart deploy/soc-rapid-block-app` |
| Rollback | `kubectl -n sophos-blocker rollout undo deploy/soc-rapid-block-app`. Schema chỉ **thêm** bảng/cột nên bản cũ vẫn chạy trên DB mới |
| Log | `kubectl -n sophos-blocker logs deploy/soc-rapid-block-app -f`; đặt `LOG_FORMAT=json` để đẩy vào Loki/ELK |
| Replica | 1 là đủ. 2 replica vẫn an toàn vì các bộ lập lịch (cache, VPN, email, rà soát, **đọc Teams**) dùng `pg_advisory_lock`. **Postgres luôn 1 replica** |
| Sao lưu DB | `kubectl -n sophos-blocker exec soc-rapid-block-db-0 -- pg_dump -U sophos -Fc sophos_blocker > srb-$(date +%F).dump`, kèm snapshot Longhorn |
| Khôi phục | `kubectl -n sophos-blocker exec -i soc-rapid-block-db-0 -- pg_restore -U sophos -d sophos_blocker --clean < srb-….dump`, với **cùng `MASTER_KEY`** |
| GitOps (Fleet) | Continuous Delivery ▸ Git Repos, path `deploy/k8s/overlays/rancher`. `local-config.yaml` cần để ở repo cấu hình riêng của site |
| Gỡ cài đặt | `kubectl delete -k deploy/k8s/overlays/rancher/`. PVC không tự xóa |

> **Pod Security Admission:** nếu cụm áp mức `restricted` thì gắn nhãn
> `kubectl label ns sophos-blocker pod-security.kubernetes.io/enforce=baseline`. Lý do: Postgres chạy bằng user của image, và
> cả hai pod chưa khai báo `seccompProfile`.

### 4.3 KubeSphere

Dùng chung `base/` và `overlays/prod/`: `kubectl apply -k deploy/k8s/overlays/prod/`. Hướng dẫn import qua UI KubeSphere
ở [`deploy/k8s/kubesphere/README.md`](deploy/k8s/kubesphere/README.md).

### 4.4 Nâng cấp từ bản cũ lên 2.2

1. **Sao lưu DB** (lệnh ở bảng vận hành trên) và kiểm tra lại `MASTER_KEY`.
2. **Đổi image** sang `2.2.0` (hoặc `rollout restart` nếu dùng `latest`). Không cần migrate tay: khi khởi động, app tự
   tạo bảng mới và **tự thêm cột mới** vào bảng đã có (log `Nâng cấp DB: thêm cột …`). Bằng chứng ghi trước khi nâng cấp
   vẫn kiểm tra toàn vẹn được.
3. **Tùy chọn trong ConfigMap / `local-config.yaml`:**
   - thêm `AUTOBLOCK_POLL_SECONDS` (mặc định 300);
   - đặt `APP_BASE_URL` nếu chưa có, vì link trong email và báo cáo dùng giá trị này.
4. **Mạng:** mở 443 ra `graph.microsoft.com` và host webhook Workflows nếu dùng tự động chặn ([mục 3.3](#33-mạng--tài-nguyên)).
5. **Sau khi nâng cấp:**
   - Tự động chặn **mặc định tắt**; cấu hình theo [mục 5](#5-cài-đặt-ban-đầu-sau-triển-khai), bước 5.
   - Báo cáo dùng được ngay với dữ liệu lịch sử thay đổi sẵn có.
   - Giao diện mới không cần cấu hình gì thêm.

### 4.5 Biến môi trường

Đặt trong `.env` (Compose) hoặc ConfigMap / `local-config.yaml` / Secret (Kubernetes). Mục ghi *Cài đặt* chỉ là giá trị
ban đầu; quản trị viên chỉnh lại trên giao diện.

| Biến | Ý nghĩa |
|---|---|
| `MASTER_KEY` | **Bắt buộc**, ≥ 16 ký tự. Khóa mã hóa credential firewall, SMTP, Graph, webhook. **Secret** |
| `APP_PASSWORD` | Mật khẩu chung để đăng nhập lần đầu / khẩn cấp. **Secret** |
| `SESSION_SECRET` | Khóa ký phiên; để trống thì mỗi lần restart mọi người phải đăng nhập lại. **Secret** |
| `POSTGRES_PASSWORD` / `OIDC_CLIENT_SECRET` | Mật khẩu DB / client secret của app đăng nhập. **Secret** |
| `DATABASE_URL` | Chuỗi kết nối PostgreSQL (manifest k8s tự ghép) |
| `FW_HEALTH_MINUTES` | Chu kỳ kiểm tra kết nối XML API từng firewall (5 phút; 0 = tắt). Cần job email (`NOTIFY_INTERVAL_SECONDS` > 0) để cảnh báo được gửi |
| `DB_POOL_SIZE` / `DB_MAX_OVERFLOW` | Pool kết nối PostgreSQL mỗi pod (5 / 10). Tăng khi chặn trên nhiều firewall cùng lúc; tổng × số pod phải nhỏ hơn `max_connections` |
| `APP_BASE_URL` | Địa chỉ người dùng mở app, dùng cho link trong email nhắc hạn, rà soát, tự động chặn |
| `SESSION_TTL_HOURS` | Thời hạn phiên (mặc định 8 giờ) |
| `SAFE_LIST` / `ALLOW_PRIVATE` | Dải **không bao giờ** bị chặn · cho phép chặn IP private (mặc định `false`) |
| `API_TIMEOUT` / `API_CONNECT_TIMEOUT` | Timeout gọi firewall / timeout kết nối (mặc định 30 / 10 giây) |
| `SOPHOS_BATCH_SIZE` / `FW_PARALLEL` | Số IP Host gộp trong một lệnh (50) / số firewall xử lý song song (4) |
| `JOB_SYNC_WAIT` | Request chặn/bỏ chặn chờ tối đa N giây (20) rồi chạy nền. Phải **nhỏ hơn** timeout của App Proxy (~85s) và Ingress |
| `GROUP_CACHE_TTL_MINUTES` / `GROUP_CACHE_DAILY_AT` | Chu kỳ quét đầy đủ IP Host Group (1440 phút) / giờ quét hằng ngày (02:00) |
| `GROUP_CACHE_REFRESH_WAIT` / `GROUP_CACHE_MIN_REFRESH_SECONDS` / `GROUP_CACHE_ERROR_RETRY_MINUTES` / `GROUP_CACHE_WARMUP` | Tinh chỉnh cache group (8 giây / 5 giây / 30 phút / `true`) |
| `GROUP_SCAN_TIMEOUT` / `HOST_LOOKUP_LIMIT` | Timeout quét đầy đủ (180 giây) / số object tra cứu từng cái (25) |
| `AUTOBLOCK_POLL_SECONDS` | Chu kỳ đọc group chat Teams **ban đầu** (300 giây). *Cài đặt* (1–60 phút). `0` = tắt hẳn bộ đọc |
| `AUTOBLOCK_OVERLAP_SECONDS` | Đọc chồng N giây trước mốc lần trước, bù độ trễ của Graph (120); tin trùng tự bỏ qua |
| `VPN_SYNC_MINUTES` / `VPN_SCAN_TIMEOUT` | Chu kỳ đồng bộ VPN (360 phút; `0` = chỉ đồng bộ tay) / timeout đọc (180 giây) |
| `VPN_RULE_GROUPS` / `VPN_EXPIRING_DAYS` | Rule Group được đọc (`VPN`, trong whitelist mã nguồn) / ngưỡng "sắp hết hạn" (30). *Cài đặt* |
| `NOTIFY_INTERVAL_SECONDS` / `SMTP_TIMEOUT` | Chu kỳ lập kế hoạch + gửi email (300 giây) / timeout SMTP (15 giây). Máy chủ SMTP cấu hình ở *Cài đặt* |
| `AUTH_MODES` / `LOCAL_ROLE` | `local`, `oidc`, `header` (kết hợp bằng dấu phẩy) / vai trò cho mật khẩu chung (`admin`) |
| `OIDC_TENANT_ID` / `OIDC_CLIENT_ID` / `OIDC_REDIRECT_URI` | App đăng nhập Entra; redirect = `<URL ngoài>/api/auth/oidc/callback` |
| `OIDC_AUTO_LOGIN` / `OIDC_PROMPT` / `OIDC_DOMAIN_HINT` | SSO một lần qua App Proxy (`true` / để trống / vd `hsc.com.vn`) |
| `OIDC_REQUIRE_MFA_CLAIM` / `OIDC_ALLOW_GUESTS` | Từ chối token có `amr` thiếu `mfa` / từ chối tài khoản khách (mặc định `false`) |
| `ROLE_ADMIN` / `ROLE_OPERATOR` / `ROLE_VIEWER` | Tên App Role (`SRB.Admin` / `SRB.Operator` / `SRB.Viewer`) |
| `TRUSTED_PROXY_CIDRS` / `HEADER_USER` / `HEADER_NAME` / `HEADER_ADMINS` / `HEADER_OPERATORS` / `HEADER_DEFAULT_ROLE` | Header SSO qua App Proxy |
| `SHARED_PASSWORD_LOGIN` / `USERS_STRICT` | Cho dùng mật khẩu chung (`true`) / chỉ chấp nhận người có trong tab Người dùng (`false`) |
| `PASSWORD_MIN_LENGTH` / `LOGIN_MAX_FAILS` / `LOGIN_LOCK_MINUTES` | Chính sách mật khẩu tài khoản riêng (10 / 5 lần / 10 phút) |
| `LOGO_MAX_KB` | Dung lượng tối đa của logo tải lên (300). Logo hiện trên giao diện và **header báo cáo** |
| `LOG_FORMAT` / `LOG_LEVEL` | `text` hoặc `json` (một dòng, có `request_id`, không bao giờ ghi mật khẩu/token) / mức log |

---

## 5. Cài đặt ban đầu sau triển khai

Thao tác trên giao diện, bằng tài khoản quản trị viên. Mỗi mục cấu hình đều có nút **ⓘ** cạnh tên: rê chuột, bấm Tab hoặc
chạm vào để xem hướng dẫn (điền gì, lấy ở đâu, ví dụ).

1. **Người dùng.** Đăng nhập bằng `APP_PASSWORD` (hoặc Microsoft). Ở tab **Người dùng**:
   - tạo tài khoản cho từng người: Readonly / Write / Quản trị viên; loại *Microsoft* (tên đăng nhập = UPN) hoặc *Mật khẩu riêng*;
   - tải **logo** ở *Cài đặt › Giao diện* (dùng cả trên giao diện và header báo cáo).

   Khi đã có quản trị viên đăng nhập được, đặt `SHARED_PASSWORD_LOGIN=false`.
2. **Firewall.** Ở tab **Firewall**, thêm từng firewall (tên, IP/host, cổng 4444, tài khoản API) rồi bấm **Kiểm tra tất cả**.
3. **SMTP.** Ở *Cài đặt › Email & thông báo › Máy chủ email*, nhập máy chủ, cổng, bảo mật, tài khoản, địa chỉ gửi, tick **Bật gửi email**, rồi **Gửi thử**.
4. **VPN, nhắc hạn và rà soát** (nếu dùng):
   - *Cài đặt › VPN & rà soát*: chọn **firewall có VPN** (firewall không cấu hình VPN thì bỏ chọn), ngưỡng hạn, lịch rà soát;
   - *Cài đặt › Email & thông báo*: email Infra, các mốc nhắc, đại diện từng team.

   Sau đó vào tab **VPN** › **Đồng bộ ngay**.
5. **Tự động chặn từ Teams** (*Cài đặt › Tự động chặn (Teams)*, form chia 6 bước đánh số, nút **Lưu** luôn ở đáy):
   1. Nhập Tenant ID, Client ID, Client secret của **app đọc chat**, và Chat ID ([mục 3.2](#32-microsoft-entra-id--teams)).
   2. **Người được gửi lệnh.** Bấm **Kiểm tra kết nối**: app liệt kê thành viên group chat kèm tenant, email và nhãn
      *External* / *HSC*. Bấm **"+ Ủy quyền"** cạnh **từng** thành viên SOC của đối tác và từng thành viên IT Security
      của HSC. Tài khoản được gắn tenant. Có thể dùng thêm nhóm Entra cho thành viên HSC.
   3. **Lịch tự chặn & giới hạn:** ngoài giờ ngày thường, cuối tuần, ngày lễ; ngưỡng IP/giờ, chu kỳ đọc, ngưỡng lệnh cũ.
   4. **Whitelist:** dải public HSC, dải Akamai (SiteShield / Origin IP ACL), IP đối tác; mỗi dòng một IP/CIDR.
   5. **Trả lời vào group chat:** dán URL webhook Workflows, bấm **Gửi thử** và kiểm tra tin trong Teams.
   6. Nhập **email nhóm Admin** và chọn **firewall đích**. Tick **Bật** rồi **Lưu**. App chỉ xử lý tin gửi **sau** lúc bật.
   7. **Thống nhất với SOC** cú pháp `ĐỀ XUẤT CỦA SOC: BLOCK IP <ip>` (dòng riêng, IN HOA) và quy định *sửa tin thì gửi lại tin mới*.
6. **Báo cáo.** Mở tab **Báo cáo**, tải thử PDF / Excel và gửi thử email cho chính mình.

---

## 6. Hướng dẫn sử dụng theo tab

Thứ tự theo menu: **Tổng quan** · **Vận hành** (Chặn nhanh · Tự động chặn · IP Host Group · Firewall) · **Giám sát** (Lịch sử thay đổi ·
Audit log · Báo cáo) · **VPN & tuân thủ** (VPN · Rà soát) · **Quản trị** (Cài đặt · Người dùng).

### 6.0 Tổng quan

Quản trị viên mở app (không kèm `#tab`) sẽ vào thẳng trang này. Write / Readonly vẫn vào **Chặn nhanh** để ca trực thao tác nhanh,
nhưng vẫn mở được Tổng quan từ menu.

- **Cần xử lý**: chỉ liệt kê việc có vấn đề. **Nghiêm trọng** (đỏ) xếp trước **Cảnh báo** (cam); không có gì thì hiện "Không có việc cần xử lý".
  Bấm một dòng để mở tab xử lý.
- **Thẻ module**: Firewall (theo kết quả quét cache gần nhất, không phải lần bấm Kiểm tra), IP Host Group, Tự động chặn (chế độ: chưa bật đọc
  Teams / đã ngắt / công tắc khẩn cấp TẮT / trong hoặc ngoài lịch), VPN, Rà soát, Sửa ngoài app (7 ngày), 7 ngày qua, Email lỗi (7 ngày, chỉ quản trị viên).
- Một nguồn dữ liệu lỗi thì chỉ thẻ đó báo "Không đọc được", phần còn lại vẫn hiện. Trang chỉ tải khi mở hoặc bấm **Làm mới**.

**Link mở thẳng trang đã lọc** (dán vào email / ticket; nếu phải đăng nhập Microsoft, app vẫn mở đúng link sau khi đăng nhập):

| Link | Mở |
|---|---|
| `#changes?q=1.2.3.4` | Lịch sử thay đổi của IP (khoá: `q`, `fw` = id firewall, `type`, `actor`, `from` / `to` = YYYY-MM-DD) |
| `#changes?type=drift&from=2026-11-21` | Các lần sửa ngoài app từ ngày đó |
| `#audit?q=1.2.3.4` | Audit log (khoá: `q`, `action`) |
| `#groups?fw=2&q=1.2.3` | IP Host Group của firewall 2, lọc thành viên |
| `#vpn?status=expired_enabled` | Rule VPN hết hạn còn bật (khoá: `status`, `fw`, `q`) |

Link có tham số thì bộ lọc của trang được đặt lại theo đúng link; khoá lạ hoặc giá trị sai bị bỏ qua. Trang **Chặn nhanh** không bao giờ
nhận tham số (link lạ không thể điền sẵn IP để chặn).

### 6.1 Chặn nhanh

1. Chọn nguồn: **Dán từ Teams** (tự bóc IPv4/CIDR, kể cả dạng làm mờ), **Nhập tay**, hoặc **CSV/TXT** (kéo-thả).
2. Tick firewall đích và điền lý do / số ticket. Group đích luôn là **`SCANPORT GROUP`** (khóa, không sửa được).
3. Tick **Chạy thử** để xem trước, kèm XML IPHostGroup đúng mẫu Sophos.
4. Bấm **Chặn ngay**. Thanh tiến độ hiện từng firewall. Nếu chạy lâu hơn `JOB_SYNC_WAIT`, việc chặn chuyển sang chạy nền;
   giao diện vẫn theo dõi tiếp và không bị 504.

<details><summary>Payload IPHostGroup gửi lên firewall</summary>

```xml
<Set operation="update">
  <IPHostGroup>
    <Name>SCANPORT GROUP</Name>
    <IPFamily>IPv4</IPFamily>
    <Description>(giữ nguyên mô tả hiện có)</Description>
    <HostList><Host>45.138.12.16</Host><Host>185.220.101.0/24</Host></HostList>
  </IPHostGroup>
</Set>
```

App tạo IP Host trước (gộp tối đa `SOPHOS_BATCH_SIZE` object trong một lệnh), rồi ghi lại toàn bộ `HostList` (cũ + mới).
</details>

### 6.2 Tự động chặn (từ Teams)

**Quy ước với SOC.** Thêm **một dòng riêng, viết IN HOA** vào tin trong group chat:

```
ĐỀ XUẤT CỦA SOC: BLOCK IP 195.178.110.102
```

- **Khớp chính xác.**
  - Chữ thường (`Đề xuất của SOC: block ip …`), hoặc lệnh lẫn trong một câu dài, đều **không** được nhận.
  - Một tin có thể chứa nhiều dòng lệnh. Chỉ nhận IPv4 đơn; CIDR, dải, IPv6 hay tên miền bị ghi "Không hợp lệ".
- **Ai được gửi lệnh:** chỉ những người được **ủy quyền đích danh**, theo một trong hai cách:
  - **Tài khoản được ủy quyền** (Object ID, gắn tenant): từng thành viên SOC của đối tác (vd HPT) và từng thành viên
    HSC được ủy quyền (vd IT Security). Tin phải đến đúng từ tenant đã gắn;
  - **Nhóm Entra của HSC** (vd `IT-Security`, SOC nội bộ, khách B2B): app đọc thành viên mỗi 30 phút, và đọc lại ngay khi
    gặp người gửi lạ.

  App **không** tin cậy cả tenant, kể cả tenant của đối tác SOC: người khác của đối tác (vd account manager) hay nhân viên
  HSC trong cùng chat đều không gửi được lệnh. Lệnh của họ bị bỏ qua và ghi sự kiện. Khi đối tác **đổi người trực**, quản
  trị viên ủy quyền người mới (bấm *Kiểm tra kết nối* › **+ Ủy quyền**) và xóa người đã rời team. Mỗi lệnh và bản chụp
  bằng chứng ghi rõ *tin cậy theo* cách nào (vd "Tài khoản Phạm C (HPT SOC)", "Nhóm IT-Security").
- **Tin đã sửa bị bỏ qua.** Gõ nhầm thì gửi tin mới.
- **Thời điểm lệnh** là lúc SOC gửi tin, theo giờ của Microsoft.
- Chặn xong, app trả lời vào chat: `INFRA ĐÃ BLOCK 195.178.110.102 THEO YÊU CẦU LÚC 18/11/2026 23:42:10`.

**Cách app xử lý mỗi lệnh** (theo thứ tự):

| Điều kiện | Kết quả |
|---|---|
| IP nội bộ / thuộc `SAFE_LIST` | Không hợp lệ, không chặn |
| IP đang có lệnh chờ hoặc đang chặn | Trùng, bỏ qua |
| IP thuộc **whitelist** (HSC / Akamai / đối tác…) | **Chờ duyệt**, chỉ **quản trị viên Approve**; không tính vào ngưỡng |
| **Công tắc khẩn cấp** đang tắt | Chờ duyệt |
| Lệnh **cũ** (đọc trễ quá ngưỡng, mặc định 30 phút) | Chờ duyệt, ghi rõ trễ bao lâu |
| SOC gửi **trong giờ hành chính** (ngoài lịch tự chặn) | Chờ duyệt |
| Đã **vượt ngưỡng** N IP/giờ (mặc định 20) | **Ngắt**: lệnh này và mọi lệnh sau chờ duyệt, email nhóm Admin ngay; quản trị viên bấm **Mở lại** |
| Còn lại | **Tự chặn** trên mọi firewall đích |

**Lịch tự chặn:**

| Loại ngày | Tự chặn |
|---|---|
| Ngày thường | Ngoài giờ, mặc định **18:00 → 08:00** sáng hôm sau |
| Thứ 7, Chủ nhật | Cả ngày (tùy chọn, mặc định bật) |
| Ngày lễ rơi vào ngày thường | Cả ngày, theo danh sách ngày lễ (một ngày hoặc cả đợt) |
| Nghỉ đột xuất | Nút **Tự chặn cả ngày hôm nay** |
| Bỏ tick "Chỉ tự chặn theo lịch" | 24/7 |

Các khoảng liền nhau gộp thành **một ca ngoài giờ** (vd 18:00 thứ 6 → 08:00 thứ 2).

**Trên tab:**
- **Thẻ trạng thái:** công tắc, số IP tự chặn trong 60 phút / ngưỡng, lịch đang áp dụng, số lệnh chờ duyệt, lần đọc Teams
  gần nhất (kèm số tin mới).
- **Tắt khẩn cấp** (Write trở lên) · **Bật lại** (quản trị viên) · **Đọc Teams ngay** · **Tự chặn cả ngày hôm nay** (quản trị viên).
- **Chờ duyệt:** **Approve** (chọn nhiều mục được) hoặc **Từ chối**. Mục thuộc whitelist có nhãn *Whitelist · Akamai: 23.32.0.0/11*.
- **Ca ngoài giờ:** IP đã tự chặn trong ca gần nhất. Khi vào ca, rà lại và **Gỡ chặn** từng IP hoặc **Gỡ tất cả IP của ca**.
  App email danh sách cho nhóm Admin khi ca kết thúc.
- **Tất cả lệnh:**
  - lọc theo trạng thái; xem kết quả trên từng firewall và *Đã báo Teams* / *Chưa báo Teams*;
  - nút **Bằng chứng** mở bản chụp tin gốc;
  - nút **Kiểm tra toàn vẹn nhật ký** xác minh chuỗi băm của sự kiện và bản chụp.

**Bằng chứng khi người gửi xóa hoặc sửa tin.**
- **Lúc nhận lệnh** (trước khi chặn), app chụp lại:
  - nguyên văn tin do Microsoft Graph trả về và nội dung văn bản;
  - người gửi (tên, Object ID), Message ID, Chat ID;
  - giờ gửi theo Microsoft, giờ app nhận;
  - SHA-256 của bản gốc. Các bản chụp nối chuỗi băm.
- **Tin bị xóa hoặc sửa sau đó:** bản chụp không đổi; app ghi thêm thời điểm xóa/sửa (giờ Microsoft) và lúc phát hiện.
  Hộp thoại hiện *"Tin đã bị XÓA trên Teams lúc …"*.
- **Tải bằng chứng (JSON):** file chứa `graph_message_raw`. Kiểm chứng độc lập: `SHA-256(graph_message_raw) = evidence.sha256`.

### 6.3 IP Host Group

Xem và tìm thành viên `SCANPORT GROUP` trên từng firewall. Dữ liệu lấy từ cache nên hiện ngay; thẻ tổng quan cho biết số IP,
lần quét gần nhất và trạng thái. **Quét lại** đọc trực tiếp từ firewall. Tick IP rồi **Bỏ chặn**; có tùy chọn xóa luôn
IP Host do app tạo.

### 6.4 Firewall

Thêm / sửa / xóa firewall (quản trị viên). **Kiểm tra** thử đăng nhập API và kiểm tra `SCANPORT GROUP`. Mật khẩu được mã hóa
và không bao giờ hiển thị lại.

### 6.5 Lịch sử thay đổi

Dòng thời gian mọi thay đổi thành viên group: người thực hiện, phương thức đăng nhập, lý do, nguồn (`teams-auto` khi app tự
chặn), số object trước → sau, từng IP `+` / `−`.
- **Thay đổi ngoài app** (sửa trực tiếp trên WebAdmin) hiện bằng thẻ cam.
- Lọc theo firewall, loại, người, khoảng ngày. Ô tìm IP trả lời nhanh *"IP này bị chặn bởi ai, khi nào, vì sao, đã gỡ chưa"*.
- Kiểm tra chuỗi băm · xuất CSV.

### 6.6 Audit log

Ghi mọi thao tác: ai, lúc nào, IP nào, firewall nào, kết quả. Có bộ lọc và xuất CSV. Một số loại sự kiện đáng chú ý:

| Sự kiện | Ý nghĩa |
|---|---|
| `policy_violation` | Lệnh bị chính sách chặn |
| `login` / `user_mgmt` | Đăng nhập / quản lý người dùng |
| `autoblock_switch` / `autoblock_decision` | Bật/tắt công tắc, ngắt ngưỡng / Approve, từ chối |
| `evidence_export` | Tải file bằng chứng |
| `report_export` / `report_email` | Tải / gửi báo cáo |
| `settings_cud` | Thay đổi cấu hình |

### 6.7 Báo cáo

1. **Chọn kỳ:** 7 / 14 / 30 ngày, hoặc **Chọn trên lịch** (từ ngày → đến ngày, tối đa 366 ngày).
2. **Executive Summary:**
   - câu tổng quan và 6 chỉ số: IP bị chặn, thủ công, tự động, tỷ lệ tự động, lượt chặn, thời gian SOC gửi → chặn xong;
   - **nhận định nổi bật**: ngày cao điểm, trung bình IP/ngày, lệnh SOC, người chặn nhiều nhất;
   - **cần lưu ý / hành động**: lệnh chờ duyệt, đề xuất chặn IP thuộc whitelist, lệnh lỗi hoặc sai cú pháp.
3. **Chi tiết:** biểu đồ theo ngày (thủ công / tự động), bảng người thực hiện, danh sách IP (thời gian thực hiện, phương
   thức, người / kênh, firewall, đang chặn / đã gỡ, lý do).
4. **Tải PDF** (bản trình lãnh đạo):
   - A4 ngang theo **HSC Design System**: font Inter / Inter Display; màu navy `#0B2D5C`, brand `#2681FF`, brand-deep `#00468C`.
   - **Logo ở header.**
   - Trang 1 là Executive Summary, các trang sau là chi tiết.
5. **Tải Excel:** sheet *Executive Summary · Theo ngày* (kèm biểu đồ) *· Danh sách IP · Chi tiết lượt chặn · Người thực hiện*.
6. **Gửi email** (Write trở lên): tối đa 20 người nhận, chọn đính kèm PDF / Excel, thêm ghi chú đầu thư. Thư đi qua SMTP đã
   cấu hình (phải đang bật).

> **Phương thức chặn:**
> - **Tự động** = app tự chặn từ lệnh SOC.
> - **Thủ công** = con người thao tác: chặn tay, **và cả** Approve lệnh SOC đang chờ duyệt.

### 6.8 VPN (chỉ đọc)

- **Dashboard 7 trạng thái:** *Sắp hết hạn · Hết hạn nhưng vẫn bật · User không còn / bị khóa · Không đọc được tên ·
  Lệch thời hạn · Không có hạn · Còn hạn*. Bấm thẻ để lọc.
- **Danh sách rule:** lọc theo firewall, team, khoảng ngày, từ khóa, hoặc *xem tại ngày*. Bấm vào rule để xem chi tiết và lịch sử.
- **Tài khoản VPN:** quyền SSL VPN / IPsec, nhóm, trạng thái khóa; tài khoản đã bị xóa vẫn được giữ.
- **Xuất CSV cần xử lý** để Infra làm trên firewall; app không tự tắt, sửa hay xóa rule. **Đồng bộ ngay** cần quyền Write.

### 6.9 Rà soát (ISO/IEC 27001:2022 A.5.18)

- **Quản trị viên:**
  - mở đợt (tự mở trong 15 ngày đầu quý, hoặc mở tay); app chụp ảnh rule VPN và tài khoản mồ côi tại thời điểm mở;
  - theo dõi tiến độ từng team, quyết định thay khi cần, đóng đợt (mục chưa quyết định ghi "Không phản hồi");
  - tải **CSV bằng chứng** và **CSV cần thu hồi**; kiểm tra chuỗi băm.
- **Đại diện team:**
  - mở link trong email, đăng nhập Microsoft, vào với vai trò **Rà soát** (chỉ thấy mục của team mình);
  - chọn *Còn cần / Thu hồi / Cần điều chỉnh*; *Thu hồi* và *Cần điều chỉnh* bắt buộc ghi lý do.

### 6.10 Cài đặt (quản trị viên)

Bốn nhóm theo công việc vận hành, chọn ở menu con bên trái (trên điện thoại là thanh cuộn ngang). App nhớ nhóm vừa xem.

| Nhóm | Nội dung |
|---|---|
| **Tự động chặn (Teams)** | Một form chia 6 bước, có mục lục nhảy nhanh và nút **Lưu** luôn ở đáy: 1 · Kết nối Microsoft Graph (+ Kiểm tra kết nối) · 2 · Người được gửi lệnh · 3 · Lịch tự chặn & giới hạn (ngày thường / cuối tuần / ngày lễ, ngưỡng IP/giờ, chu kỳ đọc, ngưỡng lệnh cũ) · 4 · Whitelist · 5 · Trả lời vào group chat (webhook) · 6 · Cảnh báo & firewall đích |
| **VPN & rà soát** | Firewall có VPN (chỉ đồng bộ các firewall này), ngưỡng "sắp hết hạn", Rule Group được đọc · rà soát định kỳ (tự mở hằng quý, hạn hoàn thành, nhắc trước hạn) |
| **Email & thông báo** | Máy chủ SMTP (STARTTLS / SSL / không mã hóa, kiểm tra TLS, mật khẩu mã hóa, **Gửi thử**) · thông báo hạn VPN (email Infra, mốc nhắc, báo hằng tuần) · **cảnh báo cho Infra** (firewall mất kết nối, sửa group ngoài giờ — xem dưới) · đại diện team · hàng đợi email (**Chạy ngay**; thư lỗi tự thử lại, lùi dần tới 6 giờ, tối đa 8 lần) |
| **Giao diện** | Logo hiển thị (PNG / JPG / WebP / SVG, ≤ `LOGO_MAX_KB`) — trên thanh trên cùng, màn hình đăng nhập, header báo cáo |

**Cảnh báo cho Infra** (gửi tới email Infra, độc lập với công tắc nhắc hạn VPN):

- **Firewall mất kết nối XML API**: app kiểm tra mỗi `FW_HEALTH_MINUTES` phút (chỉ đọc `SCANPORT GROUP`). Lỗi liên tục quá ngưỡng (mặc định
  15 phút) → một email; kết nối lại → một email. Sai mật khẩu API → app giãn kiểm tra còn 60 phút/lần để không khoá tài khoản API, sửa mật
  khẩu trong tab Firewall thì kiểm tra lại ngay. Tắt firewall khi đang báo lỗi thì không có email "đã kết nối lại".
- **Sửa SCANPORT GROUP trên WebAdmin**: phát hiện trong khoảng một chu kỳ kiểm tra. Chỉ email khi thời điểm phát hiện **ngoài giờ hành chính**
  theo lịch Tự động chặn (ngoài khung giờ, thứ 7, Chủ nhật, ngày lễ) — trong giờ hành chính team network sửa trực tiếp là bình thường, vẫn ghi
  Lịch sử thay đổi. Thời điểm là lúc app phát hiện (lệch tối đa một chu kỳ); nếu tắt kiểm tra định kỳ hoặc firewall mất kết nối, lần sửa có thể
  chỉ được phát hiện muộn (lượt quét hằng ngày) và phân loại theo giờ phát hiện.

### 6.11 Người dùng (quản trị viên)

Thêm / sửa / khóa / xóa người dùng; quyền Readonly / Write / Quản trị viên; loại Microsoft hoặc mật khẩu riêng.
Thay đổi có hiệu lực ngay ở request kế tiếp. Logo nay ở *Cài đặt › Giao diện*.

---

## 7. Phân quyền & cơ chế an toàn

| Quyền | Rà soát | Readonly | Write | Quản trị viên |
|---|---|---|---|---|
| Rà soát mục của team mình | ✓ | ✓ (nếu là đại diện) | ✓ (nếu là đại diện) | ✓ |
| Xem group, lịch sử, audit, VPN, tự động chặn, **báo cáo**, **bằng chứng**; tải PDF / Excel / CSV | — | ✓ | ✓ | ✓ |
| Chặn, bỏ chặn, quét lại, đồng bộ VPN | — | — | ✓ | ✓ |
| Tự động chặn: Approve, từ chối, gỡ chặn, **tắt** khẩn cấp · **gửi email báo cáo** | — | — | ✓ | ✓ |
| Tự động chặn: **Approve IP thuộc whitelist**, bật lại công tắc, mở lại sau khi ngắt ngưỡng, tự chặn cả ngày hôm nay | — | — | — | ✓ |
| Firewall, người dùng, logo, toàn bộ Cài đặt, mở/đóng đợt rà soát | — | — | — | ✓ |

**Đăng nhập & quyền:**
- Quyền được kiểm tra lại **ở mỗi request**.
- Vai trò Rà soát chỉ gọi được API của tab Rà soát.
- Chống tự khóa: luôn phải còn ít nhất một quản trị viên.
- Mật khẩu riêng được băm PBKDF2-SHA256 (310.000 vòng).
- OIDC dùng PKCE và kiểm tra chữ ký JWKS, issuer, audience, tenant, nonce.

**Phía firewall:**
- `SCANPORT GROUP` **gắn cứng trong mã nguồn**.
- `policy.py` phân tích mọi lệnh XML; chỉ cho tạo IP Host, ghi `SCANPORT GROUP`, xóa IP Host do app tạo, và `Get` dữ liệu VPN.
- Trường mật khẩu, hash, khóa IPsec trong phản hồi của firewall bị lọc bỏ trước khi lưu hay ghi log.

**Tự động chặn:**
- Bốn lớp kiểm soát rủi ro: whitelist, lịch tự chặn, ngưỡng IP/giờ, công tắc khẩn cấp.
- Safe-list / IP nội bộ không bao giờ bị chặn. Chỉ chặn `/32` vào `SCANPORT GROUP`, nên chặn nhầm chỉ ảnh hưởng chiều vào từ IP đó.
- Chỉ nhận lệnh từ người được ủy quyền đích danh (tài khoản gắn tenant, hoặc nhóm Entra) — không tin cậy cả tenant,
  kể cả tenant của đối tác SOC. Tin đã sửa và lệnh quá cũ không tự chặn.

**Toàn vẹn dữ liệu:**
- Mật khẩu firewall / SMTP, client secret Graph và URL webhook được mã hóa AES-256-GCM; không bao giờ trả về client.
- Các nhật ký nối **chuỗi băm SHA-256**: lịch sử thay đổi group, lịch sử rule VPN, quyết định rà soát, sự kiện tự động chặn,
  **bản chụp bằng chứng**. Sửa hay xóa trực tiếp trong DB sẽ bị phát hiện.

---

## 8. Xử lý sự cố

| Triệu chứng | Kiểm tra |
|---|---|
| Firewall trả `532` / `534` / `599` | Chưa bật API · IP đi ra của app (trên k8s là IP **node**) chưa có trong Allowed IP · tài khoản API thiếu quyền |
| Kết nối firewall timeout | Đúng cổng Admin Console chưa (thường 4444, không phải 443)? NetworkPolicy egress có chặn không? |
| Lỗi 504 qua Ingress | Timeout của Ingress phải > `JOB_SYNC_WAIT` (xem `overlays/rancher/ingress.yaml`) |
| Pod app `CrashLoopBackOff` | Thiếu `MASTER_KEY`, DB chưa sẵn sàng hoặc sai `POSTGRES_PASSWORD` (`kubectl logs`) |
| Pod Postgres `Pending` / `ErrImagePull` | `storageClassName` không khớp cụm / thiếu secret `ghcr-pull` hoặc PAT hết hạn |
| Đăng nhập Microsoft lỗi | `OIDC_REDIRECT_URI` phải trùng **chính xác** App registration; pod ra được `login.microsoftonline.com` |
| Không nhận được email | *Cài đặt › Email & thông báo › Hàng đợi email*: xem lỗi từng thư · **Gửi thử** · egress tới SMTP |
| Tự động chặn: "Đọc Teams lỗi … 403" | App đọc chat chưa có `ChatMessage.Read.Chat` (RSC) cho group chat, hoặc `Chat.Read.All` chưa được admin consent |
| Tự động chặn: "… 404" | Sai Chat ID (phải có dạng `19:…@thread.v2`) |
| Thành viên SOC mới vào ca gửi lệnh nhưng bị "bỏ qua (người gửi)" | Người đó chưa được ủy quyền: *Kiểm tra kết nối* › **+ Ủy quyền**. Đã ủy quyền mà vẫn bị bỏ qua: tenant gắn với tài khoản không khớp (xem cột *Đơn vị*). Theo nhóm Entra: đã được thêm vào nhóm chưa; tab hiện lỗi "GroupMember.Read.All" nếu app chưa được cấp quyền đọc nhóm |
| Cảnh báo "Bản trước tin cậy cả tenant…" | Nâng cấp từ bản tin cậy theo tenant: cấu hình cũ **không còn hiệu lực**. Ủy quyền từng thành viên SOC rồi bấm *Đã hiểu* |
| *Kiểm tra kết nối* báo "ChatMember.Read…" | App chưa có quyền đọc thành viên chat (tùy chọn); vẫn ủy quyền được từ danh sách người gửi gần đây |
| SOC gửi lệnh nhưng app không chặn | Đúng cú pháp IN HOA, đứng riêng một dòng? Người gửi có trong danh sách SOC? Tin bị sửa? Xem lý do ở *Tất cả lệnh* (whitelist, giờ hành chính, lệnh cũ, ngắt ngưỡng) |
| Cảnh báo "quá nhiều tin mới" | Hơn 1.000 tin trong một chu kỳ; app đọc tiếp ở chu kỳ sau. Cân nhắc rút ngắn chu kỳ đọc |
| "Chưa báo Teams" | URL webhook sai hoặc workflow bị tắt; egress tới `*.logic.azure.com`. App tự thử lại tối đa 5 lần |
| Gửi báo cáo email lỗi | SMTP chưa cấu hình hoặc đang **tắt** (thông báo nêu rõ); máy chủ từ chối người nhận |
| PDF thiếu logo | Logo dạng SVG → PDF dùng biểu tượng mặc định; tải logo PNG / JPG để hiện đúng |
| Excel không hiện font Inter | Máy xem chưa cài Inter → Excel dùng font thay thế (PDF không bị vì font đã nhúng) |
| VPN "Không đọc được tên" | Tên rule cần ngày `dd/mm/yyyy`, hoặc rule gắn Schedule OneTime |

---

## 9. Phát triển & kiểm thử

Chạy cục bộ với các hệ thống giả lập:

```bash
pip install -r backend/requirements.txt
python mock/mock_sophos.py --port 4444            # firewall giả lập: apiadmin / Sophos@123, kèm dữ liệu VPN
python mock/mock_graph.py --port 4470             # Microsoft Graph + Entra token + Teams Workflows giả lập (secret: graph-secret)
python mock/mock_smtp.py --port 2525 --out /tmp/mail.jsonl
export MASTER_KEY=$(openssl rand -hex 32) APP_PASSWORD=socadmin DATABASE_URL=sqlite:////tmp/sb.db \
       GRAPH_BASE_URL=http://127.0.0.1:4470/v1.0 GRAPH_LOGIN_URL=http://127.0.0.1:4470
python -m uvicorn app.main:app --app-dir backend --port 8080
```

API docs có ở `http://localhost:8080/api/docs`.

**Kiểm thử hồi quy:** 32 bộ, chạy được trên SQLite và PostgreSQL.

```bash
bash tests/run_all.sh                                # toàn bộ (tự đặt biến môi trường riêng của từng bộ)
bash tests/run_e2e.sh tests/<tên>_test.py
E2E_DATABASE_URL=postgresql+psycopg2://u:p@127.0.0.1:5432/srb bash tests/run_e2e.sh tests/autoblock_test.py
```

| Bộ test | Bảo vệ |
|---|---|
| `autoblock_test.py` | Cú pháp, team SOC (chỉ thành viên được ủy quyền, không cả tenant đối tác; sai tenant bị từ chối; danh sách thành viên chat; nhóm Entra tự cập nhật; thành viên IT Security của HSC; nâng cấp cấu hình cũ), tin đã sửa, whitelist, lịch (cuối tuần / ngày lễ), ngưỡng, công tắc, lọc phía Graph, lệnh cũ, **bằng chứng khi tin bị xóa / sửa** |
| `reports_test.py` | Số liệu báo cáo, khoảng ngày trên lịch, PDF (Executive Summary, logo, tiếng Việt), Excel, gửi email đính kèm |
| `db_migrate_test.py` | Nâng cấp DB bản cũ: tự thêm cột thiếu, giữ toàn vẹn chuỗi băm bằng chứng cũ |
| `contract_test.py` | Khóa danh sách API và hình dạng response (ghi lại bằng `CONTRACT_RECORD=1` khi cố ý thêm API) |
| `policy_guard_test.py` | Không lệnh ghi nào lọt lên firewall ngoài allowlist |
| `hashchain_multiproc_test.py` | Chuỗi băm vẫn liền khi nhiều tiến trình / pod ghi cùng lúc (PostgreSQL) |
| `audit_search_test.py` | Tìm Audit log trúng cả bản ghi cũ, `%` / `_` là ký tự thường, có index `action` |
| `vpn_rules_perf_test.py` | Liên kết rule ↔ tài khoản VPN nhanh, kết quả giống thuật toán cũ |
| `alerts_test.py` | Cảnh báo firewall mất kết nối / hồi phục (ngưỡng, không trùng, giãn khi sai mật khẩu), drift ngoài giờ / trong giờ, con trỏ, không drift giả khi chen lệnh chặn |
| `ops_test.py` | Nén gzip response lớn, dọn công việc nền cũ |
| `ui_smoke_test.py` | Playwright trên mọi tab: desktop, điện thoại 390px, tooltip, phân quyền giao diện · Tổng quan: mức nghiêm trọng, thẻ lỗi riêng lẻ, Back, không gọi chồng, Readonly không gọi outbox · link có tham số: áp bộ lọc, 1 request, giá trị xấu, XSS, Chặn nhanh không nhận tham số, giữ link qua SSO |

Lấy mẫu cấu hình VPN thật để phát triển (chỉ đọc, đã che dữ liệu):
`SOPHOS_PASSWORD=… python tools/sophos_sample.py --host <fw> --user <api> --insecure --out sophos-sample`.

---

## 10. Lịch sử phiên bản

| Phiên bản | Nội dung chính |
|---|---|
| **2.5.0** | **Cảnh báo email cho Infra**: firewall mất kết nối XML API / kết nối lại (kiểm tra định kỳ `FW_HEALTH_MINUTES`), sửa `SCANPORT GROUP` trên WebAdmin **ngoài giờ hành chính** (phát hiện trong ~5 phút) · trạng thái firewall là dữ liệu sống · sửa lỗi drift giả khi lượt quét chen với lệnh chặn / bỏ chặn · hàng đợi email không gửi trùng giữa các pod |
| **2.4.0** | **Link có tham số** `#tab?k=v` (Lịch sử thay đổi, Audit, IP Host Group, VPN), giữ link qua đăng nhập Microsoft · Tổng quan và kết quả chặn mở thẳng trang đã lọc · thoát thủ công xoá link khỏi thanh địa chỉ |
| **2.3.0** | **Trang Tổng quan** cho IT Infrastructure Manager (Cần xử lý + thẻ từng module, bấm để mở tab), trang mặc định của quản trị viên · nút Back về đúng trang mặc định |
| **2.2.1** | Chuỗi băm an toàn khi chạy nhiều pod · tìm Audit log đúng trên toàn bộ dữ liệu · VPN nhanh hơn ~100 lần với nhiều rule/tài khoản · gzip · dọn công việc nền định kỳ · pool DB cấu hình được · `tests/run_all.sh`. Đánh giá & lộ trình: [`docs/roadmap-infra.md`](docs/roadmap-infra.md) |
| **2.2.0** | **Tự động chặn từ group chat Teams:** cú pháp `ĐỀ XUẤT CỦA SOC: BLOCK IP <ip>`, team SOC trực 24/7 (ủy quyền từng tài khoản gắn tenant / nhóm Entra), bỏ qua tin đã sửa, whitelist + Approve, lịch tự chặn (ngoài giờ / cuối tuần / ngày lễ), ngưỡng IP/giờ, công tắc khẩn cấp, trả lời qua Teams Workflows, lọc phía Graph (không đọc lại lịch sử), thời điểm lệnh theo Teams, lệnh cũ chờ duyệt, **bằng chứng khi tin bị xóa**. **Báo cáo PDF / Excel** (Executive Summary, HSC Design System, logo, chọn kỳ trên lịch, gửi email). **Giao diện mới** (menu trái, bảng cân đối, tooltip hướng dẫn) |
| **2.1.0** | Rà soát quyền VPN định kỳ theo ISO 27001 · overlay Rancher |
| **2.0.0** | Thông báo email: SMTP trên giao diện, nhắc trước hạn, outbox chống gửi trùng |
| **1.9.0** | VPN giai đoạn 2: thời hạn qua firewall rule, dashboard, lịch sử rule, CSV cần xử lý |
| **1.8.0** | VPN giai đoạn 1: tài khoản VPN chỉ đọc, đồng bộ định kỳ, lọc trường bí mật |
| **1.7.x** | Sửa 504 khi chặn nhiều IP (gộp lệnh, song song, công việc nền) · tái cấu trúc theo module |
| **1.6.x** | Cache IP Host Group trong PostgreSQL · logo |
| **1.5.x** | Quản lý người dùng · SSO một lần qua Entra App Proxy |
| **1.4.0** | Tên IP Host = IP/CIDR |
| **1.3.0** | Hardening: chỉ thao tác `SCANPORT GROUP` |
| **1.2.0** | Entra Application Proxy + MFA, OIDC + App Role, lịch sử thay đổi có chuỗi băm |

Chi tiết thiết kế và quyết định của từng phiên bản: [`docs/architecture.md`](docs/architecture.md).

---

## 11. Nguồn tham khảo

- **Sophos:** [Sophos Firewall API (SFOS 22.0)](https://docs.sophos.com/nsg/sophos-firewall/22.0/api/apicontentpage.html) ·
  [Cấu hình API](https://docs.sophos.com/nsg/sophos-firewall/20.0/Help/en-us/webhelp/onlinehelp/AdministratorHelp/BackupAndFirmware/API/APIConfiguration/) ·
  [IPHostGroup — Add/Edit](https://docs.sophos.com/nsg/sophos-firewall/22.0/api/SYSTEM/Host%20and%20Services/IPHostGroup/operations/AddIpHostGroup&EditIpHostGroup.html) ·
  [Bảo vệ truy cập API (Avanet)](https://www.avanet.com/en/kb/sophos-firewall-api-zugriff-absichern/)
- **Microsoft Graph & Teams:** [List chat messages](https://learn.microsoft.com/graph/api/chat-list-messages) ·
  [Send message in a chat — quyền ứng dụng](https://learn.microsoft.com/graph/api/chat-post-messages) ·
  [Resource-specific consent](https://learn.microsoft.com/microsoftteams/platform/graph-api/rsc/resource-specific-consent)
- **Entra:** [Application Proxy](https://learn.microsoft.com/entra/identity/app-proxy/overview-what-is-app-proxy) ·
  [Header-based SSO](https://learn.microsoft.com/entra/identity/app-proxy/application-proxy-configure-single-sign-on-with-headers)
- **Kubernetes / Rancher:** [Rancher Manager](https://ranchermanager.docs.rancher.com/) · [RKE2 networking](https://docs.rke2.io/networking/networking_services) ·
  [ingress-nginx annotations](https://kubernetes.github.io/ingress-nginx/user-guide/nginx-configuration/annotations/)
