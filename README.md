# SOC Rapid Block — mini app chặn IP nhanh trên nhiều Sophos Firewall

Mini app HTML5 + FastAPI giúp team SOC/NOC dán thẳng đoạn chat Teams (hoặc CSV/nhập tay),
bóc IP tự động và đẩy vào **IP Host Group** trên **nhiều Sophos Firewall** cùng lúc qua XML API —
thao tác được từ điện thoại trong ngày nghỉ lễ Tết.

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

Cách chặn: với mỗi IP/CIDR, app tạo **IP Host** tên `SOC_BLOCK_<ip>` (`Set operation="add"`),
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
5. **Tạo group + rule chặn**: tạo IP Host Group (vd `SOC_BLOCKED_IPS`) rồi tạo **firewall rule Drop**
   với Source zone WAN, Source networks = group đó, đặt **lên trên cùng**. Mini app chỉ đổ IP vào group —
   không có rule thì IP vẫn không bị chặn.

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
| `HOST_PREFIX` | Tiền tố tên IP Host (mặc định `SOC_BLOCK_`) |
| `SAFE_LIST` | Dải **không bao giờ** được chặn (dải nội bộ, VPN, đối tác) |
| `ALLOW_PRIVATE` | Cho phép chặn IP private (mặc định `false`) |
| `API_TIMEOUT` | Timeout gọi firewall, giây (mặc định 30) |

### Khuyến nghị vận hành

- Đặt sau reverse proxy có HTTPS (nginx/Caddy), **không** phơi trực tiếp ra Internet; nếu cần truy cập từ xa dịp lễ thì
  cho qua VPN hoặc giới hạn IP.
- Sao lưu volume `pgdata` (chứa firewall + audit log).
- Cập nhật `SAFE_LIST` với dải IP văn phòng, VPN, đối tác để tránh tự chặn nhầm.

---

### 3.2 KubeSphere / Kubernetes

Manifests nằm ở `deploy/k8s/base/` (Namespace + ConfigMap + Secret mẫu + Postgres StatefulSet + Deployment + NodePort Service + NetworkPolicy). Image build tự động qua GitHub Actions và đẩy lên `ghcr.io/luongminhphu/firewall-api-mgmt`.

Quick start:

```bash
kubectl create namespace infra-ops
kubectl -n infra-ops create secret generic soc-rapid-block-secrets \
  --from-literal=MASTER_KEY=$(openssl rand -hex 32) \
  --from-literal=SESSION_SECRET=$(openssl rand -hex 32) \
  --from-literal=APP_PASSWORD='DoiMatKhauNay@2026' \
  --from-literal=POSTGRES_PASSWORD=$(openssl rand -hex 24)
kubectl apply -k deploy/k8s/base/
```

Truy cập `http://<node-ip>:30880`. Xem hướng dẫn đầy đủ (imagePullSecret cho GHCR private, cách import qua UI KubeSphere, upgrade/rollback, sao lưu Postgres) trong [`deploy/k8s/kubesphere/README.md`](deploy/k8s/kubesphere/README.md).

## 4. Sử dụng

**Tab Chặn nhanh**
1. Chọn nguồn: **Dán từ Teams** (app tự bóc IPv4/CIDR, hiểu cả dạng làm mờ `1.2.3[.]4`, `1.2.3(.)4`, `1.2.3[dot]4`),
   **Nhập tay**, hoặc **CSV/TXT** (kéo-thả file).
2. Tick các firewall đích (có thể chọn tất cả), điền Object Group (bỏ trống = group mặc định của từng firewall) và lý do/ticket.
3. Tick **Chạy thử (dry-run)** để xem trước sẽ tạo gì mà không ghi lên firewall.
4. Bấm **Chặn ngay** → xem kết quả từng IP trên từng firewall (đã thêm / đã có / lỗi + mã Sophos).

**Tab Object Group** — xem và tìm kiếm thành viên group hiện tại trên từng firewall, tick để **bỏ chặn**
(tùy chọn xóa luôn IP Host object).

**Tab Firewall** — thêm/sửa/xóa firewall, **Kiểm tra** từng cái hoặc **Kiểm tra tất cả**.

**Tab Audit log** — toàn bộ thao tác (ai, lúc nào, IP nào, firewall nào, kết quả, lý do), lọc + **Xuất CSV**.

### Cơ chế an toàn

- Safe-list + chặn IP private (tùy chọn) để tránh tự khóa hệ thống.
- Tối đa 500 IP mỗi lần đẩy; hộp thoại xác nhận trước khi chặn/bỏ chặn.
- Mật khẩu firewall mã hóa AES-256-GCM, không bao giờ trả về client.
- Mọi thao tác đều được ghi audit kèm IP người thao tác.

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

---

## 7. Cấu trúc thư mục

```
backend/app/config.py    cấu hình từ biến môi trường
backend/app/crypto.py    mã hóa AES-256-GCM + token phiên HMAC
backend/app/db.py        model Firewall + AuditLog (SQLAlchemy)
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
