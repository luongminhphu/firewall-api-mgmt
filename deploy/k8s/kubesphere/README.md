# Triển khai SOC Rapid Block lên KubeSphere

Hướng dẫn deploy mini app SOC Rapid Block lên cụm KubeSphere, dùng:

- **Registry**: GitHub Container Registry (`ghcr.io/luongminhphu/firewall-api-mgmt`), build tự động bằng GitHub Actions.
- **Ingress**: NodePort `30880` (đổi trong `base/app.yaml` nếu trùng cổng).
- **Database**: Postgres 16 StatefulSet trong cụm, PVC `pgdata` (mặc định 5Gi).

Manifests nằm ở `deploy/k8s/base/`, dùng chung cho `kubectl apply -k` và cho UI KubeSphere.

---

## 1. Chuẩn bị image trên GHCR

Repo đã có workflow `.github/workflows/build-image.yml` — mỗi khi push lên `main` hoặc tag `v*.*.*`, GitHub Actions sẽ build image và push lên `ghcr.io/luongminhphu/firewall-api-mgmt` (tag `latest`, `main`, `sha-xxxx`, hoặc `1.0.0`).

Package GHCR mặc định là **private**. Cụm Kubernetes cần imagePullSecret để pull được:

```bash
# Tạo Personal Access Token (classic) với scope: read:packages
kubectl -n infra-ops create secret docker-registry ghcr-pull \
  --docker-server=ghcr.io \
  --docker-username=luongminhphu \
  --docker-password='<PAT read:packages>' \
  [email protected]
```

Hoặc mở package thành public trong GitHub → tab **Packages** → Package settings → Change visibility (khi đó bỏ `imagePullSecrets` trong `app.yaml` cũng được).

---

## 2. Cách A — Deploy bằng kubectl / kustomize (nhanh nhất)

```bash
git clone https://github.com/luongminhphu/firewall-api-mgmt.git
cd firewall-api-mgmt

# 2.1 Sinh Secret thật (KHÔNG commit)
kubectl create namespace infra-ops
kubectl -n infra-ops create secret generic soc-rapid-block-secrets \
  --from-literal=MASTER_KEY=$(openssl rand -hex 32) \
  --from-literal=SESSION_SECRET=$(openssl rand -hex 32) \
  --from-literal=APP_PASSWORD='DoiMatKhauNay@2026' \
  --from-literal=POSTGRES_PASSWORD=$(openssl rand -hex 24)

# 2.2 Bỏ file secret.yaml mẫu ra khỏi kustomization (nếu bạn đã tạo Secret ở bước trên)
sed -i '/secret.yaml/d' deploy/k8s/base/kustomization.yaml

# 2.3 Cập nhật storageClassName trong deploy/k8s/base/postgres.yaml cho khớp cụm
#      (openebs-hostpath, nfs-client, local-path, csi-cephfs, …). Bỏ trống nếu có default.

# 2.4 Apply
kubectl apply -k deploy/k8s/base/

# 2.5 Kiểm tra
kubectl -n infra-ops get pods,svc,pvc
kubectl -n infra-ops logs deploy/soc-rapid-block-app -f
```

Truy cập: `http://<node-ip>:30880` → đăng nhập bằng `APP_PASSWORD`.

---

## 3. Cách B — Deploy qua UI KubeSphere

1. **Workspace ▸ Project**: tạo project (namespace) tên `infra-ops` trong workspace `soc` (hoặc workspace nội bộ của bạn).
2. **Configuration ▸ Secrets**: bấm *Create* → *Import YAML*, dán nội dung `secret.yaml` **sau khi thay giá trị thật**. Tạo thêm Secret `ghcr-pull` kiểu *Image Repository Secret* trỏ tới `ghcr.io`.
3. **Configuration ▸ ConfigMaps**: *Import YAML* → dán `configmap.yaml`, chỉnh `SAFE_LIST` cho phù hợp.
4. **Application Workloads ▸ StatefulSets**: *Create* → *Import YAML* → dán `postgres.yaml`. Đợi Pod `soc-rapid-block-db-0` chuyển **Running/Ready**.
5. **Application Workloads ▸ Deployments**: *Create* → *Import YAML* → dán `app.yaml`. Service NodePort được tạo cùng lúc.
6. **Network ▸ Services**: kiểm tra Service `soc-rapid-block` (trong namespace `infra-ops`) có port `30880/TCP` trên tất cả node.
7. (Tuỳ chọn) **Network ▸ Network Policies**: import `network-policy.yaml` để chỉ cho phép app gọi DB.

KubeSphere sẽ tự dựng dashboard **Application** nếu bạn gắn nhãn `app.kubernetes.io/part-of: soc-rapid-block` (đã có sẵn trong các manifest).

---

## 4. Nâng cấp / rollback

```bash
# Bump tag khi có release mới
cd deploy/k8s/base
kustomize edit set image ghcr.io/luongminhphu/firewall-api-mgmt=ghcr.io/luongminhphu/firewall-api-mgmt:v1.0.1
kubectl apply -k .

# Rollback
kubectl -n infra-ops rollout undo deploy/soc-rapid-block-app
```

Trên KubeSphere: **Deployment ▸ soc-rapid-block-app ▸ More ▸ Edit YAML** → sửa tag image, hoặc dùng nút **Rollback** trong tab *Revision Records*.

---

## 5. Kết nối tới các Sophos Firewall

Pod app nằm trong CIDR pod-network của cụm. Để mini app gọi được XML API:

- IP **egress** của node (hoặc IP SNAT nếu có) phải nằm trong **Allowed IP** trên từng Sophos Firewall. Nếu cụm có nhiều node, add IP của tất cả node hoặc dùng SourceNAT về một IP cố định.
- Nếu cụm dùng Calico, có thể tạo `egress-gateway` để mọi lưu lượng đi ra qua một IP duy nhất.
- Kiểm nhanh từ pod: `kubectl -n infra-ops exec deploy/soc-rapid-block-app -- curl -kv https://<firewall>:4444/webconsole/APIController`.

---

## 6. Sao lưu Postgres

```bash
kubectl -n infra-ops exec soc-rapid-block-db-0 -- \
  pg_dump -U sophos sophos_blocker | gzip > backup-$(date +%F).sql.gz
```

Trên KubeSphere: **Volumes ▸ pgdata-soc-rapid-block-db-0** — có thể snapshot nếu StorageClass hỗ trợ.

---

## 7. Xoá sạch

```bash
kubectl delete -k deploy/k8s/base/
kubectl delete pvc -n infra-ops -l app.kubernetes.io/name=soc-rapid-block-db  # xoá dữ liệu DB
```
