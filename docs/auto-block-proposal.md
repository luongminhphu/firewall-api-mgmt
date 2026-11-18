# Đề xuất: Tự động hóa chặn IP từ cảnh báo SOC

Trạng thái: **ĐỀ XUẤT, chờ duyệt.** Chưa viết code.
Phiên bản đích: v2.2 trở đi.

## 0. Tóm tắt

**Vấn đề.** SOC giám sát 24/7, nhưng Infra không trực đêm. Quy trình hiện tại:

1. SOC báo IP độc hại vào group Teams.
2. Người của Infra tỉnh dậy, đọc tin.
3. Người đó dán IP vào SOC Rapid Block.

Thời gian từ lúc báo đến lúc chặn có thể kéo dài vài giờ.

**Đề xuất.** App tự đọc tin của SOC, bóc **có ngữ cảnh** (IP nào là nguồn tấn công), chấm điểm rủi ro, rồi chia ba mức:

| Mức | Khi nào | Hành động |
|---|---|---|
| **A — Tự chặn** | IP nguồn tấn công từ ngoài, đi thẳng vào Sophos, hành vi dò quét/khai thác, TI xác nhận, không dính danh sách cấm | Chặn ngay, có **thời hạn (TTL)**, báo lại Teams + email kèm nút **Gỡ chặn** |
| **B — Chờ duyệt** | Có dấu hiệu tấn công nhưng thiếu một điều kiện (IP cloud dùng chung, TI chưa rõ, SOC ghi "cần xác minh"…) | Gửi người trực: duyệt **1 chạm** trên điện thoại (qua App Proxy + MFA). Không ai duyệt thì **không chặn** |
| **C — Không chặn** | IP nội bộ, IP đích, dịch vụ hợp pháp, cảnh báo rò rỉ dữ liệu, traffic đi qua Akamai | Chỉ ghi nhận và chuyển thông tin. Nếu chặn ở Akamai mới có tác dụng thì ghi rõ điều đó |

**Nguyên tắc.** Thà bỏ sót còn hơn chặn sai.

- Mọi lệnh chặn tự động đều **có hạn và gỡ được bằng một lần bấm**.
- Có **giới hạn số lượng**, có **công tắc tắt khẩn cấp**.
- Chạy **chế độ bóng (shadow)** 2–4 tuần trước khi bật tự chặn thật.
- Cơ chế guard hiện có vẫn giữ nguyên: app chỉ ghi được vào `SCANPORT GROUP`. Group này dùng cho rule Drop có *Source zone = WAN*, nên một lần chặn sai chỉ chặn chiều vào từ IP đó, không ảnh hưởng người dùng nội bộ đi ra.

## 1. Bài học từ 3 mẫu cảnh báo

| Cảnh báo | Bóc IP "thô" như hiện nay sẽ ra | Quyết định đúng |
|---|---|---|
| Dò quét `195.178.110.102` (Techoff Srv, Bulgaria): đi **thẳng vào Sophos**, tới Citrix 10.45.2.62:80, dò `.env`, `/remote/logincheck`, `%00` | `195.178.110.102`, `10.45.2.62` | **A — tự chặn** `195.178.110.102`. IP `10.45.2.62` là IP nội bộ của mình: bỏ qua |
| Case 151259: máy nội bộ `172.19.15.15` đẩy 1,66 GB tới `160.79.104.10:443` (api.anthropic.com) | `172.19.15.15`, **`160.79.104.10`** | **C — tuyệt đối không chặn.** Đây là điều tra rò rỉ dữ liệu từ máy nội bộ, không phải tấn công từ ngoài. Chặn `160.79.104.10` sẽ làm hỏng dịch vụ AI hợp lệ, và cũng vô tác dụng: rule SCANPORT chỉ chặn *nguồn* từ WAN |
| Case 150996: `136.85.71.38` (Google LLC, Singapore) dò sitemap + `/.aws/config`. Nguồn log **akamai.siem** | `136.85.71.38` | **C/B.** Traffic đi qua **Akamai**, nên Sophos chỉ thấy IP edge của Akamai, chặn ở Sophos **không có tác dụng**. Phải chặn ở Akamai (Network List). Ngoài ra đây là IP cloud dùng chung và đọc sitemap giống crawler, nên cần người duyệt |

Kết luận: **không thể tự động hóa bằng cách "thấy IP là chặn"**. Mỗi IP phải được biết:

- **vai trò**: nguồn hay đích;
- **chiều**: từ ngoài vào hay từ trong ra;
- **đường đi**: thẳng vào Sophos hay qua Akamai;
- **khuyến nghị của SOC**.

Ngay cả bản thủ công hiện tại cũng đang có rủi ro: dán nguyên case 151259 vào tab Chặn nhanh sẽ bóc ra `160.79.104.10`. IP này là public nên **lọt qua** kiểm tra IP private và safe-list. Vì vậy cần sửa ngay ở **giai đoạn 1** (mục 6).

## 2. Kiến trúc

```
SOC (Teams) ──► [1] Thu nhận ──► [2] Bóc cảnh báo ──► [3] Làm giàu TI ──► [4] Chấm điểm & chặn cứng
                                                                              │
                     ┌───────────────────────────┬────────────────────────────┤
                     ▼                           ▼                            ▼
              A: chặn ngay (TTL)          B: chờ duyệt 1 chạm           C: chỉ ghi nhận
                     │                           │
                     └──► ipblock hiện có (job nền, policy guard, SCANPORT GROUP, lịch sử hash chain)
                                 │
                     [5] Báo lại Teams / email · [6] Tự gỡ khi hết TTL · [7] Báo cáo sáng
```

### 2.1 Thu nhận tin của SOC: chọn một trong ba cách

| Cách | Mô tả | Ưu | Nhược |
|---|---|---|---|
| **① Graph API, app tự đọc (khuyến nghị)** | Một Teams app được cài vào **đúng team đó**, với quyền RSC `ChannelMessage.Read.Group` (cấp theo team, không phải toàn tenant). App hỏi Graph mỗi 30–60 giây | **Chỉ đi ra, không mở cổng vào.** Không phụ thuộc Power Automate. Lọc được người gửi | Cần tạo Teams app và nhờ owner của team cấp quyền. Nếu đang dùng **group chat** chứ không phải channel thì dùng quyền `ChatMessage.Read.Chat` |
| ② Power Automate / Workflows | Có tin mới thì luồng gọi webhook của app | Dựng nhanh | Phải mở một endpoint nhận từ Internet qua App Proxy với cơ chế xác thực riêng; luồng chạy dưới tài khoản cá nhân |
| ③ SOC gửi webhook/JSON có cấu trúc | Nhờ SOC (MSSP) đẩy case từ SIEM sang bằng JSON: `case_id`, `src_ip`, `direction`, `log_source`, `verdict`, `recommendation` | **Chính xác nhất**, không phải bóc văn bản | Phụ thuộc SOC; cần thỏa thuận |

Đề xuất: dùng **①** ngay, đồng thời đề nghị SOC chuyển dần sang **③**. Song song, nhờ SOC thêm một dòng cố định vào mẫu tin, vd `Đề xuất: BLOCK 195.178.110.102`.

### 2.2 Bóc cảnh báo (không dùng AI bên ngoài)

Mẫu 4W1H của SOC khá ổn định, nên dùng **bộ bóc tất định** (regex theo nhãn) thay vì gửi nội dung lên dịch vụ AI ngoài. Gửi lên AI ngoài cũng chính là loại rủi ro mà case 151259 đang điều tra. Các trường cần lấy:

- **Case:** `Case #` · Priority · True/False positive · Attack type · Thành công/thất bại · Nguồn log (`Sophos xg` / `akamai.siem`…).
- **`Source IP` / `Destination IP`:** gán vai trò cho từng IP. IP nằm trong câu "Nhờ các anh xem xét block IP …" được coi là **IP đề xuất chặn**.
- **Chiều:** suy ra từ IP. Nguồn nội bộ (RFC1918 hoặc dải của HSC) nghĩa là **trong → ngoài**, xếp mức C.

Các quy tắc an toàn:

- Chỉ nhận tin từ **danh sách tài khoản SOC** được phép.
- **Bỏ qua tin đã sửa** (chống người khác sửa tin để chèn IP).
- Tin không khớp mẫu thì không đoán: chuyển sang mức B, kèm cờ "không đọc được".

### 2.3 Làm giàu thông tin (TI)

| Nguồn | Dùng để |
|---|---|
| **GreyNoise** (Community/Enterprise) | Phân biệt scanner độc hại với scanner "lành" (Shodan, Censys). Bộ RIOT nhận ra **dịch vụ doanh nghiệp hợp pháp** (Google, Microsoft, Anthropic, CDN), giúp tránh đúng lỗi của case 151259 |
| **AbuseIPDB** | Điểm uy tín và số lần bị báo cáo |
| **ASN / Geo** (MaxMind GeoLite2 offline) | Phân loại hosting/VPS/cloud dùng chung, ISP dân dụng hay nhà cung cấp lớn |
| **Dải IP công bố** của Akamai, Microsoft 365/Azure, Google (gồm Googlebot), Cloudflare, Anthropic | Đưa vào danh sách chặn cứng (mục 2.4) |
| **Lịch sử nội bộ** | IP đã từng bị chặn hay gỡ (gỡ thì có thể đã chặn nhầm), có trong lịch sử thay đổi không |

Cần mở mạng ra ngoài tới các API trên và cấp API key (lưu mã hóa bằng `MASTER_KEY` như SMTP).
Thiếu TI thì app vẫn chạy, nhưng **không bao giờ xếp mức A**.

### 2.4 Chấm điểm và chặn cứng

**Danh sách chặn cứng.** Không bao giờ chặn, không bao giờ đề xuất chặn:

- IP private, CGNAT, multicast; `SAFE_LIST` hiện có;
- dải public của chính HSC; IP của đối tác và nhà cung cấp;
- dải Akamai, Microsoft, Google, Cloudflare, Anthropic, Sophos, DNS công cộng;
- IP mà GreyNoise RIOT xác định là dịch vụ hợp pháp;
- IP đang đóng **vai trò đích** trong cảnh báo;
- IP từng bị Infra **gỡ chặn tay** trong 90 ngày;
- CIDR rộng hơn `/32`: tự động chỉ chặn từng IP.

**Mức A (tự chặn)** chỉ khi thỏa **tất cả** điều kiện:

1. IP có vai trò **nguồn**, chiều **ngoài → trong**.
2. Nguồn log là **Sophos**, tức traffic thực sự đi qua firewall.
3. Loại tấn công nằm trong allowlist: dò quét, liệt kê, khai thác, brute-force, LFI/RCE…
4. SOC ghi *True Positive* **hoặc** có khuyến nghị block rõ ràng.
5. **Điểm TI ≥ ngưỡng**, vd AbuseIPDB ≥ 75 hoặc GreyNoise `malicious`.
6. ASN thuộc loại hosting/VPS, **không** phải cloud lớn dùng chung.
7. Không vượt giới hạn số lượng (mục 2.5).
8. Đang trong **khung giờ tự động** (tùy chọn, vd 18:00–08:00 và cuối tuần; giờ hành chính thì chuyển sang mức B).

Thiếu một điều kiện thì xuống **mức B**. Có điều kiện của mức C thì xếp **mức C**. Mỗi quyết định lưu kèm **lý do từng điều kiện**,
để giải thích được với auditor ("vì sao IP này bị tự chặn").

### 2.5 Kiểm soát rủi ro

| Cơ chế | Mặc định đề xuất |
|---|---|
| **Chế độ bóng** | Bật 2–4 tuần đầu: app chỉ ghi lại "lẽ ra sẽ chặn". Sáng hôm sau so với việc Infra làm thật. Chỉ bật tự chặn khi **độ chính xác ≥ 98%** và **0** IP bị chặn cứng lọt qua |
| **TTL** | Tự chặn: 7 ngày. Tái phạm: 30 ngày, rồi 90 ngày. Chặn tay: không hạn (như hiện nay, hoặc chọn hạn). Hết hạn thì app tự gỡ (job nền, khóa phân tán) |
| **Giới hạn số lượng** | Tối đa 10 IP/giờ và 50 IP/ngày cho mức A. Vượt ngưỡng thì **tự ngắt** (chuyển hết sang mức B) và báo động |
| **Công tắc khẩn cấp** | Nút **Tắt tự động chặn** trong tab Cài đặt (quản trị viên), có hiệu lực ngay, ghi audit |
| **Gỡ 1 chạm** | Mọi thông báo đều có link **Gỡ chặn** (qua App Proxy + MFA, quyền Write) |
| **Không tự leo thang** | Tự động chỉ chặn `/32`, chỉ ghi vào `SCANPORT GROUP`. Policy guard hiện có vẫn là lớp chặn cuối |
| **Chống giả mạo tin** | Chỉ nhận từ tài khoản SOC trong allowlist; bỏ qua tin đã sửa; lưu bản gốc + mã băm |
| **Mặc định khi lỗi** | TI lỗi, không đọc được tin hay firewall lỗi thì **không chặn** và chuyển sang mức B. Không bao giờ "chặn cho chắc" |

### 2.6 Người trực đêm duyệt mức B

- Khi có đề xuất mới, app gửi **email** và **trả lời ngay trong thread Teams** (quyền RSC `ChannelMessage.Send.Group`)
  tới người trực. Nội dung: IP, case, lý do, điểm TI, và nút **Duyệt chặn** / **Từ chối**.
- Người trực bấm nút trên điện thoại, đăng nhập App Proxy + MFA (SSO một lần), rồi xác nhận. Cả quá trình mất khoảng 30 giây, không cần mở laptop.
- Lịch trực nhập trong tab Cài đặt (theo tuần), hoặc dùng một hộp thư nhóm.
- Đề xuất **hết hạn sau 12 giờ** nếu không ai duyệt, và được đưa vào báo cáo sáng.

### 2.7 Báo lại và báo cáo

- **Trả lời trong thread của SOC**, vd: "Đã tự chặn 195.178.110.102 trên 3/3 firewall lúc 02:14, hạn 7 ngày, case #…".
  SOC biết đã xử lý, không phải nhắc lại.
- **Báo cáo 08:00 hằng ngày** gửi Infra: danh sách đã tự chặn, đã duyệt, bị từ chối, mức C cần xử lý tay (vd case 151259
  cần điều tra máy 172.19.15.15), và những gì sắp hết hạn.
- **Chỉ số theo dõi:**
  - **MTTB**, thời gian từ khi SOC báo tới khi chặn. Mục tiêu dưới 5 phút cho mức A.
  - Tỉ lệ chặn bị gỡ vì chặn nhầm. Mục tiêu dưới 2%.
  - Số đề xuất mức B quá hạn.

## 3. Ngoài app: cải thiện cấu trúc (nên làm trước, chi phí thấp)

1. **Chỉ cho Akamai vào origin.** Case `195.178.110.102` đi thẳng vào Citrix qua rule *"Any Users access OPT and STS DMZ CITRIX"*,
   **vượt qua Akamai WAF**. Cần giới hạn Source của rule này về dải IP của Akamai (Akamai SiteShield / Origin IP ACL).
   Làm vậy sẽ loại bỏ cả một nhóm cảnh báo, hiệu quả hơn mọi cơ chế tự chặn.
2. **Cảnh báo đi qua Akamai thì chặn ở Akamai.** Dùng Akamai Network Lists (thủ công trước; giai đoạn 3 có thể tự động bằng
   Network Lists API, cùng các cơ chế kiểm soát ở mục 2.5).
3. **Sophos Third-party threat feeds** (Protect ▸ Active threat response; cần Xstream Protection).
   - Cơ chế: firewall tự kéo danh sách IoC từ một URL theo chu kỳ.
   - Cách dùng thứ nhất: kéo các feed uy tín (vd GreyNoise có tích hợp cho Sophos) để chặn sẵn scanner phổ biến.
   - Cách dùng thứ hai, có thể sau này: app phát hành chính danh sách mức A thành feed, thay cho việc ghi qua API.
   - Cần xác minh trên SFOS 22 MR3 các chu kỳ kéo được hỗ trợ (một số model nhỏ chỉ có 24h/7d/30d) và giấy phép.
4. **Thỏa thuận mẫu tin với SOC:** thêm dòng `Đề xuất: BLOCK <ip>` / `Đề xuất: KHÔNG BLOCK`, hoặc gửi JSON (cách ③).

## 4. Thay đổi trong app (dự kiến)

**Bảng mới** (chỉ thêm, không sửa bảng cũ):

| Bảng | Nội dung |
|---|---|
| `soc_messages` | Tin gốc: id Graph, người gửi, thời điểm, nội dung, mã băm |
| `soc_alerts` | Các trường đã bóc: case, IP, vai trò, nguồn log |
| `block_decisions` | ip, mức A/B/C, điểm, lý do từng điều kiện (JSON), trạng thái `shadow/pending/approved/rejected/auto_blocked/expired/failed`, người duyệt; nối chuỗi băm |
| `block_entries` | IP đang bị chặn: nguồn `manual/auto/approved`, `expires_at`, case. Dùng cho TTL và tái phạm |

**Module và giao diện:**

- **Module mới `modules/autoblock/`:**
  - `ingest` (Graph), `parser`, `enrich`, `decide`, `runner`.
  - Gọi `ipblock` hiện có để chặn, giữ nguyên job nền, policy guard và lịch sử.
- **Tab mới "Tự động chặn":**
  - hàng đợi mức B (duyệt / từ chối);
  - danh sách mức A gần đây (gỡ 1 chạm);
  - mức C;
  - chế độ bóng: so sánh "lẽ ra" với thực tế.
- **Tab Cài đặt:** bật/tắt, chế độ (tắt / bóng / chỉ đề xuất / tự chặn), khung giờ, ngưỡng, TTL, giới hạn số lượng,
  danh sách chặn cứng, tài khoản SOC hợp lệ, lịch trực, API key TI.
- **Quyền:**
  - duyệt mức B: Write;
  - cấu hình và công tắc khẩn cấp: Quản trị viên;
  - tài khoản dịch vụ "autoblock" ghi audit như một người dùng riêng.

## 5. Kế hoạch triển khai

| Giai đoạn | Nội dung | Giá trị | Ước lượng |
|---|---|---|---|
| **0** (không code) | Siết rule Citrix chỉ nhận từ Akamai · Thỏa thuận mẫu tin với SOC · Lập danh sách chặn cứng (dải HSC, đối tác) | Giảm bề mặt tấn công ngay | Vài ngày |
| **1** | Bóc **có ngữ cảnh** cho tab Chặn nhanh: chỉ chọn sẵn IP nguồn; IP đích, nội bộ và dải chặn cứng thì cảnh báo và bỏ chọn · `block_entries` + TTL + tự gỡ | Sửa rủi ro chặn nhầm của bản thủ công hiện nay | 1 phase |
| **2** | Thu nhận Graph (RSC) · bộ bóc 4W1H · làm giàu TI · chấm điểm · **chế độ bóng** + tab "Tự động chặn" + **duyệt 1 chạm** mức B qua email/Teams | Người trực xử lý ban đêm trong ~1 phút từ điện thoại | 1–2 phase |
| **3** | Bật **mức A** sau khi chế độ bóng đạt chỉ tiêu · giới hạn số lượng, công tắc khẩn cấp, trả lời trong thread, báo cáo sáng | Tự chặn trong vài phút, không cần người | 1 phase |
| **4** (tùy chọn) | Akamai Network Lists API · tái phạm leo thang TTL · xuất threat feed cho Sophos | Phủ cả traffic đi qua Akamai | Sau |

Mỗi giai đoạn vẫn theo quy trình đã thống nhất: bước nhỏ, mỗi bước một commit, toàn bộ test xanh, có test riêng cho từng
quy tắc chặn cứng. Ba mẫu cảnh báo ở mục 1 sẽ thành test cố định: `195.178.110.102` → A; `160.79.104.10` và `172.19.15.15` → C;
`136.85.71.38` → C/B (đi qua Akamai).

## 6. Cần anh quyết định

1. **Kênh Teams** là *channel* trong một Team hay *group chat*? Ai là owner để cấp quyền cho Teams app (RSC)?
   Hay anh muốn dùng Power Automate, hoặc đề nghị SOC gửi JSON?
2. **TI:** có đồng ý mở mạng ra ngoài và đăng ký key GreyNoise và/hoặc AbuseIPDB (bản miễn phí đủ dùng giai đoạn đầu) không?
3. **Mức A:** chỉ ban đêm và cuối tuần, hay 24/7? TTL mặc định 7 ngày có ổn không?
4. **Duyệt mức B:** gửi qua email, trả lời thread Teams, hay cả hai? Lịch trực do ai cập nhật?
5. **Giai đoạn 0:** anh có muốn tôi soạn kèm checklist siết rule Citrix và mẫu tin đề nghị SOC không?
