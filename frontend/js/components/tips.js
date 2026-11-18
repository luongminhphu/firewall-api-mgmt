/* Tooltip hướng dẫn cho các mục cấu hình (nút ⓘ cạnh nhãn).
   - Nội dung tập trung ở HELP (khóa = id của ô nhập / vùng cấu hình) — sửa chữ ở một chỗ.
   - Hiện khi rê chuột, focus bằng bàn phím hoặc chạm (điện thoại); Esc / bấm ra ngoài để đóng.
   - Một popup dùng chung (role="tooltip"), nút ⓘ trỏ aria-describedby tới popup khi đang mở;
     vị trí tự căn để không tràn khỏi màn hình. */
import { $, $$ } from "../util.js";

const HELP = {
  // ---------------------------------------------------------------- Firewall
  "fw-name": "Tên hiển thị để phân biệt firewall, vd \"XGS-3100 · HCM\". Chỉ dùng trong app, không gửi lên firewall.",
  "fw-site": "Chi nhánh / site đặt firewall (vd HCM, HN, DR). Dùng để lọc và hiển thị.",
  "fw-host": "IP hoặc tên miền quản trị của firewall mà app gọi tới. Máy chủ app phải nằm trong Allowed IP (System › Backup & firmware › API).",
  "fw-port": "Cổng HTTPS của Admin Console (System › Administration › Admin settings), mặc định 4444 — không phải 443.",
  "fw-user": "Tài khoản admin riêng cho API (vd apiadmin). Quyền tối thiểu: đọc/ghi Hosts and services; chỉ đọc Firewall rules, Users, VPN nếu dùng module VPN.",
  "fw-pass": "Mật khẩu tài khoản API. Được mã hóa AES-256-GCM bằng MASTER_KEY, không bao giờ hiển thị lại. Để trống khi sửa = giữ mật khẩu cũ.",
  "fw-note": "Ghi chú nội bộ (người phụ trách, hợp đồng bảo hành…).",
  "fw-verify": "Bật nếu firewall dùng chứng chỉ do CA tin cậy cấp. Firewall dùng chứng chỉ tự ký mặc định thì để tắt.",
  "fw-enabled": "Bỏ tick để tạm ngưng: firewall không được chọn khi chặn, không quét cache, không đồng bộ VPN.",

  // ---------------------------------------------------------------- Người dùng
  "u-username": "Tài khoản Microsoft: nhập đúng UPN (vd phu.luong@hsc.com.vn). Tài khoản mật khẩu riêng: tên ngắn không dấu (vd soc.dem).",
  "u-display": "Tên hiển thị trong lịch sử thay đổi, audit và email.",
  "u-auth": "Microsoft (Entra ID): đăng nhập qua MFA của công ty, app không giữ mật khẩu — khuyến nghị. Mật khẩu riêng: chỉ dùng cho tài khoản khẩn cấp.",
  "u-perm": "Readonly: chỉ xem. Write: chặn / bỏ chặn, đồng bộ, duyệt lệnh tự động chặn.",
  "u-admin": "Quản trị viên: thêm/sửa firewall, người dùng, toàn bộ tab Cài đặt. Luôn phải còn ít nhất một quản trị viên đang hoạt động.",
  "u-enabled": "Bỏ tick để khóa tài khoản — có hiệu lực ngay ở request kế tiếp, không chờ hết phiên.",
  "u-note": "Ghi chú nội bộ, vd \"SOC ca đêm, trực Tết 2027\".",

  // ---------------------------------------------------------------- Tự động chặn
  "abs-enabled": "Bật để app đọc group chat theo chu kỳ và xử lý lệnh của SOC. Chỉ tin nhắn gửi SAU lúc bật mới được xử lý.",
  "abs-tenant": "Directory (tenant) ID của Entra ID — xem ở Entra admin center › Overview.",
  "abs-client": "Application (client) ID của App registration dùng để đọc chat (nên tạo riêng, khác app đăng nhập).",
  "abs-secret": "Client secret của App registration (Certificates & secrets). Lưu mã hóa, không hiển thị lại; nhớ gia hạn trước khi hết hạn.",
  "abs-chat": "ID group chat với SOC: mở chat trên Teams web, chép phần 19:…@thread.v2 trên thanh địa chỉ. Đổi Chat ID → chỉ xử lý tin mới từ thời điểm đó.",
  "abs-senders": "Chỉ tin của các tài khoản này mới được nhận lệnh. Định danh bằng Object ID Entra (không đổi khi đổi tên). Tin của người khác bị bỏ qua và ghi nhật ký.",
  "abs-new-tenant": "Tenant ID (Directory ID) của đơn vị cung cấp dịch vụ SOC. Cách lấy nhanh: bấm Kiểm tra kết nối → ở danh sách người gửi gần đây, bấm \"+ Tin cậy tenant này\" cạnh một thành viên SOC (nhãn External). Không dùng tenant của HSC.",
  "abs-new-group": "Object ID của security group trong Entra ID của HSC chứa các thành viên SOC (nội bộ hoặc khách B2B). App cần quyền ứng dụng GroupMember.Read.All (admin consent).",
  "abs-new-id": "Object ID (GUID) của tài khoản SOC — lấy nhanh bằng nút \"+ tên\" sau khi Kiểm tra kết nối, hoặc ở Entra › Users.",
  "abs-wl": "IP / dải thuộc các danh sách này KHÔNG tự chặn: lệnh chuyển sang chờ và chỉ quản trị viên Approve. Nên khai báo dải public của HSC, dải Akamai (SiteShield / Origin IP ACL), IP đối tác.",
  "abs-window": "Tick: chỉ tự chặn theo lịch (ngoài giờ, cuối tuần, ngày lễ); giờ hành chính lệnh chờ duyệt. Bỏ tick: tự chặn 24/7.",
  "abs-wstart": "Giờ bắt đầu ngoài giờ ngày thường (giờ Việt Nam), vd 18:00.",
  "abs-wend": "Giờ kết thúc vào sáng hôm sau, vd 08:00. Đặt bằng giờ bắt đầu = cả ngày.",
  "abs-weekend": "Thứ 7 và Chủ nhật tự chặn cả ngày (gộp với đêm thứ 6 và đêm Chủ nhật thành một ca).",
  "abs-hol": "Ngày lễ / nghỉ bù rơi vào ngày thường: tự chặn cả ngày. Có thể nhập cả đợt (vd Tết 05/02–11/02). Nghỉ đột xuất: dùng nút \"Tự chặn cả ngày hôm nay\" ở tab Tự động chặn.",
  "abs-limit": "Tối đa số IP được TỰ chặn trong 60 phút. Vượt ngưỡng → ngắt: lệnh tiếp theo chờ duyệt, email cảnh báo nhóm Admin, quản trị viên bấm Mở lại. Mặc định 20.",
  "abs-poll": "App đọc group chat mỗi N phút (1–60). Ngắn hơn = phản ứng nhanh hơn nhưng gọi Microsoft Graph nhiều hơn. Mặc định 5.",
  "abs-stale": "Lệnh SOC gửi quá N phút mới được app đọc (app ngừng, mất mạng, chu kỳ dài) sẽ KHÔNG tự chặn mà chuyển chờ duyệt — tình hình có thể đã khác. Mặc định 30; tự nâng lên tối thiểu gấp đôi chu kỳ đọc.",
  "abs-reply": "Sau mỗi IP chặn thành công, gửi vào group chat: \"INFRA ĐÃ BLOCK <ip> THEO YÊU CẦU LÚC <thời điểm>\".",
  "abs-reply-url": "Trong group chat chọn … › Workflows › \"Post to a chat when a webhook request is received\", chọn đúng chat rồi chép URL webhook vào đây. URL chứa chữ ký bí mật — lưu mã hóa.",
  "abs-admins": "Nhận email: vượt ngưỡng, lệnh chờ duyệt, báo cáo khi hết ca ngoài giờ. Mỗi dòng một địa chỉ. Để trống = mọi quản trị viên có email.",
  "abs-fws": "Firewall sẽ nhận lệnh tự chặn. Không chọn = mọi firewall đang bật.",

  // ---------------------------------------------------------------- Báo cáo
  "rp-from": "Chọn khoảng ngày bất kỳ (tối đa 366 ngày, giờ Việt Nam). Ngày cuối là hôm nay thì số liệu tính tới hiện tại.",
  "rp-to-addr": "Một hoặc nhiều email (tối đa 20), phân cách dấu phẩy / chấm phẩy. Thư gửi qua máy chủ SMTP ở tab Cài đặt (phải đang bật).",
  "rp-note": "Lời nhắn đặt trên đầu thư, trước Executive Summary — vd \"Kính gửi anh/chị, báo cáo tuần 47\".",
  "rp-f-pdf": "PDF: bản trình lãnh đạo — Executive Summary trang đầu, biểu đồ, bảng chi tiết; logo + màu HSC.",
  "rp-f-xlsx": "Excel: Executive Summary + các sheet chi tiết (theo ngày, danh sách IP, từng lượt chặn, người thực hiện) để lọc / phân tích.",

  // ---------------------------------------------------------------- VPN / rà soát
  "vs-days": "Rule còn hạn ≤ số ngày này được đánh dấu \"Sắp hết hạn\" trên dashboard VPN (mặc định 30).",
  "vs-groups": "Rule Group trên firewall chứa rule cấp quyền VPN. Chỉ chọn được group có trong whitelist mã nguồn (hardening).",
  "rs-auto": "Tự mở đợt rà soát trong 15 ngày đầu mỗi quý (khi đã có dữ liệu VPN). Quản trị viên vẫn mở tay được ở tab Rà soát.",
  "rs-due": "Số ngày đại diện team có để xác nhận từ lúc mở đợt (mặc định 14).",
  "rs-remind": "Còn ≤ số ngày này tới hạn thì email nhắc các mục chưa quyết định.",

  // ---------------------------------------------------------------- SMTP / thông báo
  "smtp-enabled": "Bật để app thật sự gửi email. Tắt thì thư vẫn xếp hàng và gửi khi bật lại.",
  "smtp-host": "Máy chủ SMTP / relay nội bộ, vd smtp.hsc.com.vn hoặc smtp.office365.com. Pod của app phải ra được máy này.",
  "smtp-port": "587 cho STARTTLS, 465 cho SSL/TLS, 25 cho relay nội bộ không mã hóa.",
  "smtp-security": "STARTTLS (587) là phổ biến nhất; SSL/TLS cho cổng 465; Không mã hóa chỉ dùng với relay nội bộ tin cậy.",
  "smtp-verify": "Kiểm tra chứng chỉ máy chủ SMTP. Chỉ tắt khi relay nội bộ dùng chứng chỉ tự ký.",
  "smtp-user": "Tài khoản gửi thư (vd soc-rapid-block@hsc.com.vn). Để trống nếu relay cho phép gửi không cần đăng nhập.",
  "smtp-pass": "Mật khẩu / app password của tài khoản gửi. Mã hóa bằng MASTER_KEY, không hiển thị lại; để trống = giữ mật khẩu cũ.",
  "smtp-from": "Địa chỉ người gửi hiển thị trên thư; nên trùng tài khoản đăng nhập SMTP để không bị chặn SPF/DMARC.",
  "smtp-from-name": "Tên hiển thị của người gửi, vd \"SOC Rapid Block\".",
  "smtp-test-to": "Nhập email của bạn rồi bấm Gửi thử để kiểm tra cấu hình ngay.",
  "nt-enabled": "Bật để gửi email nhắc hạn VPN theo các mốc bên dưới.",
  "nt-infra": "Email Infra nhận mọi thông báo hạn VPN (mỗi dòng một địa chỉ). Đại diện team chỉ nhận thư của team mình.",
  "nt-days": "Các mốc nhắc trước hạn, phân cách dấu phẩy (vd 30, 14, 7, 1). Mỗi mốc chỉ gửi một lần cho mỗi rule.",
  "nt-weekly": "Mỗi tuần báo Infra danh sách rule đã hết hạn mà vẫn đang bật trên firewall.",
};

const ICON = '<svg viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><circle cx="12" cy="12" r="10"/><path d="M12 16v-4"/><path d="M12 8h.01"/></svg>';
let pop = null;
let current = null;
let pinned = false; // mở bằng bấm/chạm: giữ tới khi bấm lại, bấm ra ngoài hoặc Esc

/** Ô nhãn để gắn nút ⓘ cho phần tử có id `id`. */
function anchorFor(el) {
  if (el.id === "abs-hol") return $(".ab-hol__head strong");
  const fs = el.matches("fieldset") ? el : null;
  if (fs) return fs.querySelector("legend");
  const host = el.closest("label.field, div.field, label.check, fieldset.field") || el.parentElement;
  if (host.matches("fieldset.field")) return host.querySelector("legend");
  if (host.matches("label.check")) return host.querySelector("span");
  return host.querySelector(":scope > span") || host.querySelector("legend");
}

function place(btn) {
  const r = btn.getBoundingClientRect();
  pop.style.left = "0px";
  pop.style.top = "0px";
  const w = pop.offsetWidth, h = pop.offsetHeight, m = 8;
  let left = Math.min(Math.max(m, r.left + r.width / 2 - w / 2), window.innerWidth - w - m);
  let top = r.bottom + 8;
  if (top + h > window.innerHeight - m) top = Math.max(m, r.top - h - 8);
  pop.style.left = `${left}px`;
  pop.style.top = `${top}px`;
}

function show(btn) {
  if (current && current !== btn) current.removeAttribute("aria-describedby");
  current = btn;
  pop.textContent = btn.dataset.tip;
  pop.hidden = false;
  btn.setAttribute("aria-describedby", "tip-pop");
  btn.setAttribute("aria-expanded", "true");
  place(btn);
}

function hide() {
  pinned = false;
  if (!current) return;
  current.removeAttribute("aria-describedby");
  current.setAttribute("aria-expanded", "false");
  current = null;
  pop.hidden = true;
}

/** Gắn nút ⓘ cho mọi mục có nội dung trong HELP (gọi một lần lúc khởi động; an toàn khi gọi lại). */
export function initTips() {
  if (!pop) {
    pop = document.createElement("div");
    pop.id = "tip-pop";
    pop.className = "tip-pop";
    pop.setAttribute("role", "tooltip");
    pop.hidden = true;
    document.body.append(pop);
    document.addEventListener("mouseover", (e) => {
      const b = e.target.closest?.(".tip");
      if (b) show(b);
    });
    document.addEventListener("mouseout", (e) => {
      const b = e.target.closest?.(".tip");
      if (b && b === current && !pinned && b !== document.activeElement && !b.contains(e.relatedTarget)) hide();
    });
    document.addEventListener("focusin", (e) => {
      if (e.target.classList?.contains("tip")) {
        if (e.target !== current) show(e.target);
      } else hide();
    });
    document.addEventListener("click", (e) => {
      const b = e.target.closest?.(".tip");
      if (b) {
        e.preventDefault(); // nút nằm trong <label>: không chuyển focus sang ô nhập
        if (current === b && pinned && !pop.hidden) hide();
        else {
          show(b);
          pinned = true;
        }
      } else if (!e.target.closest?.("#tip-pop")) {
        hide();
      }
    });
    document.addEventListener("keydown", (e) => e.key === "Escape" && hide());
    window.addEventListener("scroll", hide, { passive: true, capture: true });
    window.addEventListener("resize", hide);
  }
  for (const [id, text] of Object.entries(HELP)) {
    const el = $(`#${id}`);
    const at = el && anchorFor(el);
    if (!at || at.querySelector(":scope > .tip")) continue;
    const label = (at.textContent || "").trim().replace(/\s+/g, " ").slice(0, 60);
    const b = document.createElement("button");
    b.type = "button";
    b.className = "tip";
    b.dataset.tip = text;
    b.setAttribute("aria-label", `Hướng dẫn: ${label}`);
    b.setAttribute("aria-expanded", "false");
    b.innerHTML = ICON;
    at.append(b);
  }
  return $$(".tip").length;
}
