// Smoke test giao diện (Playwright, trình duyệt thật) — gọi qua tests/ui_smoke_test.py.
// Yêu cầu: app ở http://127.0.0.1:8090 + mock Sophos 4460 (tests/run_e2e.sh dựng sẵn).
// In "PASS …" / "FAIL …" / "SKIP …" từng dòng; mã thoát 1 nếu có FAIL.
const path = require("path");

function loadPlaywright() {
  const tries = [process.env.PLAYWRIGHT_PATH, "playwright", "/opt/node-tools/node_modules/playwright"].filter(Boolean);
  for (const p of tries) {
    try { return require(p); } catch {}
  }
  return null;
}

const pw = loadPlaywright();
if (!pw) {
  console.log("SKIP không có Playwright trong môi trường này");
  process.exit(0);
}

const B = "http://127.0.0.1:8090";
let fails = 0;
const chk = (name, ok, extra = "") => {
  if (!ok) fails += 1;
  console.log(`${ok ? "PASS" : "FAIL"} ${name}${extra ? " " + extra : ""}`);
};

async function token(upn) {
  const r = await fetch(`${B}/api/auth/header`, { method: "POST", headers: { "X-SRB-UPN": upn } });
  return (await r.json()).token;
}

async function newPage(browser, { tok, viewport = { width: 1440, height: 1000 } } = {}) {
  const ctx = await browser.newContext({ viewport });
  if (tok) await ctx.addInitScript((t) => localStorage.setItem("sb_token", t), tok);
  const page = await ctx.newPage();
  const errors = [];
  page.on("pageerror", (e) => errors.push(e.message));
  page.on("console", (m) => {
    if (m.type() === "error" && !/Failed to load resource/.test(m.text())) errors.push(m.text());
  });
  page.on("dialog", (d) => d.accept());
  return { ctx, page, errors };
}

// Màn hình hẹp: menu trái là ngăn kéo — mở bằng nút ☰ trước khi chọn mục
const tab = async (page, name) => {
  if (await page.isVisible("#nav-toggle")) {
    await page.click("#nav-toggle");
    await page.waitForSelector("#app.nav-open");
    await page.waitForTimeout(250);
  }
  await page.click(`.tab[data-tab="${name}"]`);
};
const visible = (page, sel) => page.isVisible(sel);
// hộp xác nhận trong app (thay confirm() của trình duyệt): chờ mở rồi bấm nút hành động
const step = (page, n) => page.click(`[data-goto="abs-sec-${n}"]`); // Cài đặt › Tự động chặn: một bước một lúc
const confirmOk = async (page) => {
  await page.waitForSelector("#confirm-dialog[open]");
  await page.click("#confirm-ok");
  await page.waitForSelector("#confirm-dialog:not([open])", { state: "attached" });
};

(async () => {
  const browser = await pw.chromium.launch();
  try {
    // ------------------------------------------------ đăng nhập bằng mật khẩu
    {
      const { ctx, page, errors } = await newPage(browser);
      await page.goto(B + "/");
      await page.waitForSelector("#login-screen:not(.hidden)");
      chk("chưa đăng nhập → màn hình đăng nhập", await visible(page, "#login-form"));
      if (await visible(page, "#local-toggle")) await page.click("#local-toggle");
      await page.fill("#login-user", "soc");
      await page.fill("#login-pass", "sai-mat-khau");
      await page.click('#login-form button[type="submit"]');
      await page.waitForSelector("#login-error:not(.hidden)");
      chk("sai mật khẩu → thông báo lỗi", (await page.textContent("#login-error")).includes("không đúng"));
      await page.fill("#login-pass", "socadmin");
      await page.click('#login-form button[type="submit"]');
      await page.waitForSelector("#app:not(.hidden)");
      chk("đăng nhập mật khẩu chung → vào app", (await page.textContent("#who")).includes("soc"));
      await page.click("#logout");
      await page.waitForSelector("#login-screen:not(.hidden)");
      chk("Thoát → về màn hình đăng nhập", await visible(page, "#login-form"));
      chk("không lỗi JS (đăng nhập)", errors.length === 0, errors.join(" | "));
      await ctx.close();
    }

    // ------------------------------------------------ admin: luồng chính
    const admin = await token("phu.luong@hsc.com.vn");
    const { ctx, page, errors } = await newPage(browser, { tok: admin });
    await page.goto(B + "/");
    await page.waitForSelector("#app:not(.hidden)");
    chk("phiên lưu sẵn → vào thẳng app", (await page.textContent("#who")).includes("phu.luong"));
    chk("admin thấy tab Người dùng", await visible(page, "#tab-users"));

    // Firewall: thêm
    await tab(page, "firewalls");
    await page.fill("#fw-name", "FW-UI");
    await page.fill("#fw-host", "127.0.0.1");
    await page.fill("#fw-port", "4460");
    await page.fill("#fw-user", "apiadmin");
    await page.fill("#fw-pass", "Sophos@123");
    await page.click('#fw-form button[type="submit"]');
    await page.waitForSelector("#fw-list .fw-card");
    chk("thêm firewall → hiện thông báo thành công", await visible(page, "#fw-form-msg.alert--ok"));
    chk("thêm firewall → hiện thẻ firewall", (await page.textContent("#fw-list")).includes("FW-UI"));
    await page.click('#fw-list button[data-act="test"]');
    await page.waitForSelector('#fw-list .chip--ok');
    chk("Kiểm tra kết nối → Kết nối OK", (await page.textContent("#fw-list")).includes("Kết nối OK"));

    // Chặn: chạy thử rồi chặn thật
    await tab(page, "block");
    await page.waitForSelector("#fw-picker input[type=checkbox]");
    await page.fill("#paste-text", "[08:12] SOC: chặn 45.155.204.77 và 185[.]220[.]101[.]0/24, bỏ qua 10.0.0.5");
    await page.waitForFunction(() => document.querySelectorAll("#candidate-list .cand").length === 2);
    chk("bóc IP từ chat (kể cả làm mờ, loại IP nội bộ)", (await page.textContent("#count-chip")).includes("2"));
    const boxes = await page.$$("#fw-picker input[type=checkbox]");
    for (const b of boxes) if (!(await b.isChecked())) await b.check();
    await page.fill("#block-reason", "UI smoke");
    await page.check("#dry-run");
    await page.click("#do-block");
    await page.waitForSelector("#block-result .result-summary", { timeout: 30000 });
    chk("chạy thử → tổng kết 'Chạy thử xong'", (await page.textContent("#block-result")).includes("Chạy thử xong"));
    await page.uncheck("#dry-run");
    await page.click("#do-block");
    await page.waitForSelector("#confirm-dialog[open]");
    chk("chặn thật → màn xác nhận trong app liệt kê IP, firewall, lý do; nút ghi đúng hành động",
      (await page.textContent("#confirm-body")).includes("185.220.101.0/24")
      && (await page.textContent("#confirm-body")).includes("UI smoke")
      && /^Chặn 2 IP trên \d+ firewall$/.test((await page.textContent("#confirm-ok")).trim())
      && (await page.evaluate(() => document.activeElement.id)) === "confirm-cancel",
      await page.textContent("#confirm-ok"));
    await page.keyboard.press("Escape");
    chk("Esc ở màn xác nhận → hủy, không chặn", !(await visible(page, "#confirm-dialog"))
      && !/Đã chặn xong/.test(await page.textContent("#block-result")));
    await page.focus("#block-reason");
    await page.keyboard.press("Control+Enter");
    chk("Phím tắt: Ctrl+Enter mở màn xác nhận chặn", await visible(page, "#confirm-dialog"));
    await confirmOk(page);
    await page.waitForFunction(() => /Đã chặn xong/.test(document.querySelector("#block-result")?.textContent || ""),
      null, { timeout: 30000 });
    chk("chặn thật → 'Đã chặn xong'", true);

    // IP Host Group: thấy IP, bỏ chặn
    await tab(page, "groups");
    await page.waitForFunction(() => /45\.155\.204\.77/.test(document.querySelector("#g-table")?.textContent || ""),
      null, { timeout: 20000 });
    chk("IP Host Group hiện IP vừa chặn", true);
    await page.fill("#g-search", "45.155.204.77");
    await page.waitForFunction(() => document.querySelectorAll("#g-table tbody input[type=checkbox]").length === 1);
    await page.check("#g-table tbody input[type=checkbox]");
    await page.click("#do-unblock");
    await confirmOk(page);
    await page.waitForFunction(() => /đã bỏ/.test(document.querySelector("#unblock-result")?.textContent || ""),
      null, { timeout: 30000 });
    chk("bỏ chặn → kết quả 'đã bỏ'", true);

    // Lịch sử thay đổi + kiểm tra chuỗi băm
    await tab(page, "changes");
    await page.waitForSelector("#c-list .cb");
    chk("Lịch sử thay đổi có bản ghi", (await page.$$("#c-list .cb")).length >= 2);
    await page.click("#c-verify");
    await page.waitForSelector("#c-verify-msg.alert--ok");
    chk("kiểm tra chuỗi băm → toàn vẹn", (await page.textContent("#c-verify-msg")).includes("Toàn vẹn"));

    // Audit
    await tab(page, "audit");
    await page.waitForFunction(() => document.querySelectorAll("#a-table tbody tr td.mono").length > 0);
    chk("Audit log có dòng", (await page.textContent("#a-table")).includes("UI smoke"));

    // Người dùng
    await tab(page, "users");
    await page.waitForSelector("#u-table tbody tr");
    await page.fill("#u-username", "ui.smoke");
    await page.fill("#u-display", "UI Smoke");
    await page.fill("#u-pass", "Matkhau12345");
    await page.fill("#u-pass2", "Matkhau12345");
    await page.click('#u-form button[type="submit"]');
    await page.waitForFunction(() => /ui\.smoke/.test(document.querySelector("#u-table")?.textContent || ""));
    chk("tạo người dùng → hiện trong bảng", true);

    // VPN: đồng bộ (tài khoản + rule, chỉ đọc) → dashboard thời hạn
    await tab(page, "vpn");
    await page.waitForSelector("#panel-vpn.is-active");
    await page.click("#v-sync");
    await page.waitForFunction(() => document.querySelectorAll("#vr-table tbody tr[data-rule]").length === 8,
      null, { timeout: 30000 });
    chk("VPN: đồng bộ → bảng rule thời hạn (8 rule trong group VPN)", true);
    chk("VPN: 'Cần xử lý' + 5 thẻ việc cần làm + 3 chip trạng thái (8 mục lọc)",
      (await page.$$("#vr-cards .status-card")).length === 5 && (await page.$$("#vr-cards [data-status]")).length === 8
      && /Cần xử lý|Không có rule nào cần xử lý/.test(await page.textContent("#vr-cards .vr-todo")));
    await page.click('#vr-cards [data-status="unreadable"]');
    await page.waitForFunction(() => document.querySelectorAll("#vr-table tbody tr[data-rule]").length === 1);
    chk("VPN: bấm thẻ → lọc theo trạng thái", (await page.getAttribute('#vr-cards [data-status="unreadable"]', "aria-pressed")) === "true");
    chk("VPN: link CSV theo bộ lọc", (await page.getAttribute("#vr-export", "href")).includes("status=unreadable"));
    await page.click('#vr-cards [data-status="unreadable"]');
    await page.waitForFunction(() => document.querySelectorAll("#vr-table tbody tr[data-rule]").length === 8);
    chk("VPN: bấm lại thẻ → bỏ lọc", true);
    await page.click("#vr-table tbody tr[data-rule] .rule-name");
    await page.waitForSelector("#modal[open] .kv");
    chk("VPN: chi tiết rule (dialog) có lịch sử", (await page.textContent("#modal")).includes("Lịch sử"));
    await page.keyboard.press("Escape");
    await page.waitForFunction(() => !document.querySelector("#modal").open);
    chk("VPN: Esc đóng chi tiết", true);
    await page.click('#v-view [data-view="accounts"]');
    await page.waitForFunction(() => document.querySelectorAll("#v-table tbody tr td.nowrap").length > 0);
    chk("VPN: view Tài khoản", (await page.$$("#v-table tbody tr")).length === 5);
    await page.fill("#v-q", "rms");
    await page.waitForFunction(() => document.querySelectorAll("#v-table tbody tr").length === 2);
    chk("VPN: lọc tài khoản theo nhóm/từ khóa", true);
    await page.fill("#v-q", "");
    await page.click('#v-view [data-view="history"]');
    await page.waitForSelector("#vh-list .hist li");
    await page.click("#vh-verify");
    await page.waitForSelector("#vh-verify-msg.text-ok");
    chk("VPN: lịch sử + kiểm tra chuỗi băm", (await page.textContent("#vh-verify-msg")).includes("Toàn vẹn"));
    await page.click('#v-view [data-view="rules"]');

    // Cài đặt (admin): ngưỡng sắp hết hạn
    await tab(page, "settings");
    chk("Cài đặt: có 4 nhóm (Tự động chặn, VPN & rà soát, Email & thông báo, Giao diện)",
      (await page.$$eval("#st-nav [data-st]", (xs) => xs.map((x) => x.dataset.st))).join(",") === "autoblock,vpn,mail,general");
    await page.click('#st-nav [data-st="vpn"]');
    chk("Cài đặt: chọn nhóm → chỉ hiện nhóm đó", await visible(page, "#vs-form") && !(await visible(page, "#ab-form"))
      && !(await visible(page, "#smtp-form")));
    await page.waitForFunction(() => document.querySelector("#vs-days").value !== "");
    await page.fill("#vs-days", "45");
    await page.click('#vs-form button[type="submit"]');
    await page.waitForSelector("#vs-msg.alert--ok");
    chk("Cài đặt: lưu ngưỡng VPN", (await page.textContent("#vs-meta")).includes("phu.luong"));
    // SMTP (để tắt), thông báo, đại diện team, hàng đợi
    await page.click('#st-nav [data-st="mail"]');
    await page.fill("#smtp-host", "smtp.example.invalid");
    await page.fill("#smtp-port", "587");
    await page.fill("#smtp-user", "soc");
    await page.fill("#smtp-pass", "Bi-mat-SMTP-1");
    await page.fill("#smtp-from", "soc-rapid-block@hsc.com.vn");
    await page.click('#smtp-form button[type="submit"]');
    await page.waitForSelector("#smtp-msg.alert--ok");
    chk("Cài đặt: lưu SMTP, mật khẩu không hiện lại", (await page.inputValue("#smtp-pass")) === ""
      && (await page.getAttribute("#smtp-pass", "placeholder")).includes("đã lưu")
      && (await page.textContent("#smtp-state")) === "Đang tắt");
    await page.check("#nt-enabled");
    await page.fill("#nt-infra", "infra@hsc.com.vn");
    await page.click('#nt-form button[type="submit"]');
    await page.waitForSelector("#nt-msg.alert--ok");
    chk("Cài đặt: bật thông báo hạn VPN", true);
    await page.fill("#tc-table tbody tr:first-child .tc-team", "RMS RESEARCH");
    await page.fill("#tc-table tbody tr:first-child .tc-emails", "rms.lead@hsc.com.vn");
    await page.click("#tc-save");
    await page.waitForSelector("#tc-msg.alert--ok");
    chk("Cài đặt: lưu đại diện team", (await page.textContent("#tc-msg")).includes("1 team"));
    await page.click("#ob-run");
    await page.waitForFunction(() => /nằm chờ|Xếp hàng/.test(document.querySelector("#ob-note").textContent));
    chk("Cài đặt: Chạy ngay → thư nằm chờ khi SMTP tắt", (await page.textContent("#ob-note")).includes("nằm chờ"));

    // Tooltip hướng dẫn cạnh mục cấu hình
    const ntip = await page.$$eval(".tip", (xs) => xs.length);
    chk("Tooltip: có nút ⓘ hướng dẫn ở các mục cấu hình", ntip >= 40, ntip);
    await page.click('#st-nav [data-st="autoblock"]');
    await page.click('[data-goto="abs-sec-3"]');
    chk("Cài đặt: bấm bước 3 → chỉ hiện bước 3 (Lịch & giới hạn)", await visible(page, "#abs-sec-3")
      && !(await visible(page, "#abs-sec-1")) && (await page.getAttribute('[data-goto="abs-sec-3"]', "aria-current")) === "step");
    await page.hover('#abs-limit');
    await page.focus('label:has(#abs-limit) .tip');
    await page.waitForSelector("#tip-pop:not([hidden])");
    chk("Tooltip: focus nút ⓘ → hiện hướng dẫn, gắn aria-describedby",
      (await page.textContent("#tip-pop")).includes("60 phút")
      && (await page.getAttribute('label:has(#abs-limit) .tip', "aria-describedby")) === "tip-pop");
    await page.keyboard.press("Escape");
    await page.waitForSelector("#tip-pop", { state: "hidden" });
    chk("Tooltip: Esc đóng hướng dẫn", true);
    await page.click('label:has(#abs-weekend) .tip');
    chk("Tooltip: bấm ⓘ trong nhãn checkbox không đổi trạng thái checkbox", await page.isChecked("#abs-weekend")
      && !(await page.isHidden("#tip-pop")));
    await page.click("#panel-settings h2");

    // Tự động chặn từ Teams (admin): cấu hình Graph, chọn tài khoản SOC từ người gửi gần đây, whitelist, bật
    const G = "http://127.0.0.1:4470";
    const SOC = "11111111-2222-3333-4444-555555555555";
    const say = (html) => fetch(`${G}/_post`, { method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ sender_id: SOC, name: "SOC Ca đêm", html }) });
    await fetch(`${G}/_reset`, { method: "POST" });
    await say("<p>Dạ chào các anh</p>");
    await step(page, 1);
    await page.fill("#abs-tenant", "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee");
    await page.fill("#abs-client", "12345678-1234-1234-1234-123456789abc");
    await page.fill("#abs-secret", "graph-secret");
    await page.fill("#abs-chat", "19:mockchat@thread.v2");
    await page.click("#abs-test");
    await page.waitForSelector("#abs-test-out .alert--ok");
    await step(page, 2);
    await page.waitForSelector(`#abs-seen [data-add="${SOC}"]`);
    chk("Tự động chặn: Kiểm tra kết nối → liệt kê người gửi gần đây", true);
    chk("Tự động chặn: nút Kiểm tra kết nối giữ nhãn sau khi chạy xong",
      (await page.textContent("#abs-test")).trim() === "Kiểm tra kết nối", await page.textContent("#abs-test"));
    await page.click(`#abs-seen [data-add="${SOC}"]`);
    chk("Tự động chặn: chọn tài khoản SOC từ người gửi", (await page.textContent("#abs-senders")).includes(SOC));
    await step(page, 4);
    chk("Tự động chặn: mặc định có whitelist HSC / Akamai / Đối tác",
      (await page.$$eval("#abs-wl [data-wl-name]", (xs) => xs.map((x) => x.value))).join(",") === "HSC,Akamai,Đối tác");
    await page.fill('#abs-wl [data-wl-text="1"]', "23.32.0.0/11   # Akamai edge\n104.64.0.0/10");
    chk("Tự động chặn: đếm số dòng whitelist khi nhập", (await page.textContent('[data-wl-count="1"]')) === "2 dòng");
    await page.click("#abs-wl-add");
    await page.fill('#abs-wl [data-wl-name="3"]', "Nhà cung cấp SOC");
    await page.fill('#abs-wl [data-wl-text="3"]', "45.117.80.0/22");
    await step(page, 5);
    await page.fill("#abs-reply-url", "http://127.0.0.1:4470/_workflow?sig=bi-mat");
    await page.check("#abs-reply");
    await page.click("#abs-reply-test");
    await page.waitForSelector("#abs-msg.alert--ok");
    chk("Tự động chặn: gửi thử trả lời vào group chat qua Workflows",
      (await page.textContent("#abs-msg")).includes("INFRA ĐÃ BLOCK 192.0.2.1 THEO YÊU CẦU LÚC"));
    chk("Tự động chặn: nút Gửi thử giữ nhãn sau khi gửi xong",
      (await page.textContent("#abs-reply-test")).trim() === "Gửi thử", await page.textContent("#abs-reply-test"));
    chk("Tự động chặn: URL webhook không hiện lại, chỉ tên máy",
      (await page.inputValue("#abs-reply-url")) === "" && (await page.getAttribute("#abs-reply-url", "placeholder")).includes("127.0.0.1"));
    chk("Tự động chặn: lịch mặc định 18:00–08:00 + cả ngày cuối tuần",
      (await page.inputValue("#abs-wstart")) === "18:00" && (await page.isChecked("#abs-weekend")));
    await step(page, 3);
    await page.click("#abs-hol-add");
    await page.fill('#abs-hol [data-k="name"]', "Nghỉ lễ thử");
    await page.uncheck("#abs-window");
    await page.fill("#abs-poll", "5");
    await step(page, 1);
    await page.check("#abs-enabled");
    await page.click('#ab-form button[type="submit"]');
    await page.waitForFunction(() => /Đã lưu/.test(document.querySelector("#abs-msg").textContent));
    chk("Tự động chặn: lưu + bật, chu kỳ 5 phút", (await page.textContent("#abs-msg")).includes("5 phút")
      && (await page.textContent("#ab-cfg-state")) === "Đang bật");
    chk("Tự động chặn: secret không hiện lại", (await page.inputValue("#abs-secret")) === "");
    chk("Tự động chặn: lưu ngày lễ", (await page.inputValue('#abs-hol [data-k="name"]')) === "Nghỉ lễ thử");
    await say("<p>ĐỀ XUẤT CỦA SOC: BLOCK IP 185.220.101.7</p><p>ĐỀ XUẤT CỦA SOC: BLOCK IP 23.33.1.1</p>");
    await tab(page, "autoblock");
    await page.waitForSelector("#panel-autoblock.is-active");
    await page.waitForSelector("#ab-cards .ab-seg");
    chk("Tự động chặn: một dòng trạng thái thay cho 5 ô số", /Tự động chặn (BẬT|TẮT)/.test(await page.textContent("#ab-cards"))
      && /giới hạn \d+/.test(await page.textContent("#ab-cards")));
    chk("Tự động chặn: nhật ký 'Tất cả lệnh' thu gọn mặc định", !(await page.$eval("#ab-all-wrap", (d) => d.open)));
    await page.click("#ab-all-wrap > summary");
    await page.click("#ab-poll");
    await page.waitForFunction(() => /23\.33\.1\.1/.test(document.querySelector("#ab-pending").textContent));
    chk("Tự động chặn: IP thuộc whitelist Akamai → chờ duyệt, có nhãn whitelist",
      (await page.textContent("#ab-pending")).includes("Whitelist · Akamai: 23.32.0.0/11"));
    await page.waitForFunction(() => /185\.220\.101\.7[\s\S]*Đã chặn/.test(document.querySelector("#ab-all").textContent), null, { timeout: 15000 }).catch(() => {});
    if (!/Đã chặn/.test(await page.textContent("#ab-all"))) {
      await page.selectOption("#ab-status", "blocked");
      await page.waitForFunction(() => /185\.220\.101\.7/.test(document.querySelector("#ab-all").textContent));
      await page.selectOption("#ab-status", "");
    }
    chk("Tự động chặn: IP thường → tự chặn", true);
    await page.click("#ab-all [data-ev]");
    await page.waitForSelector("#modal[open] .ev-text");
    chk("Tự động chặn: nút Bằng chứng → bản chụp tin gốc + SHA-256 + link tải JSON",
      (await page.textContent("#modal .ev-text")).includes("ĐỀ XUẤT CỦA SOC: BLOCK IP")
      && /evidence\.json\?token=/.test(await page.getAttribute("#modal a[download]", "href"))
      && (await page.textContent("#modal")).includes("toàn vẹn"));
    await page.click("#modal [data-close]");
    await page.waitForFunction(() => /Đã báo Teams/.test(document.querySelector("#ab-all").textContent), null, { timeout: 15000 }).catch(() => {});
    if (!/Đã báo Teams/.test(await page.textContent("#ab-all"))) { await page.selectOption("#ab-status", ""); await page.waitForTimeout(800); }
    chk("Tự động chặn: cột ghi chú hiện 'Đã báo Teams'", /Đã báo Teams/.test(await page.textContent("#ab-all")));
    await page.click("#ab-pending [data-approve]");
    await confirmOk(page);
    await page.waitForFunction(() => !/23\.33\.1\.1/.test(document.querySelector("#ab-pending").textContent), null, { timeout: 20000 });
    chk("Tự động chặn: quản trị viên Approve IP whitelist → rời danh sách chờ", true);
    await page.click("#ab-off");
    await confirmOk(page);
    await page.waitForSelector("#ab-banner .alert--warn");
    chk("Tự động chặn: Tắt khẩn cấp → banner cảnh báo, hiện nút Bật lại", await visible(page, "#ab-on"));
    await page.click("#ab-on");
    await page.waitForFunction(() => !document.querySelector("#ab-banner .alert--warn"));
    await page.click("#ab-verify");
    await page.waitForSelector("#ab-verify-msg .chip--ok");
    chk("Tự động chặn: kiểm tra chuỗi băm nhật ký", true);

    // Báo cáo: Executive Summary, chọn kỳ / chọn trên lịch, link tải PDF / Excel, form gửi email
    await tab(page, "reports");
    await page.waitForFunction(() => document.querySelector("#rp-headline").textContent.includes("Trong 7 ngày"));
    chk("Báo cáo: Executive Summary + 6 thẻ chỉ số + biểu đồ 7 cột", (await page.$$("#rp-cards .status-card")).length === 6
      && (await page.$$("#rp-chart .rp-bar")).length === 7);
    chk("Báo cáo: link tải PDF / Excel kèm kỳ + token", /blocks\.pdf\?days=7&token=/.test(await page.getAttribute("#rp-pdf", "href"))
      && /blocks\.xlsx\?days=7&token=/.test(await page.getAttribute("#rp-xlsx", "href")));
    await page.click('#rp-seg [data-days="30"]');
    await page.waitForFunction(() => document.querySelectorAll("#rp-chart .rp-bar").length === 30);
    chk("Báo cáo: chọn 30 ngày → 30 cột", true);
    await page.click('#rp-seg [data-days="custom"]');
    const from3 = await page.evaluate(() => {
      const d = new Date(Date.now() - 2 * 86400000);
      return d.toLocaleDateString("sv-SE", { timeZone: "Asia/Ho_Chi_Minh" });
    });
    await page.fill("#rp-from", from3);
    await page.click("#rp-apply");
    await page.waitForFunction(() => document.querySelectorAll("#rp-chart .rp-bar").length === 3);
    chk("Báo cáo: chọn trên lịch 3 ngày → link tải theo from/to", /from=\d{4}-\d\d-\d\d&to=/.test(await page.getAttribute("#rp-pdf", "href")));
    const pdfResp = await page.evaluate(async (u) => { const r = await fetch(u); return [r.status, r.headers.get("content-type")]; },
      await page.getAttribute("#rp-pdf", "href"));
    chk("Báo cáo: tải PDF từ giao diện", pdfResp[0] === 200 && pdfResp[1] === "application/pdf", JSON.stringify(pdfResp));
    chk("Báo cáo: admin thấy form gửi email", await visible(page, "#rp-mail"));
    await page.fill("#rp-to-addr", "sep@hsc.com.vn");
    await page.click("#rp-send");
    await page.waitForSelector("#rp-mail-msg.alert--error");
    chk("Báo cáo: SMTP đang tắt → báo lỗi rõ ràng", (await page.textContent("#rp-mail-msg")).includes("TẮT"));
    chk("Báo cáo: nút gửi email giữ nhãn sau khi báo lỗi", !!(await page.textContent("#rp-send")).trim()
      && !(await page.isDisabled("#rp-send")), await page.textContent("#rp-send"));

    // Rà soát định kỳ (admin): mở đợt, quyết định (thu hồi cần lý do), tiến độ theo team
    await tab(page, "review");
    await page.waitForSelector("#panel-review.is-active");
    await page.click("#rv-open");
    await confirmOk(page);
    await page.waitForFunction(() => /Đang mở/.test(document.querySelector("#rv-camps")?.textContent || ""));
    chk("Rà soát: admin mở đợt", (await page.$$("#rv-scopes .rv-scope")).length === 2);
    await page.waitForSelector("#rv-list .rv-item");
    const first = await page.getAttribute("#rv-list .rv-item [data-dec='revoke']", "data-id");
    await page.click(`#rv-list [data-dec='revoke'][data-id='${first}']`);
    await page.waitForSelector("#rv-comment");
    await page.click(`[data-confirm='${first}']`);
    await page.waitForTimeout(400);
    chk("Rà soát: thu hồi không lý do bị từ chối", !!(await page.$(`#rv-item-${first}`)));
    await page.fill("#rv-comment", "Không còn nhu cầu");
    await page.click(`[data-confirm='${first}']`);
    await page.waitForFunction((id) => !document.querySelector(`#rv-item-${id}`), first);
    chk("Rà soát: thu hồi kèm lý do → rời danh sách chưa quyết định", true);

    // Logo (Cài đặt › Giao diện): tải PNG lên, hiện ở thanh trên, rồi gỡ
    await tab(page, "settings");
    await page.click('#st-nav [data-st="general"]');
    await page.waitForSelector("#logo-pick", { state: "visible" });
    await page.reload();
    await page.waitForSelector("#panel-settings.is-active");
    chk("Cài đặt: tải lại trang → mở lại đúng nhóm vừa xem (Giao diện)", await visible(page, "#logo-pick"));
    const png = Buffer.concat([Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]), Buffer.alloc(40)]);
    await page.setInputFiles("#logo-file", { name: "logo.png", mimeType: "image/png", buffer: png });
    await page.waitForFunction(() => !document.querySelector("#logo-save").disabled);
    await page.click("#logo-save");
    await page.waitForFunction(() => [...document.querySelectorAll(".js-brand-logo")].some((i) => !i.hidden && i.src));
    chk("tải logo → hiện ở giao diện", true);
    await page.click("#logo-remove");
    await confirmOk(page);
    await page.waitForFunction(() => [...document.querySelectorAll(".js-brand-logo")].every((i) => i.hidden));
    chk("gỡ logo → về biểu tượng mặc định", true);

    // Giao diện sáng/tối
    const before = await page.evaluate(() => document.documentElement.dataset.theme || "");
    await page.click("#theme-toggle");
    const after = await page.evaluate(() => document.documentElement.dataset.theme || "");
    chk("nút sáng/tối đổi theme", before !== after, `${before} → ${after}`);
    await page.reload();
    await page.waitForSelector("#theme-toggle");
    const kept = await page.evaluate(() => document.documentElement.dataset.theme || "");
    chk("tải lại trang → giữ chế độ sáng/tối vừa chọn", kept === after, `${after} → ${kept}`);
    await page.click("#theme-toggle");
    await page.reload();
    await page.waitForSelector("#theme-toggle");
    const back = await page.evaluate(() => document.documentElement.dataset.theme || "");
    chk("đổi lại rồi tải lại → vẫn nhớ lựa chọn mới nhất", back === before, `${before} → ${back}`);
    chk("không lỗi JS (luồng admin)", errors.length === 0, errors.join(" | "));
    await ctx.close();

    // ------------------------------------------------ router (deep link + Back)
    {
      const { ctx: cr, page: pr, errors: er } = await newPage(browser, { tok: admin });
      await pr.goto(B + "/#audit");
      await pr.waitForSelector('#panel-audit.is-active');
      await pr.waitForFunction(() => document.querySelectorAll("#a-table tbody tr td.mono").length > 0);
      chk("deep link #audit mở đúng tab và tải dữ liệu", true);
      await tab(pr, "groups");
      await pr.waitForSelector('#panel-groups.is-active');
      await pr.goBack();
      await pr.waitForSelector('#panel-audit.is-active');
      chk("nút Back quay lại tab trước", (await pr.getAttribute("#tab-audit", "aria-selected")) === "true");
      chk("không lỗi JS (router)", er.length === 0, er.join(" | "));
      await cr.close();
    }

    // ------------------------------------------------ viewer
    {
      const viewer = await token("xem@hsc.com.vn");
      const { ctx: c2, page: p2, errors: e2 } = await newPage(browser, { tok: viewer });
      await p2.goto(B + "/");
      await p2.waitForSelector("#app:not(.hidden)");
      chk("viewer không thấy tab Người dùng", !(await visible(p2, "#tab-users")));
      await p2.goto(B + "/#users");
      await p2.waitForSelector("#app:not(.hidden)");
      await p2.waitForSelector("#panel-block.is-active");
      chk("viewer mở #users → về tab Chặn nhanh", !(await visible(p2, "#panel-users")));
      await p2.fill("#paste-text", "45.155.204.88");
      await p2.waitForFunction(() => document.querySelectorAll("#candidate-list .cand").length === 1);
      chk("viewer không bấm được Chặn ngay", await p2.isDisabled("#do-block"));
      await tab(p2, "vpn");
      await p2.waitForSelector("#panel-vpn.is-active");
      chk("viewer xem được tab VPN nhưng không có nút Đồng bộ", !(await visible(p2, "#v-sync")));
      chk("viewer không thấy tab Cài đặt", !(await visible(p2, "#tab-settings")));
      await tab(p2, "reports");
      await p2.waitForSelector("#rp-cards .status-card");
      chk("viewer xem được Báo cáo nhưng không có form gửi email", !(await visible(p2, "#rp-mail")));
      await tab(p2, "autoblock");
      await p2.waitForSelector("#ab-cards .ab-seg");
      chk("viewer xem tab Tự động chặn nhưng không có nút Tắt khẩn cấp / Approve / Gỡ chặn",
        !(await visible(p2, "#ab-off")) && !(await p2.$("#ab-pending [data-approve]")) && !(await p2.$("[data-unblock]")));
      chk("viewer không thấy nút Kiểm tra tất cả / Đồng bộ lịch sử / form firewall",
        !(await visible(p2, "#test-all")) && !(await visible(p2, "#c-sync")) && !(await visible(p2, "#fw-form")));
      chk("không lỗi JS (viewer)", e2.length === 0, e2.join(" | "));
      await c2.close();
    }

    // ------------------------------------------------ vai trò Rà soát (đại diện team)
    if (process.env.REVIEWER_TOKEN) {
      const { ctx: c4, page: p4, errors: e4 } = await newPage(browser, { tok: process.env.REVIEWER_TOKEN });
      await p4.goto(B + "/");
      await p4.waitForSelector("#app:not(.hidden)");
      await p4.waitForSelector("#panel-review.is-active");
      const tabs = await p4.$$eval(".tab", (ts) => ts.filter((t) => !t.classList.contains("hidden")).map((t) => t.dataset.tab));
      chk("reviewer chỉ thấy tab Rà soát", JSON.stringify(tabs) === '["review"]', JSON.stringify(tabs));
      chk("reviewer không thấy phần quản lý đợt", !(await visible(p4, "#rv-admin")));
      await p4.waitForSelector("#rv-list .rv-item");
      const n0 = (await p4.$$("#rv-list .rv-item")).length;
      chk("reviewer thấy mục của team mình (RMS RESEARCH)", n0 === 3, n0);
      await p4.click("#rv-list .rv-item [data-dec='keep']");
      await p4.waitForFunction((n) => document.querySelectorAll("#rv-list .rv-item").length === n - 1, n0);
      await p4.waitForFunction(() => /1\/3/.test(document.querySelector("#rv-progress").textContent));
      chk("reviewer: Còn cần → tiến độ cập nhật", true);
      chk("không lỗi JS (reviewer)", e4.length === 0, e4.join(" | "));
      await c4.close();
    }

    // ------------------------------------------------ điện thoại
    {
      const { ctx: c3, page: p3, errors: e3 } = await newPage(browser, { tok: admin, viewport: { width: 390, height: 844 } });
      await p3.goto(B + "/");
      await p3.waitForSelector("#app:not(.hidden)");
      for (const t of ["block", "groups", "firewalls", "changes", "audit", "reports", "vpn", "review", "autoblock", "settings", "users"]) {
        await tab(p3, t);
        await p3.waitForTimeout(250);
        const overflow = await p3.evaluate(() => document.documentElement.scrollWidth - window.innerWidth);
        chk(`điện thoại 390px: tab ${t} không cuộn ngang`, overflow <= 1, `lố ${overflow}px`);
      }
      chk("không lỗi JS (điện thoại)", e3.length === 0, e3.join(" | "));
      await c3.close();
    }
  } catch (ex) {
    chk("kịch bản chạy hết không lỗi", false, String(ex && ex.stack || ex).split("\n").slice(0, 3).join(" "));
  } finally {
    await browser.close();
  }
  console.log("FAILS:", fails);
  process.exit(fails ? 1 : 0);
})();
