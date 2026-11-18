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

const tab = (page, name) => page.click(`.tab[data-tab="${name}"]`);
const visible = (page, sel) => page.isVisible(sel);

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
    chk("VPN: thẻ đếm theo trạng thái", (await page.$$("#vr-cards .status-card")).length === 8);
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
    await page.waitForFunction(() => document.querySelector("#vs-days").value !== "");
    await page.fill("#vs-days", "45");
    await page.click('#vs-form button[type="submit"]');
    await page.waitForSelector("#vs-msg.alert--ok");
    chk("Cài đặt: lưu ngưỡng VPN", (await page.textContent("#vs-meta")).includes("phu.luong"));

    // Logo (tab Người dùng → Logo hiển thị): tải PNG lên, hiện ở thanh trên, rồi gỡ
    await tab(page, "users");
    await page.waitForSelector("#panel-users.is-active");
    const png = Buffer.concat([Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]), Buffer.alloc(40)]);
    await page.setInputFiles("#logo-file", { name: "logo.png", mimeType: "image/png", buffer: png });
    await page.waitForFunction(() => !document.querySelector("#logo-save").disabled);
    await page.click("#logo-save");
    await page.waitForFunction(() => [...document.querySelectorAll(".js-brand-logo")].some((i) => !i.hidden && i.src));
    chk("tải logo → hiện ở giao diện", true);
    await page.click("#logo-remove");
    await page.waitForFunction(() => [...document.querySelectorAll(".js-brand-logo")].every((i) => i.hidden));
    chk("gỡ logo → về biểu tượng mặc định", true);

    // Giao diện sáng/tối
    const before = await page.evaluate(() => document.documentElement.dataset.theme || "");
    await page.click("#theme-toggle");
    const after = await page.evaluate(() => document.documentElement.dataset.theme || "");
    chk("nút sáng/tối đổi theme", before !== after, `${before} → ${after}`);
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
      chk("viewer không thấy nút Kiểm tra tất cả / Đồng bộ lịch sử / form firewall",
        !(await visible(p2, "#test-all")) && !(await visible(p2, "#c-sync")) && !(await visible(p2, "#fw-form")));
      chk("không lỗi JS (viewer)", e2.length === 0, e2.join(" | "));
      await c2.close();
    }

    // ------------------------------------------------ điện thoại
    {
      const { ctx: c3, page: p3, errors: e3 } = await newPage(browser, { tok: admin, viewport: { width: 390, height: 844 } });
      await p3.goto(B + "/");
      await p3.waitForSelector("#app:not(.hidden)");
      for (const t of ["block", "groups", "firewalls", "changes", "audit", "vpn", "settings", "users"]) {
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
