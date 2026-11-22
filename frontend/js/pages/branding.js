/* Logo hiển thị: hiện ở màn hình đăng nhập + thanh trên; quản trị viên tải lên / gỡ (thẻ trong tab Người dùng). */
import { confirmAction } from "../components/modal.js";
import { api, API } from "../api.js";
import { toast } from "../components/toast.js";
import { $, $$, esc } from "../util.js";

// ---------------------------------------------------------------- branding
const brandState = { hasLogo: false, url: "", maxKb: 300, pending: null };
export async function loadBranding() {
  try {
    const r = await api("/api/branding");
    brandState.hasLogo = !!r.has_logo;
    brandState.url = r.logo_url ? `${API}${r.logo_url}` : "";
    brandState.maxKb = r.logo_max_kb || 300;
  } catch {
    brandState.hasLogo = false;
  }
  $$(".js-brand-logo").forEach((img) => {
    if (brandState.hasLogo) {
      img.src = brandState.url;
      img.hidden = false;
    } else {
      img.removeAttribute("src");
      img.hidden = true;
    }
  });
  $$(".js-brand-divider").forEach((el) => (el.hidden = !brandState.hasLogo));
  $$(".js-default-logo").forEach((el) => el.classList.toggle("hidden", brandState.hasLogo));
  renderLogoCard();
}

function renderLogoCard() {
  const box = $("#logo-preview");
  if (!box) return;
  $("#logo-max").textContent = brandState.maxKb;
  const src = brandState.pending?.dataUrl || (brandState.hasLogo ? brandState.url : "");
  box.innerHTML = src
    ? `<img src="${esc(src)}" alt="Xem trước logo" />`
    : `<span class="muted tiny">Chưa có logo — đang dùng biểu tượng mặc định</span>`;
  $("#logo-save").disabled = !brandState.pending;
  $("#logo-save").classList.toggle("btn--primary", !!brandState.pending);
  $("#logo-remove").disabled = !brandState.hasLogo || !!brandState.pending;
}

function logoMsg(text, kind) {
  const el = $("#logo-msg");
  el.textContent = text;
  el.className = `alert alert--${kind}`;
  if (!text) el.className = "alert hidden";
}

$("#logo-pick").addEventListener("click", () => $("#logo-file").click());
$("#logo-file").addEventListener("change", (e) => {
  const f = e.target.files[0];
  e.target.value = "";
  if (!f) return;
  const okType = ["image/png", "image/jpeg", "image/webp", "image/svg+xml"].includes(f.type);
  if (!okType) return logoMsg("Chỉ nhận PNG, JPG, WebP hoặc SVG.", "error");
  if (f.size > brandState.maxKb * 1024)
    return logoMsg(`Tệp ${Math.ceil(f.size / 1024)} KB vượt giới hạn ${brandState.maxKb} KB.`, "error");
  const reader = new FileReader();
  reader.onload = () => {
    brandState.pending = { dataUrl: reader.result, name: f.name };
    logoMsg(`Xem trước ${f.name} — bấm Lưu logo để áp dụng cho mọi người dùng.`, "info");
    renderLogoCard();
  };
  reader.readAsDataURL(f);
});
$("#logo-save").addEventListener("click", async () => {
  if (!brandState.pending) return;
  const btn = $("#logo-save");
  btn.disabled = true;
  try {
    await api("/api/branding/logo", { method: "PUT", body: { data_url: brandState.pending.dataUrl } });
    brandState.pending = null;
    logoMsg("Đã lưu logo.", "ok");
    toast("Đã cập nhật logo", "ok");
    await loadBranding();
  } catch (ex) {
    logoMsg(ex.message, "error");
    renderLogoCard();
  }
});
$("#logo-remove").addEventListener("click", async () => {
  if (!(await confirmAction({ title: "Gỡ logo?", ok: "Gỡ logo", html: "<p>Dùng lại biểu tượng mặc định trên giao diện và báo cáo.</p>" }))) return;
  try {
    await api("/api/branding/logo", { method: "DELETE" });
    logoMsg("Đã gỡ logo.", "ok");
    await loadBranding();
  } catch (ex) {
    logoMsg(ex.message, "error");
  }
});
