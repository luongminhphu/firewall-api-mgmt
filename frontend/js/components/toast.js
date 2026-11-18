/* Thông báo nổi ngắn (#toast). */
import { $ } from "../util.js";

export function toast(msg, kind = "") {
  const el = $("#toast");
  el.textContent = msg;
  el.className = `toast ${kind ? "toast--" + kind : ""}`;
  clearTimeout(toast._t);
  toast._t = setTimeout(() => el.classList.add("hidden"), 4200);
}
