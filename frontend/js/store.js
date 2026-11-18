/* Trạng thái dùng chung giữa các trang + phân quyền phía giao diện (server vẫn kiểm lại mọi request). */
export const state = {
  token: "",
  user: "",
  config: null,
  firewalls: [],
  candidates: [], // [{value, kind, object}]
  source: "paste",
  groupMembers: [],
  role: "viewer",
  blockGroup: "SCANPORT GROUP", // cố định phía server; giá trị lấy lại từ /api/config
  authModes: null,
};

export const RANK = { viewer: 0, operator: 1, admin: 2 };
export const can = (role) => (RANK[state.role] ?? -1) >= RANK[role];
export const ROLE_LABEL = { admin: "Quản trị", operator: "Write", viewer: "Readonly" };

/** Bộ nhớ trình duyệt cho token (nếu bị chặn thì chỉ giữ trong RAM). */
export const tokenStore = (() => {
  try {
    const s = window["local" + "Storage"];
    s.setItem("_sb_probe", "1");
    s.removeItem("_sb_probe");
    return s;
  } catch {
    return null;
  }
})();
