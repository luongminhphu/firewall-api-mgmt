"""Model SQLAlchemy (bảng giữ nguyên tên/cột từ v1.7 — tái cấu trúc không đổi schema)."""
from __future__ import annotations

import datetime as dt

from sqlalchemy import Boolean, Date, DateTime, ForeignKey, Integer, String, Text, UniqueConstraint, func
from sqlalchemy.orm import Mapped, mapped_column, relationship

from ..integrations.sophos.policy import BLOCK_GROUP
from .db import Base


class Firewall(Base):
    __tablename__ = "firewalls"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(120), unique=True)
    site: Mapped[str] = mapped_column(String(120), default="")
    host: Mapped[str] = mapped_column(String(255))
    port: Mapped[int] = mapped_column(Integer, default=4444)
    username: Mapped[str] = mapped_column(String(120))
    password_enc: Mapped[str] = mapped_column(Text)
    default_group: Mapped[str] = mapped_column(String(120), default=BLOCK_GROUP)
    verify_ssl: Mapped[bool] = mapped_column(Boolean, default=False)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    note: Mapped[str] = mapped_column(Text, default="")
    last_status: Mapped[str] = mapped_column(String(32), default="unknown")
    last_message: Mapped[str] = mapped_column(Text, default="")
    last_checked: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[dt.datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )

    audits: Mapped[list["AuditLog"]] = relationship(back_populates="firewall")

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "name": self.name,
            "site": self.site,
            "host": self.host,
            "port": self.port,
            "username": self.username,
            "default_group": BLOCK_GROUP,  # cố định — xem policy.py
            "verify_ssl": self.verify_ssl,
            "enabled": self.enabled,
            "note": self.note,
            "last_status": self.last_status,
            "last_message": self.last_message,
            "last_checked": self.last_checked.isoformat() if self.last_checked else None,
        }


class AuditLog(Base):
    __tablename__ = "audit_logs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    ts: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    actor: Mapped[str] = mapped_column(String(120), default="soc")
    action: Mapped[str] = mapped_column(String(32))  # block | unblock | test | firewall_cud
    firewall_id: Mapped[int | None] = mapped_column(ForeignKey("firewalls.id"), nullable=True)
    firewall_name: Mapped[str] = mapped_column(String(120), default="")
    group_name: Mapped[str] = mapped_column(String(120), default="")
    target: Mapped[str] = mapped_column(String(255), default="")  # IP / object
    result: Mapped[str] = mapped_column(String(32), default="")  # ok | skipped | error
    status_code: Mapped[str] = mapped_column(String(16), default="")
    message: Mapped[str] = mapped_column(Text, default="")
    reason: Mapped[str] = mapped_column(Text, default="")
    source: Mapped[str] = mapped_column(String(64), default="")  # teams-paste | manual | csv
    client_ip: Mapped[str] = mapped_column(String(64), default="")

    firewall: Mapped[Firewall | None] = relationship(back_populates="audits")

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "ts": self.ts.isoformat() if self.ts else None,
            "actor": self.actor,
            "action": self.action,
            "firewall_name": self.firewall_name,
            "group_name": self.group_name,
            "target": self.target,
            "result": self.result,
            "status_code": self.status_code,
            "message": self.message,
            "reason": self.reason,
            "source": self.source,
            "client_ip": self.client_ip,
        }


class GroupChange(Base):
    """Nhật ký thay đổi thành viên Object Group — mỗi dòng là một IP được thêm/bớt.

    `batch_id` gom các dòng của cùng một thao tác trên cùng firewall/group.
    `prev_hash`/`row_hash` tạo chuỗi băm (hash-chain) để phát hiện sửa/xóa log trái phép.
    """

    __tablename__ = "group_changes"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    ts: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), index=True)
    batch_id: Mapped[str] = mapped_column(String(40), index=True)
    actor: Mapped[str] = mapped_column(String(160), default="")
    actor_name: Mapped[str] = mapped_column(String(160), default="")
    auth_method: Mapped[str] = mapped_column(String(32), default="")
    firewall_id: Mapped[int | None] = mapped_column(Integer, nullable=True, index=True)
    firewall_name: Mapped[str] = mapped_column(String(120), default="")
    group_name: Mapped[str] = mapped_column(String(120), default="", index=True)
    # add | remove | drift_add | drift_remove | baseline | create_group
    change_type: Mapped[str] = mapped_column(String(20))
    object_name: Mapped[str] = mapped_column(String(160), default="")
    value: Mapped[str] = mapped_column(String(80), default="", index=True)
    count_before: Mapped[int] = mapped_column(Integer, default=0)
    count_after: Mapped[int] = mapped_column(Integer, default=0)
    reason: Mapped[str] = mapped_column(Text, default="")
    source: Mapped[str] = mapped_column(String(64), default="")
    client_ip: Mapped[str] = mapped_column(String(64), default="")
    prev_hash: Mapped[str] = mapped_column(String(64), default="")
    row_hash: Mapped[str] = mapped_column(String(64), default="")

    def hash_payload(self) -> str:
        ts = self.ts
        if ts is not None:
            # SQLite trả datetime "naive" (đã là UTC); PostgreSQL trả có múi giờ.
            ts = ts.replace(tzinfo=dt.timezone.utc) if ts.tzinfo is None else ts.astimezone(dt.timezone.utc)
        parts = [
            ts.isoformat() if ts else "",
            self.batch_id, self.actor, self.firewall_name, self.group_name, self.change_type,
            self.object_name, self.value, str(self.count_before), str(self.count_after),
            self.reason or "", self.source or "", self.prev_hash or "",
        ]
        return "\x1f".join(parts)

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "ts": (self.ts.replace(tzinfo=dt.timezone.utc) if self.ts and self.ts.tzinfo is None
                   else self.ts).isoformat() if self.ts else None,
            "batch_id": self.batch_id,
            "actor": self.actor,
            "actor_name": self.actor_name,
            "auth_method": self.auth_method,
            "firewall_id": self.firewall_id,
            "firewall_name": self.firewall_name,
            "group_name": self.group_name,
            "change_type": self.change_type,
            "object_name": self.object_name,
            "value": self.value,
            "count_before": self.count_before,
            "count_after": self.count_after,
            "reason": self.reason,
            "source": self.source,
            "client_ip": self.client_ip,
            "row_hash": self.row_hash,
        }


class GroupSnapshot(Base):
    """Ảnh chụp thành viên group lần gần nhất app nhìn thấy — dùng để phát hiện thay đổi ngoài app."""

    __tablename__ = "group_snapshots"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    firewall_id: Mapped[int] = mapped_column(Integer, index=True)
    group_name: Mapped[str] = mapped_column(String(120))
    members_json: Mapped[str] = mapped_column(Text, default="{}")  # {object_name: value}
    taken_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True))


class GroupCache(Base):
    """Cache danh sách thành viên IP Host Group theo từng firewall (v1.6) — hiển thị nhanh, quét lại sau mỗi thay đổi."""

    __tablename__ = "group_cache"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    firewall_id: Mapped[int] = mapped_column(Integer, unique=True, index=True)
    group_name: Mapped[str] = mapped_column(String(120))
    data_json: Mapped[str] = mapped_column(Text, default="{}")  # {description, ip_family, total, exists, members[]}
    status: Mapped[str] = mapped_column(String(16), default="ok")  # ok | error
    error: Mapped[str] = mapped_column(Text, default="")
    scanned_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    scan_ms: Mapped[int] = mapped_column(Integer, default=0)
    dirty: Mapped[bool] = mapped_column(Boolean, default=False)  # có thay đổi, chờ quét lại
    refreshing_since: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class Job(Base):
    """Lượt chặn/bỏ chặn chạy nền (v1.7). Lưu trong DB để mọi pod đều trả lời được /api/jobs/{id}."""

    __tablename__ = "jobs"

    id: Mapped[str] = mapped_column(String(32), primary_key=True)
    kind: Mapped[str] = mapped_column(String(16))  # block | unblock
    actor: Mapped[str] = mapped_column(String(160), default="", index=True)
    status: Mapped[str] = mapped_column(String(16), default="running")  # running | done | error
    total: Mapped[int] = mapped_column(Integer, default=0)  # số firewall
    done: Mapped[int] = mapped_column(Integer, default=0)
    result_json: Mapped[str] = mapped_column(Text, default="{}")
    error: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), index=True)
    updated_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True))
    finished_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class AppSetting(Base):
    """Cấu hình giao diện dạng key/value (logo...)."""

    __tablename__ = "app_settings"

    key: Mapped[str] = mapped_column(String(64), primary_key=True)
    value: Mapped[str] = mapped_column(Text, default="")
    updated_by: Mapped[str] = mapped_column(String(120), default="")
    updated_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class AppUser(Base):
    """Người dùng của app. Quyền: write (chặn/bỏ chặn) | readonly (chỉ xem); is_admin = quản trị user & firewall."""

    __tablename__ = "app_users"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    username: Mapped[str] = mapped_column(String(120), unique=True, index=True)  # luôn lowercase
    display_name: Mapped[str] = mapped_column(String(120), default="")
    auth_type: Mapped[str] = mapped_column(String(16), default="local")  # local | microsoft
    password_hash: Mapped[str] = mapped_column(Text, default="")
    permission: Mapped[str] = mapped_column(String(16), default="readonly")  # write | readonly
    is_admin: Mapped[bool] = mapped_column(Boolean, default=False)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    note: Mapped[str] = mapped_column(Text, default="")
    created_by: Mapped[str] = mapped_column(String(120), default="")
    created_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_login: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    # Object ID bất biến của tài khoản Entra, gắn ở lần đăng nhập Microsoft đầu tiên (UPN có thể đổi/tái sử dụng)
    entra_oid: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)

    @property
    def role(self) -> str:
        if self.is_admin:
            return "admin"
        return "operator" if self.permission == "write" else "viewer"

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "username": self.username,
            "display_name": self.display_name,
            "auth_type": self.auth_type,
            "has_password": bool(self.password_hash),
            "permission": "write" if self.is_admin else self.permission,
            "is_admin": self.is_admin,
            "role": self.role,
            "enabled": self.enabled,
            "note": self.note,
            "created_by": self.created_by,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
            "last_login": self.last_login.isoformat() if self.last_login else None,
            "entra_linked": bool(self.entra_oid),
        }


class VpnAccount(Base):
    """Tài khoản trên firewall (CHỈ ĐỌC, đã lọc theo allowlist trường — không có mật khẩu/hash/khóa).

    Không xóa khi tài khoản biến mất khỏi firewall: đánh dấu removed_at (giữ dấu vết rà soát ISO 27001);
    xuất hiện lại thì removed_at = NULL.
    """

    __tablename__ = "vpn_accounts"
    __table_args__ = (UniqueConstraint("firewall_id", "username_key", name="uq_vpn_accounts_fw_user"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    firewall_id: Mapped[int] = mapped_column(Integer, index=True)
    username: Mapped[str] = mapped_column(String(255))
    username_key: Mapped[str] = mapped_column(String(255), index=True)  # lowercase để so khớp
    display_name: Mapped[str] = mapped_column(String(255), default="")
    user_type: Mapped[str] = mapped_column(String(32), default="")
    email: Mapped[str] = mapped_column(String(255), default="")
    groups_json: Mapped[str] = mapped_column(Text, default="[]")
    sslvpn_policy: Mapped[str] = mapped_column(String(160), default="")
    status: Mapped[str] = mapped_column(String(32), default="")
    has_sslvpn: Mapped[bool] = mapped_column(Boolean, default=False)
    has_ipsec: Mapped[bool] = mapped_column(Boolean, default=False)
    description: Mapped[str] = mapped_column(Text, default="")
    first_seen_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True))
    last_seen_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True))
    removed_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class VpnSync(Base):
    """Lần đồng bộ VPN gần nhất theo firewall + loại (accounts | rules)."""

    __tablename__ = "vpn_sync"
    __table_args__ = (UniqueConstraint("firewall_id", "kind", name="uq_vpn_sync_fw_kind"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    firewall_id: Mapped[int] = mapped_column(Integer, index=True)
    kind: Mapped[str] = mapped_column(String(16))
    synced_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    status: Mapped[str] = mapped_column(String(16), default="")  # ok | error
    error: Mapped[str] = mapped_column(Text, default="")
    summary_json: Mapped[str] = mapped_column(Text, default="{}")
    duration_ms: Mapped[int] = mapped_column(Integer, default=0)


class VpnRule(Base):
    """Firewall rule thuộc Rule Group VPN (CHỈ ĐỌC) + thời hạn đã xác định (modules/vpn/expiry.py).

    Trạng thái (còn hạn / sắp hết / đã hết…) KHÔNG lưu — tính khi đọc theo ngày hôm nay và ngưỡng cấu hình.
    Rule biến mất khỏi group: removed_at (không xóa) để giữ lịch sử.
    """

    __tablename__ = "vpn_rules"
    __table_args__ = (UniqueConstraint("firewall_id", "rule_key", name="uq_vpn_rules_fw_rule"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    firewall_id: Mapped[int] = mapped_column(Integer, index=True)
    rule_name: Mapped[str] = mapped_column(String(255))
    rule_key: Mapped[str] = mapped_column(String(255), index=True)  # lowercase — tên rule là khóa (API không có ID)
    group_name: Mapped[str] = mapped_column(String(120), default="")
    position: Mapped[int] = mapped_column(Integer, default=0)  # thứ tự trong SecurityPolicyList của group
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    action: Mapped[str] = mapped_column(String(32), default="")
    policy_type: Mapped[str] = mapped_column(String(32), default="")
    log_traffic: Mapped[bool] = mapped_column(Boolean, default=False)
    detail_json: Mapped[str] = mapped_column(Text, default="{}")  # zone/mạng nguồn, identity, đích, dịch vụ…
    schedule_name: Mapped[str] = mapped_column(String(160), default="")
    schedule_end: Mapped[dt.date | None] = mapped_column(Date, nullable=True)
    description: Mapped[str] = mapped_column(Text, default="")
    team: Mapped[str] = mapped_column(String(160), default="", index=True)
    user_code: Mapped[str] = mapped_column(String(80), default="")
    name_date: Mapped[dt.date | None] = mapped_column(Date, nullable=True)
    name_status: Mapped[str] = mapped_column(String(16), default="none")  # ok | none | invalid
    expiry_date: Mapped[dt.date | None] = mapped_column(Date, nullable=True, index=True)
    expiry_source: Mapped[str] = mapped_column(String(16), default="none")  # schedule | name | none
    expiry_mismatch: Mapped[bool] = mapped_column(Boolean, default=False)
    content_hash: Mapped[str] = mapped_column(String(64), default="")
    first_seen_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True))
    last_seen_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True))
    removed_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class VpnRuleChange(Base):
    """Lịch sử thay đổi rule VPN giữa các lần đồng bộ — nối chuỗi băm (core/hashchain) như group_changes."""

    __tablename__ = "vpn_rule_changes"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    ts: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), index=True)
    firewall_id: Mapped[int | None] = mapped_column(Integer, nullable=True, index=True)
    firewall_name: Mapped[str] = mapped_column(String(120), default="")
    rule_name: Mapped[str] = mapped_column(String(255), default="", index=True)
    # baseline | rule_added | rule_removed | expiry_changed | destination_changed | identity_changed |
    # service_changed | status_changed | rule_changed
    change_type: Mapped[str] = mapped_column(String(24))
    before_json: Mapped[str] = mapped_column(Text, default="")
    after_json: Mapped[str] = mapped_column(Text, default="")
    actor: Mapped[str] = mapped_column(String(160), default="")
    prev_hash: Mapped[str] = mapped_column(String(64), default="")
    row_hash: Mapped[str] = mapped_column(String(64), default="")

    def hash_payload(self) -> str:
        ts = self.ts
        if ts is not None:
            ts = ts.replace(tzinfo=dt.timezone.utc) if ts.tzinfo is None else ts.astimezone(dt.timezone.utc)
        return "\x1f".join([ts.isoformat() if ts else "", str(self.firewall_id or ""), self.firewall_name or "",
                             self.rule_name or "", self.change_type or "", self.before_json or "", self.after_json or "",
                             self.actor or "", self.prev_hash or ""])


class EmailOutbox(Base):
    """Hàng đợi email (outbox). dedupe_key UNIQUE → lập kế hoạch chạy lại nhiều lần không gửi trùng."""

    __tablename__ = "email_outbox"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    dedupe_key: Mapped[str] = mapped_column(String(255), unique=True, index=True)
    kind: Mapped[str] = mapped_column(String(32), default="")  # vpn_expiring | vpn_expired_enabled | smtp_test
    to_addrs: Mapped[str] = mapped_column(Text, default="")  # phân cách dấu phẩy
    subject: Mapped[str] = mapped_column(String(255), default="")
    body: Mapped[str] = mapped_column(Text, default="")
    ref_json: Mapped[str] = mapped_column(Text, default="{}")  # firewall / rule liên quan
    status: Mapped[str] = mapped_column(String(16), default="pending", index=True)  # pending | sent | failed
    attempts: Mapped[int] = mapped_column(Integer, default=0)
    next_attempt_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True))
    sent_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_error: Mapped[str] = mapped_column(Text, default="")


class VpnTeamContact(Base):
    """Người đại diện của team (nhập tay — quyết định §9): nhận email báo trước hạn VPN của team."""

    __tablename__ = "vpn_team_contacts"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    team: Mapped[str] = mapped_column(String(160))
    team_key: Mapped[str] = mapped_column(String(160), unique=True, index=True)  # lowercase
    emails: Mapped[str] = mapped_column(Text, default="")  # phân cách dấu phẩy
    note: Mapped[str] = mapped_column(Text, default="")
    updated_by: Mapped[str] = mapped_column(String(120), default="")
    updated_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class ReviewCampaign(Base):
    """Đợt rà soát quyền truy cập VPN (ISO 27001 A.5.18) — docs/architecture.md §15."""

    __tablename__ = "review_campaigns"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    period_key: Mapped[str] = mapped_column(String(32), unique=True)  # 2026-Q4 | manual-<thời điểm>
    name: Mapped[str] = mapped_column(String(160))
    status: Mapped[str] = mapped_column(String(16), default="open", index=True)  # open | closed
    due_date: Mapped[dt.date] = mapped_column(Date)
    created_by: Mapped[str] = mapped_column(String(160), default="")
    created_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True))
    closed_by: Mapped[str] = mapped_column(String(160), default="")
    closed_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    note: Mapped[str] = mapped_column(Text, default="")


class ReviewItem(Base):
    """Một quyền cần xác nhận trong đợt — ẢNH CHỤP tại lúc mở đợt (không đổi theo các lần đồng bộ sau)."""

    __tablename__ = "review_items"
    __table_args__ = (UniqueConstraint("campaign_id", "kind", "firewall_id", "ref_key", name="uq_review_item"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    campaign_id: Mapped[int] = mapped_column(Integer, index=True)
    kind: Mapped[str] = mapped_column(String(16))  # rule | orphan_account
    firewall_id: Mapped[int] = mapped_column(Integer)
    firewall_name: Mapped[str] = mapped_column(String(120), default="")
    ref_key: Mapped[str] = mapped_column(String(255))  # tên rule / username (lowercase)
    title: Mapped[str] = mapped_column(String(255))
    team: Mapped[str] = mapped_column(String(160), default="")
    scope: Mapped[str] = mapped_column(String(160), default="infra", index=True)  # team_key | infra
    snapshot_json: Mapped[str] = mapped_column(Text, default="{}")
    decision: Mapped[str] = mapped_column(String(16), default="pending", index=True)  # pending|keep|revoke|change|no_response
    comment: Mapped[str] = mapped_column(Text, default="")
    decided_by: Mapped[str] = mapped_column(String(160), default="")
    decided_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    on_behalf: Mapped[bool] = mapped_column(Boolean, default=False)  # Infra quyết định thay đại diện team


class ReviewDecision(Base):
    """Nhật ký quyết định rà soát — nối chuỗi băm (core/hashchain), làm bằng chứng không sửa được."""

    __tablename__ = "review_decisions"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    ts: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), index=True)
    campaign_id: Mapped[int] = mapped_column(Integer, index=True)
    item_id: Mapped[int | None] = mapped_column(Integer, nullable=True)
    item_title: Mapped[str] = mapped_column(String(255), default="")
    decision: Mapped[str] = mapped_column(String(16))  # keep|revoke|change|no_response|open|close
    comment: Mapped[str] = mapped_column(Text, default="")
    actor: Mapped[str] = mapped_column(String(160), default="")
    on_behalf: Mapped[bool] = mapped_column(Boolean, default=False)
    prev_hash: Mapped[str] = mapped_column(String(64), default="")
    row_hash: Mapped[str] = mapped_column(String(64), default="")

    def hash_payload(self) -> str:
        ts = self.ts
        if ts is not None:
            ts = ts.replace(tzinfo=dt.timezone.utc) if ts.tzinfo is None else ts.astimezone(dt.timezone.utc)
        # giá trị mặc định của cột chỉ có sau khi ghi DB, còn băm chạy TRƯỚC → mọi trường về chuỗi
        return "\x1f".join([ts.isoformat() if ts else "", str(self.campaign_id), str(self.item_id or ""),
                            self.item_title or "", self.decision or "", self.comment or "", self.actor or "",
                            "1" if self.on_behalf else "0", self.prev_hash or ""])


# ------------------------------------------------------- tự động chặn từ Teams (v2.2)
class AutoBlockMessage(Base):
    """Tin nhắn group chat Teams app đã đọc (mỗi tin một lần — msg_id UNIQUE, nhiều pod / đọc chồng lấn không xử lý lại)."""

    __tablename__ = "autoblock_messages"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    msg_id: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    sender_id: Mapped[str] = mapped_column(String(64), default="")
    sender_name: Mapped[str] = mapped_column(String(160), default="")
    created_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), index=True)  # thời điểm tin trên Teams
    received_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True))
    # processed | no_command | ignored_sender | ignored_edited | ignored_deleted | ignored_type
    status: Mapped[str] = mapped_column(String(24), index=True)
    excerpt: Mapped[str] = mapped_column(Text, default="")  # chỉ lưu nội dung tin của tài khoản SOC
    sender_tenant: Mapped[str] = mapped_column(String(64), default="")
    trusted_by: Mapped[str] = mapped_column(String(200), default="")  # vd "Nhóm SOC-24x7" / "Tenant VNPT SOC" / "Tài khoản"
    body_hash: Mapped[str] = mapped_column(String(64), default="")
    # Theo dõi sau khi xử lý: tin bị XÓA / SỬA trên Teams (giờ Microsoft) + lúc app phát hiện
    deleted_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    deleted_seen_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    edited_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    edited_seen_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class AutoBlockRequest(Base):
    """Một lệnh 'ĐỀ XUẤT CỦA SOC: BLOCK IP <ip>' và vòng đời của nó."""

    __tablename__ = "autoblock_requests"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    message_id: Mapped[int] = mapped_column(Integer, index=True)
    ip: Mapped[str] = mapped_column(String(64), index=True)
    sender_name: Mapped[str] = mapped_column(String(160), default="")
    created_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), index=True)  # lúc app xử lý
    # Thời điểm SOC gửi lệnh = createdDateTime của tin Teams (giờ máy chủ Microsoft) — dùng cho khung giờ, ca, báo cáo
    requested_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True), nullable=True, index=True)
    # auto = tự chặn · pending = chờ duyệt · rejected_invalid = IP không hợp lệ / thuộc safe-list
    mode: Mapped[str] = mapped_column(String(16), default="pending")
    # blocking | blocked | failed | pending | approved | rejected | invalid | unblocked | unblocking
    status: Mapped[str] = mapped_column(String(16), index=True)
    pending_reason: Mapped[str] = mapped_column(String(255), default="")
    # IP thuộc whitelist (HSC / Akamai / đối tác…) → chỉ quản trị viên được Approve
    needs_admin: Mapped[bool] = mapped_column(Boolean, default=False)
    whitelist: Mapped[str] = mapped_column(String(160), default="")  # "<tên danh sách>: <dòng khớp>"
    # Trả lời kết quả vào group chat (qua Teams Workflows): "" | sent | failed | skipped
    reply_status: Mapped[str] = mapped_column(String(16), default="")
    reply_attempts: Mapped[int] = mapped_column(Integer, default=0)
    replied_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    blocked_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    job_id: Mapped[str] = mapped_column(String(32), default="")
    result_json: Mapped[str] = mapped_column(Text, default="")
    decided_by: Mapped[str] = mapped_column(String(160), default="")
    decided_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    unblocked_by: Mapped[str] = mapped_column(String(160), default="")
    unblocked_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    note: Mapped[str] = mapped_column(Text, default="")


class AutoBlockEvent(Base):
    """Nhật ký tự động chặn (nối chuỗi băm): nhận lệnh, tự chặn, chờ duyệt, duyệt, gỡ, công tắc, ngắt ngưỡng."""

    __tablename__ = "autoblock_events"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    ts: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), index=True)
    request_id: Mapped[int | None] = mapped_column(Integer, nullable=True, index=True)
    ip: Mapped[str] = mapped_column(String(64), default="")
    event: Mapped[str] = mapped_column(String(32))
    actor: Mapped[str] = mapped_column(String(160), default="")
    detail: Mapped[str] = mapped_column(Text, default="")
    prev_hash: Mapped[str] = mapped_column(String(64), default="")
    row_hash: Mapped[str] = mapped_column(String(64), default="")

    def hash_payload(self) -> str:
        ts = self.ts
        if ts is not None:
            ts = ts.replace(tzinfo=dt.timezone.utc) if ts.tzinfo is None else ts.astimezone(dt.timezone.utc)
        return "\x1f".join([ts.isoformat() if ts else "", str(self.request_id or ""), self.ip or "",
                            self.event or "", self.actor or "", self.detail or "", self.prev_hash or ""])


class AutoBlockEvidence(Base):
    """Bản chụp bằng chứng tin Teams chứa lệnh BLOCK IP, chụp NGAY lúc app nhận (trước khi chặn).

    Giữ nguyên vĩnh viễn kể cả khi người gửi xóa / sửa tin sau đó. `raw_json` = nguyên văn đối tượng chatMessage
    Microsoft Graph trả về (JSON chuẩn hóa: sort_keys, không khoảng trắng) · `sha256` = băm của raw_json ·
    nối chuỗi băm (prev_hash / row_hash) → sửa / xóa bản chụp trong DB sẽ bị phát hiện.
    """

    __tablename__ = "autoblock_evidence"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    captured_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), index=True)  # giờ app nhận
    message_id: Mapped[int] = mapped_column(Integer, index=True)  # autoblock_messages.id
    msg_id: Mapped[str] = mapped_column(String(64), index=True)   # id tin trên Teams
    chat_id: Mapped[str] = mapped_column(String(255), default="")
    sender_id: Mapped[str] = mapped_column(String(64), default="")
    sender_name: Mapped[str] = mapped_column(String(160), default="")
    sender_type: Mapped[str] = mapped_column(String(32), default="")
    sender_tenant: Mapped[str] = mapped_column(String(64), default="")
    trusted_by: Mapped[str] = mapped_column(String(200), default="")  # cách xác định người gửi là SOC lúc chụp
    teams_created_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    teams_modified_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    status: Mapped[str] = mapped_column(String(24), default="")    # trạng thái xử lý tin lúc chụp
    commands: Mapped[str] = mapped_column(Text, default="")        # các dòng lệnh bóc được (JSON)
    text: Mapped[str] = mapped_column(Text, default="")            # nội dung văn bản (đã bỏ HTML)
    raw_json: Mapped[str] = mapped_column(Text, default="")
    sha256: Mapped[str] = mapped_column(String(64), default="")
    prev_hash: Mapped[str] = mapped_column(String(64), default="")
    row_hash: Mapped[str] = mapped_column(String(64), default="")

    def hash_payload(self) -> str:
        def iso(t):
            if t is None:
                return ""
            return (t.replace(tzinfo=dt.timezone.utc) if t.tzinfo is None else t.astimezone(dt.timezone.utc)).isoformat()

        return "\x1f".join([iso(self.captured_at), str(self.message_id or ""), self.msg_id or "", self.chat_id or "",
                            self.sender_id or "", self.sender_name or "", self.sender_tenant or "",
                            self.trusted_by or "", iso(self.teams_created_at),
                            iso(self.teams_modified_at), self.status or "", self.commands or "", self.text or "",
                            self.sha256 or "", self.prev_hash or ""])
