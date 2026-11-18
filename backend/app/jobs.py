"""Chạy chặn/bỏ chặn ở chế độ nền, song song theo firewall (v1.7 — sửa lỗi 504).

Vì sao: request đồng bộ chặn N IP trên M firewall có thể kéo dài quá timeout của Entra App Proxy (~85s)
hoặc ingress NGINX (60s) → trình duyệt nhận 504 dù backend vẫn đang ghi lên firewall. Giờ:

1. Request tạo một `Job` (bảng `jobs`) rồi chạy các firewall song song (tối đa FW_PARALLEL luồng).
2. Request chờ tối đa JOB_SYNC_WAIT giây: xong kịp → trả kết quả như cũ; chưa xong → HTTP 202 + mã job.
3. Mỗi firewall xong là ghi ngay kết quả của nó vào job → giao diện hiển thị dần qua GET /api/jobs/{id}.

Mỗi firewall chạy với DB session riêng (Session của SQLAlchemy không an toàn đa luồng).
"""
from __future__ import annotations

import datetime as dt
import json
import logging
import threading
import uuid
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Callable

from sqlalchemy import delete
from sqlalchemy.orm import Session

from .core.config import settings
from .core.db import SessionLocal
from .core.models import Firewall, Job

log = logging.getLogger("jobs")

# Dùng chung cho mọi job: giới hạn tổng số kết nối đồng thời tới firewall của cả pod.
_pool = ThreadPoolExecutor(max_workers=settings.FW_PARALLEL, thread_name_prefix="fw-job")
_events: dict[str, threading.Event] = {}
_events_guard = threading.Lock()

Work = Callable[[Session, Firewall], dict]


def _now() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


def _aware(t: dt.datetime | None) -> dt.datetime | None:
    return None if t is None else (t if t.tzinfo else t.replace(tzinfo=dt.timezone.utc))


def submit(kind: str, actor: str, fw_ids: list[int], work: Work, *, meta: dict | None = None,
           on_done: Callable[[list[dict]], dict] | None = None) -> str:
    """Tạo job và chạy nền. `work(db, fw)` xử lý một firewall; `on_done(results)` trả thêm trường cho kết quả."""
    job_id = uuid.uuid4().hex
    now = _now()
    with SessionLocal() as db:
        db.add(Job(id=job_id, kind=kind, actor=actor, status="running", total=len(fw_ids), done=0,
                   result_json=json.dumps({**(meta or {}), "results": []}, ensure_ascii=False),
                   created_at=now, updated_at=now))
        db.commit()
    ev = threading.Event()
    with _events_guard:
        _events[job_id] = ev
    threading.Thread(target=_run, args=(job_id, fw_ids, work, meta or {}, on_done, ev),
                     name=f"job-{job_id[:8]}", daemon=True).start()
    return job_id


def wait(job_id: str, timeout: float) -> bool:
    """Chờ job (chạy trong pod này) xong tối đa `timeout` giây. True = đã xong."""
    with _events_guard:
        ev = _events.get(job_id)
    return True if ev is None else ev.wait(max(0.0, timeout))


def _one(fw_id: int, work: Work) -> dict:
    with SessionLocal() as db:
        fw = db.get(Firewall, fw_id)
        if fw is None:
            return {"firewall_id": fw_id, "firewall": f"#{fw_id}", "ok": False,
                    "error": "Firewall không còn tồn tại", "rows": []}
        try:
            return work(db, fw)
        except Exception as exc:  # noqa: BLE001 — một firewall lỗi không được làm hỏng cả lượt
            log.exception("Job lỗi trên firewall %s", fw.name)
            db.rollback()
            return {"firewall_id": fw.id, "firewall": fw.name, "ok": False,
                    "error": f"Lỗi không mong đợi: {exc}", "rows": []}


def _run(job_id: str, fw_ids: list[int], work: Work, meta: dict, on_done, ev: threading.Event) -> None:
    results: list[dict | None] = [None] * len(fw_ids)
    try:
        futs = {_pool.submit(_one, fid, work): i for i, fid in enumerate(fw_ids)}
        done = 0
        for fut in as_completed(futs):
            results[futs[fut]] = fut.result()
            done += 1
            _save(job_id, done=done, payload={**meta, "results": [r for r in results if r is not None]})
        final = [r for r in results if r is not None]
        extra = {}
        if on_done:
            try:
                extra = on_done(final) or {}
            except Exception:  # noqa: BLE001
                log.exception("on_done lỗi cho job %s", job_id)
        _save(job_id, done=len(fw_ids), payload={**meta, "results": final, **extra}, status="done")
    except Exception as exc:  # noqa: BLE001
        log.exception("Job %s lỗi", job_id)
        _save(job_id, status="error", error=str(exc)[:2000])
    finally:
        ev.set()
        with _events_guard:
            _events.pop(job_id, None)


def _save(job_id: str, *, done: int | None = None, payload: dict | None = None, status: str | None = None,
          error: str | None = None) -> None:
    with SessionLocal() as db:
        job = db.get(Job, job_id)
        if job is None:
            return
        if done is not None:
            job.done = done
        if payload is not None:
            job.result_json = json.dumps(payload, ensure_ascii=False)
        if error is not None:
            job.error = error
        if status is not None:
            job.status = status
            if status != "running":
                job.finished_at = _now()
        job.updated_at = _now()
        db.commit()


def to_dict(job: Job) -> dict:
    status, error = job.status, job.error
    if status == "running" and (_now() - _aware(job.updated_at)) > dt.timedelta(minutes=settings.JOB_STALE_MINUTES):
        # Pod khởi động lại giữa chừng: kết quả từng firewall đã ghi vẫn còn, phần còn lại không chắc chắn
        status = "error"
        error = error or ("Công việc bị gián đoạn (máy chủ khởi động lại?). Kiểm tra tab Lịch sử thay đổi "
                          "và IP Host Group trước khi chạy lại.")
    try:
        result = json.loads(job.result_json or "{}")
    except ValueError:
        result = {}
    return {
        "job_id": job.id, "kind": job.kind, "status": status, "error": error,
        "total": job.total, "done": job.done,
        "created_at": _aware(job.created_at).isoformat() if job.created_at else None,
        "finished_at": _aware(job.finished_at).isoformat() if job.finished_at else None,
        **result,
    }


def get(db: Session, job_id: str) -> Job | None:
    return db.get(Job, job_id)


def purge_old(db: Session) -> int:
    cutoff = _now() - dt.timedelta(days=settings.JOB_RETENTION_DAYS)
    res = db.execute(delete(Job).where(Job.created_at < cutoff))
    db.commit()
    return res.rowcount or 0

