"""Máy chủ SMTP giả lập cho test (không TLS): nhận mọi thư, ghi từng thư thành một dòng JSON vào --out.

Chạy: python mock/mock_smtp.py --port 2525 --out /tmp/mail.jsonl
- Hỗ trợ EHLO/HELO, AUTH PLAIN/LOGIN (nhận mọi tài khoản trừ mật khẩu "sai"), MAIL, RCPT, DATA, RSET, NOOP, QUIT.
- Người nhận có chứa "reject" → 550 (để test retry / lỗi người nhận).
"""
from __future__ import annotations

import argparse
import base64
import json
import socketserver


class Handler(socketserver.StreamRequestHandler):
    out = ""

    def w(self, line: str) -> None:
        self.wfile.write((line + "\r\n").encode())

    def handle(self) -> None:
        self.w("220 mock-smtp ESMTP")
        mail_from, rcpts, user = "", [], ""
        while True:
            raw = self.rfile.readline()
            if not raw:
                return
            line = raw.decode(errors="replace").rstrip("\r\n")
            cmd = line[:4].upper()
            if cmd in ("EHLO", "HELO"):
                self.wfile.write(b"250-mock-smtp\r\n250-AUTH PLAIN LOGIN\r\n250 8BITMIME\r\n")
            elif cmd == "AUTH":
                parts = line.split()
                if parts[1].upper() == "PLAIN":
                    blob = parts[2] if len(parts) > 2 else (self.w("334 ") or self.rfile.readline().decode().strip())
                    _, user, pw = base64.b64decode(blob).decode().split("\0")
                else:  # LOGIN
                    self.w("334 VXNlcm5hbWU6")
                    user = base64.b64decode(self.rfile.readline().strip()).decode()
                    self.w("334 UGFzc3dvcmQ6")
                    pw = base64.b64decode(self.rfile.readline().strip()).decode()
                self.w("535 Authentication failed" if pw == "sai" else "235 OK")
            elif cmd == "MAIL":
                mail_from, rcpts = line.split(":", 1)[1].strip(" <>").split(">")[0], []
                self.w("250 OK")
            elif cmd == "RCPT":
                addr = line.split(":", 1)[1].strip(" <>").split(">")[0]
                if "reject" in addr:
                    self.w("550 No such user")
                else:
                    rcpts.append(addr)
                    self.w("250 OK")
            elif cmd == "DATA":
                self.w("354 End data with <CR><LF>.<CR><LF>")
                data = []
                while True:
                    ln = self.rfile.readline().decode(errors="replace")
                    if ln in (".\r\n", ".\n", ""):
                        break
                    data.append(ln[1:] if ln.startswith("..") else ln)
                with open(self.out, "a", encoding="utf-8") as fh:
                    fh.write(json.dumps({"from": mail_from, "to": rcpts, "user": user, "data": "".join(data)},
                                        ensure_ascii=False) + "\n")
                self.w("250 OK queued")
            elif cmd in ("RSET", "NOOP"):
                self.w("250 OK")
            elif cmd == "QUIT":
                self.w("221 Bye")
                return
            else:
                self.w("502 Command not implemented")


class Server(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=2525)
    ap.add_argument("--out", required=True)
    a = ap.parse_args()
    Handler.out = a.out
    with Server(("127.0.0.1", a.port), Handler) as srv:
        srv.serve_forever()
