# Chạy: bash tests/run_e2e.sh tests/imports_test.py   (hoặc: PYTHONPATH=backend python3 tests/imports_test.py)
# Mọi lệnh import trong backend/app — KỂ CẢ import nằm trong thân hàm (pyflakes không kiểm) — phải trỏ tới
# module/tên tồn tại. Bắt lỗi kiểu "chuyển file nhưng quên sửa import tương đối bên trong hàm".
import ast
import importlib
import importlib.util
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent / "backend"
sys.path.insert(0, str(ROOT))
fails = 0
checked = 0
for path in sorted((ROOT / "app").rglob("*.py")):
    rel = path.relative_to(ROOT).with_suffix("")
    parts = list(rel.parts)
    is_pkg = parts[-1] == "__init__"
    modname = ".".join(parts[:-1] if is_pkg else parts)
    package = modname if is_pkg else modname.rpartition(".")[0]
    for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
        if isinstance(node, ast.ImportFrom):
            target = importlib.util.resolve_name("." * node.level + (node.module or ""), package) \
                if node.level else node.module
            names = [a.name for a in node.names]
        elif isinstance(node, ast.Import):
            target, names = None, [a.name for a in node.names]
        else:
            continue
        for name in (names if target is None else [None]):
            mod = name if target is None else target
            if not mod.startswith("app"):
                continue
            checked += 1
            try:
                m = importlib.import_module(mod)
            except Exception as exc:  # noqa: BLE001
                fails += 1
                print(f"FAIL {path.relative_to(ROOT)}:{node.lineno} import {mod}: {exc}")
                continue
            if target is not None:
                for n in names:
                    if n != "*" and not hasattr(m, n) and importlib.util.find_spec(f"{mod}.{n}") is None:
                        fails += 1
                        print(f"FAIL {path.relative_to(ROOT)}:{node.lineno} {mod} không có '{n}'")
print(f"PASS kiểm {checked} lệnh import nội bộ" if not fails else "")
print("FAILS:", fails)
sys.exit(1 if fails else 0)
