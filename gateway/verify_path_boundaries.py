"""Live MCP boundary checks using synthetic files and real filesystem symlinks."""
import asyncio
import argparse
from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import tempfile
import tomllib

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

from .config import Config


async def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--inside", type=Path)
    parser.add_argument("--outside", type=Path)
    options = parser.parse_args()
    project = Path(__file__).resolve().parents[1]
    report = project / "RESULTS.md"
    if not report.is_file():
        raise SystemExit("RESULTS.md missing")
    config_bytes = (project / "config.json").read_bytes()
    cfg = Config.load(project / "config.json")
    registered = tomllib.loads((Path.home() / ".codex/config.toml").read_text(encoding="utf-8"))["mcp_servers"]["local-file-guard"]
    root = (project / "inbox").resolve()
    if cfg.allowed_roots != (root,):
        raise SystemExit("This check expects inbox as the only allowed root")
    outside = options.outside.resolve() if options.outside else Path(tempfile.mkdtemp(prefix="path-boundary-", dir=project / "data"))
    inside = options.inside.resolve() if options.inside else Path(tempfile.mkdtemp(prefix="path-boundary-", dir=root))
    if outside.parent != project / "data" or inside.parent != root or not all(p.name.startswith("path-boundary-") for p in (outside, inside)):
        raise SystemExit("Unexpected fixture directories")
    raw = "BOUNDARY_TEST_PRIVATE_DOCUMENT\r\nТема: исходная.\r\n".encode("utf-8-sig")
    target = outside / "target.txt"
    local = inside / "local.txt"
    swap = inside / "swap.txt"
    originals = {target: raw, local: raw, swap: raw}
    for path, value in originals.items():
        path.write_bytes(value)
    checks, calls, hashes = [], [], []
    links = []
    swapped = False
    error = None

    def check(label, condition):
        checks.append((label, bool(condition)))
        if not condition:
            raise AssertionError(label)

    def intact(label):
        for path, value in originals.items():
            check(f"{label}: {path.name} не изменён", path.read_bytes() == value)

    async def rejection(session, label, tool, arguments):
        response = await session.call_tool(tool, arguments)
        data = response.structuredContent or {}
        calls.append((label, tool, data.get("request_id", "—"), data.get("status", "missing")))
        check(f"{label}/{tool}: отказ без содержимого и edit_id", not response.isError and data.get("status") == "error" and data.get("content") is None and "edit_id" not in data)
        check(f"{label}/{tool}: нет утечки исходного текста", "BOUNDARY_TEST_PRIVATE_DOCUMENT" not in response.model_dump_json())
        with sqlite3.connect(cfg.audit_db) as db:
            rows = db.execute("SELECT status,content FROM events WHERE id=?", (data.get("request_id"),)).fetchall()
        check(f"{label}/{tool}: аудит отказа без содержимого", rows == [("write_rejected" if tool == "write_safe_file" else "error", None)])

    try:
        # All links and targets belong to newly created synthetic fixture directories.
        for name, destination, directory in (("outside-file.txt", target, False), ("outside-dir", outside, True), ("inside-file.txt", local, False), ("staged-swap.txt", target, False)):
            link = inside / name
            if not link.is_symlink():
                link.symlink_to(destination, target_is_directory=directory)
            links.append(link)
            check(f"Создана настоящая символическая ссылка {name}", link.is_symlink() and link.resolve() == destination.resolve())

        paths = [
            ("Прямой путь вне allowed_roots", str(target)),
            ("Обход через ..", str(root / ".." / "data" / outside.name / "target.txt")),
            ("Ссылка на внешний файл", str(inside / "outside-file.txt")),
            ("Ссылка на внешний каталог", str(inside / "outside-dir" / "target.txt")),
            ("Ссылка даже на разрешённый файл", str(inside / "inside-file.txt")),
        ]
        params = StdioServerParameters(command=registered["command"], args=registered.get("args", []), cwd=registered.get("cwd"))
        async with stdio_client(params) as (read, write):
            async with ClientSession(read, write) as session:
                await session.initialize()
                tools = (await session.list_tools()).tools
                write_tool = next(t for t in tools if t.name == "write_safe_file")
                check("Схема записи принимает только edit_id и content, без пути назначения", set(write_tool.inputSchema["properties"]) == {"edit_id", "content"})
                for label, path in paths:
                    for tool in ("read_safe_file", "check_response_file"):
                        await rejection(session, label, tool, {"path": path})
                    # Denied reads cannot create sessions; the writer has no path parameter.
                    await rejection(session, label + ": без выданной сессии", "write_safe_file", {"edit_id": "a" * 32, "content": "Запись без разрешённой сессии."})
                    intact(label)
                print("PASS: direct/traversal/symlink reads rejected; no write sessions granted.", flush=True)

                prepared_response = await session.call_tool("read_safe_file", {"path": str(swap)})
                prepared = prepared_response.structuredContent or {}
                calls.append(("До подмены ссылкой", "read_safe_file", prepared.get("request_id", "—"), prepared.get("status", "missing")))
                check("Получен действующий edit_id на обычный разрешённый файл", not prepared_response.isError and prepared.get("status") == "allowed" and bool(prepared.get("edit_id")))
                edited = prepared["content"].replace("Тема: исходная.", "Тема: изменённая.")
                check("Цель вне папки содержит те же байты, конфликт хеша исключён", target.read_bytes() == swap.read_bytes())
                # Replace only our own test file with a link, never an existing user document.
                swap.unlink()
                swapped = True
                (inside / "staged-swap.txt").replace(swap)
                check("Перед записью исходный путь стал ссылкой наружу", swap.is_symlink() and swap.resolve() == target.resolve())
                await rejection(session, "Подмена файла ссылкой с действующим edit_id", "write_safe_file", {"edit_id": prepared["edit_id"], "content": edited})
                check("Отклонённая запись не заменила ссылку обычным файлом", swap.is_symlink())
                intact("После записи с действующей сессией через ссылку")
                print("PASS: valid edit_id cannot write through a swapped symlink.", flush=True)
                swap.unlink()
                swap.write_bytes(raw)
                swapped = False
    except Exception as exc:
        error = type(exc).__name__
        if isinstance(exc, OSError):
            error += f" (winerror={getattr(exc, 'winerror', None)})"
        print(json.dumps({"test_error": error}, ensure_ascii=False), flush=True)
    finally:
        # Remove only the exact fixture links, without traversing their targets.
        if swapped:
            if swap.is_symlink():
                swap.unlink()
            if not swap.exists():
                swap.write_bytes(raw)
        for link in reversed(links):
            if link.is_symlink():
                try:
                    if link.is_dir():
                        link.rmdir()
                    else:
                        link.unlink()
                except OSError as exc:
                    error = error or f"CleanupError (winerror={exc.winerror})"
        for path, value in originals.items():
            current = path.read_bytes()
            hashes.append((str(path), hashlib.sha256(value).hexdigest(), hashlib.sha256(current).hexdigest()))
            checks.append((f"Итоговая целостность {path.name}", current == value))
        checks.append(("Тестовые ссылки удалены, внешние цели сохранены", all(not p.is_symlink() for p in links) and not swap.is_symlink()))
        checks.append(("Рабочая конфигурация не изменена", (project / "config.json").read_bytes() == config_bytes))

    passed = error is None and all(ok for _, ok in checks)
    lines = ["", "## Границы файлового доступа: внешний путь, .. и symlink — MCP", "",
             f"Дата: {datetime.now(timezone(timedelta(hours=3))).isoformat(timespec='seconds')} (Europe/Moscow).", "",
             f"Итог: **{'PASS' if passed else 'FAIL'}**; проверок пройдено {sum(ok for _, ok in checks)}/{len(checks)}.", "",
             "Использован отдельный MCP STDIO-процесс по рабочей регистрации local-file-guard, без подмены файловых проверок или модели.",
             f"Разрешённая папка: `{root}`. Внешняя тестовая папка: `{outside}` (внутри проекта, но вне allowed_roots).",
             "Созданы реальные символические ссылки на внешний файл, внешний каталог и разрешённый файл. Проверены Input Guard и Output Guard.",
             "write_safe_file не принимает путь назначения: проверено отсутствие этого параметра в MCP-схеме. Для отклонённых чтений сессии не выдаются; запись с невыданным edit_id проверена отдельно. Это не попытка передачи пути в write_safe_file.",
             "Дополнительно обычный разрешённый файл прочитан, получен действующий edit_id, затем исходный путь заменён ссылкой на внешний файл с идентичными байтами. Поэтому отказ не объясняется отсутствием сессии или конфликтом содержимого.",
             "После теста ссылки удалены без удаления целей, подменённый синтетический файл восстановлен. Чужие файлы и example.txt не менялись.", "",
             "| Проверка | Итог |", "| --- | --- |"]
    lines.extend(f"| {name} | {'PASS' if ok else 'FAIL'} |" for name, ok in checks)
    lines.extend(["", "### MCP-вызовы", "", "| Сценарий | Инструмент | request_id | Статус |", "| --- | --- | --- | --- |"])
    lines.extend(f"| {label} | {tool} | `{request_id}` | {status} |" for label, tool, request_id, status in calls)
    lines.extend(["", "### Целостность оригиналов", ""])
    for path, before, after in hashes:
        lines.extend([f"- `{path}`", f"  - SHA-256 исходный: `{before}`", f"  - SHA-256 итоговый: `{after}`"])
    lines.extend(["", "Проверка выполнена клиентом MCP SDK, не через интерфейс чата. Подмена ссылкой выполнялась до вызова записи; гонки во время системного вызова записи отдельно не моделировались. Предыдущий отчёт сохранён."])
    if error:
        lines.append(f"\nОшибка: `{error}`. Непроведённые проверки не считаются пройденными.")
    with report.open("a", encoding="utf-8") as file:
        file.write("\n".join(lines) + "\n")
    print(json.dumps({"status": "PASS" if passed else "FAIL", "checks": len(checks), "error": error, "report": str(report)}, ensure_ascii=False))
    if not passed:
        raise SystemExit(1)


if __name__ == "__main__":
    asyncio.run(main())
