"""MCP lifecycle tests; an isolated child can use a two-second test-only TTL."""
import asyncio
from dataclasses import replace
from datetime import datetime, timedelta, timezone
import hashlib
import json
from pathlib import Path
import sqlite3
import sys
import tempfile
import time
import tomllib

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

from .config import Config


async def main():
    project = Path(__file__).resolve().parents[1]
    report = project / "RESULTS.md"
    if not report.is_file():
        raise SystemExit("RESULTS.md missing")
    cfg_bytes = (project / "config.json").read_bytes()
    reg_path = Path.home() / ".codex/config.toml"
    reg_bytes = reg_path.read_bytes()
    registration = tomllib.loads(reg_bytes.decode())["mcp_servers"]["local-file-guard"]
    cfg = Config.load(project / "config.json")
    normal = StdioServerParameters(command=registration["command"], args=registration.get("args", []), cwd=registration.get("cwd"))
    short = StdioServerParameters(command=registration["command"], args=["-m", "gateway.verify_session_lifecycle", "--short-ttl-server", "--config", str(project / "config.json")], cwd=str(project))
    checks, calls, hashes, files = [], [], [], []
    error = None
    original = "Тема: исходная.\r\nКонтакт: lifecycle@example.com\r\n".encode("utf-8-sig")

    def check(name, condition):
        checks.append((name, bool(condition)))
        if not condition:
            raise AssertionError(name)

    def fixture():
        with tempfile.NamedTemporaryFile(dir=project / "inbox", prefix="session-lifecycle-", suffix=".txt", delete=False) as file:
            path = Path(file.name)
            file.write(original)
        files.append(path)
        return path

    async def read(session, label, path):
        response = await session.call_tool("read_safe_file", {"path": str(path)})
        data = response.structuredContent or {}
        calls.append((label, "read_safe_file", data.get("request_id", "—"), data.get("status", "missing")))
        check(label + ": чтение создало edit_id", not response.isError and data.get("status") == "redacted" and bool(data.get("edit_id")))
        return data, data["content"].replace("Тема: исходная.", "Тема: обновлённая.")

    async def denied(session, label, path, edit, content):
        before = path.read_bytes()
        response = await session.call_tool("write_safe_file", {"edit_id": edit["edit_id"], "content": content})
        data = response.structuredContent or {}
        calls.append((label, "write_safe_file", data.get("request_id", "—"), data.get("status", "missing")))
        after = path.read_bytes()
        check(label + ": запись отклонена", not response.isError and data.get("status") == "error")
        check(label + ": файл побайтово неизменен", before == after)
        check(label + ": нет секретов в ответе", "lifecycle@example.com" not in response.model_dump_json() and data.get("content") is None)
        check(label + ": нет частичной записи или маркеров на диске", b"[REDACTED_" not in after and after.startswith(b"\xef\xbb\xbf"))
        with sqlite3.connect(cfg.audit_db) as db:
            rows = db.execute("SELECT status,content FROM events WHERE id=?", (data.get("request_id"),)).fetchall()
        check(label + ": аудит write_rejected без содержимого", rows == [("write_rejected", None)])
        hashes.append((label, str(path), hashlib.sha256(before).hexdigest(), hashlib.sha256(after).hexdigest()))

    async def accepted(session, label, path, edit, content, expected):
        response = await session.call_tool("write_safe_file", {"edit_id": edit["edit_id"], "content": content})
        data = response.structuredContent or {}
        calls.append((label, "write_safe_file", data.get("request_id", "—"), data.get("status", "missing")))
        check(label + ": запись успешна и email восстановлен", not response.isError and data.get("status") == "written" and data.get("restored_count") == 1 and path.read_bytes() == expected)

    try:
        expired_path = fixture()
        async with stdio_client(short) as (r, w):
            async with ClientSession(r, w) as session:
                await session.initialize()
                edit, content = await read(session, "TTL 2 секунды", expired_path)
                start = time.monotonic()
                await asyncio.sleep(2.5)
                elapsed = time.monotonic() - start
                check("После получения edit_id прошло не менее 2.5 секунд", elapsed >= 2.5)
                await denied(session, "Истёкший edit_id", expired_path, edit, content)
        print("PASS: expired edit_id rejected; isolated short-TTL process stopped.", flush=True)

        reuse_path, restart_path = fixture(), fixture()
        async with stdio_client(normal) as (r, w):
            async with ClientSession(r, w) as session:
                await session.initialize()
                edit, content = await read(session, "Первое использование", reuse_path)
                updated = original.replace("Тема: исходная.".encode(), "Тема: обновлённая.".encode())
                await accepted(session, "Первое использование", reuse_path, edit, content, updated)
                await denied(session, "Повторное использование edit_id", reuse_path, edit, content)
                check("Повторная запись сохранила успешно записанную версию", reuse_path.read_bytes() == updated)
                # Also distinguish consumed tokens from simple source-version conflicts.
                reuse_path.write_bytes(original)
                await denied(session, "Использованный edit_id после возврата исходных байтов", reuse_path, edit, content)
                pending, pending_content = await read(session, "До перезапуска", restart_path)
        print("PASS: consumed edit_id rejected; original MCP process closed.", flush=True)

        # A new stdio_client starts a NEW OS process, with the same normal configuration.
        async with stdio_client(normal) as (r, w):
            async with ClientSession(r, w) as session:
                await session.initialize()
                await denied(session, "Старый edit_id после перезапуска процесса", restart_path, pending, pending_content)
                check("Перезапуск не изменил исходный файл", restart_path.read_bytes() == original)
                fresh, fresh_content = await read(session, "Новое чтение после перезапуска", restart_path)
                check("После перезапуска выдан новый edit_id", fresh["edit_id"] != pending["edit_id"])
                await accepted(session, "Новая сессия после перезапуска", restart_path, fresh, fresh_content,
                               original.replace("Тема: исходная.".encode(), "Тема: обновлённая.".encode()))
        check("Рабочий config.json не изменён", (project / "config.json").read_bytes() == cfg_bytes)
        check("Регистрация MCP не изменена", reg_path.read_bytes() == reg_bytes)
    except Exception as exc:
        error = type(exc).__name__

    passed = error is None and all(ok for _, ok in checks)
    lines = ["", "## Срок жизни edit_id, повторное использование и перезапуск — MCP", "",
             f"Дата: {datetime.now(timezone(timedelta(hours=3))).isoformat(timespec='seconds')} (Europe/Moscow).", "",
             f"Итог: **{'PASS' if passed else 'FAIL'}**; проверок пройдено {sum(ok for _, ok in checks)}/{len(checks)}.", "",
             f"Вызовы чтения и записи выполнены через клиент MCP SDK и отдельные STDIO-процессы с реальной LM Studio (`{cfg.lm_model}`).",
             "Истечение проверено с ускоренным TTL 2 секунды в отдельном тестовом дочернем процессе: обёртка фабрики сессии меняет только expires. После чтения выдержано 2.5 секунды реального времени. Проверка срока в Gateway не подменялась, системные часы не менялись.",
             "Рабочий TTL 1800 секунд не менялся. Полное ожидание 30 минут этим тестом не выполнялось.",
             "Для одноразовости сначала выполнена успешная запись, затем повторный вызов с тем же edit_id. Дополнительно исходные байты тестового файла возвращены локально, чтобы исключить конфликт версии как единственную причину отказа, и старый edit_id проверен ещё раз.",
             "Для перезапуска завершён предыдущий тестовый MCP-процесс и запущен новый с той же рабочей конфигурацией. Старый неиспользованный edit_id проверен до нового чтения. После отказа получена новая сессия и выполнена успешная запись.",
             "MCP-процесс внутри приложения ChatGPT не перезапускался; проверка относится к жизненному циклу отдельных процессов SDK. Рабочая конфигурация и регистрация сохранены.", "",
             "| Проверка | Итог |", "| --- | --- |"]
    lines.extend(f"| {name} | {'PASS' if ok else 'FAIL'} |" for name, ok in checks)
    lines.extend(["", "### MCP-вызовы", "", "| Сценарий | Инструмент | request_id | Статус |", "| --- | --- | --- | --- |"])
    lines.extend(f"| {label} | {tool} | `{request_id}` | {status} |" for label, tool, request_id, status in calls)
    lines.extend(["", "### Проверка целостности при отказах", ""])
    for label, path, before, after in hashes:
        lines.extend([f"- {label}: `{path}`", f"  - SHA-256 непосредственно до отказа: `{before}`", f"  - SHA-256 непосредственно после отказа: `{after}`"])
    lines.extend(["", "Хеши сравнивают состояние непосредственно до/после отклонённой записи. Позднейшие явно выполненные действия (возврат исходной версии и положительный контроль) описаны отдельно.",
                  "Содержимое и edit_id не включены в отчёт; request_id служат только для поиска в аудите. example.txt не изменялся. Предыдущие результаты сохранены."])
    if error:
        lines.append(f"\nОшибка: `{error}`. Полный успех не подтверждён.")
    with report.open("a", encoding="utf-8") as file:
        file.write("\n".join(lines) + "\n")
    print(json.dumps({"status": "PASS" if passed else "FAIL", "checks": len(checks), "report": str(report)}, ensure_ascii=False))
    if not passed:
        raise SystemExit(1)


if __name__ == "__main__":
    if "--short-ttl-server" in sys.argv:
        # Test-only process: no new tool or mutable TTL setting is exposed over MCP.
        from . import service
        from .server import main as server_main
        original_factory = service.new_session

        def short_session(*args, **kwargs):
            return replace(original_factory(*args, **kwargs), expires=time.monotonic() + 2)

        service.new_session = short_session
        sys.argv.remove("--short-ttl-server")
        server_main()
    else:
        asyncio.run(main())
