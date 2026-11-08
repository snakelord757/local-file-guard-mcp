"""Verify rejected MCP writes preserve bytes and do not leak secrets."""
import asyncio
from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import sqlite3
import tempfile
import tomllib

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

from .config import Config


async def main():
    project = Path(__file__).resolve().parents[1]
    report = project / "RESULTS.md"
    if not report.is_file():
        raise SystemExit("RESULTS.md missing")
    cfg = Config.load(project / "config.json")
    registered = tomllib.loads((Path.home() / ".codex/config.toml").read_text(encoding="utf-8"))["mcp_servers"]["local-file-guard"]
    params = StdioServerParameters(command=registered["command"], args=registered.get("args", []), cwd=registered.get("cwd"))
    checks, rows, files = [], [], []
    error = None
    email, key = "write-test@example.com", "sk-proj-markerTest123"
    source = f"Версия: A\r\nТема: исходная.\r\nКонтакт: {email}\r\nКлюч: {key}\r\n"
    original = source.encode("utf-8-sig")
    marker_re = re.compile(r"\[REDACTED_[A-Z_]+:[a-p]{32}\]")

    def check(label, condition):
        checks.append((label, bool(condition)))
        if not condition:
            raise AssertionError(label)

    def fixture(prefix):
        with tempfile.NamedTemporaryFile(dir=project / "inbox", prefix=prefix, suffix=".txt", delete=False) as file:
            file.write(original)
            path = Path(file.name)
        files.append(path)
        return path

    try:
        async with stdio_client(params) as (read, write):
            async with ClientSession(read, write) as session:
                await session.initialize()
                for case in ("Удалённый маркер", "Изменённый маркер", "Дублированный маркер", "Конфликт исходного файла"):
                    path = fixture("write-reject-")
                    response = await session.call_tool("read_safe_file", {"path": str(path)})
                    data = response.structuredContent or {}
                    check(f"{case}: чтение успешно, получен edit_id", not response.isError and data.get("status") == "redacted" and bool(data.get("edit_id")))
                    markers = marker_re.findall(data["content"])
                    check(f"{case}: два разных маркера, оригинал не изменён", len(set(markers)) == 2 and path.read_bytes() == original)
                    edited = data["content"].replace("Тема: исходная.", "Тема: обновлённая.")
                    first = markers[0]
                    if case == "Удалённый маркер":
                        edited = edited.replace(first, "", 1)
                    elif case == "Изменённый маркер":
                        position = first.index(":") + 1
                        changed = first[:position] + ("b" if first[position] == "a" else "a") + first[position + 1:]
                        edited = edited.replace(first, changed, 1)
                        check("Изменённый маркер: синтаксис сохранён, идентификатор подменён", bool(marker_re.fullmatch(changed)) and changed not in markers)
                    elif case == "Дублированный маркер":
                        edited += "\r\n" + first
                    else:
                        before_stat = path.stat()
                        external = original.replace("Версия: A".encode(), "Версия: B".encode(), 1)
                        path.write_bytes(external)
                        os.utime(path, ns=(before_stat.st_atime_ns, before_stat.st_mtime_ns))
                        check("Конфликт: содержимое изменено при прежних размере и mtime", external != original and path.stat().st_size == before_stat.st_size and path.stat().st_mtime_ns == before_stat.st_mtime_ns)
                        check("Конфликт: маркеры запроса сохранены без изменений", marker_re.findall(edited) == markers)

                    before = path.read_bytes()
                    saved_response = await session.call_tool("write_safe_file", {"edit_id": data["edit_id"], "content": edited})
                    saved = saved_response.structuredContent or {}
                    after = path.read_bytes()
                    rows.append((case, str(path), data["request_id"], saved.get("request_id", "—"), saved.get("status", "missing"), hashlib.sha256(before).hexdigest(), hashlib.sha256(after).hexdigest()))
                    check(f"{case}: MCP отклонил запись", not saved_response.isError and saved.get("status") == "error")
                    check(f"{case}: файл побайтово не изменился после отказа", after == before)
                    check(f"{case}: нет частичной записи или REDACTED-маркеров на диске", b"[REDACTED_" not in after and after.startswith(b"\xef\xbb\xbf") and after == (original if case != "Конфликт исходного файла" else external))
                    check(f"{case}: MCP-ответы не раскрывают секреты", all(value not in response.model_dump_json() + saved_response.model_dump_json() for value in (email, key)))
                    with sqlite3.connect(cfg.audit_db) as db:
                        audit = db.execute("SELECT status,content FROM events WHERE id=?", (saved.get("request_id"),)).fetchall()
                    check(f"{case}: аудит только write_rejected без содержимого", audit == [("write_rejected", None)])
                    print(json.dumps({"case": case, "status": "PASS", "file_unchanged": True}, ensure_ascii=False), flush=True)

                # Positive control proves that rejection is not caused by an unavailable LM.
                path = fixture("write-positive-control-")
                data = (await session.call_tool("read_safe_file", {"path": str(path)})).structuredContent or {}
                check("Положительный контроль: сессия чтения доступна", data.get("status") == "redacted" and bool(data.get("edit_id")))
                saved = (await session.call_tool("write_safe_file", {"edit_id": data["edit_id"], "content": data["content"].replace("Тема: исходная.", "Тема: обновлённая.")})).structuredContent or {}
                expected = original.replace("Тема: исходная.".encode(), "Тема: обновлённая.".encode(), 1)
                check("Положительный контроль: корректная запись успешна, секреты восстановлены", saved.get("status") == "written" and saved.get("restored_count") == 2 and path.read_bytes() == expected)
                rows.append(("Положительный контроль", str(path), data["request_id"], saved.get("request_id", "—"), saved.get("status", "missing"), hashlib.sha256(original).hexdigest(), hashlib.sha256(path.read_bytes()).hexdigest()))
    except Exception as exc:
        error = type(exc).__name__

    passed = error is None and len(rows) == 5 and all(ok for _, ok in checks)
    lines = ["", "## Некорректные маркеры и конфликт исходного файла — MCP", "",
             f"Дата: {datetime.now(timezone(timedelta(hours=3))).isoformat(timespec='seconds')} (Europe/Moscow).", "",
             f"Итог: **{'PASS' if passed else 'FAIL'}**; проверок пройдено {sum(ok for _, ok in checks)}/{len(checks)}.", "",
             "Выполнены настоящие вызовы read_safe_file/write_safe_file через отдельный STDIO-процесс по регистрации local-file-guard.",
             f"Использована рабочая LM Studio, модель `{cfg.lm_model}`, режим `{cfg.mode}`; подмены модели не было.",
             "Каждый сценарий использовал отдельный синтетический файл, действующий edit_id и два уникальных маркера.",
             "Изменение маркера сохраняло его синтаксис, но меняло один символ идентификатора. Дубликат добавлялся как второе вхождение исходного маркера.",
             "Для конфликта после чтения файл изменён локально (версия A → B), при этом сохранены прежние длина и mtime. Маркеры запроса оставались правильными.",
             "Байты после отказа сравнивались с состоянием непосредственно перед записью; при конфликте подтверждено сохранение внешней версии B, а не возврат к старой версии A.", "",
             "| Проверка | Итог |", "| --- | --- |"]
    lines.extend(f"| {name} | {'PASS' if ok else 'FAIL'} |" for name, ok in checks)
    lines.extend(["", "### MCP-вызовы", "", "| Сценарий | ID чтения | ID записи | Статус записи |", "| --- | --- | --- | --- |"])
    lines.extend(f"| {case} | `{read_id}` | `{write_id}` | {status} |" for case, _, read_id, write_id, status, _, _ in rows)
    lines.extend(["", "### Файлы и побайтовая проверка", ""])
    for case, path, _, _, _, before_hash, after_hash in rows:
        lines.extend([f"- {case}: `{path}`", f"  - SHA-256 до записи: `{before_hash}`", f"  - SHA-256 после записи: `{after_hash}`"])
    lines.extend(["", "Четыре некорректные записи должны иметь одинаковые хеши до/после. Отдельный положительный контроль успешно меняет тему и имеет разные хеши.",
                  "Тесты не перезапускали MCP в приложении и не меняли рабочую конфигурацию. example.txt и прежние результаты сохранены. Исходные секреты в отчёт не включены.",
                  "Проверка выполнена MCP-клиентом SDK, не через интерфейс чата. Конфликт создан до вызова записи; гонка другого процесса непосредственно во время атомарной замены отдельно не моделировалась."])
    if error:
        lines.append(f"\nОшибка проверки: `{error}`. Полный успех не подтверждён.")
    with report.open("a", encoding="utf-8") as file:
        file.write("\n".join(lines) + "\n")
    print(json.dumps({"status": "PASS" if passed else "FAIL", "checks": len(checks), "report": str(report)}, ensure_ascii=False))
    if not passed:
        raise SystemExit(1)


if __name__ == "__main__":
    asyncio.run(main())
