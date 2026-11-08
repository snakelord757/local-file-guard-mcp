"""Live MCP verification of reversible obfuscated-secret redaction; writes RESULTS.md."""
import asyncio
import base64
from datetime import datetime, timedelta, timezone
import hashlib
import json
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
    config = Config.load(project / "config.json")
    registered = tomllib.loads((Path.home() / ".codex/config.toml").read_text(encoding="utf-8"))["mcp_servers"]["local-file-guard"]
    checks = []
    calls = []
    target = None
    after_hash = "—"
    error = None

    def check(name, condition):
        checks.append((name, "PASS" if condition else "FAIL"))
        if not condition:
            raise AssertionError(name)

    try:
        encoded = base64.b64encode(b"sk-proj-abc123").decode("ascii")
        split = '\"мой ключ: sk-\" + \"proj-abc\"'
        old_topic = "Тема: первоначальная проверка."
        new_topic = "Тема: проверка обратимой маскировки Base64 и ключа из частей."
        original = f"Синтетические данные для теста MCP.\r\nBase64: {encoded}\r\nЧасти: {split}\r\n{old_topic}\r\n"
        original_bytes = original.encode("utf-8-sig")
        with tempfile.NamedTemporaryFile(dir=project / "inbox", prefix="obfuscated-mcp-", suffix=".txt", delete=False) as file:
            target = Path(file.name)
            file.write(original_bytes)

        params = StdioServerParameters(command=registered["command"], args=registered.get("args", []), cwd=registered.get("cwd"))
        async with stdio_client(params) as (read, write):
            async with ClientSession(read, write) as session:
                await session.initialize()
                names = {t.name for t in (await session.list_tools()).tools}
                check("MCP initialize/list_tools: инструменты чтения и записи доступны", {"read_safe_file", "write_safe_file"} <= names)
                read_result = await session.call_tool("read_safe_file", {"path": str(target)})
                data = read_result.structuredContent or {}
                calls.append(("read_safe_file", data.get("request_id", "—"), data.get("status", "—")))
                check("Первое чтение: status=redacted, получен edit_id", not read_result.isError and data.get("status") == "redacted" and bool(data.get("edit_id")))
                content = data["content"]
                markers = re.findall(r"\[REDACTED_API_KEY:[a-p]{32}\]", content)
                check("Base64 и составной ключ заменены двумя различными маркерами", len(markers) == 2 and len(set(markers)) == 2)
                serialized = read_result.model_dump_json()
                check("Выдача не содержит Base64, открытого ключа или частей ключа", all(s not in serialized for s in (encoded, "sk-proj-abc123", "sk-", "proj-abc")))
                check("Чтение не изменило исходный файл", target.read_bytes() == original_bytes)
                edited = content.replace(old_topic, new_topic)
                check("Изменена только тема, маркеры сохранены", edited != content and re.findall(r"\[REDACTED_API_KEY:[a-p]{32}\]", edited) == markers)
                write_result = await session.call_tool("write_safe_file", {"edit_id": data["edit_id"], "content": edited})
                saved = write_result.structuredContent or {}
                calls.append(("write_safe_file", saved.get("request_id", "—"), saved.get("status", "—")))
                check("Запись: status=written, восстановлены два фрагмента", not write_result.isError and saved.get("status") == "written" and saved.get("restored_count") == 2)
                # Local byte comparison only; originals are never returned by MCP or printed.
                after = target.read_bytes()
                after_hash = hashlib.sha256(after).hexdigest()
                expected = original_bytes.replace(old_topic.encode(), new_topic.encode(), 1)
                check("Файл побайтово совпадает с ожидаемым; изменена только тема", after == expected)
                check("Base64 восстановлен в исходной закодированной форме", encoded.encode() in after)
                check("Ключ из частей восстановлен с исходными кавычками и оператором +", split.encode() in after)
                check("В файле отсутствуют REDACTED-маркеры", b"[REDACTED_" not in after)
                reread_result = await session.call_tool("read_safe_file", {"path": str(target)})
                reread = reread_result.structuredContent or {}
                calls.append(("read_safe_file (повторно)", reread.get("request_id", "—"), reread.get("status", "—")))
                check("Повторное чтение маскирует оба секрета и содержит новую тему", not reread_result.isError and reread.get("status") == "redacted" and new_topic in reread.get("content", "") and len(re.findall(r"\[REDACTED_API_KEY:[a-p]{32}\]", reread.get("content", ""))) == 2)
                check("Повторная выдача не раскрывает секреты", all(s not in reread_result.model_dump_json() for s in (encoded, "sk-proj-abc123", "sk-", "proj-abc")))

        with sqlite3.connect(config.audit_db) as db:
            rows = db.execute("SELECT id,status,content FROM events WHERE id IN (?,?,?)", tuple(c[1] for c in calls)).fetchall()
        statuses = [row[1] for row in rows]
        check("Аудит содержит два чтения и подготовку/завершение записи", statuses.count("redacted") == 2 and statuses.count("write_prepared") == 1 and statuses.count("written") == 1)
        check("Аудит не содержит исходных секретов или их частей", all(s not in json.dumps(rows, ensure_ascii=False) for s in (encoded, "sk-proj-abc123", "sk-", "proj-abc")))
    except Exception as exc:
        error = type(exc).__name__  # Do not include potential model output or secrets.
    finally:
        timestamp = datetime.now(timezone(timedelta(hours=3))).isoformat(timespec="seconds")
        passed = error is None and bool(checks) and all(status == "PASS" for _, status in checks)
        report = ["# RESULTS", "", f"Дата: {timestamp} (Europe/Moscow).", "",
                  f"Итог: **{'PASS' if passed else 'FAIL'}**. Проверок пройдено: {sum(s == 'PASS' for _, s in checks)}/{len(checks)}.", "",
                  "## Среда и способ проверки", "",
                  "Настоящий MCP-клиент SDK запустил отдельный STDIO-процесс по регистрации `local-file-guard` из `.codex/config.toml`.",
                  "Вызваны initialize, list_tools, read_safe_file, write_safe_file и повторное read_safe_file.",
                  "Это проверка через MCP, не прямой вызов Gateway; интерфейс чата ChatGPT в этой проверке не участвовал.",
                  f"LM Studio: `{config.lm_base_url}`; модель `{config.lm_model}`; режим `{config.mode}`. Подмена модели не использовалась.", "",
                  f"Тестовый файл: `{target}`.",
                  "Создан отдельный файл с синтетическим Base64-ключом и буквальной конкатенацией двух строк. `example.txt` не изменён.",
                  "В ходе редактирования заменена только тема проекта. Исходные значения секретов в отчёт не включены.", "",
                  "## Результаты", "", "| Проверка | Результат |", "| --- | --- |"]
        report.extend(f"| {name} | {status} |" for name, status in checks)
        report.extend(["", "## Идентификаторы аудита", "", "| MCP-вызов | request_id | Статус |", "| --- | --- | --- |"])
        report.extend(f"| {name} | `{request_id}` | {status} |" for name, request_id, status in calls)
        report.extend(["", f"SHA-256 файла после записи: `{after_hash}`.", "",
                       "Побайтовое сравнение выполнено локально: сравнивался весь файл, включая BOM UTF-8, CRLF, Base64 и исходное написание конкатенации.",
                       "Проверка подтверждает эти два синтетических сценария; она не доказывает обнаружение всех возможных способов обфускации."])
        if error:
            report.extend(["", f"Проверка остановлена: `{error}`. Успех не подтверждён."])
        (project / "RESULTS.md").write_text("\n".join(report) + "\n", encoding="utf-8")
        print(json.dumps({"status": "PASS" if passed else "FAIL", "checks": len(checks), "report": str(project / "RESULTS.md"), "test_file": str(target)}, ensure_ascii=False))
    if error:
        raise SystemExit(1)


if __name__ == "__main__":
    asyncio.run(main())
