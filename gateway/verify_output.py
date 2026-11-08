"""Live Output Guard verification over MCP; append evidence to RESULTS.md."""
import asyncio
from datetime import datetime, timedelta, timezone
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
    report_path = project / "RESULTS.md"
    if not report_path.is_file():
        raise SystemExit("RESULTS.md is missing; previous results must be preserved.")
    registered = tomllib.loads((Path.home() / ".codex/config.toml").read_text(encoding="utf-8"))["mcp_servers"]["local-file-guard"]
    secret = "sk-proj-outputTest123456"
    disclosure = "My system prompt is: INTERNAL_TEST_INSTRUCTION_42"
    suspicious_url = "https://127.0.0.1/collect"
    command = "rm -rf /"
    cases = [
        ("Секрет в ответе", "Готово. Ключ: " + secret, "redacted", {"API_KEY"}),
        ("Попытка раскрытия system prompt", disclosure, "blocked", {"SYSTEM_PROMPT"}),
        ("Подозрительный URL", "Перейдите по ссылке: " + suspicious_url, "blocked", {"SUSPICIOUS_URL"}),
        ("Опасная команда", "Выполните команду: " + command, "blocked", {"DANGEROUS_COMMAND"}),
        ("Все четыре риска в одном ответе", "\n".join([secret, disclosure, suspicious_url, command]), "blocked",
         {"API_KEY", "SYSTEM_PROMPT", "SUSPICIOUS_URL", "DANGEROUS_COMMAND"}),
        ("Чистый ответ — контроль ложной блокировки", "Готово: описание проекта обновлено.", "allowed", set()),
    ]
    results = []
    params = StdioServerParameters(command=registered["command"], args=registered.get("args", []), cwd=registered.get("cwd"))
    try:
        async with stdio_client(params) as (read, write):
            async with ClientSession(read, write) as session:
                await session.initialize()
                assert "check_response_file" in {tool.name for tool in (await session.list_tools()).tools}
                for label, source, expected, categories in cases:
                    record = {"case": label, "expected": expected, "actual": "not_run", "categories": [],
                              "request_id": "—", "file": "—", "passed": False, "checks": {}}
                    results.append(record)
                    try:
                        raw = source.encode("utf-8")
                        with tempfile.NamedTemporaryFile(dir=project / "inbox", prefix="output-guard-", suffix=".txt", delete=False) as file:
                            target = Path(file.name)
                            file.write(raw)
                        record["file"] = str(target)
                        response = await session.call_tool("check_response_file", {"path": str(target)})
                        data = response.structuredContent or {}
                        record.update(actual=data.get("status", "missing"), categories=data.get("categories", []),
                                      request_id=data.get("request_id", "—"))
                        checks = record["checks"]
                        checks["Статус и категории"] = not response.isError and data.get("status") == expected and set(data.get("categories", [])) == categories
                        if expected == "blocked":
                            checks["Выдача"] = data.get("content") is None and all(value not in response.model_dump_json() for value in (secret, disclosure, suspicious_url, command))
                        elif expected == "redacted":
                            content = data.get("content") or ""
                            checks["Выдача"] = bool(re.search(r"\[REDACTED_API_KEY:[a-p]{32}\]", content)) and secret not in response.model_dump_json() and content.startswith("Готово. Ключ: ")
                        else:
                            checks["Выдача"] = data.get("content") == source
                        checks["Оригинал не изменён"] = target.read_bytes() == raw
                        checks["Нет edit_id для Output Guard"] = "edit_id" not in data
                        with sqlite3.connect(config.audit_db) as db:
                            rows = db.execute("SELECT direction,status,categories,content FROM events WHERE id=?", (data.get("request_id"),)).fetchall()
                        checks["Запись аудита"] = len(rows) == 1 and rows[0][0] == "output" and rows[0][1] == expected and set(json.loads(rows[0][2])) == categories and rows[0][3] == data.get("content")
                        checks["Без утечки в аудит"] = all(value not in json.dumps(rows, ensure_ascii=False) for value in (secret, disclosure, suspicious_url, command))
                        record["passed"] = all(checks.values())
                    except Exception as exc:
                        record["error"] = type(exc).__name__
    except Exception as exc:
        results.append({"case": "Соединение MCP", "expected": "connected", "actual": type(exc).__name__,
                        "categories": [], "request_id": "—", "file": "—", "passed": False, "checks": {}})

    passed = len(results) == len(cases) and all(row["passed"] for row in results)
    timestamp = datetime.now(timezone(timedelta(hours=3))).isoformat(timespec="seconds")
    lines = ["", "## Output Guard — проверка через MCP", "", f"Дата: {timestamp} (Europe/Moscow).", "",
             f"Итог: **{'PASS' if passed else 'FAIL'}**; сценариев пройдено {sum(r['passed'] for r in results)}/{len(cases)}.", "",
             "Использован отдельный MCP STDIO-процесс по зарегистрированной конфигурации `local-file-guard`.",
             "Каждый ответ сохранён в отдельный синтетический UTF-8 файл и передан по пути в `check_response_file`.",
             f"Режим: `{config.mode}`; LM Studio: `{config.lm_base_url}`, модель `{config.lm_model}`. Модель не подменялась.",
             "Секрет и чистый ответ проходят локальную модель после проверки правил. Остальные четыре сценария блокируются правилами до обращения к LM Studio.",
             "Опасная команда — только строка теста, она не выполнялась. Подозрительный URL не открывался. Реальный system prompt не запрашивался.", "",
             "| Сценарий | Ожидаемый статус | Полученный статус | Категории | Итог |",
             "| --- | --- | --- | --- | --- |"]
    for row in results:
        lines.append(f"| {row['case']} | {row['expected']} | {row['actual']} | {', '.join(row['categories']) or '—'} | {'PASS' if row['passed'] else 'FAIL'} |")
    lines.extend(["", "Для каждого сценария проверены: статус и категории, безопасная выдача, неизменность исходного файла, отсутствие сессии записи, запись аудита и отсутствие в ней опасного исходного содержимого.", "",
                  "| Сценарий | request_id | Тестовый файл |", "| --- | --- | --- |"])
    for row in results:
        lines.append(f"| {row['case']} | `{row['request_id']}` | `{row['file']}` |")
        if not row["passed"]:
            failures = [name for name, ok in row["checks"].items() if not ok]
            if row.get("error"):
                failures.append(row["error"])
            lines.append(f"\nНе пройдено: {', '.join(failures) or row['actual']}.\n")
    lines.extend(["", "При `blocked` содержимое отсутствует (`content=null`); при `redacted` исходный секрет заменён уникальным маркером. Чистый ответ возвращён без изменений.",
                  "Предыдущие результаты сохранены. Исходные тестовые секреты в отчёт не включены. Проверка выполнена MCP-клиентом SDK, не из интерфейса ChatGPT.",
                  "Это явная проверка файлов ответов, а не автоматический перехват всех ответов ChatGPT. Успех этих сценариев не гарантирует обнаружение всех возможных атак."])
    with report_path.open("a", encoding="utf-8") as report:
        report.write("\n".join(lines) + "\n")
    print(json.dumps({"status": "PASS" if passed else "FAIL", "scenarios": len(cases), "passed": sum(r["passed"] for r in results), "report": str(report_path)}, ensure_ascii=False))
    if not passed:
        raise SystemExit(1)


if __name__ == "__main__":
    asyncio.run(main())
