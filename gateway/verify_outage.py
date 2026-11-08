"""Stop the real LM Studio API, verify fail-closed MCP behavior, restore in finally."""
import asyncio
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import shutil
import sqlite3
import subprocess
import tempfile
import tomllib

import httpx
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

from .config import Config


async def main():
    project = Path(__file__).resolve().parents[1]
    cfg = Config.load(project / "config.json")
    report_path = project / "RESULTS.md"
    if not report_path.is_file():
        raise SystemExit("RESULTS.md is missing")
    lms = shutil.which("lms")
    if not lms:
        raise SystemExit("LM Studio CLI not found")
    if cfg.lm_base_url != "http://127.0.0.1:1234/v1":
        raise SystemExit("This outage check requires the configured loopback server on port 1234")
    registered = tomllib.loads((Path.home() / ".codex/config.toml").read_text(encoding="utf-8"))["mcp_servers"]["local-file-guard"]
    checks, calls, paths = [], [], []
    error = None
    restored = False

    def check(name, condition):
        checks.append((name, bool(condition)))
        if not condition:
            raise AssertionError(name)

    async def reachable():
        try:
            async with httpx.AsyncClient(timeout=2, trust_env=False) as client:
                response = await client.get(cfg.lm_base_url + "/models")
                # Even an authentication/error HTTP response means the server is reachable.
                return response.status_code
        except httpx.TransportError:
            return None

    async def cli(*args):
        result = await asyncio.to_thread(subprocess.run, [lms, "server", *args], capture_output=True, timeout=20)
        if result.returncode:
            raise RuntimeError("LM Studio CLI failed")

    async def restore():
        await cli("start", "--bind", "127.0.0.1", "--port", "1234")
        for _ in range(30):
            if await reachable() == 200:
                return True
            await asyncio.sleep(0.5)
        return False

    async def call(session, phase, tool, arguments):
        response = await session.call_tool(tool, arguments)
        data = response.structuredContent or {}
        calls.append((phase, tool, data.get("request_id", "—"), data.get("status", "missing")))
        return response, data

    try:
        check("До теста LM Studio отвечает HTTP 200", await reachable() == 200)
        sources = ["OUTAGE_CHECK_PRIVATE_DOCUMENT\r\nТема: до проверки.\r\nКонтакт: outage-demo@example.com\r\n",
                   "OUTAGE_CHECK_CLEAN_DOCUMENT\r\nОбычный текст без секретов.\r\n"]
        for source in sources:
            with tempfile.NamedTemporaryFile(dir=project / "inbox", prefix="outage-guard-", suffix=".txt", delete=False) as file:
                paths.append(Path(file.name))
                file.write(source.encode("utf-8"))
        baseline = [p.read_bytes() for p in paths]
        params = StdioServerParameters(command=registered["command"], args=registered.get("args", []), cwd=registered.get("cwd"))
        async with stdio_client(params) as (read, write):
            async with ClientSession(read, write) as session:
                await session.initialize()
                _, edit = await call(session, "до отказа", "read_safe_file", {"path": str(paths[0])})
                check("До остановки получена действующая сессия редактирования", edit.get("status") == "redacted" and bool(edit.get("edit_id")))
                edited = edit["content"].replace("Тема: до проверки.", "Тема: после восстановления.")
                try:
                    await cli("stop")
                    offline = False
                    for _ in range(20):
                        if await reachable() is None:
                            offline = True
                            break
                        await asyncio.sleep(0.25)
                    check("API LM Studio действительно недоступен по сети", offline)
                    for tool in ("read_safe_file", "check_response_file"):
                        for index, label in ((0, "файл с секретом"), (1, "чистый файл")):
                            response, data = await call(session, "LM Studio недоступна", tool, {"path": str(paths[index])})
                            check(f"{tool}, {label}: error, content=null, нет edit_id",
                                  not response.isError and data.get("status") == "error" and data.get("content") is None and "edit_id" not in data)
                            check(f"{tool}, {label}: нет содержимого в MCP-ответе",
                                  all(value not in response.model_dump_json() for value in ("OUTAGE_CHECK_", "outage-demo@example.com", "Обычный текст без секретов")))
                    response, denied = await call(session, "LM Studio недоступна", "write_safe_file", {"edit_id": edit["edit_id"], "content": edited})
                    check("Запись с действующим edit_id отклонена при отказе LM", not response.isError and denied.get("status") == "error")
                    check("После отказов оба файла побайтово неизменны", all(p.read_bytes() == raw for p, raw in zip(paths, baseline)))
                    with sqlite3.connect(cfg.audit_db) as db:
                        for _, tool, request_id, _ in calls[1:]:
                            rows = db.execute("SELECT status,content FROM events WHERE id=?", (request_id,)).fetchall()
                            expected = "write_rejected" if tool == "write_safe_file" else "error"
                            check(f"Аудит отказа {tool}, {request_id[:8]}: без содержимого", rows == [(expected, None)])
                finally:
                    restored = await restore()
                    check("API LM Studio восстановлен на localhost:1234, HTTP 200", restored)

                _, saved = await call(session, "после восстановления", "write_safe_file", {"edit_id": edit["edit_id"], "content": edited})
                check("После восстановления запись с той же сессией успешна", saved.get("status") == "written" and saved.get("restored_count") == 1)
                expected = baseline[0].replace("Тема: до проверки.".encode(), "Тема: после восстановления.".encode(), 1)
                check("После успешной записи изменена только тема, email восстановлен", paths[0].read_bytes() == expected)
                _, reread = await call(session, "после восстановления", "read_safe_file", {"path": str(paths[0])})
                check("Повторное чтение после восстановления успешно", reread.get("status") == "redacted" and "Тема: после восстановления." in (reread.get("content") or ""))
                check("В повторном ответе email замаскирован", "outage-demo@example.com" not in json.dumps(reread) and "[REDACTED_EMAIL:" in (reread.get("content") or ""))
                check("Чистый контрольный файл не изменён", paths[1].read_bytes() == baseline[1])
    except Exception as exc:
        error = type(exc).__name__
    finally:
        # A second recovery attempt also covers a failure of the inner recovery block.
        if not restored:
            try:
                restored = await restore()
            except Exception:
                restored = False
        timestamp = datetime.now(timezone(timedelta(hours=3))).isoformat(timespec="seconds")
        passed = error is None and restored and bool(checks) and all(ok for _, ok in checks)
        lines = ["", "## Недоступность LM Studio — отказ с запретом выдачи и записи", "",
                 f"Дата: {timestamp} (Europe/Moscow).", "",
                 f"Итог: **{'PASS' if passed else 'FAIL'}**; проверок пройдено {sum(ok for _, ok in checks)}/{len(checks)}.",
                 f"Подключение после теста: **{'ВОССТАНОВЛЕНО' if restored else 'НЕ ПОДТВЕРЖДЕНО'}**.", "",
                 "Реальный локальный API остановлен командой `lms server stop`; недоступность подтверждена HTTP-клиентом.",
                 "MCP-процесс оставался запущенным. До отказа получен действующий edit_id; отклонение записи проверялось с этой сессией и корректными маркерами.",
                 "Через MCP проверены Input Guard и Output Guard на файле с секретом и на чистом файле. Модель/сеть не подменялись.",
                 "Восстановление выполнялось в finally: `lms server start --bind 127.0.0.1 --port 1234`.",
                 "После восстановления повторены запись с той же сессией и чтение через реальную модель. Это проверка SDK MCP-клиентом, не через интерфейс чата.", "",
                 "| Проверка | Результат |", "| --- | --- |"]
        lines.extend(f"| {name} | {'PASS' if ok else 'FAIL'} |" for name, ok in checks)
        lines.extend(["", "| Этап | MCP-инструмент | request_id | Статус |", "| --- | --- | --- | --- |"])
        lines.extend(f"| {phase} | {tool} | `{request_id}` | {status} |" for phase, tool, request_id, status in calls)
        lines.extend(["", "Тестовые файлы:", ""])
        lines.extend(f"- `{path}`" for path in paths)
        lines.extend(["", "Предыдущие результаты сохранены. Исходные секреты в отчёт не включены; example.txt не изменялся.",
                      "Проверен отказ соединения с остановленным API. Тайм-аут зависшей модели и прочие сетевые ошибки этим запуском отдельно не моделировались."])
        if error:
            lines.extend(["", f"Ошибка проверки: `{error}`. Полный успех не подтверждён."])
        with report_path.open("a", encoding="utf-8") as file:
            file.write("\n".join(lines) + "\n")
        print(json.dumps({"status": "PASS" if passed else "FAIL", "checks": len(checks), "connection_restored": restored, "report": str(report_path)}, ensure_ascii=False))
    if error or not restored:
        raise SystemExit(1)


if __name__ == "__main__":
    asyncio.run(main())
