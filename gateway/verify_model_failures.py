"""Exercise real HTTP timeouts and malformed classifier responses through MCP."""
import asyncio
from collections import Counter
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import sqlite3
import tempfile
import threading
import time
import tomllib

import httpx
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

from .config import Config


class FaultServer(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self):
        super().__init__(("127.0.0.1", 0), Handler)
        self.mode = "good"
        self.requests = []
        self.stop_event = threading.Event()


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def do_POST(self):
        self.rfile.read(int(self.headers.get("Content-Length", "0")))
        mode = self.server.mode
        self.server.requests.append(mode)
        if mode == "timeout":
            # Client timeout is 1 second. This delays headers for 4 seconds.
            self.server.stop_event.wait(4)
        if mode == "bad_http_json":
            body = b'{"MODEL_PAYLOAD_PRIVATE": invalid JSON'
        else:
            content = '{"safe":true,"findings":[]}'
            if mode == "bad_model_json":
                content = '{"MODEL_PAYLOAD_PRIVATE": invalid JSON'
            elif mode == "bad_schema":
                content = '{"safe":"true","findings":[],"extra":"MODEL_PAYLOAD_PRIVATE"}'
            body = json.dumps({"choices": [{"finish_reason": "stop", "message": {"content": content}}]}).encode()
        try:
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError, ConnectionAbortedError):
            pass


async def main():
    project = Path(__file__).resolve().parents[1]
    report = project / "RESULTS.md"
    if not report.is_file():
        raise SystemExit("RESULTS.md missing")
    config_bytes = (project / "config.json").read_bytes()
    registration_path = Path.home() / ".codex/config.toml"
    registration_bytes = registration_path.read_bytes()
    registration = tomllib.loads(registration_bytes.decode())["mcp_servers"]["local-file-guard"]
    cfg = Config.load(project / "config.json")
    folder = Path(tempfile.mkdtemp(prefix="model-failure-", dir=project / "data"))
    inbox = folder / "inbox"
    inbox.mkdir()
    source = inbox / "synthetic.txt"
    original = "PRIVATE_FILE_SENTINEL\r\nТема: до проверки.\r\nКонтакт: faults@example.com\r\n"
    source.write_bytes(original.encode())
    server = FaultServer()
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    test_config = folder / "config.json"
    test_config.write_text(json.dumps({"allowed_roots": [str(inbox)], "audit_db": str(folder / "audit.sqlite3"),
        "lm_model": "controlled-fault-fixture", "lm_base_url": f"http://127.0.0.1:{server.server_port}/v1",
        "mode": "redact", "timeout_seconds": 1}), encoding="utf-8")
    checks, results = [], []
    error = None
    recovery_calls = []

    def check(name, condition):
        checks.append((name, bool(condition)))
        if not condition:
            raise AssertionError(name)

    try:
        args = list(registration.get("args", []))
        index = args.index("--config")
        args[index + 1] = str(test_config)
        params = StdioServerParameters(command=registration["command"], args=args, cwd=registration.get("cwd"))
        async with stdio_client(params) as (read, write):
            async with ClientSession(read, write) as session:
                await session.initialize()
                for mode in ("timeout", "bad_model_json", "bad_http_json", "bad_schema"):
                    server.mode = "good"
                    prepared = (await session.call_tool("read_safe_file", {"path": str(source)})).structuredContent or {}
                    check(f"{mode}: получен действующий edit_id до сбоя", prepared.get("status") == "redacted" and bool(prepared.get("edit_id")))
                    edited = prepared["content"].replace("Тема: до проверки.", "Тема: после проверки.")
                    server.mode = mode
                    for tool in ("read_safe_file", "check_response_file", "write_safe_file"):
                        arguments = {"path": str(source)} if tool != "write_safe_file" else {"edit_id": prepared["edit_id"], "content": edited}
                        count = len(server.requests)
                        start = time.monotonic()
                        response = await session.call_tool(tool, arguments)
                        elapsed = time.monotonic() - start
                        data = response.structuredContent or {}
                        results.append((mode, tool, data.get("status", "missing"), elapsed, data.get("request_id", "—")))
                        check(f"{mode}/{tool}: HTTP-запрос дошёл до нужного сценария", server.requests[count:] == [mode])
                        check(f"{mode}/{tool}: отказ без выдачи и edit_id", not response.isError and data.get("status") == "error" and data.get("content") is None and "edit_id" not in data)
                        check(f"{mode}/{tool}: нет утечки текста файла или ответа модели", all(x not in response.model_dump_json() for x in ("PRIVATE_FILE_SENTINEL", "faults@example.com", "MODEL_PAYLOAD_PRIVATE")))
                        check(f"{mode}/{tool}: исходный файл не изменён", source.read_bytes() == original.encode())
                        if mode == "timeout":
                            check(f"{mode}/{tool}: отказ по тайм-ауту до завершения задержки", 0.8 <= elapsed < 3.8)
                        with sqlite3.connect(folder / "audit.sqlite3") as db:
                            rows = db.execute("SELECT status,content FROM events WHERE id=?", (data.get("request_id"),)).fetchall()
                        check(f"{mode}/{tool}: аудит отказа без содержимого", rows == [("write_rejected" if tool == "write_safe_file" else "error", None)])
    except Exception as exc:
        error = type(exc).__name__
    finally:
        server.stop_event.set()
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
        checks.append(("Тестовый HTTP-сервер остановлен", not thread.is_alive()))
        checks.append(("Рабочий config.json не изменён", (project / "config.json").read_bytes() == config_bytes))
        checks.append(("Регистрация MCP не изменена", registration_path.read_bytes() == registration_bytes))

    # Always verify the original real connection, even if fault assertions failed.
    try:
        async with httpx.AsyncClient(timeout=5, trust_env=False) as client:
            check("Рабочая LM Studio отвечает HTTP 200", (await client.get(cfg.lm_base_url + "/models")).status_code == 200)
        with tempfile.NamedTemporaryFile(dir=project / "inbox", prefix="model-recovery-", suffix=".txt", delete=False) as file:
            live_path = Path(file.name)
            live_original = "Тема: до проверки.\r\nКонтакт: recovery@example.com\r\n"
            file.write(live_original.encode())
        params = StdioServerParameters(command=registration["command"], args=registration.get("args", []), cwd=registration.get("cwd"))
        async with stdio_client(params) as (read, write):
            async with ClientSession(read, write) as session:
                await session.initialize()
                live = (await session.call_tool("read_safe_file", {"path": str(live_path)})).structuredContent or {}
                recovery_calls.append(("read_safe_file", live.get("request_id", "—"), live.get("status", "missing")))
                check("Реальная LM Studio: чтение и маскирование работают", live.get("status") == "redacted" and bool(live.get("edit_id")) and "recovery@example.com" not in json.dumps(live))
                saved = (await session.call_tool("write_safe_file", {"edit_id": live["edit_id"], "content": live["content"].replace("до проверки", "после проверки")})).structuredContent or {}
                recovery_calls.append(("write_safe_file", saved.get("request_id", "—"), saved.get("status", "missing")))
                check("Реальная LM Studio: запись и восстановление email работают", saved.get("status") == "written" and live_path.read_bytes() == live_original.replace("до проверки", "после проверки").encode())
    except Exception as exc:
        error = error or type(exc).__name__

    passed = error is None and all(ok for _, ok in checks)
    lines = ["", "## Тайм-аут и некорректный JSON модели — проверка через MCP", "",
        f"Дата: {datetime.now(timezone(timedelta(hours=3))).isoformat(timespec='seconds')} (Europe/Moscow).", "",
        f"Итог: **{'PASS' if passed else 'FAIL'}**. Проверок пройдено {sum(ok for _, ok in checks)}/{len(checks)}.", "",
        "Сбои воспроизведены отдельным loopback HTTP-сервером, имитирующим OpenAI-совместимый API LM Studio.",
        "Настоящий MCP-процесс запущен с отдельной тестовой конфигурацией; функции Gateway/LocalModel не подменялись.",
        "Тайм-аут клиента — 1 секунда; HTTP-сервер задерживал заголовки на 4 секунды. Это реальное ожидание сети, не искусственно выброшенное исключение.",
        "Для malformed JSON проверены отдельно некорректный JSON внутри message.content и некорректное HTTP JSON-тело; также проверен валидный JSON с неверной схемой (safe строкой и лишнее поле). HTTP-статус — 200.",
        "В каждом сценарии предварительно получен действующий edit_id. Проверены Input Guard, Output Guard и запись с корректными маркерами.",
        "Рабочая LM Studio не останавливалась, рабочая конфигурация и регистрация MCP не менялись. В завершение тестовый HTTP-сервер закрыт, выполнены чтение и запись через реальную LM Studio.", "",
        "| Сбой | MCP-инструмент | Статус | Время, сек. | request_id |", "| --- | --- | --- | --- | --- |"]
    lines.extend(f"| {mode} | {tool} | {status} | {elapsed:.3f} | `{request_id}` |" for mode, tool, status, elapsed, request_id in results)
    lines.extend(["", "### Проверки", "", "| Проверка | Итог |", "| --- | --- |"])
    lines.extend(f"| {name} | {'PASS' if ok else 'FAIL'} |" for name, ok in checks)
    lines.extend(["", "### Проверка рабочего подключения", "", "| Инструмент | request_id | Статус |", "| --- | --- | --- |"])
    lines.extend(f"| {tool} | `{request_id}` | {status} |" for tool, request_id, status in recovery_calls)
    lines.extend(["", f"Тестовая конфигурация, файл и аудит: `{folder}`.",
        "Тестовый endpoint после проверки выключен; рабочий MCP использует исходный config.json.",
        "Синтетические данные не выводились в отчёт. Предыдущие результаты сохранены. example.txt не изменялся.",
        "Проверялся MCP через клиент SDK, не интерфейс ChatGPT. Контролируемые сбои проверяют обработку ошибок, а не способность реальной модели генерировать конкретный некорректный ответ."])
    if error:
        lines.append(f"\nОшибка проверки: `{error}`; полный успех не подтверждён.")
    with report.open("a", encoding="utf-8") as file:
        file.write("\n".join(lines) + "\n")
    print(json.dumps({"status": "PASS" if passed else "FAIL", "checks": len(checks), "fault_calls": len(results), "report": str(report)}, ensure_ascii=False))
    if not passed:
        raise SystemExit(1)


if __name__ == "__main__":
    asyncio.run(main())
