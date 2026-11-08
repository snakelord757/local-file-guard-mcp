import asyncio
import json
import sys
from pathlib import Path

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client
from mcp.shared.memory import create_connected_server_and_client_session

from gateway.config import Config
from gateway.lm import LocalModel, Verdict
from gateway.server import create_server


def test_mcp_protocol_and_payload(tmp_path, monkeypatch):
    root = tmp_path / "inbox"
    root.mkdir()
    path = root / "document.txt"
    path.write_text("Contact: demo@example.com", encoding="utf-8")
    cfg = Config((root,), tmp_path / "audit.sqlite3", "test-model")
    monkeypatch.setattr(LocalModel, "check", lambda *args: Verdict(safe=True, findings=[]))

    async def run():
        async with create_connected_server_and_client_session(create_server(cfg)) as session:
            listed = await session.list_tools()
            assert {t.name for t in listed.tools} == {"read_safe_file", "check_response_file", "write_safe_file"}
            for tool in [t for t in listed.tools if t.name != "write_safe_file"]:
                assert set(tool.inputSchema["properties"]) == {"path"}
                result = await session.call_tool(tool.name, {"path": str(path)})
                assert not result.isError
                assert "demo@example.com" not in result.model_dump_json()
                assert result.structuredContent["status"] == "redacted"
                assert "[REDACTED_EMAIL:" in result.structuredContent["content"]
                if tool.name == "read_safe_file":
                    edit = result.structuredContent
                    saved = await session.call_tool("write_safe_file", {
                        "edit_id": edit["edit_id"], "content": edit["content"].replace("Contact:", "Updated:")
                    })
                    assert saved.structuredContent["status"] == "written"
                    assert "demo@example.com" not in saved.model_dump_json()
                    assert path.read_text(encoding="utf-8") == "Updated: demo@example.com"
            write_tool = next(t for t in listed.tools if t.name == "write_safe_file")
            assert write_tool.annotations.readOnlyHint is False
            assert write_tool.annotations.destructiveHint is True
            denied = await session.call_tool("read_safe_file", {"path": "C:\\Windows\\win.ini"})
            assert denied.structuredContent["content"] is None
    asyncio.run(run())


def test_stdio_subprocess(tmp_path):
    root = tmp_path / "inbox"
    root.mkdir()
    path = root / "secret.txt"
    path.write_text("sk-proj-abc123", encoding="utf-8")
    config = tmp_path / "config.json"
    config.write_text(json.dumps({
        "allowed_roots": [str(root)], "audit_db": str(tmp_path / "audit.sqlite3"),
        "lm_model": "not-called-in-block-mode", "mode": "block"
    }), encoding="utf-8")

    async def run():
        params = StdioServerParameters(command=sys.executable, args=[
            str(Path(__file__).resolve().parents[1] / "run_server.py"), "--config", str(config)
        ], cwd=str(tmp_path))
        async with stdio_client(params) as (read, write):
            async with ClientSession(read, write) as session:
                await session.initialize()
                assert len((await session.list_tools()).tools) == 3
                result = await session.call_tool("read_safe_file", {"path": str(path)})
                assert result.structuredContent["status"] == "blocked"
                assert "sk-proj-abc123" not in result.model_dump_json()
    asyncio.run(run())
