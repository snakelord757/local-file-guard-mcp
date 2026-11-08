"""Real stdio MCP round-trip against the configured local model."""
import asyncio
import json
from pathlib import Path
import sys
import tempfile

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client


async def main():
    project = Path(__file__).resolve().parents[1]
    params = StdioServerParameters(command=sys.executable, args=[
        str(project / "run_server.py"), "--config", str(project / "config.json")
    ])
    async with stdio_client(params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            tools = await session.list_tools()
            assert {t.name for t in tools.tools} == {"read_safe_file", "check_response_file", "write_safe_file"}
            for name in ("read_safe_file", "check_response_file"):
                result = await session.call_tool(name, {"path": str(project / "inbox/example.txt")})
                data = result.structuredContent
                assert not result.isError and data, "MCP protocol failed"
                assert data["status"] == "redacted", data.get("warning", "Expected redaction")
                assert "demo@example.com" not in result.model_dump_json()
                assert "sk-proj-abc123" not in result.model_dump_json()
                assert "[REDACTED_EMAIL:" in data["content"]
                assert "[REDACTED_API_KEY:" in data["content"]
                print(json.dumps({"tool": name, **data}, ensure_ascii=False))
            # Disposable synthetic fixture; never overwrite the user's example document.
            with tempfile.NamedTemporaryFile(dir=project / "inbox", suffix=".txt", delete=False) as file:
                target = Path(file.name)
                original = "Old demo@example.com sk-proj-abc123"
                file.write(original.encode("utf-8"))
            try:
                read_result = await session.call_tool("read_safe_file", {"path": str(target)})
                edit = read_result.structuredContent
                assert edit["status"] == "redacted", edit.get("warning")
                written = await session.call_tool("write_safe_file", {
                    "edit_id": edit["edit_id"], "content": edit["content"].replace("Old", "New")
                })
                assert written.structuredContent["status"] == "written", written.structuredContent
                assert target.read_text(encoding="utf-8") == original.replace("Old", "New")
                assert "demo@example.com" not in written.model_dump_json()
                print("PASS: write_safe_file restored original secrets locally after editing.")
            finally:
                target.unlink(missing_ok=True)
    print("PASS: real MCP + LM Studio; both tools returned only redacted test content.")


if __name__ == "__main__":
    asyncio.run(main())
