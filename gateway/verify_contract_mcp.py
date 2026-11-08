"""Controlled HTTP classifier responses through an unmodified MCP subprocess."""
import asyncio
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import tempfile
import threading
import sys

from .verify_full_mcp import PROJECT, ROWS, CALLS, session, call, record


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def do_POST(self):
        payload = json.loads(self.rfile.read(int(self.headers['Content-Length'])))
        self.server.requests.append(payload)
        body = json.dumps({'choices': [{'finish_reason': self.server.finish,
                                       'message': {'content': self.server.content}}]}).encode()
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)


async def main():
    folder = Path(tempfile.mkdtemp(prefix='contract-mcp-', dir=PROJECT / 'data'))
    root = folder / 'inbox'
    root.mkdir()
    server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
    server.requests = []
    server.content = '{"safe":true,"findings":[]}'
    server.finish = 'stop'
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    config = folder / 'config.json'
    raw = {'allowed_roots': [str(root)], 'audit_db': str(folder / 'audit.sqlite3'),
           'lm_model': 'controlled-contract-fixture', 'lm_base_url': f'http://127.0.0.1:{server.server_port}/v1'}
    config.write_text(json.dumps(raw), encoding='utf-8')
    good = server.content
    try:
        async with session(config) as client:
            path = root / 'contract.txt'
            async def protocol():
                listed = (await client.list_tools()).tools
                assert {t.name for t in listed} == {'read_safe_file', 'check_response_file', 'write_safe_file'}
                for tool in listed:
                    expected = {'edit_id', 'content'} if tool.name == 'write_safe_file' else {'path'}
                    assert set(tool.inputSchema['properties']) == expected
                    if tool.name == 'write_safe_file':
                        assert tool.annotations.readOnlyHint is False and tool.annotations.destructiveHint is True
                path.write_bytes(b'Contact: demo@example.com')
                for name in ('read_safe_file', 'check_response_file'):
                    data = await call(client, name, {'path': str(path)})
                    assert data['status'] == 'redacted' and 'demo@example.com' not in json.dumps(data)
                    if name == 'read_safe_file':
                        saved = await call(client, 'write_safe_file', {'edit_id': data['edit_id'], 'content': data['content'].replace('Contact:', 'Updated:')})
                        assert saved['status'] == 'written' and path.read_bytes() == b'Updated: demo@example.com'
                    else:
                        assert 'edit_id' not in data
            await record('protocol/schema-annotations-payload', protocol)
            path.write_bytes(b'hello')
            variants = [('valid', good, 'stop'), ('truncated', good, 'length'),
                        ('wrong-type', '{"safe":"true","findings":[]}', 'stop'),
                        ('unsafe-empty', '{"safe":false,"findings":[]}', 'stop'),
                        ('absent-span', '{"safe":false,"findings":[{"category":"API_KEY","text":"not-in-file"}]}', 'stop'),
                        ('invalid-json', 'not json', 'stop')]
            for name, content, finish in variants:
                async def run(content=content, finish=finish, name=name):
                    server.content, server.finish = good, 'stop'
                    edit = await call(client, 'read_safe_file', {'path': str(path)})
                    assert edit['status'] == 'allowed'
                    server.content, server.finish = content, finish
                    before = len(server.requests)
                    for tool in ('read_safe_file', 'check_response_file', 'write_safe_file'):
                        args = {'edit_id': edit['edit_id'], 'content': 'hello'} if tool == 'write_safe_file' else {'path': str(path)}
                        data = await call(client, tool, args)
                        expected = ('written' if tool == 'write_safe_file' else 'allowed') if name == 'valid' else 'error'
                        assert data['status'] == expected, f'{tool}: {data["status"]}'
                        if name != 'valid':
                            assert data.get('content') is None and 'edit_id' not in data
                        assert path.read_bytes() == b'hello'
                    assert len(server.requests) == before + 3
                await record('http-contract/' + name, run)

            async def model_findings():
                path.write_bytes(b'Old custom_token_value custom_token_value')
                server.finish = 'stop'
                server.content = json.dumps({'safe': False, 'findings': [{'category': 'API_KEY', 'text': 'custom_token_value'}]})
                data = await call(client, 'read_safe_file', {'path': str(path)})
                assert data['status'] == 'redacted' and data['content'].count('[REDACTED_API_KEY:') == 2
                assert 'custom_token_value' not in json.dumps(data)
                server.content = good
                saved = await call(client, 'write_safe_file', {'edit_id': data['edit_id'], 'content': data['content'].replace('Old', 'New')})
                assert saved['status'] == 'written' and path.read_bytes() == b'New custom_token_value custom_token_value'
                server.content = json.dumps({'safe': False, 'findings': [{'category': 'PROMPT_INJECTION', 'text': 'custom_token_value'}]})
                denied = await call(client, 'read_safe_file', {'path': str(path)})
                assert denied['status'] == 'blocked' and denied['content'] is None
            await record('model-findings/redact-restore-injection', model_findings)

            async def masked_before_model():
                path.write_bytes(b'Contact: demo@example.com')
                server.content = good
                before = len(server.requests)
                data = await call(client, 'read_safe_file', {'path': str(path)})
                assert data['status'] == 'redacted'
                assert len(server.requests) == before + 1
                assert 'demo@example.com' not in json.dumps(server.requests[before:])
            await record('model-input/secrets-masked', masked_before_model)

        raw['mode'] = 'block'
        config.write_text(json.dumps(raw), encoding='utf-8')
        async with session(config) as client:
            async def no_model_call():
                path.write_bytes(b'sk-proj-abc123')
                before = len(server.requests)
                data = await call(client, 'read_safe_file', {'path': str(path)})
                assert data['status'] == 'blocked' and len(server.requests) == before
            await record('block/no-http-call', no_model_call)
        for name, change in [('remote-model', {'lm_base_url': 'https://api.openai.com/v1'}),
                             ('audit-inside-root', {'audit_db': str(root / 'audit.sqlite3')})]:
            async def invalid_config(change=change):
                config.write_text(json.dumps(dict(raw, **change)), encoding='utf-8')
                process = await asyncio.create_subprocess_exec(sys.executable, str(PROJECT / 'run_server.py'), '--config', str(config),
                    stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
                out, err = await process.communicate()
                assert process.returncode == 2 and not out and b'Invalid local configuration' in err
            await record('startup-before-mcp/' + name, invalid_config)
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
    result = {'passed': sum(r['status'] == 'PASS' for r in ROWS), 'total': len(ROWS), 'cases': ROWS, 'calls': CALLS,
              'model': 'Controlled loopback HTTP fixture; real MCP transport, no Gateway/LocalModel monkeypatch'}
    report = folder / 'summary.json'
    report.write_text(json.dumps(result, indent=2), encoding='utf-8')
    print(json.dumps({'report': str(report), 'passed': result['passed'], 'total': result['total']}), flush=True)
    return int(result['passed'] != result['total'])


if __name__ == '__main__':
    raise SystemExit(asyncio.run(main()))
