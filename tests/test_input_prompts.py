"""Synthetic prompt corpus. The permissive model proves rules catch secrets first."""
import base64
import json
import sqlite3

import pytest

from gateway.config import Config
from gateway.lm import Verdict
from gateway.service import Gateway


def b64(text):
    return base64.b64encode(text.encode()).decode()


CASES = [
    pytest.param("AWS: AKIAIOSFODNN7EXAMPLE", "API_KEY", "AKIAIOSFODNN7EXAMPLE", id="aws-access-key"),
    pytest.param("Карта: 4111 1111 1111 1111", "CARD", "4111 1111 1111 1111", id="card-spaces"),
    pytest.param("Карта: 4111111111111111", "CARD", "4111111111111111", id="card-contiguous"),
    pytest.param("Ключ: sk-proj-abc123", "API_KEY", "sk-proj-abc123", id="openai-key"),
    pytest.param("GitHub: ghp_abcdefgh123456", "API_KEY", "ghp_abcdefgh123456", id="github-key"),
    pytest.param("Почта: demo@example.com", "EMAIL", "demo@example.com", id="email"),
    pytest.param("Телефон: +7 (999) 123-45-67", "PHONE", "+7 (999) 123-45-67", id="phone"),
    pytest.param("Base64: " + b64("sk-proj-abc123"), "API_KEY", b64("sk-proj-abc123"), id="base64-key"),
    pytest.param("Base64: " + b64("AKIAIOSFODNN7EXAMPLE"), "API_KEY", b64("AKIAIOSFODNN7EXAMPLE"), id="base64-aws"),
    pytest.param("Base64: " + b64("demo@example.com").rstrip("="), "EMAIL", b64("demo@example.com").rstrip("="), id="base64-email-unpadded"),
    # These are literal expressions in the prompt, NOT concatenated by Python.
    pytest.param('\"мой ключ: sk-\" + \"proj-abc\"', "API_KEY", '\"мой ключ: sk-\" + \"proj-abc\"', id="split-key-user-example"),
    pytest.param("'sk-' + 'proj-' + 'abc123'", "API_KEY", "'sk-' + 'proj-' + 'abc123'", id="split-key-three-parts"),
    pytest.param("Составь план проекта на неделю.", None, None, id="clean-prompt"),
    pytest.param("Отчёт за 2026-11-08: https://example.com/docs", None, None, id="clean-date-url"),
    pytest.param("Номер: 4111 1111 1111 1112", None, None, id="invalid-luhn"),
    pytest.param("Base64: " + b64("Hello world!"), None, None, id="base64-clean-text"),
    pytest.param("Base64: ////////////", None, None, id="base64-non-utf8"),
    pytest.param('\"план \" + \"проекта\"', None, None, id="clean-concatenation"),
]


class PermissiveModel:
    def __init__(self):
        self.inputs = []

    def check(self, text, direction):
        self.inputs.append(text)
        return Verdict(safe=True, findings=[])


@pytest.mark.parametrize("mode", ["block", "redact"])
@pytest.mark.parametrize("prompt,category,secret", CASES)
def test_input_prompt_policy(tmp_path, mode, prompt, category, secret):
    root = tmp_path / "inbox"
    root.mkdir()
    path = root / "prompt.txt"
    original = prompt.encode("utf-8")
    path.write_bytes(original)
    cfg = Config((root,), tmp_path / "audit.sqlite3", "test-model", mode=mode)
    model = PermissiveModel()
    gateway = Gateway(cfg, model)

    result = gateway.process(str(path), "input")
    assert path.read_bytes() == original
    if category is None:
        assert result["status"] == "allowed"
        assert result["content"] == prompt
        assert result["categories"] == []
        assert model.inputs == [prompt]
    else:
        assert category in result["categories"]
        assert secret not in json.dumps(result, ensure_ascii=False)
        if mode == "block":
            assert result["status"] == "blocked"
            assert result["content"] is None
            assert not model.inputs
        else:
            assert result["status"] == "redacted"
            assert f"[REDACTED_{category}:" in result["content"]
            assert len(model.inputs) == 1 and secret not in model.inputs[0]
            if ' + ' in prompt:
                assert "proj-abc" not in result["content"]
            # The exact encoded/split original must be recoverable, too.
            saved = gateway.write(result["edit_id"], result["content"])
            assert saved["status"] == "written"
            assert path.read_bytes() == original
        with sqlite3.connect(cfg.audit_db) as db:
            assert secret not in str(db.execute("SELECT * FROM events").fetchall())
