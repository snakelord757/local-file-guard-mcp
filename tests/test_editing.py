from dataclasses import replace
from pathlib import Path
import sqlite3
import time

import pytest

from gateway.config import Config
from gateway.editing import MARKER
from gateway.lm import Verdict
from gateway.service import Gateway


class Model:
    def __init__(self):
        self.calls = []

    def check(self, text, direction):
        self.calls.append(text)
        return Verdict(safe=True, findings=[])


@pytest.fixture
def context(tmp_path):
    root = tmp_path / "inbox"
    root.mkdir()
    cfg = Config((root,), tmp_path / "audit.sqlite3", "test")
    model = Model()
    return root, cfg, model, Gateway(cfg, model)


def test_restoration_distinct_repeated_and_bom(context):
    root, cfg, model, g = context
    path = root / "test.txt"
    original = "Old\r\na@example.com b@example.com a@example.com\r\nsk-proj-abc123"
    path.write_bytes(original.encode("utf-8-sig"))
    read = g.process(str(path), "input")
    markers = MARKER.findall(read["content"])
    assert len(set(markers)) == 4
    result = g.write(read["edit_id"], read["content"].replace("Old", "New"))
    assert result["status"] == "written"
    assert path.read_bytes() == original.replace("Old", "New").encode("utf-8-sig")
    assert not any("a@example.com" in text or "sk-proj-abc123" in text for text in model.calls)
    with sqlite3.connect(cfg.audit_db) as db:
        rows = str(db.execute("SELECT * FROM events").fetchall())
        assert "a@example.com" not in rows and "sk-proj-abc123" not in rows
    assert g.write(read["edit_id"], read["content"])["status"] == "error"


@pytest.mark.parametrize("change", ["remove", "duplicate", "foreign", "broken", "secret", "command"])
def test_reject_bad_edits(context, change):
    root, _, _, g = context
    path = root / "test.txt"
    original = "Old a@example.com"
    path.write_text(original, encoding="utf-8")
    read = g.process(str(path), "input")
    content = read["content"]
    marker = MARKER.findall(content)[0]
    edits = {
        "remove": content.replace(marker, ""), "duplicate": content + marker,
        "foreign": content + "[REDACTED_EMAIL:" + "a" * 32 + "]",
        "broken": content.replace(marker, "[REDACTED_EMAIL]"),
        "secret": content + " sk-proj-secret123", "command": content + " rm -rf /",
    }
    assert g.write(read["edit_id"], edits[change])["status"] == "error"
    assert path.read_text(encoding="utf-8") == original


def test_conflict_expiry_restart_and_audit_failure(context, monkeypatch):
    root, cfg, model, g = context
    path = root / "test.txt"
    path.write_text("Old", encoding="utf-8")
    read = g.process(str(path), "input")
    path.write_text("Other writer", encoding="utf-8")
    assert g.write(read["edit_id"], "New")["status"] == "error"
    assert path.read_text() == "Other writer"
    fresh = g.process(str(path), "input")
    assert Gateway(cfg, model).write(fresh["edit_id"], "New")["status"] == "error"
    g.sessions[fresh["edit_id"]].expires = time.monotonic() - 1
    assert g.write(fresh["edit_id"], "New")["status"] == "error"
    fresh = g.process(str(path), "input")
    def fail(event):
        raise sqlite3.OperationalError()
    monkeypatch.setattr(g.audit, "write", fail)
    assert g.write(fresh["edit_id"], "New")["status"] == "error"
    assert path.read_text() == "Other writer"


def test_exact_obfuscated_secret_restored(context):
    root, _, _, g = context
    path = root / "test.txt"
    original = "Old s\u200bk-proj-abc123"
    path.write_text(original, encoding="utf-8")
    read = g.process(str(path), "input")
    assert g.write(read["edit_id"], read["content"].replace("Old", "New"))["status"] == "written"
    assert path.read_text(encoding="utf-8") == original.replace("Old", "New")


def test_new_secret_from_model_restored(context):
    root, _, model, g = context
    path = root / "test.txt"
    path.write_text("Old custom_token_value", encoding="utf-8")
    model.check = lambda text, direction: Verdict.model_validate({"safe": False, "findings": [{"category": "API_KEY", "text": "custom_token_value"}]})
    read = g.process(str(path), "input")
    model.check = lambda *args: Verdict(safe=True, findings=[])
    assert g.write(read["edit_id"], read["content"].replace("Old", "New"))["status"] == "written"
    assert path.read_text() == "New custom_token_value"
