import hashlib
import json
import os
from pathlib import Path
import sqlite3
import stat
import uuid
import tempfile
import threading
import time
from datetime import datetime, timezone

from .config import Config
from .guards import Finding, SECRET_CATEGORIES, normalize, scan
from .lm import GuardUnavailable, LocalModel
from .editing import MARKER, masked, new_session, token


class FileRejected(Exception):
    pass


def read_file_bytes(path: str, cfg: Config) -> bytes:
    # No URLs, UNC shares, Windows device names, alternate data streams or links.
    if not path or len(path) > 4096 or path.startswith(("\\\\", "//")):
        raise FileRejected()
    candidate = Path(path)
    if not candidate.is_absolute() or ":" in str(candidate)[2:]:
        raise FileRejected()
    if any(part.split(".")[0].upper() in {"CON", "PRN", "AUX", "NUL", *(f"COM{i}" for i in range(10)), *(f"LPT{i}" for i in range(10))} for part in candidate.parts):
        raise FileRejected()
    # Check lexical and resolved containment, as well as each reparse point.
    if not any(candidate.is_relative_to(root) for root in cfg.allowed_roots):
        raise FileRejected()
    try:
        resolved = candidate.resolve(strict=True)
        if not any(resolved.is_relative_to(root) for root in cfg.allowed_roots):
            raise FileRejected()
        for item in (candidate, *candidate.parents):
            info = item.lstat()
            if stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & 0x400:
                raise FileRejected()
        if resolved.suffix.lower() not in {".txt", ".md", ".csv", ".json", ".log", ".yaml", ".yml"}:
            raise FileRejected()
        before = resolved.stat()
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
            raise FileRejected()
        with resolved.open("rb") as file:
            opened = os.fstat(file.fileno())
            if (before.st_dev, before.st_ino) != (opened.st_dev, opened.st_ino) or opened.st_nlink != 1:
                raise FileRejected()
            if os.name == "nt":
                import msvcrt
                import win32file
                actual = win32file.GetFinalPathNameByHandle(msvcrt.get_osfhandle(file.fileno()), 0)
                if actual.startswith("\\\\?\\"):
                    actual = actual[4:]
                if Path(actual) != resolved:
                    raise FileRejected()
            raw = file.read(cfg.max_file_bytes + 1)
            after = os.fstat(file.fileno())
            if (opened.st_size, opened.st_mtime_ns) != (after.st_size, after.st_mtime_ns):
                raise FileRejected()
        if len(raw) > cfg.max_file_bytes:
            raise FileRejected()
        text = raw.decode("utf-8-sig")
        if "\x00" in text or len(text) > cfg.max_text_chars:
            raise FileRejected()
        text = normalize(text)
        if len(text) > cfg.max_text_chars:
            raise FileRejected()
        return raw
    except (OSError, ValueError, RuntimeError):
        raise FileRejected() from None


def read_file(path: str, cfg: Config) -> str:
    return normalize(read_file_bytes(path, cfg).decode("utf-8-sig"))


class Audit:
    def __init__(self, path: Path):
        self.path = path
        path.parent.mkdir(parents=True, exist_ok=True)
        with sqlite3.connect(path) as db:
            db.execute("""CREATE TABLE IF NOT EXISTS events (
                id TEXT, timestamp TEXT, direction TEXT, source_hash TEXT,
                status TEXT, categories TEXT, content TEXT)""")

    def write(self, event: dict):
        with sqlite3.connect(self.path, timeout=5) as db:
            db.execute("INSERT INTO events VALUES (:id,:timestamp,:direction,:source_hash,:status,:categories,:content)", event)


class Gateway:
    def __init__(self, config: Config, model=None):
        self.config = config
        self.model = model if model is not None else LocalModel(config)
        self.audit = Audit(config.audit_db)
        self.sessions = {}
        self.edit_lock = threading.RLock()

    def process(self, path: str, direction: str) -> dict:
        request_id = uuid.uuid4().hex
        result = {"request_id": request_id, "status": "blocked", "categories": [], "content": None}
        try:
            if direction not in {"input", "output"}:
                raise FileRejected()
            raw = read_file_bytes(path, self.config)
            original = raw.decode("utf-8-sig")
            text = normalize(original)
            if "[REDACTED_" in text:
                raise FileRejected()
            mapping = {}
            findings = scan(text)
            cats = {f.category for f in findings}
            if cats - SECRET_CATEGORIES or (findings and self.config.mode == "block"):
                result.update(categories=sorted(cats), warning="Файл заблокирован правилами безопасности.")
            else:
                cleaned, shadow = masked(text, original, findings, mapping)
                verdict = self.model.check(cleaned, direction)
                cats.update(f.category for f in verdict.findings)
                if cats - SECRET_CATEGORIES or (verdict.findings and self.config.mode == "block"):
                    result.update(categories=sorted(cats), warning="Файл заблокирован локальной моделью.")
                else:
                    spans = []
                    for f in verdict.findings:
                        start = 0
                        while (pos := cleaned.find(f.text, start)) >= 0:
                            spans.append(Finding(pos, pos + len(f.text), f.category))
                            start = pos + len(f.text)
                    cleaned, shadow = masked(cleaned, shadow, spans, mapping)
                    # Defensive scan of exactly what will be released.
                    if scan(cleaned):
                        raise GuardUnavailable()
                    result.update(status="redacted" if cats else "allowed", categories=sorted(cats), content=cleaned)
                    if direction == "input":
                        with self.edit_lock:
                            self.sessions = {k: v for k, v in self.sessions.items() if v.expires > time.monotonic()}
                            if len(self.sessions) >= 128:
                                raise GuardUnavailable()
                            edit_id = token()
                            self.sessions[edit_id] = new_session(str(Path(path).resolve()), raw, mapping)
                            result["edit_id"] = edit_id
        except FileRejected:
            result.update(status="error", warning="Файл недоступен: проверьте разрешённую папку, тип, UTF-8 и размер.")
        except GuardUnavailable:
            result.update(status="error", content=None, warning="Проверка LM Studio не завершена. Содержимое не возвращено.")
        except Exception:
            result.update(status="error", content=None, warning="Внутренняя ошибка проверки. Содержимое не возвращено.")
        try:
            self.audit.write({
                "id": request_id, "timestamp": datetime.now(timezone.utc).isoformat(), "direction": direction,
                "source_hash": hashlib.sha256(path.encode("utf-8", errors="replace")).hexdigest(),
                "status": result["status"], "categories": json.dumps(result["categories"]),
                "content": result["content"],
            })
        except (sqlite3.Error, OSError):
            return {"request_id": request_id, "status": "error", "content": None,
                    "categories": [], "warning": "Аудит недоступен. Содержимое не возвращено."}
        return result

    def write(self, edit_id: str, content: str) -> dict:
        request_id = uuid.uuid4().hex
        with self.edit_lock:
            session = self.sessions.get(edit_id)
            event = {"id": request_id, "timestamp": datetime.now(timezone.utc).isoformat(),
                     "direction": "write", "source_hash": "", "status": "write_rejected",
                     "categories": "[]", "content": None}
            temporary = None
            committed = False
            try:
                if session is None or session.expires <= time.monotonic():
                    self.sessions.pop(edit_id, None)
                    raise ValueError("expired")
                event["source_hash"] = hashlib.sha256(session.path.encode()).hexdigest()
                if len(content) > self.config.max_text_chars or "\x00" in content:
                    raise ValueError("size")
                restored = session.restore(content)
                # Inspect only masked text; originals never return to the model.
                inspected = normalize(MARKER.sub("[REDACTED_VALUE]", content))
                if scan(inspected) or not self.model.check(inspected, "output").safe:
                    raise ValueError("unsafe edit")
                encoded = restored.encode("utf-8-sig" if session.bom else "utf-8")
                if len(encoded) > self.config.max_file_bytes or len(restored) > self.config.max_text_chars:
                    raise ValueError("size")
                path = Path(session.path)
                current = read_file_bytes(session.path, self.config)
                if hashlib.sha256(current).hexdigest() != session.digest:
                    raise ValueError("conflict")
                # A durable intent entry is required before changing the file.
                event.update(status="write_prepared")
                self.audit.write(event)
                with tempfile.NamedTemporaryFile(dir=path.parent, prefix=".guard-", suffix=".tmp", delete=False) as file:
                    temporary = Path(file.name)
                    file.write(encoded)
                    file.flush()
                    os.fsync(file.fileno())
                os.chmod(temporary, path.stat().st_mode)
                if hashlib.sha256(read_file_bytes(session.path, self.config)).hexdigest() != session.digest:
                    raise ValueError("conflict")
                os.replace(temporary, path)
                committed = True
                self.sessions.pop(edit_id, None)
                event.update(status="written")
                self.audit.write(event)
                return {"request_id": request_id, "status": "written", "restored_count": len(session.mapping)}
            except Exception:
                if committed:
                    return {"request_id": request_id, "status": "written", "warning": "Файл записан; итоговая запись аудита недоступна."}
                event.update(status="write_rejected")
                try:
                    self.audit.write(event)
                except (OSError, sqlite3.Error):
                    pass
                return {"request_id": request_id, "status": "error", "warning":
                        "Запись отклонена: проверьте срок сессии (30 минут), неизменность файла и маркеров, размер и LM Studio. Прочитайте файл заново при конфликте."}
            finally:
                if temporary is not None and temporary.exists():
                    try:
                        temporary.unlink(missing_ok=True)
                    except OSError:
                        pass
