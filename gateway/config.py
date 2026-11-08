import json
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlsplit


@dataclass(frozen=True)
class Config:
    allowed_roots: tuple[Path, ...]
    audit_db: Path
    lm_model: str
    mode: str = "redact"
    lm_base_url: str = "http://127.0.0.1:1234/v1"
    timeout_seconds: int = 60
    max_file_bytes: int = 65536
    max_text_chars: int = 12000

    def __post_init__(self):
        url = urlsplit(self.lm_base_url)
        if url.scheme not in {"http", "https"} or url.hostname not in {"127.0.0.1", "::1"} or url.username or url.password or url.query or url.fragment:
            raise ValueError("LM Studio must use a literal loopback address, without credentials or query")
        if self.mode not in {"block", "redact"} or not self.allowed_roots:
            raise ValueError("Set allowed_roots and mode=block|redact")
        if not self.lm_model or self.lm_model.startswith("SET_MODEL"):
            raise ValueError("Set lm_model to the model identifier shown in LM Studio")
        if not 1 <= self.max_text_chars <= 32000 or not 1 <= self.max_file_bytes <= 1048576 or not 1 <= self.timeout_seconds <= 90:
            raise ValueError("Invalid size or timeout limit")
        for root in self.allowed_roots:
            if not root.is_absolute() or not root.is_dir():
                raise ValueError("Allowed roots must be existing absolute directories")
            if self.audit_db.resolve().is_relative_to(root.resolve()):
                raise ValueError("Keep audit_db outside allowed_roots")

    @classmethod
    def load(cls, path: Path):
        path = path.resolve()
        raw = json.loads(path.read_text(encoding="utf-8-sig"))
        raw["allowed_roots"] = tuple((path.parent / p).resolve() for p in raw["allowed_roots"])
        raw["audit_db"] = (path.parent / raw.get("audit_db", "data/audit.sqlite3")).resolve()
        return cls(**raw)
