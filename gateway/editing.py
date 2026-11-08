"""Process-local edit sessions: secrets never enter MCP responses or audit storage."""
from collections import Counter
from dataclasses import dataclass
from difflib import SequenceMatcher
import re
import secrets
import time

from .guards import Finding

MARKER = re.compile(r"\[REDACTED_[A-Z_]+:[a-p]{32}\]")


def token():
    return secrets.token_hex(16).translate(str.maketrans("0123456789abcdef", "abcdefghijklmnop"))


def masked(text: str, shadow: str, findings: list[Finding], mapping: dict):
    """Mask normalized text while retaining the original spelling of each hidden span."""
    merged = []
    for f in sorted(findings, key=lambda f: (f.start, -f.end)):
        if merged and f.start < merged[-1][1]:
            merged[-1][1] = max(merged[-1][1], f.end)
        else:
            merged.append([f.start, f.end, f.category])
    opcodes = SequenceMatcher(None, text, shadow, autojunk=False).get_opcodes()
    for start, end, category in reversed(merged):
        spans = []
        for kind, a, b, c, d in opcodes:
            if a < end and b > start:
                spans.append((c + max(start - a, 0), c + min(end - a, b - a)) if kind == "equal" else (c, d))
            elif a == b and start <= a < end:
                spans.append((c, d))
        if not spans:
            raise ValueError("Cannot map original span")
        left, right = min(s[0] for s in spans), max(s[1] for s in spans)
        marker = f"[REDACTED_{category}:{token()}]"
        if MARKER.search(text[start:end]):
            raise ValueError("Classifier tried to redact an existing marker")
        mapping[marker] = shadow[left:right]
        text = text[:start] + marker + text[end:]
        shadow = shadow[:left] + marker + shadow[right:]
    return text, shadow


@dataclass
class EditSession:
    path: str
    digest: str
    mapping: dict[str, str]
    expires: float
    bom: bool

    def restore(self, content: str) -> str:
        if Counter(MARKER.findall(content)) != Counter(self.mapping.keys()):
            raise ValueError("Missing, duplicate or foreign marker")
        remainder = MARKER.sub("", content)
        if "[REDACTED_" in remainder:
            raise ValueError("Malformed or legacy marker")
        return MARKER.sub(lambda m: self.mapping[m.group()], content)


def new_session(path, raw, mapping):
    import hashlib
    return EditSession(path, hashlib.sha256(raw).hexdigest(), mapping,
                       time.monotonic() + 1800, raw.startswith(b"\xef\xbb\xbf"))
