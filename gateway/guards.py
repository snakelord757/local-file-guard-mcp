import ipaddress
import base64
import binascii
import re
import unicodedata
from dataclasses import dataclass
from urllib.parse import urlsplit


@dataclass(frozen=True)
class Finding:
    start: int
    end: int
    category: str


SECRET_CATEGORIES = {"API_KEY", "EMAIL", "CARD", "PHONE"}
RISK_CATEGORIES = {"SYSTEM_PROMPT", "SUSPICIOUS_URL", "DANGEROUS_COMMAND", "PROMPT_INJECTION"}
PATTERNS = [
    ("API_KEY", re.compile(r"(?<![\w-])(?:sk-[A-Za-z0-9_-]{6,}|ghp_[A-Za-z0-9]{6,}|AKIA[A-Z0-9]{16})(?![\w-])")),
    ("EMAIL", re.compile(r"(?<![\w.+-])[\w.!#$%&'*+/=?^`{|}~-]+@[\w-]+(?:\.[\w-]+)+", re.UNICODE)),
]
NUMBER = re.compile(r"(?<!\w)\+?\d(?:[ ()-]*\d){9,18}(?!\w)")
COMMAND = re.compile(
    r"\b(?:curl|wget|iwr|invoke-webrequest)\b[^\r\n]*\|\s*(?:sh|bash|iex|powershell)\b"
    r"|\brm\s+-[a-z]*r[a-z]*f\b|\brm\s+-[a-z]*f[a-z]*r\b"
    r"|\b(?:powershell|pwsh)(?:\.exe)?\b[^\r\n]*-(?:enc|encodedcommand)\b"
    r"|\bRemove-Item\b[^\r\n]*-Recurse\b|\bformat\s+[a-z]:"
    r"|\bdel\s+/[sq]\b|\b(?:eval|exec)\s*\(\s*(?:base64|decode)", re.I
)
SYSTEM = re.compile(
    r"(?:reveal|print|show|repeat|expose)\b.{0,60}\b(?:system prompt|hidden instructions)"
    r"|(?:раскрой|покажи|выведи|повтори).{0,60}(?:системн\w*\s+промпт|скрыт\w*\s+инструкц)"
    r"|(?:my|the) system prompt is|мой системный промпт|<\|im_start\|>system", re.I
)
URL = re.compile(r"(?:https?|ftp|file|javascript|data)\s*:[^\s<>\"']+", re.I)
BASE64 = re.compile(r"(?<![A-Za-z0-9_+/=-])[A-Za-z0-9_+/-]{12,}={0,2}(?![A-Za-z0-9_+/=-])")
LITERAL = r'''(?:"[^"\\\r\n]*"|'[^'\\\r\n]*')'''
CONCAT = re.compile(LITERAL + r"(?:\s*\+\s*" + LITERAL + r")+")
QUOTED = re.compile(LITERAL)


def normalize(text: str) -> str:
    # Normalize before scanning AND returning, so offsets always refer to returned text.
    text = unicodedata.normalize("NFKC", text)
    return "".join(c for c in text if unicodedata.category(c) != "Cf")


def luhn(digits: str) -> bool:
    nums = [int(c) for c in digits]
    return len(set(nums)) > 1 and sum(
        (n * 2 - 9 if n * 2 > 9 else n * 2) if i % 2 else n
        for i, n in enumerate(reversed(nums))
    ) % 10 == 0


def _scan_plain(text: str) -> list[Finding]:
    found = [Finding(m.start(), m.end(), cat) for cat, pattern in PATTERNS for m in pattern.finditer(text)]
    for m in NUMBER.finditer(text):
        digits = re.sub(r"\D", "", m.group())
        if 13 <= len(digits) <= 19 and luhn(digits):
            found.append(Finding(m.start(), m.end(), "CARD"))
        elif 10 <= len(digits) <= 15 and (m.group().startswith("+") or len(digits) in (10, 11)):
            found.append(Finding(m.start(), m.end(), "PHONE"))
    for category, pattern in [("DANGEROUS_COMMAND", COMMAND), ("SYSTEM_PROMPT", SYSTEM)]:
        found.extend(Finding(m.start(), m.end(), category) for m in pattern.finditer(text))
    for m in URL.finditer(text):
        try:
            u = urlsplit(m.group().rstrip(".,;)]}"))
            host = u.hostname or ""
            bad = u.scheme.lower() != "https" or not host or bool(u.username or u.password)
            bad |= host.lower() in {"localhost", "bit.ly", "tinyurl.com", "t.co"}
            bad |= any(part.startswith("xn--") for part in host.lower().split("."))
            bad |= host.endswith((".local", ".internal"))
            try:
                ipaddress.ip_address(host)
                bad = True
            except ValueError:
                pass
            if bad:
                found.append(Finding(m.start(), m.end(), "SUSPICIOUS_URL"))
        except ValueError:
            found.append(Finding(m.start(), m.end(), "SUSPICIOUS_URL"))
    return found


def scan(text: str) -> list[Finding]:
    return _scan_encoded(text, depth=0)


def _scan_encoded(text: str, depth: int) -> list[Finding]:
    found = _scan_plain(text)
    if depth >= 2:
        return found
    candidates = []
    for match in CONCAT.finditer(text):
        # Literal concatenation only: never eval or execute user-supplied code.
        joined = "".join(part.group()[1:-1] for part in QUOTED.finditer(match.group()))
        candidates.append((match, joined))
    for match in BASE64.finditer(text):
        if len(match.group()) > 4096:
            continue
        try:
            value = match.group()
            decoded = base64.b64decode(value + "=" * (-len(value) % 4), altchars=b"-_", validate=True).decode("utf-8")
        except (binascii.Error, UnicodeDecodeError, ValueError):
            continue
        candidates.append((match, decoded))
    for match, decoded in candidates:
        categories = {f.category for f in _scan_encoded(normalize(decoded), depth + 1)}
        # Mask the full encoded expression, preserving source offsets and reversibility.
        found.extend(Finding(match.start(), match.end(), cat) for cat in sorted(categories))
    return found


def redact(text: str, findings: list[Finding]) -> str:
    # Merge overlaps rather than leaking the tail of overlapping secrets.
    merged: list[list] = []
    for f in sorted(findings, key=lambda f: (f.start, -f.end)):
        if merged and f.start < merged[-1][1]:
            merged[-1][1] = max(merged[-1][1], f.end)
        else:
            merged.append([f.start, f.end, f.category])
    for start, end, cat in reversed(merged):
        text = text[:start] + f"[REDACTED_{cat}]" + text[end:]
    return text
