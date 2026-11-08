"""Local-only audit viewer, not exported through MCP."""
import argparse
import json
import sqlite3
from pathlib import Path


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--db", type=Path, default=Path(__file__).resolve().parents[1] / "data/audit.sqlite3")
    parser.add_argument("--limit", type=int, default=20)
    parser.add_argument("--content", action="store_true", help="Include sanitized released text")
    args = parser.parse_args()
    if not args.db.is_file():
        parser.exit(2, "Audit file does not exist yet.\n")
    with sqlite3.connect(args.db.resolve().as_uri() + "?mode=ro", uri=True) as db:
        db.row_factory = sqlite3.Row
        for row in db.execute("SELECT * FROM events ORDER BY rowid DESC LIMIT ?", (max(1, min(args.limit, 1000)),)):
            event = dict(row)
            if not args.content:
                event.pop("content")
            print(json.dumps(event, ensure_ascii=False))


if __name__ == "__main__":
    main()
