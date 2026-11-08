"""Check the local model without exposing a file to it."""
import argparse
import json
import os
from pathlib import Path

import httpx

from .config import Config
from .lm import GuardUnavailable, LocalModel


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", type=Path, default=Path(__file__).resolve().parents[1] / "config.json")
    args = parser.parse_args()
    try:
        raw = json.loads(args.config.read_text(encoding="utf-8-sig"))
        base = args.config.resolve().parent
        probe = dict(raw, lm_model="connectivity-probe")
        probe["allowed_roots"] = tuple((base / p).resolve() for p in probe["allowed_roots"])
        probe["audit_db"] = (base / probe["audit_db"]).resolve()
        cfg = Config(**probe)
        headers = {"Authorization": "Bearer " + os.environ["LM_STUDIO_API_KEY"]} if os.getenv("LM_STUDIO_API_KEY") else {}
        with httpx.Client(trust_env=False, timeout=5, follow_redirects=False) as client:
            r = client.get(cfg.lm_base_url.rstrip("/") + "/models", headers=headers)
            r.raise_for_status()
            ids = [item["id"] for item in r.json()["data"]]
        print("LM Studio models: " + json.dumps(ids, ensure_ascii=False))
        cfg = Config.load(args.config)
        if cfg.lm_model not in ids:
            parser.exit(2, "Configured model is not listed in LM Studio.\n")
        if not LocalModel(cfg).check("Hello world.", "input").safe:
            parser.exit(2, "Model rejected the benign self-test.\n")
        print("OK: LM Studio connectivity and structured classification verified.")
    except (OSError, ValueError, TypeError, KeyError, httpx.HTTPError, GuardUnavailable):
        parser.exit(2, "Check config.json, LM Studio server, loaded model and structured JSON support. No file released.\n")


if __name__ == "__main__":
    main()
