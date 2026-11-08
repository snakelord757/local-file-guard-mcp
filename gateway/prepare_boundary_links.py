"""Windows elevated setup only: create four links in existing synthetic test folders."""
import argparse
import json
import re
import subprocess
from pathlib import Path


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--inside", type=Path, required=True)
    parser.add_argument("--outside", type=Path, required=True)
    parser.add_argument("--test-user-sid", required=True)
    args = parser.parse_args()
    if not re.fullmatch(r"S-1-5-21-\d+-\d+-\d+-\d+", args.test_user_sid):
        raise SystemExit("Invalid test user SID")
    project = Path(__file__).resolve().parents[1]
    inside, outside = args.inside.resolve(strict=True), args.outside.resolve(strict=True)
    if inside.parent != project / "inbox" or outside.parent != project / "data":
        raise SystemExit("Unexpected fixture directories")
    if not all(p.name.startswith("path-boundary-") for p in (inside, outside)):
        raise SystemExit("Only generated fixtures are allowed")
    specifications = [("outside-file.txt", outside / "target.txt", False),
                      ("outside-dir", outside, True),
                      ("inside-file.txt", inside / "local.txt", False),
                      ("staged-swap.txt", outside / "target.txt", False)]
    try:
        for name, target, directory in specifications:
            link = inside / name
            if not (link.is_symlink() and link.resolve() == target):
                link.symlink_to(target, target_is_directory=directory)
            # Elevated creator and ordinary test process may be different Windows accounts.
            # /L modifies ONLY the link's ACL, not the file/directory it points to.
            subprocess.run(["icacls", str(link), "/L", "/grant", f"*{args.test_user_sid}:(F)"], check=True, capture_output=True)
        result = {"status": "ready"}
    except OSError as exc:
        result = {"status": "error", "winerror": exc.winerror}
    (outside / "link-setup.json").write_text(json.dumps(result), encoding="utf-8")
    subprocess.run(["icacls", str(outside / "link-setup.json"), "/grant", f"*{args.test_user_sid}:(R)"], check=True, capture_output=True)


if __name__ == "__main__":
    main()
