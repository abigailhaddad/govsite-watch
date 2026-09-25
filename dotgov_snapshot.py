"""Snapshot which federal .gov domains belong to a small watchlist of agencies, and
flag when a new one appears.

CISA publishes the authoritative registry of every .gov domain
(github.com/cisagov/dotgov-data) as a plain CSV, refreshed as domains are added or
removed. A new row for a watched org is the earliest public signal that a new
federal site exists at all under that org.

This only sees .gov domains. Agency-run sites on other TLDs (like usps.com) aren't
in this registry at all -- see ct_snapshot.py for those.

Usage:
    python dotgov_snapshot.py
"""
from __future__ import annotations

import csv
import gzip
import hashlib
import io
import json
import os
from datetime import date
from pathlib import Path
from urllib.request import Request, urlopen

import crtsh
from watchlist import WATCHLIST

SOURCE_URL = "https://raw.githubusercontent.com/cisagov/dotgov-data/main/current-federal.csv"
UA = {"User-Agent": "govsite-watch (https://github.com/abigailhaddad/govsite-watch)"}

# See config/watchlist.json for the actual list and why each org is on it.
WATCHED_ORGS = set(WATCHLIST["watched_orgs"])

ROOT = Path(__file__).parent
SNAPS = ROOT / "snapshots" / "dotgov"
MANIFEST = SNAPS / "manifest.json"


def fetch(url: str, timeout: int = 60) -> bytes:
    with urlopen(Request(url, headers=UA), timeout=timeout) as r:
        return r.read()


def watched_rows(raw: bytes) -> list[dict]:
    rows = csv.DictReader(io.StringIO(raw.decode("utf-8-sig")))
    return sorted(
        (r for r in rows if r["Organization name"] in WATCHED_ORGS),
        key=lambda r: r["Domain name"],
    )


def load_manifest() -> list[dict]:
    return json.loads(MANIFEST.read_text()) if MANIFEST.exists() else []


def main() -> int:
    SNAPS.mkdir(parents=True, exist_ok=True)
    rows = watched_rows(fetch(SOURCE_URL))
    domains = sorted(r["Domain name"] for r in rows)
    digest = hashlib.sha256(",".join(domains).encode()).hexdigest()

    manifest = load_manifest()
    if any(entry["sha256"] == digest for entry in manifest):
        print(f"unchanged ({len(domains)} watched domains)")
        return 0

    previous = manifest[-1] if manifest else None
    old_domains = set()
    if previous:
        old_text = gzip.decompress((SNAPS / previous["file"]).read_bytes()).decode()
        old_domains = {r["Domain name"] for r in csv.DictReader(io.StringIO(old_text))}

    stamp = date.today().isoformat()
    path = SNAPS / f"dotgov-{stamp}.csv.gz"
    buf = io.StringIO()
    writer = csv.DictWriter(buf, fieldnames=rows[0].keys())
    writer.writeheader()
    writer.writerows(rows)
    path.write_bytes(gzip.compress(buf.getvalue().encode(), 9))

    is_first_run = not manifest
    entry = {"captured": stamp, "sha256": digest, "domains": len(domains), "file": path.name}
    manifest.append(entry)
    MANIFEST.write_text(json.dumps(manifest, indent=2) + "\n")

    print(f"CHANGED — {len(domains)} watched domains, snapshot saved")

    if previous and not is_first_run:
        by_domain = {r["Domain name"]: r for r in rows}
        appeared = sorted(set(domains) - old_domains)
        disappeared = sorted(old_domains - set(domains))
        lines = []
        for d in appeared:
            r = by_domain[d]
            lines.append(f"- **{d}** — {r['Organization name']} / {r['Suborganization name'] or '—'}"
                         f"; {crtsh.history_note(d)}")
        for d in disappeared:
            lines.append(f"- ~~{d}~~ (dropped from the registry)")
        (SNAPS / "latest-diff.md").write_text("\n".join(lines) + "\n" if lines else "")

    if out := os.environ.get("GITHUB_OUTPUT"):
        with open(out, "a") as fh:
            # A cold-start baseline isn't news -- only alert from the second run on.
            fh.write(f"dotgov_changed={'false' if is_first_run else 'true'}\n")
            fh.write(f"dotgov_file={entry['file']}\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
