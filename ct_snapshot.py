"""Snapshot which hostnames Certificate Transparency logs show for each domain on
the watchlist, and flag when a new one appears.

Every publicly-trusted TLS certificate is logged to CT logs the moment it's issued.
crt.sh indexes those logs and answers "%.domain" wildcard queries for free. A new
hostname here means a certificate was issued for it, which almost always means a
site is either live or about to be.

The watchlist is dotgov_snapshot.py's latest output (see config/watchlist.json
for the underlying org list) plus a few extra roots, also in that config file,
for agency-run domains that aren't in the .gov registry at all.

This only sees hostnames that got a publicly-trusted cert. An internal-only service
on a private CA, or one that reuses an existing wildcard cert, won't show up here.

state.json holds the current known hostname set per domain (the source of truth,
carried forward across runs -- including past any domain whose crt.sh query failed
this run, so a transient error never gets misread as "everything's new" next time).
Dated snapshots in snapshots/ct/ are written only when something actually changed.

Usage:
    python ct_snapshot.py
"""
from __future__ import annotations

import csv
import gzip
import hashlib
import io
import json
import os
import time
from datetime import date
from pathlib import Path

import crtsh
from watchlist import WATCHLIST

PACE_SECONDS = 4  # be polite to a free public service across ~100+ sequential queries
EXTRA_ROOTS = WATCHLIST["extra_roots"]

# A large department mints routine infrastructure hostnames constantly (dhs.gov's
# baseline alone is ~1,200) -- most new hostnames are not going to be interesting.
# This flags (never drops) ones whose name itself reads as a pre-launch
# environment, so a daily list of dozens has somewhere to look first. It's a
# cheap substring heuristic, not a verdict -- it will flag legitimate internal
# test boxes and miss anything named blandly.
PRELAUNCH_HINTS = (
    "sandbox", "staging", "-stg", "beta", "preview", "demo", "prelaunch",
    "uat", "--", "relaunch", "redesign", "pilot", "newsite",
)


def looks_prelaunch(hostname: str) -> bool:
    return any(hint in hostname for hint in PRELAUNCH_HINTS)


ROOT = Path(__file__).parent
DOTGOV_MANIFEST = ROOT / "snapshots" / "dotgov" / "manifest.json"
DOTGOV_SNAPS = ROOT / "snapshots" / "dotgov"
SNAPS = ROOT / "snapshots" / "ct"
STATE = ROOT / "state.json"


def watchlist() -> list[str]:
    if not DOTGOV_MANIFEST.exists():
        return sorted(EXTRA_ROOTS)
    entries = json.loads(DOTGOV_MANIFEST.read_text())
    if not entries:
        return sorted(EXTRA_ROOTS)
    latest = DOTGOV_SNAPS / entries[-1]["file"]
    text = gzip.decompress(latest.read_bytes()).decode()
    domains = {r["Domain name"] for r in csv.DictReader(io.StringIO(text))}
    return sorted(domains | set(EXTRA_ROOTS))


def load_state() -> dict:
    return json.loads(STATE.read_text()) if STATE.exists() else {}


def main() -> int:
    SNAPS.mkdir(parents=True, exist_ok=True)
    state = load_state()
    is_first_run = not state
    old_hostnames = {domain: set(entry["hostnames"]) for domain, entry in state.items()}
    changed_domains = []

    for domain in watchlist():
        names = crtsh.hostnames_under(domain)
        time.sleep(PACE_SECONDS)
        if names is None:
            continue  # keep whatever state already has for this domain

        digest = hashlib.sha256(",".join(sorted(names)).encode()).hexdigest()
        prev = state.get(domain)
        if prev is None or prev["sha256"] != digest:
            changed_domains.append(domain)
        state[domain] = {
            "hostnames": sorted(names),
            "sha256": digest,
            "count": len(names),
            "last_checked": date.today().isoformat(),
        }

    STATE.write_text(json.dumps(state, indent=2) + "\n")

    if not changed_domains:
        print("unchanged")
        return 0

    stamp = date.today().isoformat()
    path = SNAPS / f"ct-{stamp}.json.gz"
    full = {domain: entry["hostnames"] for domain, entry in state.items()}
    path.write_bytes(gzip.compress(json.dumps(full, indent=2).encode(), 9))

    print(f"CHANGED — {len(changed_domains)} domain(s) show new hostnames: {', '.join(changed_domains)}")

    if not is_first_run:
        flagged, routine = [], []
        for domain in sorted(changed_domains):
            appeared = sorted(set(state[domain]["hostnames"]) - old_hostnames.get(domain, set()))
            for h in appeared:
                (flagged if looks_prelaunch(h) else routine).append(h)

        # Cert history per new hostname: was this quietly live already, or is it
        # genuinely brand new? Only fires for actual new hostnames (usually a
        # handful per run), so it doesn't add meaningfully to the crt.sh load.
        lines = []
        for h in flagged:
            hint = next(p for p in PRELAUNCH_HINTS if p in h)
            lines.append(f"- 🔺 **{h}** — looks pre-launch (matched: {hint}); {crtsh.history_note(h)}")
        for h in routine:
            lines.append(f"- {h} — {crtsh.history_note(h)}")
        (SNAPS / "latest-diff.md").write_text("\n".join(lines) + "\n" if lines else "")

    if out := os.environ.get("GITHUB_OUTPUT"):
        with open(out, "a") as fh:
            fh.write(f"ct_changed={'false' if is_first_run else 'true'}\n")
            fh.write(f"ct_file={path.name}\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
