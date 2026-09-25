"""Shared crt.sh access: wildcard hostname search (ct_snapshot.py's main job) and
exact-name certificate history (used to enrich alerts with "how long has this
actually existed").
"""
from __future__ import annotations

import json
import sys
import time
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

UA = {"User-Agent": "govsite-watch (https://github.com/abigailhaddad/govsite-watch)"}
WILDCARD_URL = "https://crt.sh/?q=%25.{}&output=json"
EXACT_URL = "https://crt.sh/?q={}&output=json"


def fetch_json(url: str, label: str, timeout: int = 45, retries: int = 2) -> list | None:
    """crt.sh is a free shared service, not built for hundreds of sequential
    scripted queries -- the first full watchlist run hit constant 429s. This
    backs off harder and longer on an explicit rate-limit response (honoring
    Retry-After when crt.sh sends one) than on an ordinary network blip.

    Kept short on purpose: state.json already carries a failed domain's last
    known result forward to the next run (see ct_snapshot.py), so there's
    nothing to gain from retrying hard here -- and a lot to lose, since a
    watchlist-wide outage (every domain 502ing, not just one) turns a long
    per-domain retry budget into a run that takes hours to fail instead of
    minutes, confirmed live on 2026-09-25.
    """
    req = Request(url, headers=UA)
    for attempt in range(retries):
        try:
            with urlopen(req, timeout=timeout) as r:
                return json.loads(r.read())
        except HTTPError as exc:
            if exc.code == 429:
                wait = int(exc.headers.get("Retry-After", 0)) or 15 * (attempt + 1)
                print(f"    {label}: 429 rate-limited, waiting {wait}s", file=sys.stderr)
            else:
                wait = 5 * (attempt + 1)
                print(f"    {label}: HTTP {exc.code}, retrying in {wait}s", file=sys.stderr)
            time.sleep(wait)
        except (URLError, TimeoutError, json.JSONDecodeError) as exc:
            wait = 5 * (attempt + 1)
            print(f"    {label}: {type(exc).__name__}, retrying in {wait}s", file=sys.stderr)
            time.sleep(wait)
    print(f"    {label}: giving up after {retries} attempts", file=sys.stderr)
    return None


def hostnames_under(domain: str) -> set[str] | None:
    """All hostnames crt.sh has ever logged under `domain` (subdomains + apex)."""
    data = fetch_json(WILDCARD_URL.format(domain), domain)
    if data is None:
        return None
    names = set()
    for entry in data:
        for n in entry["name_value"].lower().split("\n"):
            n = n.strip().lstrip("*.")
            # crt.sh's wildcard search also matches RFC822 SANs on S/MIME certs
            # (e.g. someone@dhs.gov) -- those aren't hostnames, skip them.
            if "@" not in n and n.endswith(domain):
                names.add(n)
    return names


def history(hostname: str) -> dict | None:
    """Exact-name cert history for one hostname: count, first/last not_before dates.

    None means the lookup failed; a dict with count=0 means crt.sh genuinely has
    never logged a cert for this exact name (it may still be brand new, or it may
    be served off a wildcard cert that was never logged under this specific name).
    """
    data = fetch_json(EXACT_URL.format(hostname), f"{hostname} (history)")
    if data is None:
        return None
    if not data:
        return {"count": 0, "first": None, "last": None}
    dates = sorted(entry["not_before"] for entry in data)
    return {"count": len(data), "first": dates[0][:10], "last": dates[-1][:10]}


def history_note(hostname: str) -> str:
    h = history(hostname)
    if h is None:
        return "(CT history lookup failed)"
    if h["count"] == 0:
        return "no prior CT history — genuinely new"
    return f"CT history: {h['count']} cert(s), first {h['first']}, last {h['last']}"
