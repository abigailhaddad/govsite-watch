# govsite-watch

Daily check for new federal websites under the orgs listed in `config/watchlist.json` — see that file for the current list; nothing about who/what it covers is duplicated here. It uses two public sources:

- **`dotgov_snapshot.py`** reads CISA's registry of `.gov` domains ([cisagov/dotgov-data](https://github.com/cisagov/dotgov-data)) and records new or dropped domains for those organizations.
- **`ct_snapshot.py`** asks [crt.sh](https://crt.sh), which indexes Certificate Transparency logs, for every hostname with a TLS certificate under the watched domains, and records new ones. `usps.com` is added by hand because it isn't in the `.gov` registry.

`.github/workflows/check.yml` runs both daily, commits any changed snapshots and opens an issue listing what's new. The first run only records a baseline.

A new hostname means a certificate was issued for it. It doesn't tell you what's on the site. Sites that reuse a wildcard certificate or use a private CA won't show up.

```
python dotgov_snapshot.py
python ct_snapshot.py   # slow: one crt.sh query per domain, paced to be polite
```
