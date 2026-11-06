#!/usr/bin/env python3
"""Daily watch: finds newly exploited or newly published CVEs that Am I affected? doesn't check yet,
and opens one GitHub issue per CVE labelled `queue`, so adding them is a list to work through.

Sources: CISA KEV (exploited in the wild), filtered to software people run on laptops and servers,
and the cve.now feed for each tech the tool already tracks. Stateless: an open or closed issue with
the CVE id in its title means it's already queued, so reruns never duplicate.

Usage: python3 .github/watch.py [--dry-run] [--days 14]   (needs `gh` logged in unless --dry-run)
"""
import argparse
import json
import os
import subprocess
import sys
import urllib.request
from datetime import date, timedelta

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from secinspect import ADVISORIES, FEED_URL, new_cves  # noqa: E402

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
# ponytail: keyword match on vendor/product; widen this list when a miss shows up
WATCH = ("chrom", "linux", "kernel", "nginx", "apache", "php", "node", "python", "openssl", "openssh", "sudo",
         "glibc", "git", "docker", "kubernetes", "redis", "postgres", "mysql", "mariadb", "mongodb", "wordpress",
         "nextcloud", "jenkins", "grafana", "elastic", "rails", "django", "spring", "log4j", "curl", "bind",
         "exim", "postfix", "dovecot", "roundcube", "plex", "zammad", "litellm", "npm", "pypi", "mcp", "ollama")


def known_cves():
    advs = ADVISORIES["versions"] + ADVISORIES["distro"] + ADVISORIES["packages"] + \
        [ADVISORIES["chromium_cache"], ADVISORIES["mcp"]]
    blob = json.dumps(advs)
    return {c for a in advs for c in a.get("cves", [])} | {w for w in blob.replace('"', " ").split() if w.startswith("CVE-")}


def get(url):
    with urllib.request.urlopen(url, timeout=30) as r:
        return json.load(r)


def kev_candidates(kev, since, known):
    out = []
    for v in kev["vulnerabilities"]:
        what = f'{v["vendorProject"]} {v["product"]}'.lower()
        if v["dateAdded"] >= since and v["cveID"] not in known and any(w in what for w in WATCH):
            out.append({"cve": v["cveID"], "title": f'{v["vendorProject"]} {v["product"]}: {v["vulnerabilityName"]}',
                        "why": f'Added to CISA KEV on {v["dateAdded"]} (exploited in the wild).',
                        "detail": v["shortDescription"], "fix": v.get("requiredAction", ""),
                        "source": f'https://nvd.nist.gov/vuln/detail/{v["cveID"]}'})
    return out


def feed_candidates(known):
    out = []
    for adv in ADVISORIES["versions"]:
        if not adv.get("feed") or not adv.get("checked"):
            continue
        try:
            items = get(FEED_URL.format(adv["feed"])).get("items", [])
        except Exception as e:  # one feed down shouldn't stop the rest
            print(f"skip {adv['name']} feed: {e}", file=sys.stderr)
            continue
        fresh = new_cves(items, adv["checked"], known)
        if fresh:  # one issue per tech: Chrome alone lists a dozen CVEs per release
            # ponytail: the lead CVE shifts as the feed reorders, so dedupe on tech + checked date instead
            out.append({"cve": fresh[0], "key": f'"{adv["name"]}" "since {adv["checked"][:10]}"', "title": f'{adv["name"]}: {len(fresh)} new CVE(s) since {adv["checked"][:10]}',
                        "why": f'Listed on cve.now for {adv["name"]} after {adv["checked"][:10]}.',
                        "detail": "\n".join(f"- https://nvd.nist.gov/vuln/detail/{c}" for c in fresh), "fix": "",
                        "source": f'https://cve.now/feed?tech={adv["feed"]}'})
    return out


def body(c):
    return "\n\n".join(x for x in (
        c["why"], c["detail"], f'Vendor fix / required action: {c["fix"]}' if c["fix"] else "",
        f'Source: {c["source"]}',
        "To add it: find the fixed versions (vendor advisory, plus Ubuntu/Debian/RHEL trackers for server "
        "software), add an entry to advisories.json, a test in test_secinspect.py, and a row on the page and "
        "README. Close as `wontfix` if it doesn't fit the tool. Either way, move the tech's `checked` date in "
        "advisories.json to today, or later CVEs for it won't be queued.") if x)


def queued(key):
    out = subprocess.run(["gh", "issue", "list", "--state", "all", "--search", f"{key} in:title", "--json", "number"],
                         capture_output=True, text=True, check=True).stdout
    return bool(json.loads(out))


def main(argv):
    ap = argparse.ArgumentParser()
    ap.add_argument("--dry-run", action="store_true", help="print candidates, don't open issues")
    ap.add_argument("--days", type=int, default=14, help="how far back to look in CISA KEV")
    args = ap.parse_args(argv)
    known = known_cves()
    since = (date.today() - timedelta(days=args.days)).isoformat()
    cands = kev_candidates(get(KEV_URL), since, known) + feed_candidates(known)
    seen = set()
    for c in cands:
        if c["cve"] in seen:
            continue
        seen.add(c["cve"])
        if args.dry_run:
            print(f'{c["cve"]}  {c["title"]}')
        elif not queued(c.get("key", c["cve"])):
            subprocess.run(["gh", "issue", "create", "--label", "queue", "--title", f'{c["cve"]}: {c["title"]}',
                            "--body", body(c)], check=True)
    print(f"{len(seen)} candidate(s)", file=sys.stderr)


if __name__ == "__main__":
    main(sys.argv[1:])
