#!/usr/bin/env python3
"""Watch, every 6 hours: finds newly exploited or newly published CVEs that Am I affected? doesn't check yet,
and opens one GitHub issue per CVE labelled `queue`, so adding them is a list to work through.

Sources: CISA KEV (exploited in the wild), filtered to software people run on laptops and servers,
the cve.now feed for each tech the tool already tracks, and zero-days: bugs the vendor itself says are
exploited, read from Chrome Releases, Apple's security releases and Mozilla's advisories on the day they
ship, often days before KEV lists them. Those issues also get the `zero-day` label. Stateless: an open or closed issue with
the CVE id in its title means it's already queued, so reruns never duplicate.

Usage: python3 .github/watch.py [--dry-run] [--days 14]   (needs `gh` logged in unless --dry-run)
"""
import argparse
import json
import os
import re
import subprocess
import sys
import urllib.request
from datetime import date, datetime, timedelta

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from secinspect import ADVISORIES, FEED_URL, new_cves, nums  # noqa: E402

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


def get_text(url):
    req = urllib.request.Request(url, headers={"User-Agent": "amiaffected-watch"})  # some sites block Python's default
    with urllib.request.urlopen(req, timeout=30) as r:
        return r.read().decode("utf-8", "replace")


def get(url):
    return json.loads(get_text(url))


CHROME_FEED = "https://chromereleases.googleblog.com/feeds/posts/default?alt=json&max-results=25"
APPLE_INDEX = "https://support.apple.com/en-us/100100"
MOZILLA_DIR = "https://api.github.com/repos/mozilla/foundation-security-advisories/contents/announce/{}"
CVE = re.compile(r"CVE-\d{4}-\d{4,}")


def text(h):
    return re.sub(r"\s+", " ", re.sub(r"<[^>]+>", " ", h)).replace("&nbsp;", " ")


def chrome_exploited(feed, since):
    """(cve, title, url) for each CVE a Desktop release post says has an exploit in the wild."""
    out = []
    for e in feed["feed"]["entry"]:
        if e["published"]["$t"][:10] < since or "Desktop" not in e["title"]["$t"]:
            continue
        url = next((link["href"] for link in e["link"] if link["rel"] == "alternate"), CHROME_FEED)
        body = text(e["content"]["$t"])
        for sentence in re.findall(r"[^.]*exploit[^.]*in the wild[^.]*", body):
            out += [(c, f"Chrome: {e['title']['$t']} ({e['published']['$t'][:10]})", url) for c in CVE.findall(sentence)]
    return out


def apple_index(page, since):
    """[(url, name)] for the security releases on Apple's index page dated `since` or later."""
    out = []
    for row in re.findall(r"<tr>(.*?)</tr>", page, re.S):
        link = re.search(r'href="(https://support\.apple\.com/[^"]+)"[^>]*>([^<]+)<', row)
        day = re.search(r"\b(\d{1,2} \w{3} \d{4})\b", text(row))
        if link and day and datetime.strptime(day[1], "%d %b %Y").date().isoformat() >= since:
            out.append((link[1], link[2].strip()))
    return out


def apple_exploited(note):
    """CVEs in an Apple security note whose entry says it may have been exploited."""
    # ponytail: one entry runs from one "Impact:" to the next; Apple has used this layout for years
    return [c for entry in text(note).split("Impact:") if re.search(r"exploited", entry) for c in CVE.findall(entry)]


def mozilla_exploited(yml):
    """CVEs in a Mozilla advisory (YAML from foundation-security-advisories) described as exploited in the wild."""
    return [m[1] for m in re.finditer(r"\n  (CVE-\d{4}-\d+):(.*?)(?=\n  CVE-|\Z)", yml, re.S)
            if re.search(r"exploited in the wild|exploitation in the wild|being exploited", m[2])]


def zero_day_candidates(since, known):
    found = []  # (cve, title, url)
    try:
        found += chrome_exploited(get(CHROME_FEED), since)
    except Exception as e:  # one source down shouldn't stop the rest
        print(f"skip Chrome Releases: {e}", file=sys.stderr)
    try:
        for url, name in apple_index(get_text(APPLE_INDEX), since):
            found += [(c, f"Apple: {name}", url) for c in apple_exploited(get_text(url))]
    except Exception as e:
        print(f"skip Apple: {e}", file=sys.stderr)
    try:
        files = get(MOZILLA_DIR.format(since[:4])) + (get(MOZILLA_DIR.format(date.today().year)) if since[:4] != str(date.today().year) else [])
        for f in sorted(files, key=lambda f: int(re.findall(r"-(\d+)", f["name"])[0]))[-8:]:  # ponytail: last 8 covers two weeks
            yml = get_text(f["download_url"])
            day = re.search(r"announced: (\w+ \d+, \d{4})", yml)
            if day and datetime.strptime(day[1], "%B %d, %Y").date().isoformat() >= since:
                title = re.search(r"\ntitle: (.*)", yml)
                found += [(c, f"Mozilla: {title[1] if title else f['name']}", f"https://www.mozilla.org/security/advisories/{f['name'][:-4]}/")
                          for c in mozilla_exploited(yml)]
    except Exception as e:
        print(f"skip Mozilla: {e}", file=sys.stderr)
    return [{"cve": c, "title": f"zero-day in {title}", "zero_day": True,
             "why": "The vendor says this bug is exploited in the wild (a zero-day). Treat it before anything else in the queue.",
             "detail": "", "fix": "", "source": url} for c, title, url in found if c not in known]


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


ELECTRON_RELEASES = "https://releases.electronjs.org/releases.json"


def electron_candidates(releases, supported):
    """A stable Electron major newer than the ones we list means the oldest listed one just lost support."""
    majors = {int(r["version"].split(".")[0]) for r in releases if "-" not in r["version"]}
    newest = max(majors, default=0)
    if newest <= max(supported):
        return []
    return [{"cve": f"Electron {newest}", "title": f"Electron {newest} is out: update the supported list ({', '.join(map(str, supported))})",
             "why": f"Electron supports its newest three majors, so {newest} ending up stable moves the oldest out of support.",
             "detail": f"Set electron.supported in advisories.json to {list(range(newest - 2, newest + 1))} and update its about text.",
             "fix": "", "source": "https://www.electronjs.org/docs/latest/tutorial/electron-timelines"}]


def awaiting_candidates(page, adv):
    """The vendor said a fix is coming (Edge): queue once their notes list a newer build than the last affected one."""
    w = adv["awaiting"]
    newer = sorted({v for v in re.findall(w["regex"], page) if nums(v) > nums(w["above"])}, key=nums)
    if not newer:
        return []
    return [{"cve": f'{adv["name"]} {newer[-1]}', "title": f'{adv["name"]} {newer[-1]} is out: is it the fix we were waiting for?',
             "why": f'The {adv["name"]} entry waits for a vendor fix; their notes now list {", ".join(newer)}.',
             "detail": "Check the notes, set the fixed version in advisories.json and drop `awaiting`.", "fix": "", "source": w["url"]}]


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
    zsince = (date.today() - timedelta(days=3)).isoformat()  # vendor notes are same-day; KEV can lag weeks
    try:
        kev = kev_candidates(get(KEV_URL), since, known)
    except Exception as e:  # don't let CISA being down stop the zero-day and feed checks (or the signature step after)
        print(f"skip CISA KEV: {e}", file=sys.stderr)
        kev = []
    cands = zero_day_candidates(zsince, known) + kev + feed_candidates(known)
    try:
        cands += electron_candidates(get(ELECTRON_RELEASES), ADVISORIES["electron"]["supported"])
    except Exception as e:
        print(f"skip Electron releases: {e}", file=sys.stderr)
    for adv in ADVISORIES["versions"]:
        if adv.get("awaiting"):
            try:
                cands += awaiting_candidates(get_text(adv["awaiting"]["url"]), adv)
            except Exception as e:
                print(f"skip {adv['name']} notes: {e}", file=sys.stderr)
    seen = set()
    for c in cands:
        if c["cve"] in seen:
            continue
        seen.add(c["cve"])
        if args.dry_run:
            print(f'{c["cve"]}  {c["title"]}')
        elif not queued(c.get("key", c["cve"])):
            labels = ["--label", "zero-day"] if c.get("zero_day") else []
            subprocess.run(["gh", "issue", "create", "--label", "queue", *labels, "--title", f'{c["cve"]}: {c["title"]}',
                            "--body", body(c)], check=True)
    print(f"{len(seen)} candidate(s)", file=sys.stderr)


if __name__ == "__main__":
    main(sys.argv[1:])
