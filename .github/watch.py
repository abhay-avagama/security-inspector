#!/usr/bin/env python3
"""Watch, every 6 hours: finds newly exploited or newly published CVEs that Am I affected? doesn't check yet,
and opens one GitHub issue per CVE labelled `queue`, so adding them is a list to work through.

Sources: CISA KEV (exploited in the wild), filtered to software people run on laptops and servers,
the cve.now feed for each tech the tool already tracks, the vendors' own release feeds (GitLab, PostgreSQL,
Node.js, PHP), releases scheduled in advance (PostgreSQL, Oracle's Java CPU; issue opens 2 days ahead), and zero-days: bugs the vendor itself says are
exploited, read from Chrome Releases, Apple's security releases and Mozilla's advisories on the day they
ship, often days before KEV lists them. Those issues also get the `zero-day` label. Stateless: an open or closed issue with
the CVE id in its title means it's already queued, so reruns never duplicate.

Changes that need no judgement (end-of-life dates, a new Electron major) come as a draft PR with the edit made,
labelled `queue`; the release is still signed by hand after merging, so nothing goes live by itself.

Usage: python3 .github/watch.py [--dry-run] [--days 14] [--refresh-eol] [--refresh-agent-feed]   (needs `gh` logged in unless --dry-run)
"""
import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
import urllib.parse
import urllib.request
from datetime import date, datetime, timedelta, timezone

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ADVISORIES_JSON = os.path.join(ROOT, "advisories.json")
sys.path.insert(0, ROOT)
from secinspect import ADVISORIES, FEED_URL, _dt, new_cves, nums  # noqa: E402

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
# ponytail: keyword match on vendor/product; widen this list when a miss shows up
WATCH = ("chrom", "linux", "kernel", "nginx", "apache", "php", "node", "python", "openssl", "openssh", "sudo",
         "glibc", "git", "docker", "kubernetes", "redis", "postgres", "mysql", "mariadb", "mongodb", "wordpress",
         "nextcloud", "jenkins", "grafana", "elastic", "rails", "django", "spring", "log4j", "curl", "bind",
         "exim", "postfix", "dovecot", "roundcube", "plex", "zammad", "litellm", "npm", "pypi", "mcp", "ollama", "gpustack")


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


def kev_digest(kev, today, known):
    """One issue a week listing what CISA added that matched none of WATCH: the gaps no other check would raise."""
    monday = today - timedelta(days=today.weekday())
    week = [v for v in kev["vulnerabilities"] if (monday - timedelta(days=7)).isoformat() <= v["dateAdded"] < monday.isoformat()
            and v["cveID"] not in known and not any(w in f'{v["vendorProject"]} {v["product"]}'.lower() for w in WATCH)]
    if not week:
        return []
    label = f"KEV week of {(monday - timedelta(days=7)).isoformat()}"
    return [{"cve": label, "title": f"{len(week)} exploited bug(s) in software we don't watch",
             "why": "Added to CISA KEV last week, outside the WATCH keywords. Add a check, or a keyword, for any that run on laptops "
                    "or servers our users have; close the rest.",
             "detail": "\n".join(f'- {v["cveID"]} {v["vendorProject"]} {v["product"]}: {v["vulnerabilityName"]}' for v in week),
             "fix": "", "source": "https://www.cisa.gov/known-exploited-vulnerabilities-catalog"}]

def cve_line(cve, said):
    return f"- https://nvd.nist.gov/vuln/detail/{cve}" + (f" {said[cve]}" if said.get(cve) else "")


def late(cves, issues):
    """(lines no issue for this key mentions yet, the open issue to add them to or None). An issue stays open for days
    while its tech's `checked` date stands still, and CVEs listed in that time were never queued."""
    seen = " ".join(i.get("body", "") + " ".join(c.get("body", "") for c in i.get("comments", [])) for i in issues)
    return [line for cve, line in cves.items() if cve not in seen], next((i["number"] for i in issues if i.get("state") == "OPEN"), None)


def feed_candidates():
    out = []
    for adv in ADVISORIES["versions"] + ADVISORIES["distro"] + ADVISORIES["packages"]:
        if not adv.get("feed") or not adv.get("checked"):
            continue
        try:
            items = get(FEED_URL.format(adv["feed"])).get("items", [])
        except Exception as e:  # one feed down shouldn't stop the rest
            print(f"skip {adv['name']} feed: {e}", file=sys.stderr)
            continue
        own = {w for w in json.dumps(adv).replace('"', " ").split() if w.startswith("CVE-")}
        # ponytail: judged against this product's own CVEs, not every CVE we list: GitLab's fix for a git CVE we
        # already had under Git (CVE-2026-105437) is still news for GitLab. Same rule as the scanner's stale check.
        fresh = new_cves(items, adv["checked"], own)
        # cve.now's title names the product, so a mysql_fdw or psqlODBC CVE in MySQL's or PostgreSQL's feed shows at a glance
        said = {it["id"].split("#")[0]: it.get("title", "").split(": ", 1)[-1] for it in reversed(items) if it.get("id")}
        if fresh:  # one issue per tech: Chrome alone lists a dozen CVEs per release
            # ponytail: the lead CVE shifts as the feed reorders, so dedupe on tech + checked date instead;
            # each key must match only its own title ("new CVE" vs "CVEs we check") or one kind hides the other
            out.append({"cve": fresh[0], "key": f'"{adv["name"]}" "new CVE" "since {adv["checked"][:10]}"', "title": f'{adv["name"]}: {len(fresh)} new CVE(s) since {adv["checked"][:10]}',
                        "why": f'Listed on cve.now for {adv["name"]} after {adv["checked"][:10]}.',
                        "detail": "\n".join(cve_line(c, said) for c in fresh), "fix": "", "cves": {c: cve_line(c, said) for c in fresh},
                        "source": f'https://cve.now/feed?tech={adv["feed"]}'})
        # cve.now re-lists a CVE as "<id>#<time>" when it changes; for one we already check, that's news like a public exploit
        upd = [it for it in items if "#" in it.get("id", "") and it["id"].split("#")[0] in own
               and _dt(it.get("date_modified", "1970-01-01")) > _dt(adv["checked"])]
        if upd:
            out.append({"cve": upd[0]["id"].split("#")[0], "key": f'"{adv["name"]}" "CVEs we check" "since {adv["checked"][:10]}"',
                        "title": f'{adv["name"]}: {len(upd)} update(s) to CVEs we check, since {adv["checked"][:10]}',
                        "why": "A CVE we already check changed on cve.now (public exploit, KEV listing, rescore). "
                               "Decide whether the note or the urgency should change; close it if not.",
                        "detail": "\n".join(f'- {it.get("title", it["id"])}' for it in upd), "fix": "",
                        "source": f'https://cve.now/feed?tech={adv["feed"]}'})
    return out


# Vendors' own release feeds: the release is out hours to a day before its CVEs reach cve.now, and some (GitLab's
# bundled-git fix) never show up there under the product at all. name -> (feed, title pattern for a release).
VENDOR_FEEDS = {
    "GitLab": ("https://about.gitlab.com/security-releases.xml", r"Patch Release"),
    "PostgreSQL server": ("https://www.postgresql.org/news.rss", r"^PostgreSQL [\d., ]+(and [\w .]+)?Released"),
    "Node.js": ("https://nodejs.org/en/feed/vulnerability.xml", r"Security Releases"),
    "PHP": ("https://www.php.net/releases/feed.php", r"^PHP [\d.]+ released"),
    "Ruby": ("https://www.ruby-lang.org/en/feeds/news.rss", r"CVE-|Security advisories"),  # release posts name no CVEs
    "Ruby on Rails": ("https://discuss.rubyonrails.org/c/security-announcements/9.rss", r"\S"),  # every post is one
}
ATOM = "{http://www.w3.org/2005/Atom}"


def feed_entries(xml):
    """[(when, title, link)] from an RSS or Atom feed, times as naive UTC."""
    import email.utils
    import xml.etree.ElementTree as ET
    out = []
    for it in ET.fromstring(xml).iter():
        if it.tag not in ("item", ATOM + "entry"):
            continue
        when = it.findtext("pubDate") or it.findtext(ATOM + "updated") or it.findtext(ATOM + "published") or ""
        try:
            t = email.utils.parsedate_to_datetime(when) if "," in when else datetime.fromisoformat(when.replace("Z", "+00:00"))
        except (TypeError, ValueError):
            continue
        link = it.findtext("link") or (it.find(ATOM + "link").get("href", "") if it.find(ATOM + "link") is not None else "")
        title = " ".join((it.findtext("title") or it.findtext(ATOM + "title") or "").split())
        out.append((t.astimezone(timezone.utc).replace(tzinfo=None) if t.tzinfo else t, title, link))
    return out


def vendor_candidates(name, xml, checked, pattern):
    fresh = [(t, title, link) for t, title, link in feed_entries(xml) if t > _dt(checked) and re.search(pattern, title)]
    if not fresh:
        return []
    return [{"cve": f"Release {max(fresh)[0]:%Y-%m-%d}", "key": f'"{name}" "vendor release" "since {checked[:10]}"',
             "title": f"{name}: {len(fresh)} vendor release(s) since {checked[:10]}",
             "why": f"{name} published this after we last checked it; its CVEs often reach cve.now a day later, or never.",
             "detail": "\n".join(f"- {t:%Y-%m-%d} {title}: {urllib.parse.urljoin(VENDOR_FEEDS[name][0], link)}"
                                  for t, title, link in sorted(fresh)), "fix": "",
             "source": VENDOR_FEEDS[name][0]}]


PG_ROADMAP = "https://www.postgresql.org/developer/roadmap/"
ORACLE_CPU = "https://www.oracle.com/security-alerts/"
MONTHS = "January February March April May June July August September October November December".split()


def scheduled(today, roadmap_html):
    """[(day, what, url)]: security releases dated in advance, so the check can be ready the day they ship."""
    text = re.sub(r"<[^>]+>", " ", roadmap_html)
    text = text[text.find("Upcoming minor releases"):text.find("Next major release")]
    out = [(date(int(y), MONTHS.index(m) + 1, int(d)), "PostgreSQL minor release", PG_ROADMAP)
           for m, d, y in re.findall(rf"({'|'.join(MONTHS)}) (\d+)(?:st|nd|rd|th)?, (\d{{4}})", text)]
    for y in (today.year, today.year + 1):  # Oracle: third Tuesday of Jan, Apr, Jul, Oct (matches its published 2027 dates)
        for m in (1, 4, 7, 10):
            out.append((date(y, m, 15) + timedelta(days=(1 - date(y, m, 15).weekday()) % 7), "Oracle Critical Patch Update (Java)", ORACLE_CPU))
    return out


def scheduled_candidates(events, today, ahead=2):
    return [{"cve": f"Due {d}", "key": f'"Due {d}" "{what}"', "title": what,
             "why": f"{what} is scheduled for {d}. Read the notes the day they're out and update the check that day; "
                    "close this once it's live, or if the release has no security fixes.",
             "detail": "", "fix": "", "source": url} for d, what, url in events if 0 <= (d - today).days <= ahead]


ELECTRON_RELEASES = "https://releases.electronjs.org/releases.json"


def electron_candidates(releases, supported):
    """A stable Electron major newer than the ones we list means the oldest listed one just lost support."""
    majors = {int(r["version"].split(".")[0]) for r in releases if "-" not in r["version"]}
    newest = max(majors, default=0)
    if newest <= max(supported):
        return []
    return [{"cve": f"Electron {newest}", "title": f"Electron {newest} is out: update the supported list ({', '.join(map(str, supported))})",
             "why": f"Electron supports its newest three majors, so {newest} ending up stable moves the oldest out of support.",
             "detail": f"The PR sets electron.supported to {list(range(newest - 2, newest + 1))} and updates the wording on the pages; check the date in the about text (the day the old major lost support).",
             "fix": "", "source": "https://www.electronjs.org/docs/latest/tutorial/electron-timelines",
             "apply": lambda: bump_electron(supported, newest)}]


def bump_electron(old, newest, root=ROOT):
    """The draft PR's change: the supported list in advisories.json and the "43 to 45" wording on the pages."""
    new = list(range(newest - 2, newest + 1))
    say = lambda v: f"{v[0]}, {v[1]} and {v[2]}"
    edits = {"advisories.json": [(json.dumps(old, indent=2).replace("\n", "\n    "), json.dumps(new, indent=2).replace("\n", "\n    ")),
                                 (f"({say(old)} since ", f"({say(new)} since ")],
             "README.md": [(f"{old[0]} to {old[-1]}", f"{new[0]} to {new[-1]}")],
             "index.html": [(f"{old[0]} to {old[-1]}", f"{new[0]} to {new[-1]}")]}
    for name, pairs in edits.items():
        path = os.path.join(root, name)
        text = open(path).read()
        for a, b in pairs:
            text = text.replace(a, b)
        if name == "advisories.json":  # the date in "(44, 45 and 46 since <date>)"
            text = re.sub(rf"(\({re.escape(say(new))} since )[^)]*\)", rf"\g<1>{date.today():%-d %b %Y})", text)
        open(path, "w").write(text)


def awaiting_candidates(page, adv):
    """The vendor said a fix is coming (Edge): queue once their notes list a newer build than the last affected one."""
    w = adv["awaiting"]
    if "above" not in w:  # no version to beat (MySQL's fix isn't public): queue once the distro's CVE page says released
        return [{"cve": f'{adv["name"]} fix', "key": f'"{adv["name"]}" "has shipped"', "title": f'{adv["name"]}: a fix has shipped',
                 "why": f'The {adv["name"]} entry is REVIEW because no fix was public; {w["url"]} now lists one.',
                 "detail": "Put the fixed builds in the entry's `fixed` map (and `upstream_fixed`), drop `status` and `awaiting`.",
                 "fix": "", "source": w["url"]}] if re.search(w["regex"], page) else []
    newer = sorted({v for v in re.findall(w["regex"], page) if nums(v) > nums(w["above"])}, key=nums)
    if not newer:
        return []
    return [{"cve": f'{adv["name"]} {newer[-1]}', "title": f'{adv["name"]} {newer[-1]} is out: is it the fix we were waiting for?',
             "why": f'The {adv["name"]} entry waits for a vendor fix; their notes now list {", ".join(newer)}.',
             "detail": "Check the notes, set the fixed version in advisories.json and drop `awaiting`.", "fix": "", "source": w["url"]}]


EOL_API = "https://endoflife.date/api/{}.json"


def eol_cycles(api):
    """endoflife.date's list -> ({cycle: end date, True (ended, no date) or False (supported)}, cycle to move to).
    The move-to is the newest supported cycle, LTS only when the product has LTS releases (Ubuntu, Node)."""
    cycles = {c["cycle"]: c["eol"] for c in api if not isinstance(c["eol"], str) or c["eol"] >= "2018"}  # older ones: nobody's left
    alive = [c for c in api if c["eol"] is False or (c["eol"] is not True and c["eol"] > date.today().isoformat())]
    lts = [c for c in alive if c.get("lts")] if any(c.get("lts") for c in api) else alive
    return cycles, (lts or alive or api)[0]["cycle"]


def eol_block(eol):
    """The eol section, one product per line, in the hand-kept layout of advisories.json."""
    top = {k: v for k, v in eol.items() if k != "products"}
    lines = ",\n".join("      " + json.dumps(p, ensure_ascii=False) for p in eol["products"])
    return json.dumps(top, ensure_ascii=False)[:-1] + ',\n    "products": [\n' + lines + "\n    ]\n  }"


def eol_candidates(products, apis):
    """Changed or new end-of-life dates upstream, all products in one candidate. apis: {slug: endoflife.date list}.
    The key hashes the changes, so the same changes never open a second PR and new ones open a new one."""
    changed = {p["items"][0]: sorted(c for c, end in eol_cycles(apis[p["slug"]])[0].items() if p["cycles"].get(c, "missing") != end)
               for p in products if p["slug"] in apis}
    changed = {k: v for k, v in changed.items() if v}
    if not changed:
        return []
    key = hashlib.sha256(json.dumps(changed, sort_keys=True).encode()).hexdigest()[:8]
    return [{"cve": f"EOL {key}", "title": "end-of-life dates changed: " + "; ".join(f"{k} {', '.join(v[:4])}" for k, v in changed.items()),
             "why": "endoflife.date lists a new cycle or a moved date, so the end-of-life check is out of date.",
             "detail": "The PR runs `python3 .github/watch.py --refresh-eol`. Check the dates in the diff.",
             "fix": "", "source": "https://endoflife.date", "apply": lambda: refresh_eol(apis)}]


def refresh_eol(apis, path=ADVISORIES_JSON):
    """Rewrites only the eol block of advisories.json (it stays the last key) from endoflife.date."""
    text = open(path).read()
    eol = json.loads(text)["eol"]
    for p in eol["products"]:
        if p["slug"] in apis:
            p["cycles"], p["newest"] = eol_cycles(apis[p["slug"]])
    eol["checked"] = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    with open(path, "w") as fh:
        fh.write(text[:text.index('\n  "eol": ')] + '\n  "eol": ' + eol_block(eol) + "\n}\n")


# --- Agent feed: known advisories for MCP servers and agent tools, compiled from OSV so the scanner can match offline ---
OSV_QUERY, OSV_VULN = "https://api.osv.dev/v1/querybatch", "https://api.osv.dev/v1/vulns/{}"


def osv_post(url, body=None):
    req = urllib.request.Request(url, json.dumps(body).encode() if body else None,
                                 {"Content-Type": "application/json", "User-Agent": "amiaffected-watch"})
    with urllib.request.urlopen(req, timeout=60) as r:
        return json.load(r)


def feed_advisory(d, name):
    """One OSV record as the feed keeps it: id (the CVE when there is one), severity, [first affected, first fixed] ranges
    for this package ("" = no fix listed; a third item "last" = the second is the last affected version) and a short summary."""
    ranges = []
    for a in d.get("affected", []):
        if a.get("package", {}).get("name") != name:
            continue
        for r in a.get("ranges", []):
            lo = None
            for ev in r.get("events", []):
                if "introduced" in ev:
                    lo = ev["introduced"]
                elif lo is not None and "fixed" in ev:
                    ranges.append([lo, ev["fixed"]]); lo = None
                elif lo is not None and "last_affected" in ev:
                    ranges.append([lo, ev["last_affected"], "last"]); lo = None
            if lo is not None:
                ranges.append([lo, ""])
        if not a.get("ranges"):  # a malicious package lists versions, or nothing: every version
            ranges.append(["0", ""])
    cve = next((x for x in d.get("aliases", []) if x.startswith("CVE-")), "")
    sev = "MALICIOUS" if d["id"].startswith("MAL-") else str((d.get("database_specific") or {}).get("severity", "")).upper()
    return {"id": cve or d["id"], "osv": d["id"], "severity": sev, "ranges": sorted(ranges),
            "summary": " ".join((d.get("summary") or d.get("details") or "").split())[:110]}


def agent_feed(watch, fetch=osv_post):
    """[{ecosystem, package, advisories}] for the watched packages that have any, from OSV. Only public package names are sent."""
    out = []
    for eco, names in sorted(watch.items()):
        names = sorted(set(names))
        res = fetch(OSV_QUERY, {"queries": [{"package": {"name": n, "ecosystem": eco}} for n in names]})["results"]
        for n, r in zip(names, res):
            got = {}
            for i in sorted(v["id"] for v in r.get("vulns", [])):
                a = feed_advisory(fetch(OSV_VULN.format(i)), n)
                # PyPA re-issues GitHub's advisories as PYSEC-…: one entry per CVE, GitHub's first since it rates severity
                if a["ranges"] and (a["id"] not in got or (not got[a["id"]]["severity"] and a["severity"])):
                    got[a["id"]] = a
            if got:
                out.append({"ecosystem": eco, "package": n, "advisories": sorted(got.values(), key=lambda a: a["id"])})
    return out


def feed_block(feed):
    """The agent_feed section, one package per line, in the hand-kept layout of advisories.json."""
    top = {k: v for k, v in feed.items() if k != "packages"}
    lines = ",\n".join("      " + json.dumps(p, ensure_ascii=False) for p in feed["packages"])
    return json.dumps(top, ensure_ascii=False)[:-1] + ', "packages": [\n' + lines + "\n    ]}"


def refresh_agent_feed(packages, path=ADVISORIES_JSON):
    """Rewrites only the agent_feed block of advisories.json (it sits just before eol, the last key)."""
    text = open(path).read()
    feed = {**json.loads(text)["agent_feed"], "packages": packages, "checked": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")}
    start, end = text.index('\n  "agent_feed": '), text.index('\n  "eol": ')
    with open(path, "w") as fh:
        fh.write(text[:start] + '\n  "agent_feed": ' + feed_block(feed) + "," + text[end:])


def agent_feed_candidates(current, packages):
    """A draft PR when OSV's advisories for the watched agent packages differ from the signed feed."""
    ids = lambda ps: {(p["ecosystem"], p["package"], a["id"]) for p in ps for a in p["advisories"]}
    if packages == current:
        return []
    new = sorted(ids(packages) - ids(current))
    key = hashlib.sha256(json.dumps(packages, sort_keys=True).encode()).hexdigest()[:8]
    what = "; ".join(f"{n} {i}" for _, n, i in new[:4]) + (f" and {len(new) - 4} more" if len(new) > 4 else "") if new else "ranges or severities changed"
    return [{"cve": f"Agent feed {key}", "title": f"MCP server and agent advisories changed: {what}",
             "why": "OSV lists advisories for watched agent packages that the signed feed doesn't have, or has differently.",
             "detail": "The PR runs `python3 .github/watch.py --refresh-agent-feed`. Check the diff: new packages, ranges and severities.",
             "fix": "", "source": "https://osv.dev", "apply": lambda: refresh_agent_feed(packages)}]


def eol_apis():
    apis = {}
    for p in ADVISORIES["eol"]["products"]:
        try:
            apis[p["slug"]] = get(EOL_API.format(p["slug"]))
        except Exception as e:
            print(f"skip {p['slug']} end-of-life dates: {e}", file=sys.stderr)
    return apis


def body(c):
    return "\n\n".join(x for x in (
        c["why"], c["detail"], f'Vendor fix / required action: {c["fix"]}' if c["fix"] else "",
        f'Source: {c["source"]}',
        "To add it: find the fixed versions (vendor advisory, plus Ubuntu/Debian/RHEL trackers for server "
        "software), add an entry to advisories.json, a test in test_secinspect.py, and a row on the page and "
        "README. Close as `wontfix` if it doesn't fit the tool. Either way, move the tech's `checked` date in "
        "advisories.json to today, or later CVEs for it won't be queued.") if x)


def git(*args):
    return subprocess.run(["git", "-C", ROOT, *args], capture_output=True, text=True, check=True).stdout


def open_pr(c):
    """A draft PR with the change made, for the cases that need no judgement. The release stays unsigned until the
    maintainer reviews, merges, pulls and signs, so nothing here can go live by itself."""
    branch = "watch/" + re.sub(r"[^a-z0-9]+", "-", c["cve"].lower()).strip("-")
    start = git("rev-parse", "--abbrev-ref", "HEAD").strip()
    git("checkout", "-B", branch)
    try:
        c["apply"]()
        subprocess.run([sys.executable, os.path.join(ROOT, "changelog.py")], cwd=ROOT, capture_output=True, check=True)
        t = subprocess.run([sys.executable, os.path.join(ROOT, "test_secinspect.py")], cwd=ROOT, capture_output=True, text=True)
        tests = "Tests pass." if t.returncode == 0 else "Tests FAIL, fix before merging:\n\n```\n" + (t.stdout + t.stderr)[-2500:] + "\n```"
        git("add", "-A")
        git("commit", "-m", f'{c["cve"]}: {c["title"]}')
        git("push", "-f", "origin", branch)
        subprocess.run(["gh", "pr", "create", "--draft", "--label", "queue", "--head", branch, "--title", f'{c["cve"]}: {c["title"]}',
                        "--body", "\n\n".join((c["why"], c["detail"], f'Source: {c["source"]}', tests,
                                                "To ship: review the diff, add a changelog.json entry if users should hear about it, "
                                                "merge, pull, then `sh .github/sign-release.sh`."))], check=True)
    finally:
        git("checkout", "-f", start)


def proposed(key):
    out = subprocess.run(["gh", "pr", "list", "--state", "all", "--search", f"{key} in:title", "--json", "number"],
                         capture_output=True, text=True, check=True).stdout
    return bool(json.loads(out))


def queued(key):
    """The issues, open or closed, already raised for this key."""
    out = subprocess.run(["gh", "issue", "list", "--state", "all", "--search", f"{key} in:title", "--json", "number,state,body,comments"],
                         capture_output=True, text=True, check=True).stdout
    return json.loads(out)


def main(argv):
    ap = argparse.ArgumentParser()
    ap.add_argument("--dry-run", action="store_true", help="print candidates, don't open issues")
    ap.add_argument("--days", type=int, default=14, help="how far back to look in CISA KEV")
    ap.add_argument("--refresh-eol", action="store_true", help="rewrite advisories.json's end-of-life dates from endoflife.date")
    ap.add_argument("--refresh-agent-feed", action="store_true", help="rewrite advisories.json's agent_feed from OSV")
    args = ap.parse_args(argv)
    if args.refresh_eol:
        return refresh_eol(eol_apis())
    if args.refresh_agent_feed:
        return refresh_agent_feed(agent_feed(ADVISORIES["agent_feed"]["watch"]))
    known = known_cves()
    since = (date.today() - timedelta(days=args.days)).isoformat()
    zsince = (date.today() - timedelta(days=3)).isoformat()  # vendor notes are same-day; KEV can lag weeks
    try:
        catalog = get(KEV_URL)
        kev = kev_candidates(catalog, since, known) + kev_digest(catalog, date.today(), known)
    except Exception as e:  # don't let CISA being down stop the zero-day and feed checks (or the signature step after)
        print(f"skip CISA KEV: {e}", file=sys.stderr)
        kev = []
    cands = zero_day_candidates(zsince, known) + kev + feed_candidates()
    try:
        cands += electron_candidates(get(ELECTRON_RELEASES), ADVISORIES["electron"]["supported"])
    except Exception as e:
        print(f"skip Electron releases: {e}", file=sys.stderr)
    cands += eol_candidates(ADVISORIES["eol"]["products"], eol_apis())
    try:
        cands += agent_feed_candidates(ADVISORIES["agent_feed"]["packages"], agent_feed(ADVISORIES["agent_feed"]["watch"]))
    except Exception as e:
        print(f"skip agent feed: {e}", file=sys.stderr)
    checked = {a["name"]: a.get("checked") for a in ADVISORIES["versions"] + ADVISORIES["distro"] + ADVISORIES["packages"]}
    for name, (url, pattern) in VENDOR_FEEDS.items():
        try:
            cands += vendor_candidates(name, get_text(url), checked[name], pattern)
        except Exception as e:  # one vendor down shouldn't stop the rest
            print(f"skip {name} releases: {e}", file=sys.stderr)
    try:
        cands += scheduled_candidates(scheduled(date.today(), get_text(PG_ROADMAP)), date.today())
    except Exception as e:
        print(f"skip schedules: {e}", file=sys.stderr)
    for adv in ADVISORIES["versions"] + ADVISORIES["distro"]:
        if adv.get("awaiting"):
            try:
                cands += awaiting_candidates(get_text(adv["awaiting"]["url"]), adv)
            except Exception as e:
                print(f"skip {adv['name']} notes: {e}", file=sys.stderr)
    seen = set()
    for c in cands:
        k = c.get("key", c["cve"])  # two candidates can share a lead CVE or a date; the key is what's unique
        if k in seen:
            continue
        seen.add(k)
        if args.dry_run:
            print(f'{c["cve"]}  {c["title"]}' + ("  (draft PR)" if c.get("apply") else ""))
        elif c.get("apply"):
            if not proposed(c["cve"]):
                open_pr(c)
        else:
            issues = queued(c.get("key", c["cve"]))
            more, open_issue = late(c["cves"], issues) if issues and c.get("cves") else ([], None)
            if more and open_issue:  # listed after the issue was opened: add them to it
                subprocess.run(["gh", "issue", "comment", str(open_issue), "--body", "Also listed since:\n\n" + "\n".join(more)], check=True)
            elif more:  # the issue was closed without moving `checked` past these: they need their own
                c = {**c, "detail": "\n".join(more), "title": c["title"] + " (after the earlier issue)"}
            if not issues or (more and not open_issue):
                labels = ["--label", "zero-day"] if c.get("zero_day") else []
                subprocess.run(["gh", "issue", "create", "--label", "queue", *labels, "--title", f'{c["cve"]}: {c["title"]}',
                                "--body", body(c)], check=True)
    print(f"{len(seen)} candidate(s)", file=sys.stderr)


if __name__ == "__main__":
    main(sys.argv[1:])
