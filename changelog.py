#!/usr/bin/env python3
"""Writes the generated pages: changelog/index.html and changelog.xml (RSS) from changelog.json, newest
first, watchlist/index.html (agent skills, MCP servers and extensions someone has flagged), one page per advisory
under advisories/ and sitemap.xml, all from advisories.json.

Add an entry to changelog.json with each change, run `python3 changelog.py`, commit the outputs.
CI runs `python3 changelog.py --check`, which fails if any page or the feed is out of date.
"""
import datetime
import hashlib
import html
import json
import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).parent
SITE = "https://amiaffected.now"
REPO = "https://github.com/abhay-avagama/security-inspector"
INDEX = (ROOT / "index.html").read_text()
STYLE = INDEX.split("<style>", 1)[1].split("</style>", 1)[0]  # one look and one menu for the whole site
NAV = '<header class="top">' + INDEX.split('<header class="top">', 1)[1].split("</header>", 1)[0] + "</header>"
BEACON = "<!-- Cloudflare Web Analytics -->" + INDEX.split("<!-- Cloudflare Web Analytics -->", 1)[1].split("<!-- End Cloudflare Web Analytics -->", 1)[0] + "<!-- End Cloudflare Web Analytics -->"  # same counter as the home page


def nav(href):
    """The site menu with this page's link marked current."""
    assert f'href="{href}"' in NAV, href
    return NAV.replace(f'href="{href}">', f'href="{href}" aria-current="page">')


def render(entries):
    e = html.escape
    days = {}
    for x in entries:
        days.setdefault(x["date"], []).append(x)
    body = ""
    for day, items in days.items():
        nice = datetime.date.fromisoformat(day).strftime("%-d %B %Y")
        body += f'<h2 id="{day}">{nice}</h2>\n<ul class="log">\n' + "".join(
            f'<li><b>{e(x["title"])}</b>. {e(x["body"])} <a class="muted" href="{REPO}/commit/{x["commit"]}">{x["commit"]}</a></li>\n'
            for x in items) + "</ul>\n"
    page = f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Changelog · Am I affected?</title>
<meta name="description" content="Every check added to Am I affected?, newest first, with the date it went live.">
<link rel="canonical" href="{SITE}/changelog/">
<link rel="alternate" type="application/rss+xml" title="Am I affected? changelog" href="{SITE}/changelog.xml">
<style>{STYLE}.log{{padding-left:1.1rem}}.log li{{margin:.6rem 0}}.log a{{font:13px ui-monospace,monospace;text-decoration:none}}</style>{BEACON}</head>
<body>{nav("/changelog/")}
<main>
<h1>Changelog</h1>
<p>What the tool checks, and when each check went live. New exploited bugs usually land within a day of disclosure. Follow along with the <a href="/changelog.xml">RSS feed</a>.</p>
{body}
<footer>Built and maintained by <a href="https://avagama.co/services/?utm_source=amiaffected.now&amp;utm_medium=footer#security">Avagama Consulting</a>, who also test agents and MCP servers for security. Every entry links to its commit on <a href="{REPO}">GitHub</a>.</footer>
</main></body></html>
"""
    rfc = lambda d: datetime.datetime.combine(datetime.date.fromisoformat(d), datetime.time(12)).strftime("%a, %d %b %Y %H:%M:%S +0000")
    items = "".join(
        f"<item><title>{e(x['title'])}</title><link>{SITE}/changelog/#{x['date']}</link>"
        f"<guid isPermaLink=\"false\">{x['commit']}</guid><pubDate>{rfc(x['date'])}</pubDate>"
        f"<description>{e(x['body'])}</description></item>\n" for x in entries)
    feed = f"""<?xml version="1.0" encoding="utf-8"?>
<rss version="2.0"><channel><title>Am I affected? changelog</title><link>{SITE}/changelog/</link>
<description>Every check added to Am I affected?, newest first.</description>
{items}</channel></rss>
"""
    return {"changelog/index.html": page, "changelog.xml": feed, "watchlist/index.html": watchlist(), **advisory_pages()}


def slug(name):
    return re.sub(r"[^a-z0-9]+", "-", name.lower()).strip("-")


def advisory_pages():
    """advisories/<slug>/index.html for every version, server-package and library check, an index, and sitemap.xml.
    Only what advisories.json says, worded as the tool reports it, so a page never claims more than the tool checks."""
    from secinspect import ADVISORIES
    e = html.escape
    kinds = [("versions", "App"), ("distro", "Linux server package"), ("packages", "Library or package")]
    advs = [(a, kind) for key, kind in kinds for a in ADVISORIES[key]] + [(ADVISORIES["electron"], "Desktop apps"), (ADVISORIES["chromium_cache"], "Agent browser")]
    slugs = [slug(a["name"]) for a, _ in advs]
    assert len(set(slugs)) == len(slugs), "two advisories share a page name"
    nvd = lambda c: f'<a href="https://nvd.nist.gov/vuln/detail/{e(c)}">{e(c)}</a>'
    nofix = lambda v: "no fix yet" if v == "unfixed" else v
    distro = {"ubuntu": "Ubuntu", "debian": "Debian", "el": "RHEL family", "alma": "AlmaLinux", "rocky": "Rocky", "ol": "Oracle Linux"}
    rel_name = lambda r: " ".join([distro.get(r.split(":")[0], r.split(":")[0]), *r.split(":")[1:]])
    code = lambda xs: ", ".join(f"<code>{e(x)}</code>" for x in xs)

    def facts(a):
        rows = []
        if a.get("fixed") and isinstance(a["fixed"], list):
            rows.append(("Fixed in", code(a["fixed"]) + (" (older branches get no fix: move to a listed one)" if a.get("branch_width") else "")))
        for lo, hi, fix, *only in a.get("affected", []):
            rows.append(("Affected", f"<code>{e(lo)}</code> to <code>{e(hi)}</code>{' on ' + e(only[0]) if only else ''}: {e(fix)}"))
        if a.get("upstream_fixed"):
            rows.append(("Fixed upstream in", code(a["upstream_fixed"])))
        if isinstance(a.get("fixed"), dict):
            cells = "".join(f"<tr><td>{e(rel_name(rel))}</td><td>{'' if isinstance(v, str) else e(pkg)}</td><td><code>{e(nofix(v if isinstance(v, str) else fx))}</code></td></tr>"
                            for rel, v in a["fixed"].items() for pkg, fx in ([("", v)] if isinstance(v, str) else v.items()))
            rows.append(("Fixed packages", f"<div class=\"tw\"><table><tr><th>Release</th><th>Package</th><th>Fixed in</th></tr>{cells}</table></div>"))
        if a.get("supported"):
            rows.append(("Still patched", f"Electron {min(a['supported'])} to {max(a['supported'])}; an app on an older Electron is flagged"))
        if a.get("bad"):
            rows.append(("Bad versions", code(a["bad"]) + (f"; safe: <code>{e(a['safe'])}</code>" if a.get("safe") else "")))
        if a.get("bad_range"):
            rows.append(("Affected", f"<code>{e(a['bad_range'][0])}</code> to <code>{e(a['bad_range'][1])}</code>"))
        if a.get("present_paths"):
            rows.append(("Status", f"REVIEW whenever it's installed: {e(a['review_note'])}"))
        if a.get("status") == "REVIEW":
            rows.append(("Status", "REVIEW, not AFFECTED: a person needs to look"))
        where = ([f"<code>{e(a['binary'])} {e(a['flag'])}</code>"] if a.get("binary") else []) + \
                [f"<code>{e(p)}</code>" for p in a.get("globs", []) + a.get("version_files", []) + ([a["version_file"]] if a.get("version_file") else []) + a.get("present_paths", []) + a.get("dirs", []) + a.get("mac", []) + a.get("linux", [])] + \
                [f"{e(fam)} package <code>{e(p)}</code>" for fam in ("deb", "rpm", "brew") for p in a.get(f"{fam}_packages", [])] + \
                ([f"{e(a.get('ecosystem', 'pypi'))} package <code>{e(a['package'])}</code> in environments and lock files"] if a.get("package") else [])
        if where:
            rows.append(("Where it looks", "<br>".join(where)))
        todo = a.get("cleanup") or a.get("after_fix")
        if a.get("mitigation"):
            rows.append(("Until you can update", e(a["mitigation"])))
        if todo:
            rows.append(("After fixing" if a.get("after_fix") else "Do this", e(todo)))
        return "".join(f"<dt>{k}</dt><dd>{v}</dd>" for k, v in rows)

    css = """.facts{display:grid;grid-template-columns:9rem 1fr;gap:.5rem 1rem;margin:1.5rem 0}.facts dt{color:var(--muted)}.facts dd{margin:0;min-width:0;overflow-wrap:anywhere}.tw{overflow-x:auto}
.facts table{border-collapse:collapse;font-size:14px}.facts td,.facts th{border-bottom:1px solid var(--line);padding:.2rem .8rem .2rem 0;text-align:left}
.cves{display:flex;flex-wrap:wrap;gap:.3rem .9rem;list-style:none;padding:0;font:14px ui-monospace,monospace}
.alist{padding-left:1.1rem}.alist li{margin:.5rem 0}@media (max-width:560px){.facts{grid-template-columns:1fr;gap:0}.facts dd{margin-bottom:.6rem}}"""
    foot = (f'<footer>Built and maintained by <a href="https://avagama.co/services/?utm_source=amiaffected.now&amp;utm_medium=footer#security">Avagama Consulting</a>, '
            f'who also test agents and MCP servers for security. Generated from <a href="/advisories.json">advisories.json</a>, the same data the tool reads.</footer>')
    head = lambda title, desc, path: (f'<!doctype html>\n<html lang="en"><head><meta charset="utf-8">\n<meta name="viewport" content="width=device-width, initial-scale=1">\n'
                                      f'<title>{e(title)}</title>\n<meta name="description" content="{e(desc)}">\n<link rel="canonical" href="{SITE}{path}">\n'
                                      f'<style>{STYLE}{css}</style>{BEACON}</head>\n<body>{nav("/advisories/")}\n<main>\n')
    run = '<pre><code>curl -fsSL https://amiaffected.now/run | sh</code></pre>'
    def title_name(a):  # "WordPress: s2Member" reads better in a search result as "the s2Member WordPress plugin"
        n = a["name"]
        return f"the {n.split(': ', 1)[1]} WordPress plugin" if n.startswith("WordPress: ") else n

    def description(a):
        """Under 160 characters: the CVE and the fixed version, which are what people search for."""
        if a.get("supported"):  # Electron: no single CVE, the question is the Electron version
            return f"Check which apps on your machine run an Electron that no longer gets Chrome's security fixes (only {min(a['supported'])} to {max(a['supported'])} do). Nothing to install."
        cves = a.get("cves", [])
        what = f"{cves[0]}{f' and {len(cves) - 1} more' if len(cves) > 1 else ''}" if cves else f"the bad release {', '.join(a.get('bad', []))}".rstrip()
        fixed = a.get("upstream_fixed") or (a["fixed"] if isinstance(a.get("fixed"), list) else None)
        fixed = f" Fixed in {', '.join(fixed[:3])}." if fixed else f" Last safe release: {a['safe']}." if a.get("safe") else ""
        tail = " One command checks it; nothing to install."
        d = f"Check whether {title_name(a)} on your machine is affected by {what}.{fixed}"
        return d + tail if len(d + tail) <= 160 else d if len(d) <= 160 else d[:157].rsplit(" ", 1)[0] + "…"

    out, items = {}, ""
    for (a, kind), sl in zip(advs, slugs):
        path = f"/advisories/{sl}/"
        cves = '<ul class="cves">' + "".join(f"<li>{nvd(c)}</li>" for c in a.get("cves", [])) + "</ul>" if a.get("cves") else ""
        out[f"advisories/{sl}/index.html"] = (
            head(f"Am I affected by {title_name(a)}? · Am I affected?", description(a), path)
            + f'<p class="muted"><a href="/advisories/">Advisories</a> · {kind}</p>\n<h1>{e(a["name"])}</h1>\n<p class="lede">{e(a["about"][0].upper() + a["about"][1:])}.</p>\n{cves}\n'
            + f'<dl class="facts">{facts(a)}<dt>Source</dt><dd><a href="{e(a["source"])}">{e(a["source"])}</a></dd></dl>\n'
            + f'<h2>Check this machine</h2>\n<p>One command checks this and every other advisory against what is installed. Nothing about this machine is sent anywhere.</p>\n{run}\n{foot}\n</main></body></html>\n')
        items += f'<li><a href="{path}">{e(a["name"])}</a> <span class="muted">· {kind}</span><br><span class="muted">{e(a["about"][:160])}{"…" if len(a["about"]) > 160 else ""}</span></li>\n'
    out["advisories/index.html"] = (head("Advisories · Am I affected?", "Every vulnerability Am I affected? checks for, one page each: what's affected, the fixed versions and where the tool looks.", "/advisories/")
                                    + f'<h1>Advisories</h1>\n<p>Every advisory the tool checks, one page each: what is affected, the fixed versions and where it looks. Agent skills and MCP servers are on the <a href="/watchlist/">watchlist</a>.</p>\n{run}\n<ul class="alist">\n{items}</ul>\n{foot}\n</main></body></html>\n')
    # GitHub Pages' built-in 404 sometimes answers 503 on a cache miss; serving our own file avoids it.
    out["404.html"] = ('<!doctype html>\n<html lang="en"><head><meta charset="utf-8">\n<meta name="viewport" content="width=device-width, initial-scale=1">\n'
                       f'<title>Page not found · Am I affected?</title>\n<meta name="robots" content="noindex">\n<style>{STYLE}</style>{BEACON}</head>\n<body>{NAV}\n<main>\n'
                       '<h1>Page not found</h1>\n<p>There is nothing at this address. Try the <a href="/advisories/">advisories</a> or the <a href="/">home page</a>, or check this machine now:</p>\n'
                       f'{run}\n{foot}\n</main></body></html>\n')
    urls = ["/", "/changelog/", "/watchlist/", "/advisories/"] + [f"/advisories/{sl}/" for sl in slugs]
    out["sitemap.xml"] = ('<?xml version="1.0" encoding="UTF-8"?>\n<!-- Generated by changelog.py from advisories.json: edit the URL list there, not here. -->\n'
                          '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n' + "".join(f"  <url><loc>{SITE}{u}</loc></url>\n" for u in urls) + "</urlset>\n")
    return out


def watchlist():
    """One card per agent risk someone named publicly: what, who said so, what the tool reports, what to do."""
    from secinspect import ADVISORIES, SKILL_NOTES  # ponytail: same data and wording the CLI prints, no copy to drift
    e = html.escape
    sk, mcp, iocs = ADVISORIES["skills"], ADVISORIES["mcp"], ADVISORIES["iocs"]
    src = lambda url, name: f'<a href="{e(url)}">{e(name)}</a>'
    snyk, mcp_src = src(sk["source"], "Snyk ToxicSkills"), src(mcp["source"], "Help Net Security")
    rotate = "Delete the skill, then rotate any keys the agent could reach."

    def card(title, status, why, how, action, names=()):
        chips = '<ul class="chips">' + "".join(f"<li>{e(n)}</li>" for n in names) + "</ul>" if names else ""
        return (f'<article class="card"><header><h3>{title}</h3><span class="tag {status.lower()}">{status}</span></header>{chips}'
                f'<dl><dt>Why</dt><dd>{why}</dd><dt>Found by</dt><dd>{how[0].upper() + how[1:]}</dd><dt>Do this</dt><dd>{action}</dd></dl></article>\n')

    skills = (card("Skills published by these ClawHub accounts", "AFFECTED",
                   f"{snyk} confirmed these accounts published malicious skills on ClawHub, a public registry of agent skills.",
                   "the account name appearing anywhere in a skill's files", rotate, sk["bad_authors"])
              + card("Skills with these names", "AFFECTED", f"Malicious skills {snyk} found on ClawHub.",
                     "a skill folder with one of these names", rotate, sk["bad_names"])
              + card("Skills that mention this name", "AFFECTED", f"{snyk} found this name in the malicious skills.",
                     "the exact text in any of a skill's files", rotate, sk["bad_strings"]))
    servers = "".join(card(f"<code>@modelcontextprotocol/<wbr>{e(x)}</code>", "AFFECTED",
                           f"Archived, and a prompt injection can make it start any program, per {mcp_src}.", "its name in an MCP config", "Remove it. No fix is coming.")
                      for x in mcp["rce"])
    servers += card("Official example MCP servers, now archived", "REVIEW",
                    f"These <code>@modelcontextprotocol</code> servers were archived in May 2025 and get no security fixes, per {mcp_src}.",
                    "their names in an MCP config", "Switch to the vendor's own server, for example GitHub's for <code>server-github</code>.", mcp["deprecated"])
    ext = "".join(card(e(x["name"]), "AFFECTED", f'{e(x["about"])}. {src(x["source"], "The vendor notice")}.',
                       "its SSH key, files and launch agent on disk, and the bad versions if still installed",
                       e(x["cleanup"][0].upper() + x["cleanup"][1:]) + ".")
                  for x in iocs)
    patterns = "".join(f"<div><b>{e(k[0].upper() + k[1:])}</b><span>{e(v[0].upper() + v[1:])}</span></div>\n" for k, v in SKILL_NOTES.items())
    count = len(sk["bad_authors"]) + len(sk["bad_names"]) + len(sk["bad_strings"]), len(mcp["rce"]) + len(mcp["deprecated"]), len(iocs)
    css = """
.lede{font-size:1.1rem}
nav.jump{display:flex;flex-wrap:wrap;gap:.4rem 1.2rem;margin:1.5rem 0 0;font-size:15px}nav.jump a{text-decoration:none}nav.jump span{color:var(--muted)}
h2{font-size:1.35rem;margin:3rem 0 .25rem;letter-spacing:-.01em}h2+p{margin-top:0}
.card{border:1px solid var(--line);border-radius:10px;padding:1rem 1.15rem;margin:.9rem 0;background:var(--card)}
.card header{display:flex;justify-content:space-between;align-items:baseline;gap:.75rem}
.card h3{font-size:1.02rem;margin:0;line-height:1.35}
.tag{flex:none;font:600 11px/1 ui-monospace,SFMono-Regular,Menlo,monospace;letter-spacing:.06em;padding:.35rem .55rem;border-radius:999px}
.tag.affected{color:var(--accent);background:var(--accent-soft)}.tag.review{color:var(--muted);border:1px solid var(--line)}
.chips{display:flex;flex-wrap:wrap;gap:.4rem;list-style:none;margin:.8rem 0 0;padding:0}
.chips li{font:13px/1.4 ui-monospace,SFMono-Regular,Menlo,monospace;background:var(--code);border:1px solid var(--line);border-radius:5px;padding:.15rem .45rem;overflow-wrap:anywhere}
.card dl{display:grid;grid-template-columns:5rem 1fr;gap:.35rem .75rem;margin:.9rem 0 0;font-size:15px}
.card dt{color:var(--muted)}.card dd{margin:0}
.patterns{display:grid;grid-template-columns:1fr 1fr;gap:1rem 1.5rem;margin-top:1rem}
.patterns div{border-top:1px solid var(--line);padding-top:.6rem}.patterns b{display:block;font-size:15px}.patterns span{font-size:14px;color:var(--muted)}
@media (max-width:560px){.patterns{grid-template-columns:1fr}.card dl{grid-template-columns:1fr;gap:0}.card dd+dt{margin-top:.5rem}h1{font-size:2.1rem}}
:root{--card:#fff;--accent-soft:#f6e3dd}@media (prefers-color-scheme:dark){:root{--card:#1c1b18;--accent-soft:#3a221b}}
"""
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Agent watchlist · Am I affected?</title>
<meta name="description" content="Agent skills, MCP servers and extensions that a named source has flagged, what the tool reports for each, and what to do.">
<link rel="canonical" href="{SITE}/watchlist/">
<style>{STYLE}{css}</style>{BEACON}</head>
<body>{nav("/watchlist/")}
<main>
<h1>Agent watchlist</h1>
<p class="lede">Skills, MCP servers and extensions that someone has named in public as malicious or unsafe, each linked to who said so.</p>
<p>It's a short, hand-picked list, not a directory. One command checks everything here against what's installed on your machine:</p>
<pre><code>curl -fsSL https://amiaffected.now/run | sh</code></pre>
<nav class="jump"><a href="#skills">Skills</a><span>{count[0]}</span><a href="#mcp">MCP servers</a><span>{count[1]}</span><a href="#extensions">Extensions</a><span>{count[2]}</span><a href="#patterns">What it looks for in any skill</a></nav>

<h2 id="skills">Skills</h2>
<p class="muted">A skill is a folder of instructions and scripts that your coding agent reads and runs, so a bad one acts with your files and keys.</p>
{skills}
<h2 id="mcp">MCP servers</h2>
<p class="muted">MCP servers give an agent tools. The tool reads their names from Claude, Cursor, VS Code, Codex and Gemini configs.</p>
{servers}
<h2 id="extensions">Extensions</h2>
{ext}
<h2 id="patterns">What it looks for in any skill</h2>
<p>For a skill that isn't listed above, the tool checks its files for these patterns. A finding means a person should look, not that the skill is malicious, and a clean result means nothing obvious was found, not that it's safe. All of them are reported as REVIEW.</p>
<div class="patterns">
{patterns}</div>
<p class="muted" style="margin-top:2.5rem">Know of a skill or server that belongs here? Open an <a href="{REPO}/issues">issue</a> with the source. Want a second pair of eyes on your agent setup? That's what our <a href="https://avagama.co/services/">agent security review</a> covers.</p>
<footer>Built and maintained by <a href="https://avagama.co/services/?utm_source=amiaffected.now&amp;utm_medium=footer#security">Avagama Consulting</a>, who also test agents and MCP servers for security. Generated from <a href="/advisories.json">advisories.json</a>, the same data the tool reads. What changed and when: the <a href="/changelog/">changelog</a>.</footer>
</main></body></html>
"""


def release_stamp(adv_text, script, now):
    """advisories.json with a "release" line naming secinspect.py's sha256 and when it last changed. Both files are
    signed, so --update can refuse a mixed pair (an old signed script beside new signed advisories)."""
    sha = hashlib.sha256(script).hexdigest()
    m = re.search(r'^  "release": \{"script_sha256": "([0-9a-f]{64})", "released": "[^"]+"\},\n', adv_text, re.M)
    if m and m.group(1) == sha:
        return adv_text
    line = f'  "release": {{"script_sha256": "{sha}", "released": "{now}"}},\n'
    return adv_text.replace(m.group(0), line) if m else adv_text.replace("{\n", "{\n" + line, 1)


if __name__ == "__main__":
    entries = sorted(json.loads((ROOT / "changelog.json").read_text()), key=lambda x: x["date"], reverse=True)
    out = render(entries)
    now = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    out["advisories.json"] = release_stamp((ROOT / "advisories.json").read_text(), (ROOT / "secinspect.py").read_bytes(), now)
    if "--check" in sys.argv:
        stale = [p for p, text in out.items() if not (ROOT / p).exists() or (ROOT / p).read_text() != text]
        sys.exit(f"out of date, run python3 changelog.py: {', '.join(stale)}" if stale else 0)
    for p, text in out.items():
        (ROOT / p).parent.mkdir(parents=True, exist_ok=True)
        (ROOT / p).write_text(text)
    print("wrote", ", ".join(out))
