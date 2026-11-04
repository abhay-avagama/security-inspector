#!/usr/bin/env python3
"""Writes the generated pages: changelog/index.html and changelog.xml (RSS) from changelog.json, newest
first, and watchlist/index.html (agent skills, MCP servers and extensions someone has flagged) from advisories.json.

Add an entry to changelog.json with each change, run `python3 changelog.py`, commit the outputs.
CI runs `python3 changelog.py --check`, which fails if any page or the feed is out of date.
"""
import datetime
import html
import json
import pathlib
import sys

ROOT = pathlib.Path(__file__).parent
SITE = "https://amiaffected.now"
REPO = "https://github.com/abhay-avagama/security-inspector"
STYLE = (ROOT / "index.html").read_text().split("<style>", 1)[1].split("</style>", 1)[0]  # one look for the whole site


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
<style>{STYLE}.log{{padding-left:1.1rem}}.log li{{margin:.6rem 0}}.log a{{font:13px ui-monospace,monospace;text-decoration:none}}</style></head>
<body><main>
<p class="muted"><a href="/">Am I affected?</a></p>
<h1>Changelog</h1>
<p>What the tool checks, and when each check went live. New exploited bugs usually land within a day of disclosure. Follow along with the <a href="/changelog.xml">RSS feed</a>.</p>
{body}
<footer>Built and maintained by <a href="https://avagama.co">Avagama Consulting</a>. Every entry links to its commit on <a href="{REPO}">GitHub</a>.</footer>
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
    return {"changelog/index.html": page, "changelog.xml": feed, "watchlist/index.html": watchlist()}


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
<style>{STYLE}{css}</style></head>
<body><main>
<p class="muted"><a href="/">Am I affected?</a></p>
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
<footer>Built and maintained by <a href="https://avagama.co">Avagama Consulting</a>. Generated from <a href="/advisories.json">advisories.json</a>, the same data the tool reads. What changed and when: the <a href="/changelog/">changelog</a>.</footer>
</main></body></html>
"""


if __name__ == "__main__":
    entries = sorted(json.loads((ROOT / "changelog.json").read_text()), key=lambda x: x["date"], reverse=True)
    out = render(entries)
    if "--check" in sys.argv:
        stale = [p for p, text in out.items() if not (ROOT / p).exists() or (ROOT / p).read_text() != text]
        sys.exit(f"out of date, run python3 changelog.py: {', '.join(stale)}" if stale else 0)
    for p, text in out.items():
        (ROOT / p).parent.mkdir(exist_ok=True)
        (ROOT / p).write_text(text)
    print("wrote", ", ".join(out))
