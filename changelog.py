#!/usr/bin/env python3
"""Writes changelog/index.html and changelog.xml (RSS) from changelog.json, newest first.

Add an entry to changelog.json with each change, run `python3 changelog.py`, commit all three.
CI runs `python3 changelog.py --check`, which fails if the page or feed is out of date.
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
    return {"changelog/index.html": page, "changelog.xml": feed}


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
