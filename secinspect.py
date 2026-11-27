#!/usr/bin/env python3
"""Am I affected? Checks this machine for the issues listed in advisories.json (Oct 2026: PHP,
Node.js, BIND, LiteLLM, GitLab, eMudhra; Nov 2026: exploited Chrome bugs, stale Puppeteer/Playwright
browsers and the deprecated Puppeteer MCP server; on Linux servers also the kernel, nginx, Apache,
MariaDB, MongoDB, WordPress and more). Stdlib only. Exit code 1 if anything is affected.

Usage: python3 secinspect.py [dirs ...] [--docker] [--html report.html] [--no-update-check]
       python3 secinspect.py --files-only DIR  only the files in DIR (lockfiles, MCP configs, skills, .env); for CI
       python3 secinspect.py --watch STATE [--notify URL] [--mail ADDRESS]  for cron: report only what changed
       python3 secinspect.py --skills-baseline FILE  also report skills that changed since the last run
       python3 secinspect.py --fix        offer each vendor update, apply only what you approve, log every step
       python3 secinspect.py --verify-log check the --fix audit log hasn't been edited
       python3 secinspect.py --install    keep a copy that updates only from signed releases (then --update from cron)
       python3 secinspect.py --update     take a new release only if it's signed by the pinned key
  With no dirs, searches your home folder and system Python paths for envs, lockfiles and CA bundles.
  With dirs, searches only those. Installed programs and system trust stores are checked too, unless
  --files-only. --audit-log FILE picks the log that --fix, --install and --update write and --verify-log checks.
"""
import argparse
import base64
import bz2
import concurrent.futures
import datetime
import getpass
import glob
import hashlib
import html
import io
import http.client
import json
import os
import platform
import plistlib
import re
import shlex
import shutil
import subprocess
import sys
import tarfile
import tempfile
import textwrap
import zipfile
import time
import urllib.request
import xml.etree.ElementTree as ET

HOME = os.path.expanduser("~")
ADVISORIES = json.load(open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "advisories.json")))
PACKAGES = ADVISORIES["packages"]
CHROMIUM = ADVISORIES["chromium_cache"]
MCP = ADVISORIES["mcp"]
ROOTS = {r["name"]: base64.b64decode(r["der"]) for r in ADVISORIES["ca"]["roots"]}
INTERMEDIATES = {i["name"]: base64.b64decode(i["der"]) for i in ADVISORIES["ca"]["intermediates"]}
AAA = "AAA Certificate Services"
OPENSSL = shutil.which("openssl")


def ver(s):
    m = re.search(r"(\d+)\.(\d+)\.(\d+)(?:\.(\d+))?", s or "")  # Chrome has four parts
    return tuple(int(x) for x in m.groups() if x is not None) if m else None


def fmt(v):
    return ".".join(map(str, v))


def run(*cmd):
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        return p.stdout + p.stderr
    except (OSError, subprocess.TimeoutExpired):
        return ""


def binaries(name, *globs):
    found = [shutil.which(name)] + [p for g in globs for p in glob.glob(os.path.expanduser(g))]
    return sorted({os.path.realpath(p) for p in found if p})


def by_branch(v, fixed, width):
    """fixed: first fixed version per supported branch; width: how many parts make a branch.
    A branch older than the newest fixed one but missing from the list is end-of-life, which the
    PHP, Node and GitLab advisories all count as affected with no fix."""
    for f in fixed:
        if f[:width] == v[:width]:
            return ("AFFECTED", f"upgrade to {fmt(f)}+") if v < f else ("OK", "")
    if v < max(fixed):
        return "AFFECTED", f"end-of-life branch, no fix coming: move to {fmt(max(fixed))}+ or another patched branch"
    return "UNKNOWN", "newer than the advisory, check for a later one"


def version_status(adv, v):
    if "affected" in adv:  # explicit inclusive ranges, e.g. BIND
        return next(((adv.get("status", "AFFECTED"), fix) for lo, hi, fix, *only in adv["affected"]  # optional 4th item: sys.platform
                     if nums(lo) <= v <= nums(hi) and (not only or sys.platform in only)), ("OK", ""))
    status, note = by_branch(v, [nums(f) for f in adv["fixed"]], adv["branch_width"])
    if status == "AFFECTED" and adv.get("after_fix"):
        note += ", " + adv["after_fix"]
    return status, note


def check_version(adv):
    name = adv["name"]
    if "present_paths" in adv:  # no reliable version on disk (Control Web Panel): installed means check it by hand
        here = sorted({p for g in adv["present_paths"] for p in glob.glob(g)})
        return [(name, p, "installed", "REVIEW", adv["review_note"]) for p in here] or [(name, "-", "-", "NOT FOUND", "")]
    if "version_files" in adv:  # apps in web roots (WordPress, Nextcloud apps, plugins): one row per install
        found = []
        for p in sorted({p for g in adv["version_files"] for p in glob.glob(os.path.expanduser(g))}):
            try:
                m = re.search(adv["version_regex"], open(p, errors="replace").read(MAX_READ))
            except OSError:
                m = None
            if m or not adv.get("match_required"):
                found.append((os.path.dirname(os.path.dirname(p)), nums(m[1]) if m else None))
    elif "version_file" in adv:
        found = [(adv["version_file"], ver(open(adv["version_file"]).read()))] if os.path.exists(adv["version_file"]) else []
    else:
        def parse(out):  # PostgreSQL says 16.10: two parts, so it brings its own pattern
            m = re.search(adv["version_regex"], out) if "version_regex" in adv else None
            return nums(m[1]) if m else ver(out) if "version_regex" not in adv else None
        skip = tuple(adv.get("skip_prefixes", ()))  # distro builds backport fixes without a new version: the vendor notices judge those
        found = [(b, parse(run(b, adv["flag"]))) for b in binaries(adv["binary"], *adv.get("globs", [])) if not b.startswith(skip) or not skip]
    if not found:
        return [(name, "-", "-", "NOT FOUND", adv.get("not_found", ""))]
    return [(name, p, fmt(v) if v else "?", *(version_status(adv, v) if v else ("UNKNOWN", "couldn't read version")))
            for p, v in found]


# --- Browsers Puppeteer and Playwright download --------------------------------------------------
# They sit in a cache and never update, so a laptop with an up-to-date Chrome can still drive a
# year-old Chromium that any page it opens can exploit.

def chromium_version(d):
    m = re.search(r"\d+\.\d+\.\d+\.\d+$", d)  # Puppeteer names folders by version: mac_arm-142.0.7444.175
    if m:
        return ver(m[0])
    for plist in glob.glob(os.path.join(d, "*", "*.app", "Contents", "Info.plist")):  # macOS, no need to start it
        try:
            return ver(plistlib.load(open(plist, "rb")).get("CFBundleShortVersionString"))
        except (OSError, plistlib.InvalidFileException, AttributeError):
            pass
    for exe in glob.glob(os.path.join(d, "*", "chrome")) + glob.glob(os.path.join(d, "*", "*headless*shell")):
        v = ver(run(exe, "--version"))
        if v:
            return v
    return None


def check_chromium_cache():
    name = CHROMIUM["name"]
    globs = CHROMIUM["dirs"] + [os.path.join(os.environ[e], "chrom*", "*") if e == "PUPPETEER_CACHE_DIR"
                                else os.path.join(os.environ[e], "chromium*")
                                for e in ("PUPPETEER_CACHE_DIR", "PLAYWRIGHT_BROWSERS_PATH") if os.environ.get(e)]
    dirs = sorted({os.path.realpath(p) for g in globs for p in glob.glob(os.path.expanduser(g)) if os.path.isdir(p)})
    rows = []
    for d in dirs:
        v = chromium_version(d)
        if v:
            status, note = version_status(CHROMIUM, v)
            rows.append((name, d, fmt(v), status, "never updates itself: " + note if status == "AFFECTED" else note))
        elif re.search(r"-\d{6,7}$", d):  # revision-numbered builds are from Puppeteer < 20 (2023)
            rows.append((name, d, "old revision", "AFFECTED", "a 2023-or-older build: delete it"))
        else:
            rows.append((name, d, "?", "UNKNOWN", "couldn't read version"))
    return rows or [(name, "-", "-", "NOT FOUND", "")]


# --- Electron apps --------------------------------------------------------------------------------
# VS Code, Cursor, Slack, Postman... each ships its own Chromium. Electron backports Chrome's security
# fixes only to its newest three majors, so an app on an older one keeps every Chrome bug fixed since.

ELECTRON = ADVISORIES["electron"]
ELECTRON_TAG = re.compile(rb"Electron/(\d+\.\d+\.\d+)")
CHROME_TAG = re.compile(rb"Chrome/(\d+\.\d+\.\d+\.\d+)")


def electron_binaries(adv=ELECTRON):
    """{app folder: binary holding the Electron and Chrome version strings}."""
    out = {}
    for g in adv["mac"]:  # .../X.app/Contents/Frameworks/Electron Framework.framework/Electron Framework
        for fw in glob.glob(os.path.expanduser(g)):
            out.setdefault(fw.split(".app/Contents/")[0] + ".app", fw)
    for g in adv["linux"]:  # the app's main executable sits next to resources/app.asar
        for asar in glob.glob(os.path.expanduser(g)):
            d = os.path.dirname(os.path.dirname(asar))
            exes = [p for p in glob.glob(os.path.join(d, "*")) if os.path.isfile(p) and os.access(p, os.X_OK)]
            if exes:
                out.setdefault(d, max(exes, key=os.path.getsize))
    return out


def electron_versions(path):
    """(Electron version, Chromium version) read from the binary without running it."""
    found, tail = {}, b""
    try:
        with open(path, "rb") as f:
            while len(found) < 2 and (chunk := f.read(1 << 22)):
                buf = tail + chunk
                for key, rx in (("e", ELECTRON_TAG), ("c", CHROME_TAG)):
                    if key not in found and (m := rx.search(buf)):
                        found[key] = m[1].decode()
                tail = buf[-64:]  # a version string split across two reads
    except OSError:
        pass
    return found.get("e"), found.get("c")


def check_electron(adv=ELECTRON):
    name, sup = adv["name"], adv["supported"]
    rows = []
    for app, binary in sorted(electron_binaries(adv).items()):
        e, c = electron_versions(binary)
        if not e:
            rows.append((name, app, "?", "UNKNOWN", "couldn't read its Electron version"))
            continue
        major = int(e.split(".")[0])
        shown = f"Electron {e}" + (f", Chromium {c}" if c else "")
        if major < min(sup):
            rows.append((name, app, shown, "AFFECTED", f"Electron {major} no longer gets Chrome's security fixes (only {min(sup)}-{max(sup)} do): "
                         "update the app; if it is already up to date, its maker ships an unsupported Electron"))
        elif major > max(sup):
            rows.append((name, app, shown, "UNKNOWN", "newer than the Electron versions this release knows"))
        else:
            rows.append((name, app, shown, "OK", ""))
    return rows or [(name, "-", "-", "NOT FOUND", "")]


# --- MCP servers that will never be patched -------------------------------------------------------

# --- How safe is this machine for an AI agent? -----------------------------------------------------
# Config findings, not CVEs, so everything here is REVIEW. Values of secrets are never read out or printed.

AGENT = ADVISORIES["agent"]
AGENT_MARKERS = {"CLAUDE.md", "AGENTS.md", ".mcp.json", "GEMINI.md", ".cursorrules"}
AGENT_DIRS = {".claude", ".cursor", ".codex", ".gemini"}


def server_entries(obj):
    """Every {"command": ..., "args": [...]} in an MCP config, however deeply it's nested
    (~/.claude.json keeps one list per project; VS Code says "servers", Claude "mcpServers")."""
    if isinstance(obj, dict):
        if isinstance(obj.get("command"), str):
            yield obj
        for v in obj.values():
            yield from server_entries(v)
    elif isinstance(obj, list):
        for v in obj:
            yield from server_entries(v)


def unpinned(command, args):
    """The package spec if this server is fetched fresh on every start (npx/bunx/uvx without a version)."""
    args = [a for a in (args or []) if isinstance(a, str)]
    base = os.path.basename(command)
    if base in ("pnpm", "yarn") and args[:1] == ["dlx"]:
        base, args = "npx", args[1:]
    if base not in ("npx", "bunx", "uvx"):
        return None
    if base == "uvx" and "--from" in args[:-1]:
        spec = args[args.index("--from") + 1]
    else:
        spec = next((a for a in args if not a.startswith("-")), None)
    if not spec:
        return None
    if base == "uvx":
        return None if re.search(r"==|@\d", spec) else spec
    name, _, version = spec[1:].partition("@") if spec.startswith("@") else spec.partition("@")
    return spec if version in ("", "latest", "next") else None


FOUND_MCP = {}  # (config path, server name) -> its entry; filled as configs are read, like FOUND_LOCKFILES
MCP_KEYS = ("mcpServers", "servers", "mcp_servers", "context_servers")  # Claude and Cursor, VS Code, Codex, Zed


def named_servers(obj):
    """(name, entry) for every MCP server in a config, wherever its servers map sits (~/.claude.json has one per project)."""
    if isinstance(obj, dict):
        for k, v in obj.items():
            if k in MCP_KEYS and isinstance(v, dict):
                yield from ((n, e) for n, e in v.items()
                            if isinstance(e, dict) and (isinstance(e.get("command"), str) or isinstance(e.get("url"), str)))
            else:
                yield from named_servers(v)
    elif isinstance(obj, list):
        for v in obj:
            yield from named_servers(v)


def server_package(command, args):
    """(ecosystem, package, version or "") for a server started through npx / bunx / pnpm dlx / uvx; None for a local program.
    ponytail: docker run images aren't parsed (its options take values, so the image isn't findable by position)."""
    args = [a for a in (args or []) if isinstance(a, str)]
    base = os.path.basename(command or "")
    if base in ("pnpm", "yarn") and args[:1] == ["dlx"]:
        base, args = "npx", args[1:]
    if base not in ("npx", "bunx", "uvx"):
        return None
    flag = next((f for f in (("--from",) if base == "uvx" else ("-p", "--package")) if f in args[:-1]), None)
    spec = args[args.index(flag) + 1] if flag else next((a for a in args if not a.startswith("-")), None)
    if not spec:
        return None
    if base == "uvx":
        m = re.fullmatch(r"([A-Za-z0-9][\w.-]*)(?:\[[^\]]*\])?(?:(?:==|@)(\d[\w.!+]*))?", spec)
        return ("PyPI", m[1], m[2] or "") if m else None
    name, _, version = spec[1:].partition("@") if spec.startswith("@") else spec.partition("@")
    name = "@" + name if spec.startswith("@") else name
    return ("npm", name, version if re.fullmatch(r"\d[\w.+-]*", version) else "") if re.fullmatch(r"[@\w./-]+", name) else None


def npx_cached(name, home=HOME):
    """The newest version of a package in npx's cache: what an unpinned server last ran. npx may fetch a newer one next time."""
    found = []
    for p in glob.glob(os.path.join(home, ".npm", "_npx", "*", "node_modules", *name.split("/"), "package.json")):
        try:
            found.append(str(json.load(open(p)).get("version", "")))
        except (OSError, ValueError, AttributeError):
            pass
    return max((v for v in found if re.fullmatch(r"\d[\w.+-]*", v)), key=nums, default="")


def server_summary(name, e, home=HOME):
    """What one MCP server entry runs, without its secrets: env and header names only, the URL's host only, and for a
    local program its name and first argument (later arguments can carry tokens or connection strings)."""
    out = {"kind": "MCP server", "name": name, "package": "", "ecosystem": "", "version": "", "last_fetched": "", "pinned": None, "url": "",
           "env": sorted(str(k) for d in (e.get("env"), e.get("headers")) if isinstance(d, dict) for k in d)}
    if isinstance(e.get("url"), str):
        u = urllib.parse.urlsplit(e["url"])
        out["url"] = out["runs"] = f"{u.scheme}://{u.hostname or ''}"
        return out
    pkg = server_package(e.get("command"), e.get("args"))
    if pkg:
        eco, pname, version = pkg
        out.update(ecosystem=eco, package=pname, version=version, pinned=bool(version),
                   last_fetched="" if version or eco != "npm" else npx_cached(pname, home))
        out["runs"] = f"{eco} {pname}" + (f"@{version}" if version else " (no version pinned" + (f", last fetched {out['last_fetched']})" if out["last_fetched"] else ")"))
    else:
        first = next((a for a in (e.get("args") or []) if isinstance(a, str) and not a.startswith("-") and "://" not in a and "=" not in a), "")
        out["runs"] = (os.path.basename(e["command"]) + " " + first).strip()
    return out


AGENT_FEED = ADVISORIES.get("agent_feed", {"name": "AI agent: MCP server advisories", "packages": []})
FEED_RANK = {"MALICIOUS": 0, "CRITICAL": 0, "HIGH": 1, "MODERATE": 2, "LOW": 3}  # 0 and 1 are AFFECTED, like --osv


def feed_hits(eco, package, version):
    """The feed's advisories for this package that cover this version, and all of them (for a version we can't tell).
    A range is [first affected, first fixed]; "" = no fix listed; a third item = the second is the last affected version."""
    key = lambda v: tuple(int(x) for x in re.findall(r"\d+", v))  # ponytail: digits only, so 2.0.0a1 sorts after 2.0.0
    entry = next((p for p in AGENT_FEED["packages"] if p["package"] == package and p["ecosystem"].lower() == eco.lower()), None)
    every = entry["advisories"] if entry else []
    covers = lambda lo, hi, last=None: key(lo) <= key(version) and (not hi or key(version) < key(hi) or (last and key(version) == key(hi)))
    return [a for a in every if version and any(covers(*r) for r in a["ranges"])], every


def feed_row(name, path, label, eco, package, version, pin=" and pin it"):
    """One row for a package the feed has advisories against, or None: AFFECTED / REVIEW at a known version, REVIEW at an unknown one."""
    hits, every = feed_hits(eco, package, version)
    fixes = [r[1] for a in (hits or every) for r in a["ranges"] if r[1] and len(r) == 2]
    fix = f"update to {max(fixes, key=vkey)}+{pin}" if fixes else "no fixed version listed: remove it or replace it"
    if hits:
        worst = min(FEED_RANK.get(a["severity"], 9) for a in hits)
        what = "a malicious package" if any(a["severity"] == "MALICIOUS" for a in hits) else \
            f"{len(hits)} known ({ {0: 'critical', 1: 'high', 2: 'medium', 3: 'low'}.get(worst, 'unrated')})"
        ids = ", ".join(a["id"] for a in sorted(hits, key=lambda a: FEED_RANK.get(a["severity"], 9))[:3]) + (", …" if len(hits) > 3 else "")
        return (name, path, f"{label} {version}", "AFFECTED" if worst <= 1 else "REVIEW", f"{what}: {ids}; {fix}")
    if every and not version:
        return (name, path, label, "REVIEW",
                f"{len(every)} advisories are known for this package and {'no version is pinned' if pin else 'its version could not be read'}, so it can't be judged: {fix}")


def check_agent_feed(home=HOME):
    """Each configured MCP server's package against the signed feed: offline, at the pinned version or the one npx last fetched."""
    name, rows, seen = AGENT_FEED["name"], [], 0
    for (path, server), e in sorted(FOUND_MCP.items()):
        eco, package, version = server_package(e.get("command"), e.get("args")) or ("", "", "")
        if not package:
            continue
        seen += 1
        row = feed_row(name, path, f"{server}: {package}", eco, package, version or (npx_cached(package, home) if eco == "npm" else ""))
        rows += [row] if row else []
    return rows or [(name, f"{seen} MCP server packages" if seen else "-", "-", "OK" if seen else "NOT FOUND",
                     "none has a known advisory in the feed" if seen else "")]


AGENT_TOOLS = "AI agent: coding agent advisories"
# the agents themselves, which the feed also covers: command, the package its advisories are filed under, where else it installs
TOOLS = (("Claude Code", "claude", "@anthropic-ai/claude-code", ("~/.local/bin/claude", "~/.claude/local/claude", "/opt/homebrew/bin/claude", "/usr/local/bin/claude")),
         ("Codex", "codex", "@openai/codex", ("~/.local/bin/codex", "/opt/homebrew/bin/codex", "/usr/local/bin/codex")))
FOUND_TOOLS = []  # (name, binary, package, version), for the inventory


def check_agent_tools(tools=TOOLS):
    """The installed coding agents against the same feed, at the version each one reports."""
    rows = []
    for label, cmd, package, globs in tools:
        for b in binaries(cmd, *globs):
            m = re.search(r"\d+\.\d+\.\d+[\w.-]*", run(b, "--version"))
            FOUND_TOOLS.append((label, b, package, m[0] if m else ""))
            rows.append(feed_row(AGENT_TOOLS, b, label, "npm", package, m[0] if m else "", pin="")
                        or (AGENT_TOOLS, b, f"{label} {m[0] if m else ''}".strip(), "OK", ""))
    return rows or [(AGENT_TOOLS, "-", "-", "NOT FOUND", "")]


def agent_inventory(rows, home=HOME):
    """One entry per MCP server, skill, hook and permission setting: everything the agents on this machine can load or
    run, with the findings the checks above raised against each. Built from what the scan already read."""
    worst = lambda rs: min((r[3] for r in rs), key=STATUSES.index, default="OK")
    inv = [{"kind": "agent", "name": label, "where": b, "version": version, "runs": f"{package} {version}".strip(),
            "status": worst(mine), "findings": sorted({r[4] for r in mine})}
           for label, b, package, version in FOUND_TOOLS
           for mine in [[r for r in rows if r[0] == AGENT_TOOLS and r[1] == b and r[3] in ("AFFECTED", "REVIEW")]]]
    for (path, name), e in sorted(FOUND_MCP.items()):
        it = server_summary(name, e, home)
        mine = [r for r in rows if r[1].startswith(path) and r[3] in ("AFFECTED", "REVIEW") and it["package"]
                and (r[0] == "AI agent: unpinned MCP servers" and r[2].startswith(it["package"])
                     or r[0] == MCP["name"] and it["package"].endswith(r[2])
                     or r[0] == AGENT_FEED["name"] and r[2].startswith(f"{name}: {it['package']}")
                     or r[0] == OSV_ITEM and f" {it['package']} " in f" {r[2]} " and r[1].endswith(f"(MCP server {name})"))]
        inv.append({**it, "where": path, "status": worst(mine), "findings": sorted({f"{r[0]}: {r[4]}" for r in mine})})
    for d in skill_dirs(home, FOUND_SKILL_DIRS):
        mine = [r for r in rows if r[0] == SKILLS["name"] and r[3] in ("AFFECTED", "REVIEW") and (r[1] == d or r[1].startswith(d + os.sep))]
        m = re.search(r"/plugins/cache/([^/]+)/([^/]+)/([^/]+)/", d + "/")
        inv.append({"kind": "skill", "name": os.path.basename(d), "where": d, "version": m[3] if m else "",
                    "runs": f"plugin {m[2]} ({m[1]})" if m else "home folder" if d.startswith(home + os.sep + ".") else "project",
                    "status": worst(mine), "findings": sorted({f"{r[2]}: {r[4]}" for r in mine})})
    for item, kind in (("AI agent: hooks", "hook"), ("AI agent: permissions", "permission")):
        inv += [{"kind": kind, "name": r[2], "where": r[1], "runs": "runs on its own" if kind == "hook" else "setting",
                 "status": r[3], "findings": [r[4]]} for r in rows if r[0] == item and r[3] == "REVIEW"]
    return inv


def inventory_table(inv):
    """The inventory as lines for the terminal: what there is, then one line each."""
    if not inv:
        return ["Agent inventory: no MCP servers, skills, hooks or agent settings found"]
    count = lambda k: sum(i["kind"] == k for i in inv)
    out = [f"Agent inventory: {count('agent')} agents, {count('MCP server')} MCP servers, {count('skill')} skills, {count('hook')} hooks, "
           f"{count('permission')} permission settings to review"]
    quiet = sum(i["kind"] == "skill" and i["status"] == "OK" for i in inv)  # hundreds on a busy machine: counted, not listed
    cells = [(i["kind"], i["name"][:40], i["runs"][:60], i["status"], i["where"]) for i in inv if i["kind"] != "skill" or i["status"] != "OK"]
    widths = [max(len(str(c[n])) for c in cells) for n in range(4)] if cells else []
    return out + ["  ".join(str(c).ljust(w) for c, w in zip(row, widths)) + "  " + row[4] for row in cells] \
        + ([f"{quiet} skills with nothing flagged aren't listed; --json FILE has every one"] if quiet else [])


def load_config(path, data):
    try:
        if path.endswith(".toml"):
            import tomllib  # 3.11+; older Pythons just skip Codex's config
            return tomllib.loads(data.decode("utf-8", "replace"))
        return json.loads(data)
    except Exception:  # ponytail: JSONC with comments (VS Code) is skipped, not half-parsed
        return None


def agent_config_rows(path, data):
    # catalogs of plugins you could install, and package caches holding a package's own sample config: not ones that run
    if re.search(r"/plugins/marketplaces/|/\.tmp/|/\.bun/install/cache/|/\.npm/|/node_modules/", path):
        return []
    rows = mcp_rows(path, data)
    cfg = load_config(path, data)
    if not isinstance(cfg, dict):
        return rows
    FOUND_MCP.update({(path, n): e for n, e in named_servers(cfg)})
    for spec in sorted({unpinned(e["command"], e.get("args")) for e in server_entries(cfg)} - {None}):
        rows.append(("AI agent: unpinned MCP servers", path, spec, "REVIEW",
                     "starts whatever version was published last: pin an exact version"))
    perms = cfg.get("permissions") if isinstance(cfg.get("permissions"), dict) else {}
    if perms.get("defaultMode") == "bypassPermissions":
        rows.append(("AI agent: permissions", path, "bypassPermissions", "REVIEW", "Claude Code runs every tool without asking"))
    if {"Bash", "Bash(*)", "Bash(:*)"} & set(perms.get("allow") or []):
        rows.append(("AI agent: permissions", path, "allow Bash", "REVIEW", "Claude Code runs any shell command without asking"))
    if cfg.get("sandbox_mode") == "danger-full-access" or cfg.get("approval_policy") == "never":
        rows.append(("AI agent: permissions", path, f"{cfg.get('approval_policy', '-')}/{cfg.get('sandbox_mode', '-')}", "REVIEW",
                     "Codex runs without a sandbox or without asking"))
    return rows


def ssh_key_encrypted(text):
    if "BEGIN OPENSSH PRIVATE KEY" in text:
        body = "".join(text.split("-----")[2].split())
        try:
            raw = base64.b64decode(body)
            n = int.from_bytes(raw[15:19], "big")  # after b"openssh-key-v1\0": length-prefixed cipher name
            return raw[19:19 + n] != b"none"
        except (ValueError, IndexError):
            return True
    return "ENCRYPTED" in text  # PEM: "Proc-Type: 4,ENCRYPTED" or "BEGIN ENCRYPTED PRIVATE KEY"


# --- Agent skills: what an installed skill could make your agent do --------------------------------
# A skill is a folder with a SKILL.md the agent reads as instructions, often with scripts it runs.
# ponytail: pattern checks, not a sandbox; they find the shapes Snyk's ToxicSkills research names, and
# a clean result means "nothing obvious", not "safe". Findings are REVIEW unless a known-bad author/name matches.

SKILLS = ADVISORIES["skills"]
FOUND_SKILL_DIRS = set()  # ponytail: filled by the home walk so project skills don't need a second walk
SCRIPT_EXT = (".sh", ".bash", ".zsh", ".py", ".js", ".mjs", ".cjs", ".ts", ".rb", ".pl", ".ps1", ".bat", ".cmd")
SKILL_TEXT_CHECKS = [  # (label, pattern, scripts only?)
    # the lookbehind skips quoted examples: defensive skills quote "ignore previous instructions" to warn about it
    ("hidden instruction", r"(?i)(?<![\"'\u201c\u2018(])\b(ignore (all |any )?(previous|prior|above|earlier) (instructions|prompts)|"
     r"disregard (all |the )?(previous|prior|above) (instructions|prompts)|(do not|don't|never) (tell|inform|alert) the user(?! to\b)|"
     r"hide (this|it) from the user|you are now (DAN|in developer mode))", False),
    ("invisible characters", "[\u200b\u200c\u200e\u200f\u202a-\u202e\u2060-\u2064\u2066-\u2069\U000e0000-\U000e007f]", False),
    ("pipes a download into a shell", r"(?i)\b(curl|wget)\b[^\n|;]*\|\s*(sudo\s+)?(ba|z|da)?sh\b|\biex\s*\(\s*(irm|iwr|invoke-)", False),
    ("sends data to a capture service", r"(?i)webhook\.site|requestbin|pipedream\.net|ngrok(-free)?\.(io|app)|interact\.sh|"
     r"oast\.(fun|pro|live)|burpcollaborator|discord(app)?\.com/api/webhooks|api\.telegram\.org/bot|pastebin\.com/raw", False),
    ("hard-coded secret", r"AKIA[0-9A-Z]{16}|\bsk-(ant-|proj-)?[A-Za-z0-9_-]{32,}|\bgh[pousr]_[A-Za-z0-9]{36}\b|"
     r"\bxox[abpr]-[A-Za-z0-9-]{20,}|-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----", False),
    ("reads credentials", r"(?i)\.ssh/(id_|authorized_keys)|\.aws/credentials|\.config/gcloud|\.kube/config|\.docker/config\.json|"
     r"\.netrc|\.npmrc|\.pypirc|Login Data|Cookies\.binarycookies|security find-(generic|internet)-password", True),
    ("sets up something that survives a restart", r"(?i)LaunchAgents|LaunchDaemons|crontab\b|systemctl (--user )?enable|"
     r"/etc/systemd|>>\s*\S*\.(bashrc|zshrc|profile|bash_profile)|authorized_keys", True),
    ("hides what it runs", r"(?i)eval\s*\(\s*(atob|Buffer\.from)|base64\s+(-d|--decode)[^\n]*\|\s*(ba|z)?sh|exec\s*\(\s*"
     r"(base64\.b64decode|bytes\.fromhex|codecs\.decode)|new Function\s*\(\s*atob|-enc(odedcommand)?\s+[A-Za-z0-9+/=]{20,}", True),
]
SKILL_NOTES = {
    "hidden instruction": "wording that tells the agent to override you or keep things from you",
    "invisible characters": "characters you can't see but the agent reads: check the file in a hex viewer",
    "pipes a download into a shell": "runs whatever that URL serves at the time, unreviewed",
    "sends data to a capture service": "a URL used to collect data, rarely needed by a real skill",
    "hard-coded secret": "a key or token is written into the skill (value not shown)",
    "reads credentials": "a script touches SSH, cloud or browser credentials",
    "sets up something that survives a restart": "a script installs a login item, cron job, service or shell startup line",
    "hides what it runs": "a script decodes and runs code it doesn't show",
    "downloads a program and runs it": "fetches a program at run time; what runs can change after you reviewed it",
    "ships a compiled program": "a binary the agent can run but you can't read",
    "can run any shell command": "allowed-tools lets the agent run any shell command without asking while this skill is active",
    "password-protected archive": "an encrypted zip can't be inspected; Snyk saw these in malicious skills",
}
BINARY_MAGIC = (b"\x7fELF", b"\xcf\xfa\xed\xfe", b"\xce\xfa\xed\xfe", b"\xca\xfe\xba\xbe", b"MZ")


def skill_file_findings(path, data):
    """Labels for one file in a skill. data is bytes; nothing from it is ever printed."""
    found = set()
    if data[:4] in BINARY_MAGIC[:4] or data[:2] == b"MZ":
        return {"ships a compiled program"}
    if path.endswith(".zip") and len(data) > 8 and data[:2] == b"PK" and data[6] & 1:
        return {"password-protected archive"}
    if b"\0" in data[:4096]:
        return found
    text = data.decode("utf-8", "replace")
    script = path.endswith(SCRIPT_EXT) or text.startswith("#!")
    for label, pat, scripts_only in SKILL_TEXT_CHECKS:
        if (script or not scripts_only) and re.search(pat, text.lstrip("\ufeff")):
            found.add(label)
    if script and re.search(r"(?i)\b(curl|wget)\b[^\n]*(-o\b|-O\b|--output)|urlretrieve|-OutFile|urllib\.request\.urlopen", text) \
            and re.search(r"chmod\s+(\+x|[0-7]?7[0-7]{2})|os\.chmod|chmodSync", text):
        found.add("downloads a program and runs it")
    if os.path.basename(path) == "SKILL.md":
        front = text.split("---", 2)[1] if text.startswith("---") and text.count("---") >= 2 else ""
        tools = front.split("allowed-tools", 1)[1][:400] if "allowed-tools" in front else ""
        if re.search(r"\bBash\b(?!\()|Bash\(\*\)", tools):
            found.add("can run any shell command")
    return found


def skill_dirs(home=HOME, extra=()):
    dirs = set(extra)
    for r in SKILLS["roots"]:
        for p in glob.glob(os.path.join(r.replace("~", home, 1), "**", "SKILL.md"), recursive=True):
            dirs.add(os.path.dirname(p))
    return sorted(d for d in dirs if not re.search(r"/plugins/marketplaces/|/\.tmp/|/node_modules/", d))


def skill_fingerprint(d):
    """{relative path: sha256} for every file in one skill (node_modules and .git skipped)."""
    out = {}
    for root, subdirs, files in os.walk(d):
        subdirs[:] = [x for x in subdirs if x not in SKIP]
        for f in files[:500]:
            p = os.path.join(root, f)
            try:
                with open(p, "rb") as fh:
                    out[os.path.relpath(p, d)] = hashlib.sha256(fh.read(MAX_READ)).hexdigest()
            except OSError:
                pass
    return out


def check_skill_changes(dirs, baseline):
    """Opt-in (--skills-baseline FILE): compares every skill with the last run recorded in FILE, then
    rewrites FILE (only because you named it)."""
    name, now = "AI agent: skill changes", datetime.datetime.now().strftime("%Y-%m-%d %H:%M")
    try:
        old = json.load(open(baseline))
    except (OSError, ValueError):
        old = None
    current = {d: skill_fingerprint(d) for d in dirs}
    rows = []
    if old:
        since = old.get("when", "the last run")
        for d, files in current.items():
            before = old.get("skills", {}).get(d)
            if before is None:
                rows.append((name, d, "new skill", "REVIEW", f"installed since {since}: read it before you rely on it"))
                continue
            changed = sorted(f for f in files if before.get(f) != files[f])
            if changed:
                rows.append((name, d, f"{len(changed)} file(s) changed", "REVIEW",
                             f"changed since {since}: {', '.join(changed[:5])}{' ...' if len(changed) > 5 else ''}"))
    with open(baseline, "w") as fh:
        json.dump({"when": now, "skills": current}, fh)
    first = "" if old else f"first run: recorded {len(current)} skills, changes show from the next run"
    return rows or [(name, baseline, "-", "OK", first or f"no skill changed since {old.get('when')}")]


def check_skills(home=HOME, extra=()):
    name = SKILLS["name"]
    dirs = skill_dirs(home, extra)
    rows, bad = [], [b.lower() for b in SKILLS["bad_authors"]]
    for d in dirs:
        if os.path.basename(d) in SKILLS["bad_names"]:
            rows.append((name, d, "known malicious skill", "AFFECTED", "named in Snyk's ToxicSkills research: remove it and rotate the keys it could reach"))
        for root, subdirs, files in os.walk(d):
            subdirs[:] = [x for x in subdirs if x not in SKIP and x not in ("evals", "tests", "test", "fixtures")]  # test data quotes attacks
            for f in files[:500]:
                p = os.path.join(root, f)
                try:
                    data = open(p, "rb").read(2_000_000) if os.path.getsize(p) < 20_000_000 else b""
                except OSError:
                    continue
                low = data.lower()
                if any(a.encode() in low for a in bad) or any(x.encode() in data for x in SKILLS["bad_strings"]):
                    rows.append((name, p, "known malicious author", "AFFECTED", "matches an author or file Snyk confirmed malicious: remove the skill, rotate keys"))
                rows += [(name, p, label, "REVIEW", SKILL_NOTES[label]) for label in sorted(skill_file_findings(p, data))]
    if not dirs:
        return [(name, "-", "-", "NOT FOUND", "")]
    rows.append((name, f"{len(dirs)} skills checked", "-", "OK", "")) if not rows else None
    return rows


def check_hooks(home=HOME):
    """Plugin and settings hooks run a command on their own, on events like SessionStart. Listing them is the check."""
    name, rows = "AI agent: hooks", []
    paths = glob.glob(os.path.join(home, ".claude", "plugins", "cache", "**", "hooks.json"), recursive=True) + \
        [os.path.join(home, ".claude", "settings.json")]
    for p in sorted(set(paths)):
        try:
            hooks = json.load(open(p)).get("hooks", {})
        except (OSError, ValueError, AttributeError):
            continue
        cmds = {}
        for event, groups in (hooks.items() if isinstance(hooks, dict) else []):
            for h in (x for g in groups if isinstance(g, dict) for x in g.get("hooks", []) if isinstance(x, dict)):
                c = str(h.get("command") or "").strip()
                if c:
                    first = c[1:].split(c[0], 1)[0] if c[0] in "\"'" else c.split()[0]  # quoted paths have spaces
                    label = os.path.basename(first) if first not in ("[", "test", "if", "sh", "bash", "zsh", "node", "python", "python3", "npx") else c[:50]
                    cmds.setdefault(label, set()).add(event)
        for cmd, events in sorted(cmds.items()):
            rows.append((name, p, cmd, "REVIEW", f"runs automatically on {len(events)} event(s) ({', '.join(sorted(events)[:4])}"
                         f"{'...' if len(events) > 4 else ''}): make sure you know what it does"))
    return rows or [(name, "-", "-", "NOT FOUND", "")]


def check_iocs(home=HOME):
    """Traces a known malware campaign leaves on disk. Reports which file matched, never its contents."""
    rows = []
    for ioc in ADVISORIES.get("iocs", []):
        name, hits = ioc["name"], []
        at = lambda g: g.replace("~", home, 1).replace("{tmp}", tempfile.gettempdir())
        for g in ioc.get("files", []):
            hits += [(p, "persistence file") for p in glob.glob(at(g)) if re.search(ioc["file_regex"], p)]
        for g, needle in ioc.get("contains", []):
            for p in glob.glob(at(g)):
                try:
                    if needle in open(p, errors="replace").read(MAX_READ):
                        hits.append((p, f"{needle} entry"))
                except OSError:
                    pass
        if ioc.get("crontab") and ioc["crontab"] in run("crontab", "-l"):
            hits.append(("crontab", "@reboot entry"))
        for g in ioc.get("extensions", []):
            hits += [(p, "malicious extension version") for p in glob.glob(at(g))]
        rows += [(name, p, what, "AFFECTED", ioc["cleanup"]) for p, what in sorted(set(hits))]
        if not any(r[0] == name for r in rows):
            rows.append((name, "-", "-", "NOT FOUND", ""))
    return rows


def check_ssh_keys():
    rows = []
    for p in sorted(glob.glob(os.path.join(HOME, ".ssh", "*"))):
        if p.endswith(".pub") or not os.path.isfile(p) or os.path.getsize(p) > 64_000:
            continue
        try:
            head = open(p, errors="replace").read()
        except OSError:
            continue
        if "PRIVATE KEY-----" in head and not ssh_key_encrypted(head):
            rows.append(("AI agent: secrets in reach", p, "no passphrase", "REVIEW",
                         "anything running as you, including an agent following a prompt injection, can copy and use it"))
    return rows


def env_rows(d, dirs, files, home=HOME):
    """A folder an agent works in (it has CLAUDE.md, AGENTS.md, .claude/ ...) that also holds a .env."""
    envs = sorted(f for f in files if f == ".env" or (f.startswith(".env.") and not f.endswith((".example", ".sample", ".template"))))
    if not envs or not (AGENT_MARKERS & set(files) or AGENT_DIRS & set(dirs)):
        return []
    deny = []
    for sp in (os.path.join(d, ".claude", "settings.json"), os.path.join(d, ".claude", "settings.local.json"),
               os.path.join(home, ".claude", "settings.json")):
        try:
            deny += json.load(open(sp)).get("permissions", {}).get("deny", [])
        except (OSError, ValueError, AttributeError):
            pass
    if any(".env" in str(x) for x in deny):
        return []
    return [("AI agent: secrets in reach", os.path.join(d, e), ".env", "REVIEW",
             "an agent works in this folder and can read it") for e in envs]


def mcp_rows(path, data):
    rows = []
    for server in sorted(set(re.findall(rb"@modelcontextprotocol/(server-[a-z0-9-]+)", data))):
        server = server.decode()
        if server in MCP["rce"]:
            rows.append((MCP["name"], path, server, "AFFECTED",
                         "remote code execution through prompt injection, and no fix is coming: remove it"))
        elif server in MCP["deprecated"]:
            rows.append((MCP["name"], path, server, "REVIEW", "archived, gets no security fixes: switch to the vendor's own server"))
    return rows


def check_mcp(rows):
    """Configs outside the walked folders (~/Library is skipped, and some names are too generic to match)."""
    out = []
    for p in sorted({os.path.expanduser(c) for c in MCP["configs"]}):
        if os.path.isfile(p) and os.path.getsize(p) < MAX_READ and not any(r[1] == p for r in rows):
            try:
                out += agent_config_rows(p, open(p, "rb").read())
            except OSError:
                pass
    out += check_ssh_keys()
    for name in (MCP["name"], "AI agent: unpinned MCP servers", "AI agent: permissions", "AI agent: secrets in reach"):
        if not any(r[0] == name for r in rows + out):
            out.append((name, "-", "-", "NOT FOUND", ""))
    return out


# --- Linux server packages (apt / dnf) ----------------------------------------------------------
# Distros backport fixes without changing the upstream version (a patched Ubuntu nginx still says
# 1.24.0), so these compare the installed package against the distro's own fixed build, using
# dpkg/rpm themselves to order versions. Builds from vendor repos (nginx.org, PGDG, MongoDB, Docker)
# carry a different upstream version and fall back to the upstream fixed versions.

DISTRO = ADVISORIES.get("distro", [])


def os_release(text):
    """'ubuntu:24.04', 'debian:12', 'el:9' (RHEL, Alma, Rocky, CentOS Stream, Oracle) or None."""
    d = dict(re.findall(r'^(\w+)="?([^"\n]*)"?$', text, re.M))
    os_id, like, v = d.get("ID", ""), d.get("ID_LIKE", "").split(), d.get("VERSION_ID", "")
    if os_id == "ubuntu":
        return f"ubuntu:{v}"
    if os_id == "debian" and v:
        return f"debian:{v.split('.')[0]}"
    if os_id != "fedora" and {"rhel", "centos", "ol"} & {os_id, *like} and v:  # Oracle Linux says ID_LIKE="fedora"
        return f"el:{v.split('.')[0]}"
    return None


def upstream(v):
    """'1:9.6p1-3ubuntu13.5' -> '9.6p1': drop the epoch and the distro revision."""
    v = re.sub(r"^\d+:", "", v)
    return v.rsplit("-", 1)[0] if "-" in v else v


def nums(v):
    return tuple(int(x) for x in re.findall(r"\d+", v))


def verrevcmp(a, b):
    """dpkg's own comparison of one version part: ~ sorts first, letters before other symbols, digit runs as numbers."""
    def order(c):
        return 0 if c.isdigit() else ord(c) if c.isalpha() else -1 if c == "~" else ord(c) + 256
    i = j = 0
    while i < len(a) or j < len(b):
        while (i < len(a) and not a[i].isdigit()) or (j < len(b) and not b[j].isdigit()):
            ac, bc = order(a[i]) if i < len(a) else 0, order(b[j]) if j < len(b) else 0
            if ac != bc:
                return ac - bc
            i, j = i + 1, j + 1
        m, n = re.match(r"\d*", a[i:])[0], re.match(r"\d*", b[j:])[0]
        if int(m or 0) != int(n or 0):
            return int(m or 0) - int(n or 0)
        i, j = i + len(m), j + len(n)
    return 0


def deb_lt(a, b):
    """True if Debian version a sorts before b, as dpkg --compare-versions a lt b."""
    def split(v):
        e, _, rest = v.partition(":") if ":" in v else ("0", "", v)
        u, _, r = rest.rpartition("-") if "-" in rest else (rest, "", "")
        return int(e or 0), u, r
    (ea, ua, ra), (eb, ub, rb) = split(a), split(b)
    return ea < eb if ea != eb else (verrevcmp(ua, ub) or verrevcmp(ra, rb)) < 0


def rpmvercmp(a, b):
    """rpm's own comparison of one version part: alphanumeric runs, digits beat letters, ~ sorts first, ^ after."""
    i = j = 0
    while i < len(a) or j < len(b):
        while i < len(a) and not (a[i].isascii() and a[i].isalnum()) and a[i] not in "~^":
            i += 1
        while j < len(b) and not (b[j].isascii() and b[j].isalnum()) and b[j] not in "~^":
            j += 1
        ca, cb = a[i:i + 1], b[j:j + 1]
        if ca == "~" or cb == "~":
            if ca != cb:
                return -1 if ca == "~" else 1
            i, j = i + 1, j + 1
            continue
        if ca == "^" or cb == "^":
            if not ca:
                return -1
            if not cb:
                return 1
            if ca != cb:
                return 1 if cb == "^" else -1
            i, j = i + 1, j + 1
            continue
        if not ca or not cb:
            break
        pat = r"[0-9]+" if ca.isdigit() else r"[A-Za-z]+"
        m, n = re.match(pat, a[i:]), re.match(pat, b[j:])
        if not n:
            return 1 if ca.isdigit() else -1  # a number beats letters
        m, n = m[0], n[0]
        if ca.isdigit():
            if int(m) != int(n):
                return 1 if int(m) > int(n) else -1
        elif m != n:
            return 1 if m > n else -1
        i, j = i + len(m), j + len(n)
    return 0 if i >= len(a) and j >= len(b) else -1 if i >= len(a) else 1


def rpm_lt(a, b):
    """EVR comparison as rpm does it: epoch, then version, then release."""
    def evr(s):
        e, _, vr = s.rpartition(":") if ":" in s else ("0", "", s)
        v, _, r = vr.partition("-")
        return int(e or 0), v, r
    (ea, va, ra), (eb, vb, rb) = evr(a), evr(b)
    return ea < eb if ea != eb else (rpmvercmp(va, vb) or rpmvercmp(ra, rb)) < 0


def installed(fam, names):
    """[(package, version, source package)] for the installed ones."""
    if not names:
        return []  # dpkg-query/rpm with no names list every package
    if fam == "brew":  # "mongodb-community 7.0.12 8.3.7": old kegs stay until brew cleanup; the newest is the one that runs
        try:  # stdout only: names that aren't installed print errors and exit 1, the rest are still listed
            out = subprocess.run(["brew", "list", "--versions", "--formula", *names], capture_output=True, text=True, timeout=60).stdout
        except (OSError, subprocess.TimeoutExpired):
            return []
        return [(p, max(vs, key=nums), p) for p, *vs in (l.split() for l in out.splitlines()) if vs]
    if fam == "deb":
        out = run("dpkg-query", "-W", "-f", "${db:Status-Abbrev}\t${Package}\t${Version}\t${source:Package}\n", *names)
        rows = [l.split("\t") for l in out.splitlines()]
        return [tuple(r[1:]) for r in rows if len(r) == 4 and r[0].startswith("ii")]
    out = run("rpm", "-q", "--qf", "%{NAME}\t%|EPOCH?{%{EPOCH}:}:{}|%{VERSION}-%{RELEASE}\t%{NAME}\n", *names)
    return [tuple(l.split("\t")) for l in out.splitlines() if l.count("\t") == 2]


def running_kernel(fam):
    """(package, version, source) of the kernel actually booted: a fixed one only counts after a reboot."""
    rel = platform.release()
    if fam == "deb":
        owner = run("dpkg-query", "-S", f"/boot/vmlinuz-{rel}").split(": ")[0].split(":")[0].strip()
        found = installed("deb", [owner]) if owner and " " not in owner else []
        # linux-signed-hwe-6.8 / linux-signed-amd64 ship the image; the advisory names linux-hwe-6.8 / linux
        return [(p, v, re.sub(r"-signed(-(amd64|arm64|i386))?", "", s)) for p, v, s in found]
    out = run("rpm", "-qf", "--qf", "%{NAME}\t%|EPOCH?{%{EPOCH}:}:{}|%{VERSION}-%{RELEASE}\t%{NAME}\n", f"/lib/modules/{rel}/vmlinuz")
    return [tuple(l.split("\t")) for l in out.splitlines() if l.count("\t") == 2]


def distro_status(adv, release, version, source, lt):
    """Status for one installed package. adv["fixed"][release] is the first fixed build, a
    {source package: build} map (kernel flavours), "not-affected" or "unfixed"; release "*" covers every release
    and Homebrew (e.g. a vendor fix nobody ships yet)."""
    fixed = adv.get("fixed", {}).get(release) or adv.get("fixed", {}).get("*")
    if isinstance(fixed, dict):
        fixed = fixed.get(source) or fixed.get("*")
    proposed = isinstance(fixed, str) and fixed.startswith("proposed:")  # fix only in Ubuntu's testing pocket so far
    fixed = fixed[len("proposed:"):] if proposed else fixed
    ups = [nums(f) for f in adv.get("upstream_fixed", [])]
    after = (", " + adv["after_fix"]) if adv.get("after_fix") else ""
    extra = adv.get("release_notes", {}).get((release or "").split(":")[0])  # e.g. an AlmaLinux-only remark
    after += f" ({extra})" if extra else ""
    if fixed == "not-affected":
        return "OK", f"{release} isn't affected"
    if fixed and fixed != "unfixed" and (not ups or upstream(version) == upstream(fixed)):
        if not lt(version, fixed):
            return "OK", ""
        if proposed:
            return "AFFECTED", f"fixed in {fixed}, so far only in {release}'s -proposed pocket: install it from there or wait for -updates{after}"
        return "AFFECTED", f"update to {fixed}+{after}"
    unfixed = (adv.get("status", "AFFECTED"), f"no fixed {release or 'upstream'} package yet: {adv.get('mitigation', 'watch for the update')}")
    if ups:  # vendor build, or the distro moved to a new upstream release
        status, note = by_branch(nums(upstream(version)), ups, adv.get("branch_width", 2))
        if status == "AFFECTED" and fixed == "unfixed":
            return unfixed
        return status, (note + after if status == "AFFECTED" else note)
    if fixed == "unfixed":
        return unfixed
    return "UNKNOWN", f"no fixed version known for {release or 'this distro'}"


def check_distro(os_text=None, offline=True):
    rows = check_distro_fam("brew", None) if shutil.which("brew") else []  # macOS, or Linuxbrew next to apt/dnf
    if os_text is None:
        try:
            os_text = open("/etc/os-release").read()
        except OSError:
            return rows  # not Linux: Homebrew is the only package manager to ask
    fam = "deb" if shutil.which("dpkg-query") else "rpm" if shutil.which("rpm") else None
    if not fam:
        return rows + [("Server packages", "-", "-", "UNKNOWN", "only apt (Ubuntu/Debian) and dnf (RHEL family) systems are checked")]
    return rows + merge_vendor(check_distro_fam(fam, os_release(os_text)), check_vendor(os_text, offline))


def merge_vendor(hand, vendor):
    """A vendor row for packages a hand-picked AFFECTED row already names goes into that row's note: one row to fix."""
    hand = list(hand)
    for v in vendor:
        bins, pm = set(VENDOR_FIXES.get(v[0], ())), str(v[1]).rsplit(" (", 1)[-1]
        i = next((i for i, h in enumerate(hand) if h[3] == "AFFECTED" and str(h[1]).endswith(f"({pm}")
                  and bins & set(str(h[1]).rsplit(" (", 1)[0].split())), None)
        if i is None:
            hand.append(v)
        else:
            hand[i] = hand[i][:4] + (f"{hand[i][4]}; {v[0]} also pending: {v[4]}",)
    return hand


def check_distro_fam(fam, release):
    """One row per advisory for packages from apt (deb), dnf (rpm) or Homebrew (brew; upstream versions, no release)."""
    lt = deb_lt if fam == "deb" else rpm_lt
    rows = []
    for adv in DISTRO:
        if not adv.get("kernel") and not adv.get(f"{fam}_packages"):
            continue  # e.g. mod_http2 is its own package only on RHEL; apache2 covers it on Debian
        if adv.get("kernel") and fam == "brew":
            continue
        found = running_kernel(fam) if adv.get("kernel") else installed(fam, adv.get(f"{fam}_packages", []))
        if not found:
            rows += [] if fam == "brew" else [(adv["name"], "-", "-", "NOT FOUND", "")]  # not on a Mac, nor twice on Linux
            continue
        # one row per advisory: nginx + nginx-core or mariadb-server + -core are one thing to fix
        checked = [(pkg, version, *distro_status(adv, release, version, source, lt)) for pkg, version, source in found]
        worst = min(checked, key=lambda c: STATUSES.index(c[2]))
        pkgs = " ".join(sorted({c[0] for c in checked}))
        rows.append((adv["name"], f"{pkgs} ({ {'deb': 'apt', 'rpm': 'dnf'}.get(fam, fam)})", worst[1], worst[2], worst[3]))
    return rows


# --- Vendor security data: every installed package, not only the hand-picked list ---------------
# The machine lists what it has, then matches it against the vendor's own notices, downloaded and
# kept here. Only the vendor's public file is fetched; the package list never leaves the machine.
# os-release ID -> (label, OVAL file, which os-release field goes in it)
VENDOR_OVAL = {
    "ubuntu": ("Ubuntu", "https://security-metadata.canonical.com/oval/com.ubuntu.{}.usn.oval.xml.bz2", "VERSION_CODENAME"),
    "rhel": ("RHEL", "https://security.access.redhat.com/data/oval/v2/RHEL{0}/rhel-{0}.oval.xml.bz2", "VERSION_ID"),
    "almalinux": ("AlmaLinux", "https://security.almalinux.org/oval/org.almalinux.alsa-{}.xml.bz2", "VERSION_ID"),
    # Rocky's own OVAL stopped being updated in 2024; Rocky rebuilds RHEL with identical package versions, so Red Hat's fits
    "rocky": ("Rocky Linux", "https://security.access.redhat.com/data/oval/v2/RHEL{0}/rhel-{0}.oval.xml.bz2", "VERSION_ID"),
    "ol": ("Oracle Linux", "https://linux.oracle.com/security/oval/com.oracle.elsa-ol{}.xml.bz2", "VERSION_ID"),
    # one definition per fixed CVE, tested on the source package; Debian rates no severity, so KEV alone makes AFFECTED
    "debian": ("Debian", "https://www.debian.org/security/oval/oval-definitions-{}.xml.bz2", "VERSION_CODENAME"),
}
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
VENDOR_FIXES = {}  # row item -> {binary package: first fixed version}, for --fix


def cache_dir():
    return "/var/cache/amiaffected" if is_root() else os.path.join(HOME, ".cache", "amiaffected")


def cached(url, name, offline, max_age=6 * 3600):
    """Path of a local copy of url, refreshed when older than max_age; the old copy if the download fails."""
    path = os.path.join(cache_dir(), name)
    fresh = os.path.exists(path) and time.time() - os.path.getmtime(path) < max_age
    if not fresh and not offline:
        try:
            data = fetch(url)
            os.makedirs(cache_dir(), mode=0o755, exist_ok=True)
            with open(path + ".tmp", "wb") as fh:
                fh.write(data)
            os.replace(path + ".tmp", path)
        except OSError:
            pass
    return path if os.path.exists(path) else None


def oval_notices(path, inst, lt):
    """[(title, severity, [cve], {installed package: first fixed version})] for the notices in a vendor OVAL file
    (Canonical, Debian, Red Hat, Alma, Rocky, Oracle) whose conditions hold on this machine. inst is {name: (version, source,
    arch)}. Version, release, arch and existence tests are judged; signature and release-file tests pass; anything
    else (kernel uname with a state, module streams) is unknown, and unknown stays unknown even under negate, so a
    condition it can't judge can miss a notice, never invent one. extend_definition (the OS check) and Debian's
    release-file and state-less uname tests pass."""
    tests, objs, states, names, defs = {}, {}, {}, {}, []

    def tree(c):
        kids = []
        for k in c:
            t = k.tag.rsplit("}", 1)[-1]
            if t == "criteria":
                kids.append(tree(k))
            elif t == "criterion":
                kids.append(("T", k.get("test_ref"), k.get("negate") == "true"))
            elif t == "extend_definition":  # "Ubuntu 24.04 is installed": known from /etc/os-release
                kids.append(("D", None, k.get("negate") == "true"))
        return (c.get("operator", "AND"), kids, c.get("negate") == "true")

    for _, el in ET.iterparse(bz2.open(path)):
        tag, i = el.tag.rsplit("}", 1)[-1], el.get("id")
        if tag.endswith("_test"):
            o, st = el.find("{*}object"), el.find("{*}state")
            tests[i] = (tag, el.get("check", "at least one"), o.get("object_ref") if o is not None else None,
                        st.get("state_ref") if st is not None else None)
        elif tag == "textfilecontent54_object":
            objs[i] = ("file", el.findtext("{*}filename"))
        elif tag in ("dpkginfo_object", "rpminfo_object"):
            n = el.find("{*}name")
            objs[i] = ("var", n.get("var_ref")) if n is not None and n.get("var_ref") else ("name", n.text if n is not None else None)
        elif tag in ("dpkginfo_state", "rpminfo_state"):
            states[i] = {k.tag.rsplit("}", 1)[-1]: (k.get("operation", "equals"), k.text or "") for k in el}
        elif tag == "constant_variable":
            names[i] = [v.text for v in el.findall("{*}value")]
        elif tag == "definition" and el.get("class") in ("patch", "vulnerability"):
            sev, c = el.find(".//{*}severity"), el.find("{*}criteria")
            defs.append((" ".join(el.find(".//{*}title").text.split()), (sev.text or "") if sev is not None else "",
                         sorted({x.text for x in el.findall(".//{*}cve")} |
                                {r.get("ref_id") for r in el.findall(".//{*}reference") if r.get("source") == "CVE"}),
                         tree(c) if c is not None else ("AND", [], False)))
        else:
            continue
        el.clear()

    def field_ok(b, field, op, want):
        v = inst[b][0]
        part = {"evr": v, "version": re.sub(r"^\d+:", "", v).rsplit("-", 1)[0], "release": v.rsplit("-", 1)[-1],
                "arch": inst[b][2]}.get(field)
        if field == "signature_keyid":
            return True  # ponytail: trusts that installed packages came from the vendor's signed repos
        if part is None:
            return False
        if op == "less than" and field == "evr":
            return lt(v, want)
        if op == "pattern match":
            return re.search(want, part) is not None
        return op == "equals" and part == want

    def test(ref):
        kind, check, o, s = tests.get(ref, ("?", "", None, None))
        if kind == "rpmverifyfile_test":  # "<distro> is installed" (or, with none satisfy, isn't)
            return check != "none satisfy", {}
        if kind == "textfilecontent54_test" and objs.get(o) == ("file", "debian_version"):
            return True, {}  # "Debian 12 is installed": known from /etc/os-release
        if kind == "uname_test" and s is None:
            return True, {}  # Debian's "architecture is all": uname exists; kernel tests carry a state and stay unmet
        if kind not in ("dpkginfo_test", "rpminfo_test") or o not in objs:
            return None, {}  # can't judge it: unknown, which stays unknown under negate

        how, v = objs[o]
        here = [b for b in (names.get(v, []) if how == "var" else [v]) if b in inst]
        if s is None:
            return bool(here), {}
        if s not in states or any(f != "signature_keyid" and f not in ("evr", "version", "release", "arch")
                                  or op not in ("equals", "pattern match") and (f, op) != ("evr", "less than")
                                  for f, (op, _) in states[s].items()):
            return None, {}
        ok = [b for b in here if all(field_ok(b, f, op, want) for f, (op, want) in states[s].items())]
        hit = {"at least one": bool(ok), "all": bool(here) and len(ok) == len(here), "none satisfy": not ok}.get(check, False)
        fixed = states[s].get("evr", ("", ""))
        return hit, ({b: fixed[1] for b in ok} if hit and fixed[0] == "less than" else {})

    def judge(node):
        op, kids, neg = node if len(node) == 3 and isinstance(node[1], list) else (None, None, None)
        if op is None:
            kind, ref, neg = node
            hit, fixed = (True, {}) if kind == "D" else test(ref)
        else:  # three-valued: None (unknown) never becomes True, not even through negate
            results = [judge(k) for k in kids]
            hits = [h for h, _ in results]
            if op == "AND":
                hit = False if False in hits else None if None in hits else True
            else:
                hit = True if True in hits else None if None in hits else False
            fixed = {b: f for h, fx in results if h is True for b, f in fx.items()}
        if neg and hit is not None:
            return not hit, {}
        return hit, fixed if hit is True else {}

    out = []
    for title, sev, cves, crit in defs:
        hit, fixed = judge(crit)
        if hit is True and fixed:
            out.append((title, sev, cves, fixed))
    return out


def dpkg_installed(source_version=False):
    """{binary: (version, source package, arch)} for every installed deb; with source_version, the source's version."""
    out = run("dpkg-query", "-W", "-f", "${db:Status-Abbrev}\t${Package}\t${Version}\t${source:Package}\t${Architecture}\t${source:Version}\n")
    return {r[1]: (r[5] if source_version else r[2], r[3] or r[1], r[4])
            for r in (l.split("\t") for l in out.splitlines()) if len(r) == 6 and r[0].startswith("ii")}


def rpm_installed():
    """{name: (epoch:version-release, source package, arch)}; with several installed (kernels, multilib) the newest counts."""
    out = run("rpm", "-qa", "--qf", "%{NAME}\t%|EPOCH?{%{EPOCH}}:{0}|:%{VERSION}-%{RELEASE}\t%{SOURCERPM}\t%{ARCH}\n")
    inst = {}
    for r in (l.split("\t") for l in out.splitlines()):
        if len(r) == 4 and r[0] != "gpg-pubkey" and (r[0] not in inst or rpm_lt(inst[r[0]][0], r[1])):
            inst[r[0]] = (r[1], r[2].rsplit("-", 2)[0] if r[2].endswith(".rpm") else r[0], r[3])
    return inst


def kev_ids(offline):
    """CVE ids on CISA's exploited list, or None if it can't be had."""
    path = cached(KEV_URL, "kev.json", offline)
    try:
        return {v["cveID"] for v in json.load(open(path))["vulnerabilities"]} if path else None
    except (OSError, ValueError, KeyError, TypeError):
        return None


SEVERITY = {"critical": 0, "high": 1, "important": 1, "medium": 2, "moderate": 2, "low": 3}
SEVERITY_WORD = ("critical", "high", "medium", "low")


def vendor_rows(label, pm, notices, inst, kev, lt):
    """One row per source package with pending security fixes: AFFECTED if exploited (KEV), Critical/High/Important."""
    by_src = {}
    for title, sev, cves, fixed in notices:
        for b, f in fixed.items():
            if b in inst and lt(inst[b][0], f):
                g = by_src.setdefault(inst[b][1], {"bins": {}, "ids": set(), "sev": 4, "kev": set()})
                g["bins"][b] = f if b not in g["bins"] or lt(g["bins"][b], f) else g["bins"][b]
                g["ids"].add(re.split(r"\s*(?:--|:)\s|\s", title)[0])  # USN-1-1 -- x, RHSA-2024:1: x, CVE-2024-1 glibc
                g["sev"] = min(g["sev"], SEVERITY.get(sev.strip().lower(), 4))
                g["kev"] |= {c for c in cves if c in kev}
    rows = []
    for src, g in sorted(by_src.items(), key=lambda s: (not s[1]["kev"], s[1]["sev"], s[0])):
        item = f"{label}: {src}"
        VENDOR_FIXES[item] = g["bins"]
        b0, ids = sorted(g["bins"])[0], sorted(g["ids"])
        note = f"update to {re.sub(r'^0:', '', g['bins'][b0])}+ ({', '.join(ids[:3])}{f' and {len(ids) - 3} more' if len(ids) > 3 else ''}"
        note += f"; exploited: {', '.join(sorted(g['kev']))} in CISA KEV)" if g["kev"] else (f"; {SEVERITY_WORD[g['sev']]} severity)" if g["sev"] < 4 else "; severity not rated)")
        status = "AFFECTED" if g["kev"] or g["sev"] <= 1 else "REVIEW"
        rows.append((item, f"{' '.join(sorted(g['bins']))} ({pm})", inst[b0][0], status, note))
    return rows


def check_vendor(os_text, offline):
    """Every installed package against the distro vendor's own security notices."""
    d = dict(re.findall(r'^(\w+)="?([^"\n]*)"?$', os_text, re.M))
    if d.get("ID") == "centos":  # Stream builds sort below RHEL's fixed ones even when they carry the fix
        return [("CentOS security notices", "-", "-", "UNKNOWN",
                 "CentOS publishes no security notices of its own, so only the hand-picked checks above apply")]
    if d.get("ID") not in VENDOR_OVAL:
        return []
    label, url, field = VENDOR_OVAL[d["ID"]]
    deb = d["ID"] in ("ubuntu", "debian")
    key = d.get(field, "") if deb else d.get(field, "").split(".")[0]
    if not key or not shutil.which("dpkg-query" if deb else "rpm"):
        return []
    path = cached(url.format(key), f"{d['ID']}-{key}.oval.xml.bz2", offline)
    if not path:
        return [(f"{label} security notices", "-", "-", "UNKNOWN",
                 f"couldn't download {label}'s notices (run without --no-update-check, or check the connection)")]
    inst, lt = (dpkg_installed(d["ID"] == "debian"), deb_lt) if deb else (rpm_installed(), rpm_lt)
    try:
        if d["ID"] == "debian":  # tested on source packages: match by source, then name its installed binaries
            notices = [(t, sev, c, {b: fx[x[1]] for b, x in inst.items() if x[1] in fx})
                       for t, sev, c, fx in oval_notices(path, {x[1]: x for x in inst.values()}, lt)]
        else:
            notices = oval_notices(path, inst, lt)
    except (OSError, EOFError, ET.ParseError) as e:
        return [(f"{label} security notices", path, "-", "UNKNOWN", f"couldn't read {label}'s notices: {e}")]
    kev = kev_ids(offline)
    rows = vendor_rows(label, "apt" if deb else "dnf", notices, inst, kev or set(), lt)
    if kev is None:
        rows.append(("CISA exploited list", "-", "-", "UNKNOWN", "couldn't load CISA's KEV list, so exploited CVEs "
                     "aren't ranked first or marked AFFECTED (run without --no-update-check, or check the connection)"))
    return rows


# --- CA bundles ---------------------------------------------------------------------------------

PEM = re.compile(rb"-----BEGIN CERTIFICATE-----(.+?)-----END CERTIFICATE-----", re.S)
BUNDLE_FILES = {"cacert.pem", "cert.pem", "ca-bundle.crt", "ca-certificates.crt", "tls-ca-bundle.pem", "cacerts"}

# Stores outside the walked folders. Linux system trust lands in the extracted bundles, after blocklists apply.
STORES = [
    # OpenSSL, curl and whatever links them
    "/etc/ssl/cert.pem", "/etc/ssl/certs/ca-certificates.crt", "/etc/pki/tls/certs/ca-bundle.crt",
    "/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem", "/opt/homebrew/etc/ca-certificates/cert.pem",
    "/opt/homebrew/etc/openssl*/cert.pem", "/usr/local/etc/openssl*/cert.pem", "/usr/local/etc/ca-certificates/cert.pem",
    # Java
    "/Library/Java/JavaVirtualMachines/*/Contents/Home/lib/security/cacerts",
    "/Library/Java/JavaVirtualMachines/*/Contents/Home/jre/lib/security/cacerts",
    "/usr/lib/jvm/*/lib/security/cacerts", "/etc/ssl/certs/java/cacerts", "/etc/pki/ca-trust/extracted/java/cacerts",
    "C:/Program Files/Java/*/lib/security/cacerts",
    # NSS built-in roots (Firefox, Thunderbird)
    "/Applications/Firefox*.app/Contents/MacOS/libnssckbi.dylib", "/Applications/Thunderbird.app/Contents/MacOS/libnssckbi.dylib",
    "/usr/lib/firefox*/libnssckbi.so", "/usr/lib/thunderbird/libnssckbi.so", "C:/Program Files/Mozilla Firefox/nssckbi.dll",
]


def pem(der):
    return ("-----BEGIN CERTIFICATE-----\n" + "\n".join(textwrap.wrap(base64.b64encode(der).decode(), 64))
            + "\n-----END CERTIFICATE-----\n").encode()


def roots_in(data):
    """Listed roots in a PEM bundle or a binary store (JKS/PKCS12 cacerts, libnssckbi), matched by certificate bytes."""
    if b"-----BEGIN CERTIFICATE-----" in data:
        blocks = {b"".join(m.split()) for m in PEM.findall(data)}
        return [n for n, der in ROOTS.items() if base64.b64encode(der) in blocks]
    return [n for n, der in ROOTS.items() if der in data]


def chain_accepts(bundle):
    """Cracked intermediates `openssl verify` accepts against a PEM bundle, or None if it can't run.
    OpenSSL doesn't check revocation by default, so a bundle trusting the root accepts them."""
    if not OPENSSL or b"-----BEGIN CERTIFICATE-----" not in bundle:
        return None
    with tempfile.TemporaryDirectory() as d:
        open(f"{d}/bundle.pem", "wb").write(bundle)
        accepted = []
        for name, der in INTERMEDIATES.items():
            open(f"{d}/i.pem", "wb").write(pem(der))
            if run(OPENSSL, "verify", "-CAfile", f"{d}/bundle.pem", f"{d}/i.pem").strip().endswith(": OK"):
                accepted.append(name)
        return accepted


BREW_BUNDLE = "/opt/homebrew/etc/ca-certificates/cert.pem"


def old_brew_bundle(path, new=None):
    """An Apple-silicon Mac that still has the Intel Homebrew in /usr/local: its OpenSSL bundles date from that install,
    and `brew upgrade` (the /opt/homebrew one) never touches them."""
    return path.startswith("/usr/local/etc/openssl") and os.path.exists(new or BREW_BUNDLE)


def fix_hint(path):
    p = path.lower()
    if old_brew_bundle(path):
        return (f"left by an older Homebrew in /usr/local, which brew upgrade doesn't reach: cp {BREW_BUNDLE} {shlex.quote(path)} "
                "(or remove that old OpenSSL with /usr/local/bin/brew uninstall)")
    if p.startswith("/usr/lib/python3/dist-packages/"):  # Debian/Ubuntu: apt owns these, pip refuses (PEP 668)
        return f"apt owns it (python3-{p.split('dist-packages/')[1].split('/')[0]}): sudo apt upgrade once the distro drops the root"
    if "/certifi/" in p:  # not "ca-certificates"
        return "pip install -U certifi once a release drops it"
    if "site-packages" in p:  # e.g. botocore ships its own bundle
        return f"upgrade the {p.split('site-packages/')[1].split('/')[0]} Python package once it drops the root"
    if "cacerts" in p:
        return "update the JDK, or keytool -delete the alias"
    return "update ca-certificates once it drops the root, or blocklist it (Red Hat KB 7149312)"


def store_status(path, names, accepted):
    """Status for one trust store. accepted: chain_accepts() result (None = couldn't test)."""
    if not names:
        return "OK", ""
    hint = fix_hint(path)
    if accepted:
        return "AFFECTED", f"openssl verify accepts the cracked {', '.join(accepted)}: {hint}"
    if "nss" in path.lower():
        return "REVIEW", "Firefox also blocks the intermediates via OneCRL, keep it updated"
    if accepted is None and AAA in names:
        return "AFFECTED", f"trusts {AAA}, which cross-signed the cracked intermediates: {hint}"
    return "REVIEW", f"has a root Red Hat lists, but no cracked chain verified through it: {hint}"


def bundle_summary(bundles):
    """Every venv has its own certifi, so one row per status and fix instead of one per bundle."""
    groups = {}
    for path, names, accepted in bundles:
        status, _ = store_status(path, names, accepted)
        groups.setdefault((status, fix_hint(path)), []).append((path, names, accepted))
    rows = []
    for (status, hint), items in groups.items():
        names = sorted({n for _, ns, _ in items for n in ns})
        proven = sum(bool(a) for _, _, a in items)
        note = (f"openssl verify accepts the cracked chain in {proven} of them: " if proven else "") + hint
        rows.append(("eMudhra CA", f"{len(items)} app CA bundles, e.g. {items[0][0]}", ", ".join(names), status, note))
    return rows


# --- File checks, shared by the folder walk and Docker layers -----------------------------------

LOCKFILE = re.compile(r"(requirements.*\.txt|pyproject\.toml|uv\.lock|poetry\.lock|Pipfile\.lock"
                      r"|package-lock\.json|pnpm-lock\.yaml|yarn\.lock|bun\.lock|Cargo\.lock|go\.sum|Gemfile\.lock)$")
FOUND_LOCKFILES = set()  # ponytail: filled by the file walk, read again only with --osv
FOUND_DIST_INFO = set()  # (site-packages folder, name, version) of installed Python packages
SKIP = {"node_modules", ".git", ".Trash"}
ARCHIVES = (".jar", ".war", ".ear")
JAR_CACHE = re.compile(r"/\.m2/repository/|/\.gradle/caches/")  # one artifact per jar, named by version: no need to open it
MAX_READ = 50_000_000  # cap per-file reads (disk and tar members) so an untrusted file can't exhaust memory


def pkg_bad(pkg, v):
    ranges = pkg.get("bad_ranges", [pkg["bad_range"]] if "bad_range" in pkg else [])  # inclusive [lo, hi] pairs
    return v in pkg.get("bad", ()) or any(nums(lo) <= nums(v) <= nums(hi) for lo, hi in ranges)


def npm_versions(pat, data):
    """Resolved versions of one npm package in package-lock / pnpm-lock / yarn.lock / bun.lock.
    ponytail: format-shaped regexes, not parsers; they skip the ^ranges in package.json-style specs."""
    return set(re.findall(rb"node_modules/" + pat + rb'"\s*:\s*\{[^}]*?"version"\s*:\s*"([\d.]+)"', data)
               + re.findall(rb"[/'\"\s]" + pat + rb"@(\d+\.\d+\.\d+)", data)
               + re.findall(rb"\n\"?" + pat + rb"@[^\n]*:\n\s+version:? \"?(\d+\.\d+\.\d+)", data))


def inspect_file(path, read):
    """Checks one file; read() returns its bytes and is only called when needed. Returns (rows, bundles)."""
    cache = []

    def data():
        if not cache:
            cache.append(read())
        return cache[0]

    rows, bundles = [], []
    base, parent = os.path.basename(path), os.path.basename(os.path.dirname(path))
    inside = []

    def maven_inside():
        """{(artifactId, version, where)} in a jar/war/ear: its own pom.properties, and bundled jars by file name
        (WEB-INF/lib, BOOT-INF/lib). ponytail: one level deep; a jar inside a jar inside a war isn't opened."""
        if not inside:
            found = set()
            try:
                # a file on disk is opened in place: zipfile reads only the index and pom.properties, so a war
                # past MAX_READ (Roller's is 56 MB) is still checked
                on_disk = getattr(read, "path", None)
                z = zipfile.ZipFile(on_disk if on_disk else io.BytesIO(data()))
                for n in z.namelist():
                    if n.startswith("META-INF/maven/") and n.endswith("/pom.properties") and z.getinfo(n).file_size < 100_000:
                        props = z.read(n).decode("utf-8", "replace")
                        a, v = re.search(r"(?m)^artifactId=(\S+)", props), re.search(r"(?m)^version=(\S+)", props)
                        if a and v:
                            found.add((a[1], v[1], ""))
                    elif m := re.search(r"(?:^|/)([A-Za-z][\w.-]*?)-(\d[\w.-]*)\.jar$", n):
                        found.add((m[1], m[2], n))
            except (zipfile.BadZipFile, OSError, ValueError, RuntimeError, NotImplementedError):
                pass
            inside.append(found)
        return inside[0]

    if LOCKFILE.search(base) and base != "pyproject.toml":  # pyproject.toml holds ranges, not what is installed
        FOUND_LOCKFILES.add(path)
    if base == "METADATA" and (m := re.fullmatch(r"(.+)-([^-]+)\.dist-info", parent)):
        FOUND_DIST_INFO.add((os.path.dirname(os.path.dirname(path)), m[1], m[2]))
    for pkg in PACKAGES:
        name, status = pkg["name"], pkg.get("status", "AFFECTED")
        pat = re.escape(pkg["package"]).replace(r"\-", "[-_]")  # dist-info folders say python_jose
        lock_note = pkg.get("lock_note", f"lockfile pins the backdoored build: pin {pkg.get('safe')}")
        m = re.fullmatch(rf"{pat}-([\w.]+)\.(?:dist|egg)-info", parent, re.I)
        if m and base in ("METADATA", "PKG-INFO"):
            bad = pkg_bad(pkg, m[1])
            rows.append((name, os.path.dirname(path), m[1], status if bad else "OK", pkg["cleanup"] if bad else ""))
        if pkg.get("ecosystem") == "rubygems" and parent == "specifications" and base.startswith(pkg["package"] + "-") \
                and (m := re.fullmatch(rf"{re.escape(pkg['package'])}-(\d[\w.]*?)(?:-[a-z][\w-]*)?\.gemspec", base)):
            bad = pkg_bad(pkg, m[1])  # installed gem: <gem dir>/specifications/actionpack-8.0.5.1.gemspec
            rows.append((name, os.path.dirname(os.path.dirname(path)), m[1], status if bad else "OK", pkg["cleanup"] if bad else ""))
        if "site-packages" in path and base in pkg.get("malware_files", ()):
            rows.append((name, path, "malware file", "AFFECTED", pkg["cleanup"]))
        # Python only auto-runs it from the top of site-packages; Homebrew ships a legit one there
        elif base in pkg.get("suspicious_files", ()) and parent == "site-packages" and b"created by Homebrew" not in data()[:200]:
            rows.append((name, path, "possible malware", "REVIEW", f"{name} malware drops this; check it if you didn't add it"))
        if pkg.get("ecosystem") == "maven" and base.lower().endswith(ARCHIVES):
            art = pkg["package"]
            m = re.fullmatch(rf"{re.escape(art)}-(\d[\w.-]*)\.jar", base)
            hits = {(m[1], "")} if m else set() if JAR_CACHE.search(path) else {(v, at) for a, v, at in maven_inside() if a == art}
            for v, at in sorted(hits):
                bad = pkg_bad(pkg, v)
                rows.append((name, path + (f"!/{at}" if at else ""), v, status if bad else "OK", pkg["cleanup"] if bad else ""))
        if not LOCKFILE.search(base) or pkg.get("ecosystem") == "maven":  # ponytail: pom.xml / Gradle pins not read
            continue
        if pkg.get("ecosystem") == "rubygems":
            if base == "Gemfile.lock":
                for _, n, v in sorted(lock_packages(path, data())):
                    if n == pkg["package"] and pkg_bad(pkg, v):
                        rows.append((name, path, v, status, lock_note))
        elif pkg.get("ecosystem") == "npm":
            for v in sorted(npm_versions(pat.encode(), data())):
                if pkg_bad(pkg, v.decode()):
                    rows.append((name, path, v.decode(), status, lock_note))
        elif "bad_range" in pkg or "bad_ranges" in pkg:  # ponytail: proximity regex, first version after the name; fine for pins
            for v in sorted({x.decode() for x in re.findall(rf"{pat}\W.{{0,80}}?(\d+\.\d+\.\d+)".encode(), data(), re.S | re.I)}):
                if pkg_bad(pkg, v):
                    rows.append((name, path, v, status, lock_note))
        else:
            for bad in pkg["bad"]:
                if re.search(rf"{pat}.{{0,80}}?{re.escape(bad)}".encode(), data(), re.S | re.I):
                    rows.append((name, path, bad, status, lock_note))
    if base in MCP["files"] or (parent in AGENT_DIRS and base in ("settings.json", "settings.local.json", "config.toml")):
        rows += agent_config_rows(path, data())
    if base in BUNDLE_FILES:
        names = roots_in(data())
        if names:
            bundles.append((path, names, chain_accepts(data())))
    return rows, bundles


def scan_files(roots):
    roots = sorted({os.path.realpath(os.path.expanduser(r)) for r in roots})
    roots = [r for r in roots if not any(r.startswith(o + os.sep) for o in roots)]  # nested roots = duplicate rows
    rows, bundles = [], []
    for root in roots:
        for d, dirs, files in os.walk(root):
            dirs[:] = [x for x in dirs if x not in SKIP]
            rows += env_rows(d, dirs, files)
            if "SKILL.md" in files:
                FOUND_SKILL_DIRS.add(d)
            if d == f"{HOME}/Library":  # huge on macOS; only its Python site-packages matter
                dirs[:] = [x for x in dirs if x == "Python"]
            for f in files:
                p = os.path.join(d, f)

                def read(p=p):
                    try:
                        # isfile: not a device or FIFO behind a symlink (a repo's requirements.txt -> /dev/zero)
                        return open(p, "rb").read(MAX_READ) if os.path.isfile(p) and os.path.getsize(p) < MAX_READ else b""
                    except OSError:
                        return b""

                if f.lower().endswith(ARCHIVES) and os.path.isfile(p):
                    read.path = p
                r, b = inspect_file(p, read)
                rows += r
                bundles += b
    for pkg in PACKAGES:
        if os.path.exists(pkg.get("lock_file", "")):
            rows.append((pkg["name"], pkg["lock_file"], "malware lock", "AFFECTED", "malware daemon may be running: " + pkg["cleanup"]))
        if not any(r[0] == pkg["name"] for r in rows):
            rows.append((pkg["name"], "-", "-", "NOT FOUND", ""))
    return rows + bundle_summary(bundles)


# --- Every pinned dependency, against OSV (opt-in: --osv) --------------------------------------------
# Off by default because it sends package names and versions to api.osv.dev; nothing else leaves the machine.

OSV_ITEM = "Dependencies (OSV)"
OSV_BATCH = "https://api.osv.dev/v1/querybatch"
OSV_VULN = "https://api.osv.dev/v1/vulns/{}"
OSV_SEVERITY = {"CRITICAL": 0, "HIGH": 1, "MODERATE": 2, "MEDIUM": 2, "LOW": 3}


def lock_packages(path, data):
    """{(ecosystem, name, version)} pinned in one lockfile.
    ponytail: format-shaped regexes like npm_versions, not full parsers; npm v1 lockfiles are skipped."""
    base, text, out = os.path.basename(path), data.decode("utf-8", "replace"), set()
    try:
        if base == "package-lock.json":
            pk = json.loads(text).get("packages", {})
            out = {("npm", k.rsplit("node_modules/", 1)[1], v["version"]) for k, v in pk.items()
                   if "node_modules/" in k and isinstance(v, dict) and isinstance(v.get("version"), str)}
        elif base == "Pipfile.lock":
            j = json.loads(text)
            out = {("PyPI", n, v["version"][2:]) for sec in ("default", "develop") for n, v in (j.get(sec) or {}).items()
                   if isinstance(v, dict) and str(v.get("version", "")).startswith("==")}
    except (ValueError, AttributeError):
        return set()
    if base.startswith("requirements"):
        out = {("PyPI", n, v) for n, v in re.findall(r"(?m)^\s*([A-Za-z0-9][\w.-]*)(?:\[[^\]]*\])?\s*==\s*([\w.!+]+)", text)}
    elif base in ("poetry.lock", "uv.lock", "Cargo.lock"):
        out = {("crates.io" if base == "Cargo.lock" else "PyPI", n, v) for n, v in re.findall(r'(?m)^name = "([^"]+)"\nversion = "([^"]+)"', text)}
    elif base == "go.sum":
        out = {("Go", n, v) for n, v in re.findall(r"(?m)^(\S+) (v[^\s/]+) h1:", text)}
    elif base == "pnpm-lock.yaml":
        out = {("npm", n, v) for n, v in re.findall(r"(?m)^\s+'?/?(@?[^@\s'/][^@\s']*)@(\d[^\s:'(]*)(?:\([^\n]*\))?'?:", text)}
    elif base == "yarn.lock":
        out = {("npm", n, v) for n, v in re.findall(r'(?m)^"?(@?[^@\s",]+)@[^\n]*:\n\s+version:? "?([^"\s]+)', text)}
    elif base == "Gemfile.lock":  # specs are indented 4 spaces, their dependencies 6; a platform suffix isn't the version
        out = {("RubyGems", n, v) for n, v in re.findall(r"(?m)^    ([A-Za-z0-9][\w.-]*) \((\d[\w.]*?)(?:-[a-z][\w-]*)?\)$", text)}
    elif base == "bun.lock":
        out = {("npm", n, v) for n, v in re.findall(r'\[\s*"(@?[^"@]+)@(\d[^"]*)"', text)}
    return out


def osv_fetch(url, body=None):
    req = urllib.request.Request(url, data=None if body is None else json.dumps(body).encode(),
                                 headers={"User-Agent": "amiaffected", "Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=30) as r:
        return json.load(r)


def vkey(v):
    return tuple(int(x) for x in re.findall(r"\d+", v))


def check_osv(fetch=osv_fetch):
    where = {}  # (ecosystem, name, version) -> lockfiles / site-packages that have it
    for p in sorted(FOUND_LOCKFILES):
        try:
            data = open(p, "rb").read(MAX_READ) if os.path.isfile(p) else b""
        except OSError:
            data = b""
        for k in lock_packages(p, data):
            where.setdefault(k, []).append(p)
    for site, n, v in FOUND_DIST_INFO:
        where.setdefault(("PyPI", n, v), []).append(site)
    for (path, name), e in sorted(FOUND_MCP.items()):  # an MCP server's own package: the pinned version, or the one npx last fetched
        eco, pname, version = server_package(e.get("command"), e.get("args")) or ("", "", "")
        version = version or (npx_cached(pname, HOME) if eco == "npm" else "")
        if version:
            where.setdefault((eco, pname, version), []).append(f"{path} (MCP server {name})")
    if not where:
        return [(OSV_ITEM, "-", "-", "NOT FOUND", "no lockfiles or installed Python packages found")]
    keys = sorted(where)
    print(f"osv: sending {len(keys)} package names and versions to api.osv.dev, nothing else", file=sys.stderr)
    try:
        hits = {}
        for i in range(0, len(keys), 1000):  # ponytail: a package with >1000 advisories would need next_page_token
            batch = keys[i:i + 1000]
            res = fetch(OSV_BATCH, {"queries": [{"package": {"name": n, "ecosystem": e}, "version": v} for e, n, v in batch]})["results"]
            hits.update({k: [x["id"] for x in r["vulns"]] for k, r in zip(batch, res) if r.get("vulns")})
        ids = sorted({i for v in hits.values() for i in v})
        with concurrent.futures.ThreadPoolExecutor(8) as ex:
            details = dict(zip(ids, ex.map(lambda i: fetch(OSV_VULN.format(i)), ids)))
    except (OSError, ValueError, KeyError, TypeError) as e:
        return [(OSV_ITEM, "-", "-", "UNKNOWN", f"couldn't check with api.osv.dev: {e}")]
    norm = lambda s: re.sub(r"[-_.]+", "-", s).lower()  # PyPI: python_jose is python-jose
    rows = []
    for (eco, name, v), vids in sorted(hits.items()):
        worst, fixes, labels = 9, [], []
        for i in vids:
            d = details.get(i) or {}
            worst = min(worst, OSV_SEVERITY.get(str((d.get("database_specific") or {}).get("severity", "")).upper(), 9))
            labels.append(next((a for a in d.get("aliases", []) if a.startswith("CVE-")), i))
            fixed = [ev["fixed"] for a in d.get("affected", []) if norm(a.get("package", {}).get("name", "")) == norm(name)
                     for r in a.get("ranges", []) for ev in r.get("events", []) if "fixed" in ev and vkey(ev["fixed"]) > vkey(v)]
            if fixed:
                fixes.append(min(fixed, key=vkey))  # the first fix above this version, per advisory
        sev = {0: "critical", 1: "high", 2: "medium", 3: "low"}.get(worst, "unrated")
        note = (f"{len(vids)} known ({sev}): {', '.join(labels[:3])}{', …' if len(labels) > 3 else ''}; "
                + (f"fixed in {max(fixes, key=vkey)}" if fixes else "no fixed version listed"))
        rows += [(OSV_ITEM, p, f"{eco} {name} {v}", "AFFECTED" if worst <= 1 else "REVIEW", note) for p in where[(eco, name, v)]]
    return rows or [(OSV_ITEM, f"{len(keys)} packages", "-", "OK", "no known vulnerabilities in OSV")]


def scan_image_tar(label, stream):
    """Walks a `docker save` stream (a tar of layer tars) without running the image.
    ponytail: ignores whiteouts, so files deleted in a later layer still count; zstd layers are skipped."""
    rows, bundles = [], []
    with tarfile.open(fileobj=stream, mode="r|") as outer:
        for member in outer:
            if not member.isfile():
                continue
            try:
                with tarfile.open(fileobj=outer.extractfile(member), mode="r|*") as layer:
                    for f in layer:
                        if f.isfile():
                            # cap by tar metadata before reading: an untrusted image could ship a huge/bomb member
                            read = (lambda f=f: layer.extractfile(f).read()) if f.size < MAX_READ else (lambda: b"")
                            r, b = inspect_file("/" + f.name, read)
                            rows += [(i, f"{label}:{p}", *rest) for i, p, *rest in r]
                            bundles += [(f"{label}:{p}", n, a) for p, n, a in b]
            except tarfile.ReadError:  # manifest/config json, or a layer format tarfile can't read
                continue
    return rows, bundles


def check_docker(scan_images):
    if not shutil.which("docker"):
        return [("Docker", "-", "-", "NOT FOUND", "docker not installed")]
    out = run("docker", "images", "--digests", "--format", "{{.ID}} {{.Repository}}:{{.Tag}} {{.Digest}}")
    # daemon-down / permission errors go to the daemon, not per-image output; match those, not an image named "error"
    if any(s in out.lower() for s in ("cannot connect", "permission denied", "is the docker daemon running")):
        return [("Docker", "-", "-", "UNKNOWN", "docker is installed but not reachable (daemon down or no permission)")]
    rows, bundles, ids = [], [], {}
    for line in out.splitlines():
        parts = line.split()
        if len(parts) != 3:  # unexpected format; don't crash the whole scan
            continue
        image_id, name, digest = parts
        ids.setdefault(image_id, name if not name.startswith("<none>") else image_id)
        for pkg in PACKAGES:
            if digest.startswith(tuple(pkg.get("image_digests", []))):
                rows.append((pkg["name"], f"docker:{name}", digest[:19], "AFFECTED", "backdoored image: remove it, rebuild, " + pkg["cleanup"]))
    for image_id, label in ids.items() if scan_images else []:
        print(f"  scanning image {label}...", file=sys.stderr)
        p = subprocess.Popen(["docker", "save", image_id], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
        r, b = scan_image_tar(label, p.stdout)
        p.wait()
        rows += r or [("Docker", label, "-", "OK", "")]
        bundles += b
    return rows + bundle_summary(bundles)


# --- System trust stores ------------------------------------------------------------------------

def check_os_store():
    if sys.platform == "darwin":
        # ask macOS itself: it checks revocation, which OpenSSL bundles don't
        with tempfile.TemporaryDirectory() as d:
            trusted = []
            for name, der in INTERMEDIATES.items():
                open(f"{d}/i.pem", "wb").write(pem(der))
                if "successful" in run("security", "verify-cert", "-c", f"{d}/i.pem").lower():
                    trusted.append(name)
        if trusted:
            return [("eMudhra CA", "macOS Keychain", ", ".join(trusted), "AFFECTED", "macOS trusts the cracked intermediates: install pending updates")]
        return [("eMudhra CA", "macOS Keychain", "-", "OK", "macOS rejects the cracked intermediates (revoked or untrusted)")]
    if sys.platform == "win32":
        # ponytail: untested on Windows. Root stores plus Disallowed, where Windows Update puts distrusted certs
        ps = ("Get-ChildItem Cert:\\LocalMachine\\Root,Cert:\\CurrentUser\\Root,Cert:\\LocalMachine\\Disallowed | "
              "% { $_.PSParentPath.Split('\\')[-1] + ' ' + $_.Thumbprint }")
        lines = run("powershell", "-NoProfile", "-Command", ps).upper().splitlines()
        thumb = lambda der: hashlib.sha1(der).hexdigest().upper()
        if all(f"DISALLOWED {thumb(d)}" in lines for d in INTERMEDIATES.values()):
            return [("eMudhra CA", "Windows cert store", "-", "OK", "the cracked intermediates are in the Disallowed store")]
        names = [n for n, d in ROOTS.items() if f"ROOT {thumb(d)}" in lines]
        status, note = store_status("windows", names, None)
        return [("eMudhra CA", "Windows cert store", ", ".join(names) or "-", status,
                 note + ("; CryptoAPI accepts the chain unless revocation checking is on" if names else ""))]
    return []  # Linux system trust is covered by the extracted bundles in STORES


def test_bundle(path, label=None):
    """One eMudhra row for a PEM bundle on disk, or None if it can't be read."""
    try:
        data = open(path, "rb").read()
    except OSError:
        return None
    names = roots_in(data)
    status, note = store_status(path, names, chain_accepts(data) if names else None)
    return ("eMudhra CA", label or path, ", ".join(names) or "-", status, note)


# CA-bundle overrides: a custom bundle here replaces the system store for that tool, so a machine can
# look clean while its real trust anchor is still compromised. Env vars read by curl/OpenSSL, Node,
# Python requests, Git, the AWS SDKs; plus config a tool keeps in its own file.
CA_ENV_VARS = ["SSL_CERT_FILE", "CURL_CA_BUNDLE", "NODE_EXTRA_CA_CERTS", "REQUESTS_CA_BUNDLE",
               "AWS_CA_BUNDLE", "GIT_SSL_CAINFO", "PIP_CERT", "DENO_CERT", "CARGO_HTTP_CAINFO"]
CA_CONFIG_CMDS = {  # tool: argv that prints the configured bundle path (empty/null if unset)
    "npm": ["npm", "config", "get", "cafile"],
    "pip": ["pip", "config", "get", "global.cert"],
    "git": ["git", "config", "--global", "--get", "http.sslCAInfo"],
    "yarn": ["yarn", "config", "get", "cafile"],
}


def check_overrides():
    found = {}  # path -> source label, so one custom bundle shared by several tools is tested once
    for var in CA_ENV_VARS:
        if os.environ.get(var):
            found.setdefault(os.path.realpath(os.path.expanduser(os.environ[var])), []).append(f"${var}")
    for tool, cmd in CA_CONFIG_CMDS.items():
        if not shutil.which(cmd[0]):
            continue
        out = run(*cmd).strip()
        # tools print their own "unset" marker: npm/yarn "null", pip "ERROR: No such key", git nothing
        if out and out.lower() not in ("null", "undefined", "none", "") and "error" not in out.lower() and "no such key" not in out.lower():
            found.setdefault(os.path.realpath(os.path.expanduser(out)), []).append(f"{tool} config")
    rows = []
    for path, sources in found.items():
        label = f"{path} (via {', '.join(sources)})"
        rows.append(test_bundle(path, label) or ("eMudhra CA", label, "-", "REVIEW", "configured CA bundle is missing or unreadable; the tool may fall back to the system store"))
    return rows


def check_stores():
    rows = check_os_store() + check_overrides()
    for p in sorted({os.path.realpath(p) for g in STORES for p in glob.glob(g)}):
        row = test_bundle(p)
        if row:
            rows.append(row)
    return rows


# --- Output -------------------------------------------------------------------------------------

# --- End of life: a branch that gets no more fixes will miss the next bug too, CVE or not -----------

EOL = ADVISORIES["eol"]
OS_NAMES = {"ubuntu": "Ubuntu", "debian": "Debian", "rhel": "Red Hat Enterprise Linux", "almalinux": "AlmaLinux", "rocky": "Rocky Linux"}


def os_row(os_text):
    """This Linux release as a row, so apply_eol judges it like any other version."""
    d = dict(re.findall(r'^(\w+)="?([^"\n]*)"?$', os_text or "", re.M))
    name = OS_NAMES.get(d.get("ID"))
    return [(name, "/etc/os-release", d["VERSION_ID"], "OK", "")] if name and d.get("VERSION_ID") else []


def apply_eol(rows, today=None):
    """OK on an ended branch becomes REVIEW; an ending branch (90 days) gets a note. Dates come from endoflife.date."""
    today = today or datetime.date.today().isoformat()
    soon = (datetime.date.fromisoformat(today) + datetime.timedelta(days=90)).isoformat()
    by_item = {i: p for p in EOL["products"] for i in p["items"]}
    out = []
    for item, where, v, status, note in rows:
        p, n = by_item.get(item), nums(str(v))
        cyc = next((c for c in p["cycles"] if n and nums(c) == n[:len(nums(c))]), None) if p else None
        end = p["cycles"][cyc] if cyc else False
        if end is True or (end and end <= today):
            gone = f"{item} {cyc} reached end of life{'' if end is True else ' on ' + end}: no more security fixes, move to {p['newest']}"
            if status in ("OK", "UNKNOWN"):
                status, note = "REVIEW", gone
            elif "end-of-life" not in note:
                note = f"{note}; {gone}" if note else gone
        elif end and end <= soon:
            note = (note + "; " if note else "") + f"{item} {cyc} gets security fixes until {end}, plan the move to {p['newest']}"
        out.append((item, where, v, status, note))
    return out


# --- Settings that blunt bugs nobody has found yet ------------------------------------------------
# Read-only: each is a command any user can run, and nothing is changed.

LISTENING = "Listening on the network"
MAC_SETTINGS = [  # (item, command, text when on, why it matters, how to turn it on)
    ("Setting: FileVault", ("fdesetup", "status"), "FileVault is On", "a lost or stolen Mac gives up its files",
     "System Settings > Privacy & Security > FileVault > Turn On"),
    ("Setting: Gatekeeper", ("spctl", "--status"), "assessments enabled", "apps that aren't signed and notarized open without a warning",
     "sudo spctl --global-enable"),
    ("Setting: System Integrity Protection", ("csrutil", "status"), "status: enabled", "malware running as root can change system files",
     "restart into Recovery (hold the power button), open Terminal, run: csrutil enable"),
    ("Setting: macOS firewall", ("/usr/libexec/ApplicationFirewall/socketfilterfw", "--getglobalstate"), "is enabled",
     "anything listening on a port is reachable from the Wi-Fi you're on", "System Settings > Network > Firewall > on"),
]
SETTING_FIX = {item: (f"Turn on {item.split(': ')[1]}", how) for item, _, _, _, how in MAC_SETTINGS}
SETTING_FIX["Setting: automatic security updates"] = (
    "Turn on automatic security updates",
    "System Settings > General > Software Update > Automatic Updates > Install Security Responses and system files")
SETTING_FIX[LISTENING] = ("Check what's reachable from your network",
                          "quit what you don't need, bind dev servers to 127.0.0.1, and turn on a firewall "
                          "(Mac: System Settings > Network > Firewall; Linux: ufw or firewalld)")
APT_AUTO = ("sudo apt install unattended-upgrades && sudo dpkg-reconfigure -plow unattended-upgrades")
DNF_AUTO = ("sudo dnf install dnf-automatic && sudo systemctl enable --now dnf-automatic-install.timer")


def local(addr):
    host = addr.rsplit(":", 1)[0]
    return host.startswith(("127.", "[::1]", "[::ffff:127.")) or host == "localhost"


def listening(lsof_out, path_of, skip=lambda path: path.startswith(("/System/", "/usr/libexec/", "/usr/sbin/"))):
    """One REVIEW row per program taking connections from other machines; Apple's own daemons are left out."""
    ports, pid = {}, None
    for line in lsof_out.splitlines():
        if line.startswith("p"):
            pid = line[1:]
        elif line.startswith("n") and pid and not local(line[1:]):
            ports.setdefault(pid, set()).add(line[1:])
    return listen_rows(ports, path_of, skip)


def proc_exe(pid):
    try:
        return os.readlink(f"/proc/{pid}/exe")
    except OSError:  # another user's process, without root
        return ""


def ss_listening(ss_out, exe=proc_exe):
    """Linux: `ss -Hltnp`. Without root, other users' programs have no pid; they still get a row.
    sshd is left out: a server without it is the odd one."""
    ports, names = {}, {}
    for line in ss_out.splitlines():
        f = line.split()
        if len(f) < 4 or local(f[3]):
            continue
        m = re.search(r'\("([^"]+)",pid=(\d+)', line)
        pid = m.group(2) if m else ""
        names[pid] = m.group(1) if m else "a program run by another user (run as root to see which)"
        ports.setdefault(pid, set()).add(f[3])
    path_of = lambda pid: (pid and exe(pid)) or names[pid]
    return listen_rows(ports, path_of, lambda path: os.path.basename(path) == "sshd")


def listen_rows(ports, path_of, skip):
    rows = []
    for pid, addrs in sorted(ports.items()):
        path = path_of(pid) or f"pid {pid}"
        if not skip(path):
            rows.append((LISTENING, path, ", ".join(sorted(addrs)), "REVIEW",
                         "takes connections from other machines on your network; check you meant that"))
    return rows


RELOAD_SSH = "then: sudo systemctl reload ssh || sudo systemctl reload sshd"
SETTING_FIX["Setting: Linux firewall"] = (
    "Turn on a firewall", "sudo ufw allow OpenSSH && sudo ufw enable   # RHEL family: sudo systemctl enable --now firewalld")
SETTING_FIX["Setting: SSH password login"] = (
    "Turn off SSH password login", "check you can log in with a key first, then set PasswordAuthentication no in "
    "/etc/ssh/sshd_config and any file in /etc/ssh/sshd_config.d that sets it; " + RELOAD_SSH)
SETTING_FIX["Setting: SSH root login"] = (
    "Stop root logging in over SSH", "set PermitRootLogin prohibit-password in /etc/ssh/sshd_config; " + RELOAD_SSH)
SETTING_FIX["Setting: Docker ports past the firewall"] = (
    "Keep Docker's ports behind the firewall", "publish them as 127.0.0.1:PORT:PORT (docker run -p, compose ports:), "
    "or add DROP rules to the DOCKER-USER iptables chain")


def sshd_settings(path="/etc/ssh/sshd_config"):
    """({keyword: value}, files we couldn't read) as sshd sees them for a normal login: the first value wins,
    Include is read in place, and reading stops at the first Match block."""
    seen, unread = {}, []

    def walk(p):
        try:
            lines = open(p, errors="replace").read().splitlines()
        except OSError:
            unread.append(p)
            return False
        for line in lines:
            f = line.split("#", 1)[0].split(None, 1)
            if len(f) < 2:
                continue
            k, v = f[0].lower(), f[1].strip()
            if k == "match":
                return True
            if k == "include":
                for pat in v.split():
                    if any(walk(q) for q in sorted(glob.glob(pat if pat.startswith("/") else "/etc/ssh/" + pat))):
                        return True
            else:
                seen.setdefault(k, v.split()[0].lower())
        return False
    walk(path)
    return seen, unread


def linux_hardening(read=run, sshd_config="/etc/ssh/sshd_config", ufw_conf="/etc/ufw/ufw.conf"):
    rows = []
    try:  # ufw.service reports active even when ufw is disabled; its own conf says
        ufw = bool(re.search(r"^ENABLED=yes", open(ufw_conf).read(), re.M))
    except OSError:
        ufw = False
    on = ["ufw"] * ufw + [u for u in ("firewalld", "nftables") if read("systemctl", "is-active", u).strip() == "active"]
    if ufw or read("systemctl", "--version").strip():  # no systemd (a container): no row rather than a guess
        rows.append(("Setting: Linux firewall", ", ".join(on) or "ufw, firewalld, nftables", "on" if on else "off", "OK" if on else "REVIEW",
                     "" if on else "off: every listening port is reachable unless your provider's firewall (security group) blocks it"))
    published = []
    for line in read("docker", "ps", "--format", "{{.Names}}\t{{.Ports}}").splitlines():
        name, _, ports = line.partition("\t")
        published += [f"{name}:{p}" for p in dict.fromkeys(re.findall(r"(?:0\.0\.0\.0|\[::\]|:::?):(\d+)->", ports))]
    if on and published:
        rows.append(("Setting: Docker ports past the firewall", "docker ps", ", ".join(published), "REVIEW",
                     "Docker writes its own iptables rules, so the firewall doesn't block these published ports"))
    if os.path.exists(sshd_config):
        conf, unread = sshd_settings(sshd_config)
        caveat = f" (couldn't read {', '.join(unread)}: run as root to be sure)" if unread else ""
        pw = conf.get("passwordauthentication", "yes") == "yes"  # sshd's default is yes
        rows.append(("Setting: SSH password login", sshd_config, "on" if pw else "off", "REVIEW" if pw else "OK",
                     ("on: bots try passwords against every server all day" if pw else "") + caveat))
        root = conf.get("permitrootlogin", "prohibit-password") == "yes"
        if root:
            rows.append(("Setting: SSH root login", sshd_config, "yes", "REVIEW",
                         "root can log in over SSH" + (", with a password too" if pw else "") + caveat))
    return rows


def check_settings(read=run):
    rows = []
    if sys.platform == "darwin":
        for item, cmd, on_text, why, _ in MAC_SETTINGS:
            out = read(*cmd)
            if out.strip():  # missing tool (older macOS, a container): no row rather than a guess
                on = on_text in out
                rows.append((item, " ".join(cmd), "on" if on else "off", "OK" if on else "REVIEW", "" if on else f"off: {why}"))
        su = read("defaults", "read", "/Library/Preferences/com.apple.SoftwareUpdate")
        off = re.search(r"\b(CriticalUpdateInstall|ConfigDataInstall) = 0;", su)  # absent means the default, which is on
        rows.append(("Setting: automatic security updates", "/Library/Preferences/com.apple.SoftwareUpdate", "off" if off else "on",
                     "REVIEW" if off else "OK", "off: security fixes wait until someone installs them by hand" if off else ""))
        rows += listening(read("lsof", "-nP", "-iTCP", "-sTCP:LISTEN", "-F", "pn"),
                          lambda pid: read("ps", "-p", pid, "-o", "comm=").strip())
        return rows
    if sys.platform.startswith("linux"):
        rows += ss_listening(read("ss", "-Hltnp"))
        rows += linux_hardening(read)
    if shutil.which("apt-get"):
        conf = "".join(open(f, errors="replace").read() for f in glob.glob("/etc/apt/apt.conf.d/*") if os.path.isfile(f))
        on = bool(shutil.which("unattended-upgrade")) and re.search(r'Unattended-Upgrade\s+"1"', conf)
        rows.append(("Setting: automatic security updates", "unattended-upgrades", "on" if on else "off", "OK" if on else "REVIEW",
                     "" if on else "off: security fixes wait until someone runs apt"))
    elif shutil.which("dnf"):
        on = any(read("systemctl", "is-enabled", t).strip() == "enabled"
                 for t in ("dnf-automatic.timer", "dnf-automatic-install.timer", "dnf5-automatic.timer"))
        rows.append(("Setting: automatic security updates", "dnf-automatic", "on" if on else "off", "OK" if on else "REVIEW",
                     "" if on else "off: security fixes wait until someone runs dnf"))
    return rows


STATUSES = ("AFFECTED", "REVIEW", "UNKNOWN", "OK", "NOT FOUND")


# From ubuntu.com/blog/fixes-available-in-proposed-pocket-for-cve-2026-98432 (kernels installed via a meta-package)
PROPOSED_KERNEL = ("sudo add-apt-repository --component main --pocket proposed http://archive.ubuntu.com/ubuntu && sudo apt update && "
                   "dpkg-query -W -f '${source:Package}\\t${binary:Package}\\n' | awk '$1 ~ \"^linux-meta\" { print $2 }' | "
                   "xargs sudo apt install -t \"$(. /etc/os-release && echo $VERSION_CODENAME)-proposed\" --only-upgrade && sudo reboot")


def fix_for(item, where, note=""):
    """One (title, command) for an actionable row, or None. Rows with the same command collapse into
    one job in the fix plan, so 15 Node installs or 80 venvs become a single step."""
    w = where.lower()
    if item == "Node.js":
        if ".nvm" in w:
            return ("Replace end-of-life Node versions under nvm",
                    "nvm install --lts && nvm alias default 'lts/*'   # then: nvm uninstall <each old version>")
        if ".volta" in w:
            return ("Upgrade the Volta-managed Node", "volta install node@22")
        return ("Upgrade Homebrew Node to a patched release", "brew upgrade node")
    if item == "eMudhra CA":
        if "keychain" in w:
            return ("Install pending macOS updates (system Keychain trust)", "softwareupdate --install --all")
        if "nss" in w or "firefox" in w or "thunderbird" in w:
            return ("Update Firefox / Thunderbird (they carry their own roots)", "update Firefox/Thunderbird to the latest version")
        if "cacerts" in w or "/java/" in w or "jvm" in w:
            return ("Update the Java trust store", "update the JDK, or: keytool -delete -alias <cracked alias> -keystore <cacerts>")
        if "/usr/lib/python3/dist-packages/" in w:
            return ("Update the distro's Python packages that ship their own CA bundle", "sudo apt update && sudo apt upgrade   # once the distro drops the root")
        if "certifi" in w:  # before site-packages and /vendor/: pip ships certifi under pip/_vendor/certifi
            return ("Update certifi in affected virtualenvs (after a fixed release ships)", "pip install -U certifi   # run in each affected venv")
        if "/vendor/" in w:  # composer convention; note /vendor/ not _vendor/ (python)
            return ("Refresh vendored CA bundles (e.g. PHP/composer packages)", "composer update   # in each project shipping its own cacert.pem")
        if "site-packages" in w:
            return ("Update Python packages that ship their own CA bundle", "pip install -U <package>   # e.g. botocore, once it drops the root")
        if "(via" in where:
            return ("Fix the custom CA bundle pointed to by an env var / tool config", "point the override at a patched bundle, or unset it to use the system store")
        if old_brew_bundle(where):
            return ("Replace CA bundles left by an older Homebrew in /usr/local",
                    f"cp {BREW_BUNDLE} <each file listed>   # or: /usr/local/bin/brew uninstall openssl openssl@1.1")
        return ("Update the system CA bundle (OpenSSL / curl / git)",
                "brew upgrade ca-certificates   # Linux: sudo update-ca-certificates  (Red Hat: sudo update-ca-trust)")
    if item == "PHP":
        return ("Upgrade PHP and restart workers", "upgrade to 8.5.12 / 8.4.27 / 8.3.36 / 8.2.35, then restart PHP-FPM")
    if item == "BIND":
        return ("Upgrade BIND", "upgrade to 9.20.30+ / 9.21.27+")
    if item == "GitLab":
        return ("Upgrade self-managed GitLab", "upgrade to 19.5.1 (or the latest patch for your branch, back to 18.11.13)")
    if item == "LiteLLM":
        return ("Remove the backdoored LiteLLM and rotate credentials",
                "don't pip install first; delete cook.pth/cook.py/sitecustomize.py, kill the daemon, rebuild pinned to 1.106.2, rotate keys")
    if item == "Google Chrome / Chromium":
        if w.startswith(("/applications", "/users")):
            return ("Update Chrome and relaunch it", "Chrome menu > Settings > About Chrome, let it update, then click Relaunch")
        return ("Update Chrome / Chromium and restart it",
                "sudo apt update && sudo apt upgrade   # dnf: sudo dnf upgrade   snap: sudo snap refresh chromium")
    if item == CHROMIUM["name"]:  # ponytail: the latest Playwright/Puppeteer lag Chrome, so upgrading them isn't the fix
        if "puppeteer" in w:
            return ("Run Puppeteer on your installed Chrome and delete its cached browsers",
                    "puppeteer.launch({ channel: 'chrome' })   # keep Chrome updated; then: rm -rf ~/.cache/puppeteer")
        return ("Run Playwright on your installed Chrome, sandbox on, and delete its cached browsers",
                "chromium.launch({ channel: 'chrome', chromiumSandbox: true })   # MCP: npx @playwright/mcp@<pinned> --browser chrome; then delete the chromium* folders in the ms-playwright cache")
    if item == "Git":
        if "/xcode.app/" in w or "/commandlinetools/" in w:
            return ("Update Apple's Git", "softwareupdate --list, then install the Command Line Tools or Xcode update it shows")
        if "/homebrew/" in w or w.startswith("/usr/local/"):
            return ("Upgrade Homebrew Git", "brew upgrade git")
    if item == "curl" and ("/homebrew/" in w or w.startswith("/usr/local/")):
        return ("Upgrade Homebrew curl", "brew upgrade curl")
    if item == OSV_ITEM:
        return ("Update vulnerable dependencies",
                "upgrade each to the fixed version shown, then refresh the lockfile (npm install, uv lock, poetry lock, cargo update, go get)")
    if item == ELECTRON["name"]:
        return ("Update apps built on an unsupported Electron",
                "update each app from its own menu or site; if it is already current, ask its maker for a build on a supported Electron, and don't open untrusted links or files in it")
    if item == "Microsoft Edge":
        return ("Update Edge and restart it", "Edge menu > Settings > About Microsoft Edge (edge://settings/help), then Restart")
    if item == "Brave":
        return ("Update Brave and relaunch it", "Brave menu > About Brave (brave://settings/help), then Relaunch")
    if item == MCP["name"]:
        if note.startswith("remote code"):
            return ("Remove the Puppeteer MCP server (no fix is coming)",
                    "delete the server-puppeteer entry from the config; for a browser use @playwright/mcp or chrome-devtools-mcp")
        return ("Replace archived @modelcontextprotocol servers", "switch each one to the vendor's own server, e.g. github/github-mcp-server")
    if item == SKILLS["name"]:
        if note.startswith(("named in", "matches an")):
            return ("Remove known-malicious skills and rotate keys", "delete the skill folder, check SOUL.md / MEMORY.md for changes, rotate every key it could reach")
        return ("Read the flagged skill files before you keep using them", "open each file listed; remove the skill if you can't explain what it does")
    if item == "AI agent: skill changes":
        return ("Read what changed in your skills", "open each skill listed and diff it against its source; remove it if you can't explain the change")
    if item == "AI agent: hooks":
        return ("Check what each hook runs", "read the hooks.json listed; remove the plugin if a hook runs something you don't recognise")
    if item == AGENT_FEED["name"]:
        return ("Update MCP servers that have known advisories",
                "in the MCP config listed, set the package to the fixed version in the note, e.g. npx -y <package>@<fixed version>, and restart the agent")
    if item == AGENT_TOOLS:
        return ("Update coding agents that have known advisories", "update the agent to the version in the note (claude update, or npm install -g <package>@latest) and restart it")
    if item == "AI agent: unpinned MCP servers":
        return ("Pin MCP server versions", "replace @latest or a bare package name with an exact version, e.g. npx -y @playwright/mcp@0.0.84")
    if item == "AI agent: permissions":
        return ("Make your coding agent ask before it runs commands",
                'Claude Code: drop "Bash" from permissions.allow and defaultMode bypassPermissions; Codex: approval_policy = "on-request", sandbox_mode = "workspace-write"')
    if item == "AI agent: secrets in reach":
        if "/.ssh/" in where:
            return ("Put a passphrase on SSH private keys", "ssh-keygen -p -f <key>   # macOS: then ssh-add --apple-use-keychain <key>")
        return ("Keep agents away from .env files",
                'add "permissions": {"deny": ["Read(./.env*)"]} to the project\'s .claude/settings.json, or keep secrets in a secret manager')
    if item == "Setting: automatic security updates" and where in ("unattended-upgrades", "dnf-automatic"):
        return ("Turn on automatic security updates", APT_AUTO if where == "unattended-upgrades" else DNF_AUTO)
    if item in SETTING_FIX:
        return SETTING_FIX[item]
    if item in OS_NAMES.values():
        return (f"Move to a supported {item} release", "plan the upgrade (Ubuntu: sudo do-release-upgrade), or buy the vendor's extended support")
    if item == "Docker":
        return ("Rebuild the affected Docker image", "remove the image, rebuild from a patched base, rotate any keys it held")
    plan = next((a["plan"] for a in ADVISORIES["versions"] + PACKAGES + ADVISORIES.get("iocs", []) if a["name"] == item and "plan" in a), None)
    if plan:
        return tuple(plan)
    adv = next((a for a in DISTRO if a["name"] == item), None)
    if adv and where.endswith(("(apt)", "(dnf)")):
        if "-proposed pocket" in note:  # a plain upgrade won't pick it up; Ubuntu's own steps
            return (f"Install the fixed kernel from -proposed and reboot ({item}), or wait for -updates", PROPOSED_KERNEL)
        if note.startswith("no fixed"):  # upgrading won't help yet: the workaround is the job
            return (f"Work around {item} until your distro ships a fix", adv.get("mitigation", "watch for the update"))
        if adv.get("kernel"):
            cmd = "sudo apt update && sudo apt full-upgrade" if where.endswith("(apt)") else "sudo dnf upgrade 'kernel*'"
            return (f"Update the kernel and reboot ({item})", cmd + " && sudo reboot")
        pkg = where.rsplit(" (", 1)[0]
        cmd = (f"sudo apt update && sudo apt install --only-upgrade {pkg}" if where.endswith("(apt)")
               else f"sudo dnf upgrade {pkg}")
        return (f"Update {item}" + (f", then {adv['after_fix']}" if adv.get("after_fix") else ""), cmd)
    return None


def bundle_count(where):
    m = re.match(r"(\d+) app CA bundles", where)
    return int(m.group(1)) if m else 1


def fix_plan(rows):
    """Deduplicated, prioritized actions from AFFECTED/REVIEW rows: [(worst_status, title, command, count, examples)]."""
    groups = {}
    for item, where, _, status, note in rows:
        if status not in ("AFFECTED", "REVIEW"):
            continue
        fix = fix_for(item, str(where), note or "")
        if not fix:
            continue
        title, command = fix
        g = groups.setdefault(command, {"title": title, "statuses": set(), "count": 0, "examples": []})
        g["statuses"].add(status)
        g["count"] += bundle_count(str(where))
        if len(g["examples"]) < 3 and str(where) not in g["examples"]:
            g["examples"].append(str(where))
    plan = [("AFFECTED" if "AFFECTED" in g["statuses"] else "REVIEW", g["title"], cmd, g["count"], g["examples"])
            for cmd, g in groups.items()]
    return sorted(plan, key=lambda x: (STATUSES.index(x[0]), -x[3]))


RUN_CMD = "curl -fsSL https://amiaffected.now/run | sh"


def share_line(rows):
    """The line that asks people to pass the check on: worded for whether anything here was affected."""
    if any(r[3] == "AFFECTED" for r in rows):
        return "Colleagues on the same setup are likely affected too. Send them the check: "
    return "Nothing affected here. To check a colleague's laptop or a server, send them: "


def html_report(rows, path):
    e = html.escape
    cls = lambda s: s.replace(" ", "")
    counts = "".join(f'<div class="stat {cls(s)}"><b>{sum(r[3] == s for r in rows)}</b>{s.lower()}</div>' for s in STATUSES)

    # Fix plan: one card per distinct job, affected first
    plan = fix_plan(rows)
    if plan:
        cards = "".join(
            f'<div class="fix {cls(status)}"><div class="fixhead"><span class="pill {cls(status)}">{e(status)}</span>'
            f'<b>{e(title)}</b><span class="count">{count} item{"s" if count != 1 else ""}</span></div>'
            f'<pre>{e(command)}</pre>'
            f'<details><summary>where</summary><ul>' + "".join(f'<li class="path">{e(x)}</li>' for x in examples)
            + (f'<li class="path">… and more</li>' if count > len(examples) else '') + '</ul></details></div>'
            for status, title, command, count, examples in plan)
        fixhtml = f'<h2>Fix plan</h2><p class="sub">{len(plan)} distinct actions, most urgent first.</p>{cards}'
    else:
        fixhtml = '<h2>Fix plan</h2><p class="sub">Nothing affected. No action needed.</p>'

    # Issue tree: item → status → rows
    tree = ""
    for item in sorted({r[0] for r in rows}, key=lambda i: min(STATUSES.index(r[3]) for r in rows if r[0] == i)):
        irows = [r for r in rows if r[0] == item]
        worst = min(irows, key=lambda r: STATUSES.index(r[3]))[3]
        tally = " ".join(f'<span class="pill {cls(s)}">{sum(r[3] == s for r in irows)} {s.lower()}</span>'
                         for s in STATUSES if any(r[3] == s for r in irows))
        leaves = "".join(
            f'<li><span class="pill {cls(r[3])}">{e(r[3])}</span> '
            f'<b>{e(str(r[2]))}</b> <span class="path">{e(str(r[1]))}</span>'
            + (f'<div class="note">{e(r[4])}</div>' if r[4] else '') + '</li>'
            for r in sorted(irows, key=lambda r: STATUSES.index(r[3])))
        openattr = " open" if worst in ("AFFECTED", "REVIEW") else ""
        tree += (f'<details class="node {cls(worst)}"{openattr}><summary><b>{e(item)}</b> {tally}</summary>'
                 f'<ul class="leaves">{leaves}</ul></details>')

    sources = "".join(f'<li><a href="{e(a["source"])}">{e(a["name"])}</a>: {e(a["about"])}</li>'
                      for a in ADVISORIES["versions"] + DISTRO + PACKAGES + ADVISORIES.get("iocs", []) + [CHROMIUM, ELECTRON, MCP, AGENT_FEED, {**AGENT_FEED, "name": AGENT_TOOLS}, AGENT, SKILLS, {"name": "eMudhra CA", **ADVISORIES["ca"]}] if a.get("source"))
    when = datetime.datetime.now().strftime("%d %b %Y, %H:%M")
    open(path, "w").write(f"""<!doctype html><html><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1"><title>Am I affected? — report</title><style>
:root{{--bg:#fafaf9;--fg:#1c1917;--muted:#78716c;--card:#fff;--line:#e7e5e4;--bad:#b91c1c;--warn:#b45309;--ok:#15803d;--na:#a8a29e}}
@media (prefers-color-scheme:dark){{:root{{--bg:#1c1917;--fg:#f5f5f4;--muted:#a8a29e;--card:#292524;--line:#44403c;--bad:#f87171;--warn:#fbbf24;--ok:#4ade80;--na:#78716c}}}}
body{{margin:0;padding:32px 16px;background:var(--bg);color:var(--fg);font:14px/1.5 system-ui,sans-serif}}
main{{max-width:1000px;margin:auto}} h1{{margin:0;font-size:24px}} h2{{font-size:16px;margin:32px 0 8px}} .sub{{color:var(--muted);margin:4px 0 16px}}
a{{color:inherit}} li{{margin:4px 0}} .sources li{{color:var(--muted)}} .sources li a{{color:var(--fg)}}
.stats{{display:flex;gap:12px;flex-wrap:wrap;margin-bottom:8px}}
.stat{{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:12px 18px;color:var(--muted)}}
.stat b{{display:block;font-size:26px;color:var(--fg)}} .stat.AFFECTED b{{color:var(--bad)}} .stat.REVIEW b{{color:var(--warn)}}
.pill{{font-size:11px;font-weight:600;padding:2px 8px;border-radius:99px;border:1px solid;white-space:nowrap}}
.AFFECTED{{color:var(--bad)}} .REVIEW,.UNKNOWN{{color:var(--warn)}} .OK{{color:var(--ok)}} .NOTFOUND{{color:var(--na)}}
.path{{font:12px ui-monospace,monospace;word-break:break-all;color:var(--muted)}}
.fix{{background:var(--card);border:1px solid var(--line);border-left:4px solid var(--warn);border-radius:10px;padding:14px 16px;margin:10px 0}}
.fix.AFFECTED{{border-left-color:var(--bad)}}
.fixhead{{display:flex;align-items:center;gap:10px;flex-wrap:wrap}} .fixhead b{{font-size:15px}} .count{{color:var(--muted);font-size:12px;margin-left:auto}}
.fix pre{{background:var(--bg);border:1px solid var(--line);border-radius:8px;padding:10px 12px;margin:10px 0 6px;overflow-x:auto;font:12px ui-monospace,monospace;white-space:pre-wrap}}
details.node{{background:var(--card);border:1px solid var(--line);border-left:4px solid var(--na);border-radius:10px;margin:8px 0;padding:4px 14px}}
details.node.AFFECTED{{border-left-color:var(--bad)}} details.node.REVIEW{{border-left-color:var(--warn)}} details.node.OK{{border-left-color:var(--ok)}}
summary{{cursor:pointer;padding:8px 0;display:flex;gap:8px;align-items:center;flex-wrap:wrap}} summary b{{font-size:15px}}
.leaves{{list-style:none;padding-left:14px;border-left:1px solid var(--line);margin:4px 0 10px}}
.leaves li{{padding:6px 0;border-bottom:1px solid var(--line)}} .leaves li:last-child{{border-bottom:0}}
.note{{color:var(--muted);font-size:13px;margin-top:3px}}
.share{{background:var(--card);border:1px solid var(--line);border-radius:8px;padding:10px 12px;font:13px ui-monospace,monospace;overflow-x:auto}}
.fix details summary{{color:var(--muted);font-size:12px}} .fix ul{{margin:6px 0 0;padding-left:18px}}
</style></head><body><main><h1>Am I affected?</h1>
<p class="sub">{e(platform.node())} · {e(platform.platform())} · {when}<br>{e(release_line())}</p><div class="stats">{counts}</div>
{fixhtml}
<h2>Issues by component</h2>{tree}
<h2>Advisories checked</h2><ul class="sources">{sources}</ul>
<h2>Pass it on</h2><p class="sub">{e(share_line(rows))}</p><pre class="share">{e(RUN_CMD)}</pre></main></body></html>""")


FEED_URL = "https://cve.now/feed?tech={}&format=json"


def _dt(s):
    return datetime.datetime.fromisoformat(s.replace("Z", "").split("+")[0])


def new_cves(items, checked, known=()):
    """CVE ids in a cve.now JSON-feed changed after the 'checked' watermark that the advisory doesn't
    already cover. The feed re-lists a CVE whenever its record changes (KEV listing, CVSS rescore),
    so known ids and ids from before last year are updates, not new issues.
    ponytail: the year cut can hide a genuinely late old-year CVE; cve.now has no published date to do better."""
    cut = _dt(checked)
    out = []
    for it in items:
        try:
            cve = it["id"].split("#")[0]
            if _dt(it["date_modified"]) > cut and cve not in known and int(cve.split("-")[1]) >= cut.year - 1 \
                    and cve not in out:
                out.append(cve)
        except (KeyError, ValueError, IndexError):
            continue  # ponytail: skip malformed items, the feed shape is not ours to trust
    return out


def check_feed_updates(advs, timeout=6):
    """Best-effort: one 'data may be stale' line per tech with CVEs newer than its watermark.

    Read-only GET of the public cve.now feed; nothing about this machine is sent. Any
    network/parse error is swallowed so the scan never depends on it."""
    lines = []
    for adv in advs:
        slug, checked = adv.get("feed"), adv.get("checked")
        if not slug or not checked:
            continue  # no feed slug (e.g. BIND) -> not feed-tracked
        try:
            with urllib.request.urlopen(FEED_URL.format(slug), timeout=timeout) as r:
                items = json.load(r).get("items", [])
        except Exception:
            continue
        fresh = new_cves(items, checked, adv.get("cves", ()))
        if fresh:
            shown = ", ".join(fresh[:5]) + (f" +{len(fresh) - 5} more" if len(fresh) > 5 else "")
            lines.append(f"{adv['name']}: {len(fresh)} CVE(s) on cve.now newer than {checked[:10]} "
                         f"({shown}) -- secinspect data may be stale, see cve.now")
    return lines


# --- Watch mode: run from cron (the --install line runs it every 6 hours), speak only when something changes ---------------------------

def watch_diff(rows, state_file):
    """(new findings, fixed findings, first run?) against the last run, then records this run.
    A finding is item + where + status, so AFFECTED -> OK shows as fixed and OK -> AFFECTED as new."""
    # compare with version numbers blanked: a kernel going 6.8.0-139 -> 147 while still affected is the same finding
    same = lambda k: re.sub(r"\d+(?:[.\-]\d+)+", "#", k)
    def keyed(keys):  # two installs that differ only in numbers (node v18 and v20) stay two findings
        out, seen = {}, {}
        for k in keys:
            n = seen[same(k)] = seen.get(same(k), 0) + 1
            out[same(k) + (f" #{n}" if n > 1 else "")] = k
        return out
    now = keyed(sorted(f"{r[0]} | {r[1]} | {r[3]}" for r in rows if r[3] in ("AFFECTED", "REVIEW", "PATCH")))
    try:
        before = keyed(json.load(open(state_file))["findings"])
        first = False
    except (OSError, ValueError, KeyError, TypeError):
        before, first = {}, True
    os.makedirs(os.path.dirname(os.path.abspath(state_file)), exist_ok=True)
    with open(state_file, "w") as fh:
        json.dump({"when": datetime.datetime.now().isoformat(timespec="seconds"), "findings": sorted(now.values())}, fh, indent=1)
    return sorted(now[k] for k in now.keys() - before.keys()), sorted(before[k] for k in before.keys() - now.keys()), first


def watch_message(new, fixed, first, rows):
    host = platform.node()
    patch = [x for x in new if x.endswith(" | PATCH")]  # a fix reached this machine's package sources
    new, fixed = [x for x in new if x not in patch], [x for x in fixed if not x.endswith(" | PATCH")]
    affected = sum(r[3] == "AFFECTED" for r in rows)
    ready = f", {len(patch)} fix(es) ready to apply" if patch else ""
    head = (f"Am I affected? is now watching {host}: {affected} affected, {len(new) - affected if first else 0} to review{ready}"
            if first else f"Am I affected? on {host}: {len(new)} new, {len(fixed)} fixed since the last run{ready}")
    lines = [head] + [f"PATCH  {x.split(' | ')[1]}: run --fix to apply it" for x in patch[:30]]
    lines += [f"NEW  {x}" for x in new[:30]] + [f"FIXED  {x}" for x in fixed[:30]]
    if len(new) + len(fixed) > 60:
        lines.append("... and more: run it by hand for the full list")
    return "\n".join(lines)


def notify(message, url=None, mail=None, desktop=False):
    """Sends only to what the user named on the command line."""
    if desktop:  # a banner on this machine; the text goes in as arguments, so nothing in it is run
        title, body = "Am I affected?", message.splitlines()[0]
        if sys.platform == "darwin":
            subprocess.run(["osascript", "-e", "on run argv", "-e", "display notification (item 2 of argv) with title (item 1 of argv)",
                            "-e", "end run", title, body], capture_output=True)
        elif shutil.which("notify-send"):
            subprocess.run(["notify-send", title, body], capture_output=True)
    if url:
        body = json.dumps({"text": message, "content": message[:1900]}).encode()  # Slack/Teams read text, Discord content
        try:
            urllib.request.urlopen(urllib.request.Request(url, body, {"Content-Type": "application/json"}), timeout=10)
        except Exception as e:
            print(f"watch: couldn't post to the webhook: {e}", file=sys.stderr)
    if mail:
        sendmail = shutil.which("sendmail") or ("/usr/sbin/sendmail" if os.path.exists("/usr/sbin/sendmail") else None)
        if not sendmail:
            print("watch: no sendmail on this machine, so no email was sent", file=sys.stderr)
            return
        msg = f"To: {mail}\nSubject: {message.splitlines()[0]}\n\n{message}\n"
        subprocess.run([sendmail, "-t"], input=msg, text=True, capture_output=True)


# --- Fix: vendor updates through the package manager, approved at the terminal, logged ---------
# Sanctity: the commands are built here, from package names the package manager itself reports.
# No command comes from advisories.json; it only decides which installed packages need an update.
# The update comes from the sources this machine already trusts (signed apt/dnf repositories,
# including vendor ones like nginx.org, PGDG or MySQL's, and Homebrew), never from us.

PKG_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9+._@-]*$")
KERNEL_PKG = re.compile(r"^(kernel(-(uek|rt|64k|debug|zfcpdump))*(-core|-modules.*)?|linux-(image|modules)-.+)$")  # needs a reboot to count
REFRESH = {"apt": ["apt-get", "update"], "dnf": ["dnf", "makecache"], "brew": ["brew", "update"]}


def is_root():
    return getattr(os, "geteuid", lambda: 1)() == 0


def default_audit_log():
    return "/var/log/amiaffected/audit.jsonl" if is_root() else os.path.join(HOME, ".local", "state", "amiaffected", "audit.jsonl")


def who():
    user, via = getpass.getuser(), os.environ.get("SUDO_USER")
    return f"{via} (sudo as {user})" if via else user


def entry_hash(e):
    return hashlib.sha256(json.dumps({k: v for k, v in e.items() if k != "hash"}, sort_keys=True).encode()).hexdigest()


def verify_log(path):
    """(True, entries) or (False, 'line N: what is wrong'). Each entry holds the hash of the one before it."""
    try:
        lines = open(path).read().splitlines()
    except FileNotFoundError:
        return True, 0
    prev = ""
    for i, line in enumerate(lines, 1):
        try:
            e = json.loads(line)
        except ValueError:
            return False, f"line {i}: not valid JSON"
        if not isinstance(e, dict) or e.get("prev") != prev:
            return False, f"line {i}: doesn't follow the line before it (a line was removed, added or moved)"
        if e.get("hash") != entry_hash(e):
            return False, f"line {i}: changed after it was written"
        prev = e["hash"]
    return True, len(lines)


class AuditLog:
    """Append-only JSON lines, hash-chained; created readable only by the owner."""
    # ponytail: tamper-evident, not tamper-proof: root can rewrite the whole chain; keep a copy of the last hash elsewhere if that matters
    def __init__(self, path):
        self.path = path
        os.makedirs(os.path.dirname(os.path.abspath(path)), mode=0o700, exist_ok=True)
        try:
            lines = open(path).read().splitlines()
        except FileNotFoundError:
            lines = []
        try:
            self.prev = json.loads(lines[-1])["hash"] if lines else ""
        except (ValueError, KeyError, TypeError):  # a torn last line: keep logging; --verify-log reports the break
            self.prev = "broken"

    def write(self, event, **data):
        e = {"time": datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds"), "host": platform.node(),
             "user": who(), "event": event, **data, "prev": self.prev}
        e["hash"] = self.prev = entry_hash(e)
        with os.fdopen(os.open(self.path, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600), "a") as fh:
            fh.write(json.dumps(e, sort_keys=True) + "\n")


def package_manager():
    if sys.platform.startswith("linux"):
        if shutil.which("apt-get") and shutil.which("dpkg-query"):
            return "apt"
        if shutil.which("dnf") and shutil.which("rpm"):
            return "dnf"
    return "brew" if shutil.which("brew") else None


def out_ok(*cmd):
    """stdout of a command that succeeded, else ''."""
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
    except (OSError, subprocess.TimeoutExpired):
        return ""
    return p.stdout if p.returncode == 0 else ""


def owner(pm, path):
    """The package that installed this file, or None (nvm, a tarball, an app that updates itself)."""
    if pm == "apt":
        lines = [l for l in out_ok("dpkg-query", "-S", path).splitlines() if not l.startswith("diversion")]
        name = lines[0].split(": ")[0].split(":")[0].strip() if len(lines) == 1 else ""
    elif pm == "dnf":
        lines = out_ok("rpm", "-qf", "--qf", "%{NAME}\n", path).split()
        name = lines[0] if len(lines) == 1 else ""
    else:
        m = re.search(r"/Cellar/([^/]+)/", os.path.realpath(path))
        name = m[1] if m else ""
    return name if PKG_NAME.match(name) else None


def candidate(pm, pkg):
    """The newest version the configured sources offer for pkg, or None."""
    if pm == "apt":
        m = re.search(r"^\s*Candidate:\s*(\S+)", out_ok("apt-cache", "policy", pkg), re.M)
        return m[1] if m and m[1] != "(none)" else None
    if pm == "dnf":
        found = out_ok("dnf", "-q", "repoquery", "--latest-limit=1", "--qf", "%{evr}\n", pkg).split()
        return found[-1] if found else None
    try:
        f = (json.loads(out_ok("brew", "info", "--json=v2", "--formula", pkg) or "{}").get("formulae") or [{}])[0]
    except ValueError:
        return None
    v, rev = f.get("versions", {}).get("stable"), f.get("revision", 0)
    return f"{v}_{rev}" if v and rev else v


def as_admin(pm, cmd):
    return cmd if pm == "brew" or is_root() else ["sudo"] + cmd


def upgrade_cmd(pm, pkgs):
    cmd = {"apt": ["env", "DEBIAN_FRONTEND=noninteractive", "apt-get", "install", "--only-upgrade", "-y",
                   "-o", "Dpkg::Options::=--force-confold", *pkgs],  # keep the admin's config files
           "dnf": ["dnf", "upgrade", "-y", *pkgs], "brew": ["brew", "upgrade", *pkgs]}[pm]
    return as_admin(pm, cmd)


def patch_plan(rows, pm, release=None):
    """AFFECTED rows (and REVIEW vendor-notice rows) split into (updates the configured sources can fix now, [(item, where, why)] for the rest).
    An update is offered only if the candidate version itself passes the same check the scan used."""
    fam = {"apt": "deb", "dnf": "rpm", "brew": "brew"}.get(pm)
    lt = deb_lt if fam == "deb" else rpm_lt
    release = None if pm == "brew" else release
    updates, manual = {}, []
    for item, where, version, status, _ in rows:
        where = str(where)
        if status != "AFFECTED" and not (status == "REVIEW" and item in VENDOR_FIXES):  # medium/low vendor fixes too
            continue
        distro = next((a for a in DISTRO if a["name"] == item), None)
        vadv = next((a for a in ADVISORIES["versions"] if a["name"] == item and "binary" in a), None)
        kernel = item in VENDOR_FIXES and any(KERNEL_PKG.match(b) for b in VENDOR_FIXES[item])
        if kernel or (distro and distro.get("kernel")):  # ponytail: kernels need a reboot and a new package name; by hand for now
            manual.append((item, where, "kernel updates need a reboot: use the fix plan"))
            continue
        if distro and fam and where.endswith(f"({pm})"):
            found = installed(fam, where.rsplit(" (", 1)[0].split())
            after = {p: candidate(pm, p) for p, _, _ in found}
            fixes = bool(found) and all(after[p] and distro_status(distro, release, after[p], src, lt)[0] == "OK" for p, _, src in found)
            before, after_fix = {p: v for p, v, _ in found}, distro.get("after_fix")
        elif item in VENDOR_FIXES and fam in ("deb", "rpm") and where.endswith(f"({pm})"):
            # vendor notices: every listed package must reach its fixed version
            fixed = {b: f for b, f in VENDOR_FIXES[item].items() if PKG_NAME.match(b)}
            found = installed(fam, sorted(fixed))
            after = {p: candidate(pm, p) for p, _, _ in found}
            fixes = bool(found) and all(after[p] and not lt(after[p], fixed[p]) for p, _, _ in found)
            before, after_fix = {p: v for p, v, _ in found}, "restart services that use it (needrestart shows which)"
        elif vadv and pm and os.path.isabs(where) and owner(pm, where):
            pkg = owner(pm, where)
            after, before, after_fix = {pkg: candidate(pm, pkg)}, {pkg: version}, vadv.get("after_fix")
            fixes = bool(after[pkg]) and version_status(vadv, nums(upstream(after[pkg])))[0] == "OK"
        else:
            manual.append((item, where, "not installed through apt, dnf or Homebrew: use the fix plan"))
            continue
        if not fixes:
            newest = ", ".join(f"{p} {v or 'none'}" for p, v in after.items())
            manual.append((item, where, f"no fixed build in this machine's package sources yet (newest: {newest})"))
            continue
        u = updates.setdefault(tuple(sorted(after)), {"items": [], "rows": [], "before": before, "after": after, "after_fix": after_fix})
        u["items"] += [item] if item not in u["items"] else []
        u["rows"].append((item, where))
    return list(updates.values()), manual


def patch_rows(rows, os_text=None):
    """For watch mode: one PATCH row per affected package whose fix is already in this machine's sources."""
    # ponytail: reads the package lists as they are (apt-daily / dnf-makecache keep them fresh); no refresh from cron
    pm = package_manager()
    if not pm or not any(r[3] == "AFFECTED" for r in rows):
        return []
    if os_text is None and os.path.exists("/etc/os-release"):
        os_text = open("/etc/os-release").read()
    updates, _ = patch_plan(rows, pm, os_release(os_text) if os_text else None)
    return [("Patch available", f"{', '.join(u['items'])} -> " + ", ".join(f"{p} {v}" for p, v in u["after"].items()),
             "-", "PATCH", "") for u in updates]


def execute(cmd):
    try:
        # no stdin: a package that prompts fails instead of hanging, and can't swallow the answers typed for --fix
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=3600, stdin=subprocess.DEVNULL)
    except (OSError, subprocess.TimeoutExpired) as e:
        return 127, str(e)
    return p.returncode, (p.stdout + p.stderr)[-4000:]


def sha256_file(path):
    return hashlib.sha256(open(path, "rb").read()).hexdigest()


def recheck(u):
    rows = [r for a in ADVISORIES["versions"] if a["name"] in u["items"] for r in check_version(a)]
    rows += [r for r in check_distro() if r[0] in u["items"]]
    def status(i, w):
        if i in VENDOR_FIXES:  # a notice row disappears once nothing is pending for that package
            return next((r[3] for r in rows if r[0] == i), "OK")
        return next((r[3] for r in rows if (r[0], str(r[1])) == (i, w)), "NOT FOUND")
    return {f"{i} | {w}": status(i, w) for i, w in u["rows"]}


def run_fix(rows, log_path, tty=None, os_text=None):
    ok, why = verify_log(log_path)
    if not ok:
        print(f"fix: the audit log {log_path} fails its check ({why}). Nothing was changed; "
              "move the log aside and find out why before fixing anything.", file=sys.stderr)
        return 2
    pm = package_manager()
    if not pm:
        print("fix: no apt, dnf or Homebrew on this machine, so there is nothing --fix can apply", file=sys.stderr)
        return 2
    try:
        ask_in, ask_out = (tty, tty) if tty else (open("/dev/tty"), open("/dev/tty", "w"))  # not stdin: with curl | sh, stdin is the script
    except OSError:
        print("fix: --fix asks before every change and needs a terminal for that; nothing was changed", file=sys.stderr)
        return 2
    log = AuditLog(log_path)
    here = os.path.dirname(os.path.abspath(__file__))
    log.write("start", tool_sha256=sha256_file(os.path.join(here, "secinspect.py")),
              advisories_sha256=sha256_file(os.path.join(here, "advisories.json")), package_manager=pm,
              affected=[f"{r[0]} | {r[1]} | {r[2]}" for r in rows if r[3] == "AFFECTED"])
    print(f"\nRefreshing the package lists ({' '.join(REFRESH[pm])})...")
    code, out = execute(as_admin(pm, REFRESH[pm]))
    log.write("refresh", command=as_admin(pm, REFRESH[pm]), exit=code)
    if code:
        print(f"  that failed (exit {code}), so the newest versions below may be out of date:\n{out[-600:]}")
    if os_text is None and os.path.exists("/etc/os-release"):
        os_text = open("/etc/os-release").read()
    release = os_release(os_text) if os_text else None
    updates, manual = patch_plan(rows, pm, release)
    log.write("plan", updates=[{"items": u["items"], "before": u["before"], "after": u["after"]} for u in updates],
              manual=[list(m) for m in manual])
    print(f"\n{len(updates)} update(s) ready from this machine's own package sources ({pm}); {len(manual)} need you.")
    left = len(manual)
    for n, u in enumerate(updates, 1):
        cmd = upgrade_cmd(pm, list(u["after"]))
        print(f"\n[{n}/{len(updates)}] {', '.join(u['items'])}")
        for p in u["after"]:
            print(f"      {p}: {u['before'][p]} -> {u['after'][p]}")
        print(f"      runs: {' '.join(cmd)}")
        if u["after_fix"]:
            print(f"      afterwards, by hand: {u['after_fix']}")
        sys.stdout.flush()
        ask_out.write("      Apply this update? Type yes to apply, anything else to skip: ")
        ask_out.flush()
        answer = ask_in.readline().strip().lower()
        if answer != "yes":
            log.write("declined", items=u["items"], packages=list(u["after"]))
            left += 1
            continue
        log.write("approved", items=u["items"], packages=list(u["after"]), command=cmd, approved_by=who())
        code, out = execute(cmd)
        log.write("applied", items=u["items"], command=cmd, exit=code, output=out[-2000:])
        after = recheck(u)
        log.write("verified", items=u["items"], status=after, still_to_do=u["after_fix"] or "")
        fixed = code == 0 and all(s == "OK" for s in after.values())
        left += 0 if fixed else 1
        print(f"      {'fixed' if fixed else 'NOT fixed'}: " + ", ".join(f"{k} is {v}" for k, v in after.items()) +
              (f"\n      exit {code}:\n{out[-800:]}" if code else "") + (f"\n      now: {u['after_fix']}" if fixed and u["after_fix"] else ""))
    if manual:
        print("\nNeeds you (see the fix plan):")
        for item, where, why in manual:
            print(f"  {item}  {where}\n      {why}")
    log.write("end", still_affected=left)
    print(f"\nEvery step is logged in {log_path}; check it any time with --verify-log.")
    return 1 if left else 0


# --- Agent: install once, then update only from releases signed with the key pinned at install ---
SITE = "https://amiaffected.now/"
SIGNER = "release@amiaffected.now"
SIGNING_KEY = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAINNGctHXayqCsdirLrReypA24IT2fPuIWgGM55YfntaM"  # Avagama release key, kept offline
AGENT_FILES = ("secinspect.py", "advisories.json")
HERE = os.path.dirname(os.path.abspath(__file__))


def agent_dir():
    return "/opt/amiaffected" if is_root() else os.path.join(HOME, ".local", "share", "amiaffected")


def fingerprint(key):
    blob = base64.b64decode(key.split()[1])
    return "SHA256:" + base64.b64encode(hashlib.sha256(blob).digest()).decode().rstrip("=")


def signers_line(key):
    return f'{SIGNER} namespaces="amiaffected" {key}\n'


def sig_ok(signers, path, sig):
    """True only if ssh-keygen says sig is a signature over path by a key in the signers file."""
    try:
        with open(path, "rb") as fh:
            p = subprocess.run(["ssh-keygen", "-Y", "verify", "-f", signers, "-I", SIGNER, "-n", "amiaffected", "-s", sig],
                               stdin=fh, capture_output=True, timeout=60)
    except (OSError, subprocess.TimeoutExpired):
        return False
    return p.returncode == 0


def release_signed(d=HERE, key=None):
    """For CI: do the .sig files next to the release files match SIGNING_KEY?"""
    with tempfile.NamedTemporaryFile("w", suffix=".signers") as fh:
        fh.write(signers_line(key or SIGNING_KEY))
        fh.flush()
        return all(sig_ok(fh.name, os.path.join(d, f), os.path.join(d, f + ".sig")) for f in AGENT_FILES)


def release_of(path):
    """advisories.json's "release": {"script_sha256", "released"}, or {} (an install from before releases were stamped)."""
    try:
        rel = json.load(open(path)).get("release")
        return rel if isinstance(rel, dict) else {}
    except (OSError, ValueError, AttributeError):
        return {}


def release_line(d=HERE, key=None):
    """Which release produced this result: its date, the script's hash and whether both files match the release
    key, so a table or report someone passes on can be traced to a signed, publicly logged version."""
    rel = release_of(os.path.join(d, "advisories.json")).get("released", "unstamped")
    try:
        sha = sha256_file(os.path.join(d, "secinspect.py"))[:16]
    except OSError:
        sha = "?"
    have = all(os.path.exists(os.path.join(d, f + ".sig")) for f in AGENT_FILES)
    try:  # OpenSSH before 8.1 can't check a signature: "unknown option -- Y"
        can = have and b"option -- Y" not in subprocess.run(["ssh-keygen", "-Y", "verify"], capture_output=True, timeout=20).stderr
    except (OSError, subprocess.TimeoutExpired):
        can = False
    state = "signature not checked" if not can else f"signed by release key {fingerprint(key or SIGNING_KEY)}" if release_signed(d, key) \
        else "NOT the signed release (changed, or files from two releases)"
    return f"Release {rel}, secinspect.py sha256 {sha}, {state}"


def newest_checked(path):
    try:
        return max(re.findall(r'"checked":\s*"([^"]+)"', open(path).read()), default="")
    except FileNotFoundError:
        return ""


def fetch(url):
    # Cloudflare in front of the site turns away Python's default User-Agent
    try:
        with urllib.request.urlopen(urllib.request.Request(url, headers={"User-Agent": "amiaffected"}), timeout=60) as r:
            return r.read()
    except http.client.HTTPException as e:  # a cut-off response isn't an OSError; callers handle OSError
        raise OSError(f"{url}: {e!r}") from e


def update_agent(d, log):
    """Download the release and its signatures; swap the files in only if every signature matches the pinned key."""
    signers = os.path.join(d, "allowed_signers")
    if not os.path.exists(signers):
        print(f"{d} isn't an installed copy: run --install first", file=sys.stderr)
        return 1
    if not shutil.which("ssh-keygen"):
        log.write("update_refused", dir=d, reason="ssh-keygen not found")
        print("Update refused, nothing changed: signatures are checked with ssh-keygen, which isn't installed "
              "(apt-get install openssh-client, or dnf install openssh)", file=sys.stderr)
        return 1
    tmp = tempfile.mkdtemp(dir=d)
    try:
        problem = None
        try:
            for f in AGENT_FILES:
                for name in (f, f + ".sig"):
                    with open(os.path.join(tmp, name), "wb") as fh:
                        fh.write(fetch(SITE + name))
        except OSError as e:
            problem = f"download failed: {e}"
        for f in AGENT_FILES if not problem else ():
            if not sig_ok(signers, os.path.join(tmp, f), os.path.join(tmp, f + ".sig")):
                problem = f"{f} isn't signed by the pinned key"
                break
        new_rel, old_rel = release_of(os.path.join(tmp, "advisories.json")), release_of(os.path.join(d, "advisories.json"))
        if not problem and new_rel.get("script_sha256") != sha256_file(os.path.join(tmp, "secinspect.py")):
            # each file has its own signature, so the signed advisories name the script they belong to
            problem = "secinspect.py isn't the one the signed advisories.json names (mixed or downgraded files?)"
        elif not problem and (newest_checked(os.path.join(tmp, "advisories.json")) < newest_checked(os.path.join(d, "advisories.json"))
                              or str(new_rel.get("released", "")) < str(old_rel.get("released", ""))):
            problem = "the downloaded release is older than the installed one (an old release replayed?)"
        if problem:
            log.write("update_refused", dir=d, reason=problem)
            print(f"Update refused, nothing changed: {problem}", file=sys.stderr)
            return 1
        before = {f: sha256_file(os.path.join(d, f)) if os.path.exists(os.path.join(d, f)) else None for f in AGENT_FILES}
        after = {f: sha256_file(os.path.join(tmp, f)) for f in AGENT_FILES}
        for f in AGENT_FILES:  # keep the signatures so --fix can re-check the installed files
            os.replace(os.path.join(tmp, f + ".sig"), os.path.join(d, f + ".sig"))
        if before != after:
            # ponytail: two renames, not one atomic step; a crash between them leaves new data with the old script for one run
            for f in ("advisories.json", "secinspect.py"):
                os.replace(os.path.join(tmp, f), os.path.join(d, f))
            log.write("updated", dir=d, before=before, after=after)
            print(f"Updated {d} to the signed release", file=sys.stderr)
        return 0
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def installed_copy_ok(d=HERE):
    """--fix runs only from an installed copy whose files still match their signatures, so what it decides comes from us."""
    # ponytail: catches edited data or a swapped file; someone who can rewrite this script as root can also remove this check
    signers = os.path.join(d, "allowed_signers")
    if not os.path.exists(signers):
        sudo, home = ("", "~/.local/share/amiaffected") if sys.platform == "darwin" else ("sudo ", "/opt/amiaffected")  # brew won't run as root
        return "--fix runs only from the installed copy, which takes signed releases only. Install it once:\n" \
               f"  curl -fsSL https://amiaffected.now/run | {sudo}sh -s -- --install\n" \
               f"then run:  {sudo}python3 {home}/secinspect.py --fix"
    if not shutil.which("ssh-keygen"):
        return "signatures are checked with ssh-keygen, which isn't installed (apt-get install openssh-client, or dnf install openssh)"
    bad = [f for f in AGENT_FILES if not sig_ok(signers, os.path.join(d, f), os.path.join(d, f + ".sig"))]
    return f"{', '.join(bad)} in {d} doesn't match its signature: run --update, or --install again" if bad else None


LAUNCH_LABEL = "now.amiaffected.watch"


def launch_agent(d, py, agents=os.path.join(HOME, "Library", "LaunchAgents")):
    """Writes the macOS LaunchAgent (launchd is cron's Mac equivalent, and runs missed jobs after sleep). Not started:
    --install prints the command, as it does the cron line."""
    q = shlex.quote
    cmd = (f"{q(sys.executable)} {q(py)} --update; "
           f"{q(sys.executable)} {q(py)} --watch {q(os.path.join(d, 'watch.json'))} --desktop")
    os.makedirs(agents, exist_ok=True)
    path = os.path.join(agents, LAUNCH_LABEL + ".plist")
    with open(path, "wb") as fh:
        plistlib.dump({"Label": LAUNCH_LABEL, "ProgramArguments": ["/bin/sh", "-c", cmd], "StartInterval": 6 * 3600,
                       "RunAtLoad": True, "StandardErrorPath": os.path.join(d, "watch.log")}, fh)
    return path


def install_agent(d, log, key=None):
    key = key or SIGNING_KEY
    if not key:
        print("Signed releases haven't started yet, so there's nothing safe to install. Use the one-liner for now.", file=sys.stderr)
        return 1
    os.makedirs(d, mode=0o755, exist_ok=True)
    signers = os.path.join(d, "allowed_signers")
    if os.path.exists(signers) and open(signers).read() != signers_line(key):
        print(f"A different release key is already pinned in {signers}. If you trust the new one, delete that file "
              "and run --install again.", file=sys.stderr)
        log.write("install_refused", dir=d, reason="a different key is pinned", key=fingerprint(key))
        return 1
    with open(signers, "w") as fh:
        fh.write(signers_line(key))
    print(f"Pinned release key {fingerprint(key)}\nCompare it with the one at github.com/abhay-avagama/security-inspector "
          "before relying on updates.", file=sys.stderr)
    log.write("installed", dir=d, key=fingerprint(key))
    rc = update_agent(d, log)
    if rc == 0:
        py = os.path.join(d, "secinspect.py")
        print(f"\nInstalled. Run it with:  python3 {py}\nApply fixes:            python3 {py} --fix", file=sys.stderr)
        if sys.platform == "darwin" and not is_root():
            plist = launch_agent(d, py)
            print(f"To check every 6 hours and show a notification when something changes (a refused update keeps the last "
                  f"signed copy and says why):\n  launchctl bootstrap gui/{os.getuid()} {plist}\nTo stop:  launchctl bootout "
                  f"gui/{os.getuid()} {plist}\nGive {sys.executable} Full Disk Access (System Settings > Privacy & Security) "
                  "or it can't read Documents, Desktop or Downloads in the background.", file=sys.stderr)
        else:
            print(f"For cron (every 6 hours; a refused update keeps the last signed copy and says why):\n"
                  f"  0 */6 * * * python3 {py} --update; python3 {py} --watch {os.path.join(d, 'watch.json')}", file=sys.stderr)
    return rc


def main(argv):
    ap = argparse.ArgumentParser(description="Am I affected by the issues in advisories.json?")
    ap.add_argument("dirs", nargs="*", help="search only these folders for Python envs, lockfiles and CA bundles")
    ap.add_argument("--docker", action="store_true", help="also look inside every local Docker image (slow)")
    ap.add_argument("--html", metavar="FILE", help="also write an HTML report")
    ap.add_argument("--json", metavar="FILE", help="also write the findings and the agent inventory as JSON")
    ap.add_argument("--agents", action="store_true", help="also list every MCP server, skill, hook and agent permission setting "
                                                          "found: what it runs, whether it is pinned, and what was flagged")
    ap.add_argument("--watch", metavar="STATE_FILE",
                    help="for cron: compare with the last run recorded in STATE_FILE and report only what changed")
    ap.add_argument("--notify", metavar="URL", help="with --watch: post changes to this webhook (Slack, Discord, Teams or any JSON endpoint)")
    ap.add_argument("--mail", metavar="ADDRESS", help="with --watch: email changes through this machine's sendmail")
    ap.add_argument("--desktop", action="store_true", help="with --watch: show changes as a notification on this machine")
    ap.add_argument("--files-only", action="store_true",
                    help="only check files in the folders given (lockfiles, MCP configs, skills, .env, CA bundles), not this "
                         "machine's programs; for CI, where the runner's own Chrome or Node aren't yours to fix")
    ap.add_argument("--skills-baseline", metavar="FILE",
                    help="remember a fingerprint of every installed skill in FILE and report what changed since the last run")
    ap.add_argument("--no-update-check", action="store_true",
                    help="offline: skip the cve.now advisory-freshness check and use only cached vendor notices, "
                         "never downloading them (also $SECINSPECT_NO_UPDATE_CHECK)")
    ap.add_argument("--osv", action="store_true",
                    help="also check every package pinned in the lockfiles found (npm, PyPI, Cargo, Go) and installed Python "
                         "packages against OSV.dev; sends their names and versions to api.osv.dev, nothing else")
    ap.add_argument("--fix", action="store_true",
                    help="offer the vendor's update for each affected package (apt, dnf, Homebrew), apply only what you "
                         "approve at the terminal, and log every step")
    ap.add_argument("--audit-log", metavar="FILE", help="the audit log --fix, --install and --update write and --verify-log checks "
                    "(default /var/log/amiaffected/audit.jsonl as root, else ~/.local/state/amiaffected/audit.jsonl)")
    ap.add_argument("--verify-log", action="store_true", help="check the --fix audit log hasn't been edited, then exit")
    ap.add_argument("--install", action="store_true", help="keep a copy in /opt/amiaffected (or ~/.local/share/amiaffected), "
                    "pin the release key, and print the cron line")
    ap.add_argument("--update", action="store_true", help="update the installed copy, only if the release is signed by the pinned key")
    args = ap.parse_args(argv)
    log_path = os.path.expanduser(args.audit_log or default_audit_log())
    if args.install:
        return install_agent(agent_dir(), AuditLog(log_path))
    if args.update:
        return update_agent(HERE if os.path.exists(os.path.join(HERE, "allowed_signers")) else agent_dir(), AuditLog(log_path))
    if args.verify_log:
        ok, why = verify_log(log_path)
        print(f"{log_path}: {why} entries, chain intact" if ok else f"{log_path}: BROKEN at {why}")
        return 0 if ok else 1
    if args.fix and (args.watch or args.files_only):
        ap.error("--fix can't be combined with --watch or --files-only")
    if args.fix and (problem := installed_copy_ok()):
        print(f"fix: {problem}", file=sys.stderr)
        AuditLog(log_path).write("fix_refused", reason=problem.splitlines()[0])
        return 1
    roots = args.dirs or [HOME, "/usr/local/lib", "/opt/homebrew/lib", *glob.glob("/usr/lib/python3*"),
                          *glob.glob("/var/lib/gems"), *glob.glob("/usr/share/rubygems-integration"),  # Debian's gems
                          *glob.glob("/var/www"), *glob.glob("/srv"),  # where server apps and their lockfiles live
                          *glob.glob("/usr/share/java"), *glob.glob("/var/lib/tomcat*"), *glob.glob("/opt/tomcat*")]  # Java libraries and webapps
    if not args.watch:  # cron mails anything printed, so a quiet day must print nothing
        print(f"Scanning {', '.join(roots)} for Python envs, lockfiles and CA bundles, give it a minute...", file=sys.stderr)
    if not (args.watch or args.no_update_check or os.environ.get("SECINSPECT_NO_UPDATE_CHECK")):
        for line in check_feed_updates(ADVISORIES["versions"] + ADVISORIES["distro"] + ADVISORIES["packages"]):
            print("update: " + line, file=sys.stderr)
    if not OPENSSL:
        print("openssl not found: CA bundles are judged by which roots they hold, not by a chain test", file=sys.stderr)
    if args.files_only:  # the repo, not the runner: no binaries, caches, trust stores, keys or home configs (docker
        # images are only listed by digest; --docker reads them)
        rows = scan_files(roots) + check_docker(args.docker)
        rows += check_skills(home=os.path.join(roots[0], ".no-home"), extra=FOUND_SKILL_DIRS)
        rows += check_agent_feed(os.path.join(roots[0], ".no-home"))  # a repo's .mcp.json: pinned versions only, not this machine's npx cache
        rows += check_osv() if args.osv else []
    else:
        offline = bool(args.no_update_check or os.environ.get("SECINSPECT_NO_UPDATE_CHECK"))
        rows = [r for adv in ADVISORIES["versions"] for r in check_version(adv)] + check_distro(offline=offline)
        rows += check_chromium_cache() + check_electron() + scan_files(roots) + check_docker(args.docker) + check_stores()
        rows += check_mcp(rows) + check_agent_feed() + check_agent_tools() + check_iocs() + check_skills(extra=FOUND_SKILL_DIRS) + check_hooks()
        rows += check_osv() if args.osv else []
        try:
            rows += os_row(open("/etc/os-release").read())
        except OSError:
            pass
        rows = apply_eol(rows) + check_settings()
    if args.skills_baseline:
        home = os.path.join(roots[0], ".no-home") if args.files_only else HOME
        rows += check_skill_changes(skill_dirs(home=home, extra=FOUND_SKILL_DIRS), os.path.expanduser(args.skills_baseline))
    if args.watch:  # cron mode: say only what changed
        new, fixed, first = watch_diff(rows + patch_rows(rows), os.path.expanduser(args.watch))
        if new or fixed or first:
            message = watch_message(new, fixed, first, rows)
            print(message)
            notify(message, args.notify, args.mail, args.desktop)
        return 1 if any(r[3] == "AFFECTED" for r in rows) else 0
    widths = [max(len(str(r[i])) for r in rows) for i in range(4)]
    for r in rows:
        print("  ".join(str(c).ljust(w) for c, w in zip(r, widths)), r[4])
    inventory = agent_inventory(rows, os.path.join(roots[0], ".no-home") if args.files_only else HOME) if args.agents or args.json else []
    if args.agents:
        print("\n" + "\n".join(inventory_table(inventory)))
    if args.json:
        json.dump({"release": release_line(), "generated": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
                   "machine": platform.node(), "findings": [dict(zip(("item", "where", "found", "status", "note"), r)) for r in rows],
                   "agents": inventory}, open(args.json, "w"), indent=1)
        print(f"JSON written to {os.path.abspath(args.json)}", file=sys.stderr)
    print("\n" + release_line(), file=sys.stderr)  # stderr, so the table on stdout stays clean for scripts
    if not args.files_only:  # not in CI or cron
        print(share_line(rows) + RUN_CMD, file=sys.stderr)
    if args.html:
        html_report(rows, args.html)
        print(f"Report written to {os.path.abspath(args.html)}", file=sys.stderr)
    if args.fix:
        return run_fix(rows, log_path)
    return 1 if any(r[3] == "AFFECTED" for r in rows) else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
