#!/usr/bin/env python3
"""Am I affected? Checks this machine for the issues listed in advisories.json (Oct 2026: PHP,
Node.js, BIND, LiteLLM, GitLab, eMudhra; Nov 2026: exploited Chrome bugs, stale Puppeteer/Playwright
browsers and the deprecated Puppeteer MCP server; on Linux servers also the kernel, nginx, Apache,
MariaDB, MongoDB, WordPress and more). Stdlib only. Exit code 1 if anything is affected.

Usage: python3 secinspect.py [dirs ...] [--docker] [--html report.html] [--no-update-check]
  With no dirs, searches your home folder and system Python paths for envs, lockfiles and CA bundles.
  With dirs, searches only those. Installed programs and system trust stores are always checked.
"""
import argparse
import base64
import datetime
import glob
import hashlib
import html
import json
import os
import platform
import plistlib
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
import textwrap
import urllib.request

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
        found = [(b, parse(run(b, adv["flag"]))) for b in binaries(adv["binary"], *adv.get("globs", []))]
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


def load_config(path, data):
    try:
        if path.endswith(".toml"):
            import tomllib  # 3.11+; older Pythons just skip Codex's config
            return tomllib.loads(data.decode("utf-8", "replace"))
        return json.loads(data)
    except Exception:  # ponytail: JSONC with comments (VS Code) is skipped, not half-parsed
        return None


def agent_config_rows(path, data):
    if re.search(r"/plugins/marketplaces/|/\.tmp/", path):  # catalogs of plugins you could install, not ones that run
        return []
    rows = mcp_rows(path, data)
    cfg = load_config(path, data)
    if not isinstance(cfg, dict):
        return rows
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
    rewrites FILE. The only file the tool writes besides --html, and only because you named it."""
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
    if os_id != "fedora" and {"rhel", "centos"} & {os_id, *like} and v:
        return f"el:{v.split('.')[0]}"
    return None


def upstream(v):
    """'1:9.6p1-3ubuntu13.5' -> '9.6p1': drop the epoch and the distro revision."""
    v = re.sub(r"^\d+:", "", v)
    return v.rsplit("-", 1)[0] if "-" in v else v


def nums(v):
    return tuple(int(x) for x in re.findall(r"\d+", v))


def deb_lt(a, b):
    return subprocess.run(["dpkg", "--compare-versions", a, "lt", b]).returncode == 0


def rpm_lt(a, b):
    """EVR comparison with rpm's own rpmvercmp, applied to epoch, version and release in turn."""
    def evr(s):
        e, _, vr = s.rpartition(":") if ":" in s else ("0", "", s)
        v, _, r = vr.partition("-")
        return [e or "0", v, r]
    for x, y in zip(evr(a), evr(b)):
        c = run("rpm", "--eval", f'%{{lua:print(rpm.vercmp("{x}", "{y}"))}}').strip()
        if c != "0":
            return c == "-1"
    return False


def installed(fam, names):
    """[(package, version, source package)] for the installed ones."""
    if not names:
        return []  # dpkg-query/rpm with no names list every package
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
    {source package: build} map (kernel flavours), "not-affected" or "unfixed"."""
    fixed = adv.get("fixed", {}).get(release)
    if isinstance(fixed, dict):
        fixed = fixed.get(source) or fixed.get("*")
    proposed = isinstance(fixed, str) and fixed.startswith("proposed:")  # fix only in Ubuntu's testing pocket so far
    fixed = fixed[len("proposed:"):] if proposed else fixed
    ups = [nums(f) for f in adv.get("upstream_fixed", [])]
    after = (", " + adv["after_fix"]) if adv.get("after_fix") else ""
    if fixed == "not-affected":
        return "OK", f"{release} isn't affected"
    if fixed and fixed != "unfixed" and (not ups or upstream(version) == upstream(fixed)):
        if not lt(version, fixed):
            return "OK", ""
        if proposed:
            return "AFFECTED", f"fixed in {fixed}, so far only in {release}'s -proposed pocket: install it from there or wait for -updates{after}"
        return "AFFECTED", f"update to {fixed}+{after}"
    unfixed = ("AFFECTED", f"no fixed {release} package yet: {adv.get('mitigation', 'watch for the update')}")
    if ups:  # vendor build, or the distro moved to a new upstream release
        status, note = by_branch(nums(upstream(version)), ups, adv.get("branch_width", 2))
        if status == "AFFECTED" and fixed == "unfixed":
            return unfixed
        return status, (note + after if status == "AFFECTED" else note)
    if fixed == "unfixed":
        return unfixed
    return "UNKNOWN", f"no fixed version known for {release or 'this distro'}"


def check_distro(os_text=None):
    if os_text is None:
        try:
            os_text = open("/etc/os-release").read()
        except OSError:
            return []  # not Linux: nothing to say about server packages
    fam = "deb" if shutil.which("dpkg-query") else "rpm" if shutil.which("rpm") else None
    release = os_release(os_text)
    if not fam:
        return [("Server packages", "-", "-", "UNKNOWN", "only apt (Ubuntu/Debian) and dnf (RHEL family) systems are checked")]
    lt = deb_lt if fam == "deb" else rpm_lt
    rows = []
    for adv in DISTRO:
        if not adv.get("kernel") and not adv.get(f"{fam}_packages"):
            continue  # e.g. mod_http2 is its own package only on RHEL; apache2 covers it on Debian
        found = running_kernel(fam) if adv.get("kernel") else installed(fam, adv.get(f"{fam}_packages", []))
        if not found:
            rows.append((adv["name"], "-", "-", "NOT FOUND", ""))
            continue
        # one row per advisory: nginx + nginx-core or mariadb-server + -core are one thing to fix
        checked = [(pkg, version, *distro_status(adv, release, version, source, lt)) for pkg, version, source in found]
        worst = min(checked, key=lambda c: STATUSES.index(c[2]))
        pkgs = " ".join(sorted({c[0] for c in checked}))
        rows.append((adv["name"], f"{pkgs} ({'apt' if fam == 'deb' else 'dnf'})", worst[1], worst[2], worst[3]))
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


def fix_hint(path):
    p = path.lower()
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
                      r"|package-lock\.json|pnpm-lock\.yaml|yarn\.lock|bun\.lock)$")
SKIP = {"node_modules", ".git", ".Trash"}
MAX_READ = 50_000_000  # cap per-file reads (disk and tar members) so an untrusted file can't exhaust memory


def pkg_bad(pkg, v):
    lo, hi = pkg.get("bad_range", (None, None))
    return v in pkg.get("bad", ()) or bool(lo and nums(lo) <= nums(v) <= nums(hi))


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
    for pkg in PACKAGES:
        name, status = pkg["name"], pkg.get("status", "AFFECTED")
        pat = re.escape(pkg["package"]).replace(r"\-", "[-_]")  # dist-info folders say python_jose
        lock_note = pkg.get("lock_note", f"lockfile pins the backdoored build: pin {pkg.get('safe')}")
        m = re.fullmatch(rf"{pat}-([\w.]+)\.(?:dist|egg)-info", parent, re.I)
        if m and base in ("METADATA", "PKG-INFO"):
            bad = pkg_bad(pkg, m[1])
            rows.append((name, os.path.dirname(path), m[1], status if bad else "OK", pkg["cleanup"] if bad else ""))
        if "site-packages" in path and base in pkg.get("malware_files", ()):
            rows.append((name, path, "malware file", "AFFECTED", pkg["cleanup"]))
        # Python only auto-runs it from the top of site-packages; Homebrew ships a legit one there
        elif base in pkg.get("suspicious_files", ()) and parent == "site-packages" and b"created by Homebrew" not in data()[:200]:
            rows.append((name, path, "possible malware", "REVIEW", f"{name} malware drops this; check it if you didn't add it"))
        if not LOCKFILE.search(base):
            continue
        if pkg.get("ecosystem") == "npm":
            for v in sorted(npm_versions(pat.encode(), data())):
                if pkg_bad(pkg, v.decode()):
                    rows.append((name, path, v.decode(), status, lock_note))
        elif "bad_range" in pkg:  # ponytail: proximity regex, first version after the name; fine for pins
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
                        return open(p, "rb").read() if os.path.getsize(p) < MAX_READ else b""
                    except OSError:
                        return b""

                r, b = inspect_file(p, read)
                rows += r
                bundles += b
    for pkg in PACKAGES:
        if os.path.exists(pkg.get("lock_file", "")):
            rows.append((pkg["name"], pkg["lock_file"], "malware lock", "AFFECTED", "malware daemon may be running: " + pkg["cleanup"]))
        if not any(r[0] == pkg["name"] for r in rows):
            rows.append((pkg["name"], "-", "-", "NOT FOUND", ""))
    return rows + bundle_summary(bundles)


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
        if "certifi" in w:  # before site-packages and /vendor/: pip ships certifi under pip/_vendor/certifi
            return ("Update certifi in affected virtualenvs (after a fixed release ships)", "pip install -U certifi   # run in each affected venv")
        if "/vendor/" in w:  # composer convention; note /vendor/ not _vendor/ (python)
            return ("Refresh vendored CA bundles (e.g. PHP/composer packages)", "composer update   # in each project shipping its own cacert.pem")
        if "site-packages" in w:
            return ("Update Python packages that ship their own CA bundle", "pip install -U <package>   # e.g. botocore, once it drops the root")
        if "(via" in where:
            return ("Fix the custom CA bundle pointed to by an env var / tool config", "point the override at a patched bundle, or unset it to use the system store")
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
                      for a in ADVISORIES["versions"] + DISTRO + PACKAGES + ADVISORIES.get("iocs", []) + [CHROMIUM, MCP, AGENT, SKILLS, {"name": "eMudhra CA", **ADVISORIES["ca"]}])
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
.fix details summary{{color:var(--muted);font-size:12px}} .fix ul{{margin:6px 0 0;padding-left:18px}}
</style></head><body><main><h1>Am I affected?</h1>
<p class="sub">{e(platform.node())} · {e(platform.platform())} · {when}</p><div class="stats">{counts}</div>
{fixhtml}
<h2>Issues by component</h2>{tree}
<h2>Advisories checked</h2><ul class="sources">{sources}</ul></main></body></html>""")


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
    network/parse error is swallowed so the offline scan never depends on it."""
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


def main(argv):
    ap = argparse.ArgumentParser(description="Am I affected by the issues in advisories.json?")
    ap.add_argument("dirs", nargs="*", help="search only these folders for Python envs, lockfiles and CA bundles")
    ap.add_argument("--docker", action="store_true", help="also look inside every local Docker image (slow)")
    ap.add_argument("--html", metavar="FILE", help="also write an HTML report")
    ap.add_argument("--skills-baseline", metavar="FILE",
                    help="remember a fingerprint of every installed skill in FILE and report what changed since the last run")
    ap.add_argument("--no-update-check", action="store_true",
                    help="skip the cve.now advisory-freshness check (offline/CI; also $SECINSPECT_NO_UPDATE_CHECK)")
    args = ap.parse_args(argv)
    roots = args.dirs or [HOME, "/usr/local/lib", "/opt/homebrew/lib", *glob.glob("/usr/lib/python3*")]
    print(f"Scanning {', '.join(roots)} for Python envs, lockfiles and CA bundles, give it a minute...", file=sys.stderr)
    if not (args.no_update_check or os.environ.get("SECINSPECT_NO_UPDATE_CHECK")):
        for line in check_feed_updates(ADVISORIES["versions"]):
            print("update: " + line, file=sys.stderr)
    if not OPENSSL:
        print("openssl not found: CA bundles are judged by which roots they hold, not by a chain test", file=sys.stderr)
    rows = [r for adv in ADVISORIES["versions"] for r in check_version(adv)] + check_distro()
    rows += check_chromium_cache() + scan_files(roots) + check_docker(args.docker) + check_stores()
    rows += check_mcp(rows) + check_iocs() + check_skills(extra=FOUND_SKILL_DIRS) + check_hooks()
    if args.skills_baseline:
        rows += check_skill_changes(skill_dirs(extra=FOUND_SKILL_DIRS), os.path.expanduser(args.skills_baseline))
    widths = [max(len(str(r[i])) for r in rows) for i in range(4)]
    for r in rows:
        print("  ".join(str(c).ljust(w) for c, w in zip(r, widths)), r[4])
    if args.html:
        html_report(rows, args.html)
        print(f"Report written to {os.path.abspath(args.html)}", file=sys.stderr)
    return 1 if any(r[3] == "AFFECTED" for r in rows) else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
