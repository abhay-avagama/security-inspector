#!/usr/bin/env python3
"""Am I affected? Checks this machine for the Oct 2026 PHP, Node.js, BIND, LiteLLM,
GitLab and eMudhra issues. Stdlib only. Exit code 1 if anything is affected.

Usage: python3 secinspect.py [dirs ...] [--html report.html]
  With no dirs, searches your home folder and system Python paths for envs, lockfiles and CA bundles.
  With dirs, searches only those. Installed programs and system trust stores are always checked.
"""
import argparse
import base64
import datetime
import glob
import hashlib
import html
import os
import platform
import re
import shutil
import subprocess
import sys

HOME = os.path.expanduser("~")


def ver(s):
    m = re.search(r"(\d+)\.(\d+)\.(\d+)", s or "")
    return tuple(map(int, m.groups())) if m else None


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
    A branch older than the newest fixed one but missing from the list is end-of-life, which all
    three advisories (PHP, Node, GitLab) count as affected with no fix."""
    for f in fixed:
        if f[:width] == v[:width]:
            return ("AFFECTED", f"upgrade to {fmt(f)}+") if v < f else ("OK", "")
    if v < max(fixed):
        return "AFFECTED", f"end-of-life branch, no fix coming: move to {fmt(max(fixed))}+ or another patched branch"
    return "UNKNOWN", "newer than the advisory, check for a later one"


def php_status(v):
    # CVE-2026-109618 / CVE-2026-109619 (PHP2Shell)
    status, note = by_branch(v, [(8, 5, 12), (8, 4, 27), (8, 3, 36), (8, 2, 35)], 2)
    return status, (note + ", restart PHP-FPM/workers" if status == "AFFECTED" else note)


def node_status(v):
    # Oct 21 2026 release, 10 CVEs incl. CVE-2026-111497 (Brotli RCE); also refreshes Node's bundled CA store for eMudhra
    return by_branch(v, [(26, 12, 1), (24, 22, 1), (22, 23, 4)], 1)


def gitlab_status(v):
    # CVE-2026-110264 (CVSS 10.0) affects everything from 7.0; 11 more CVEs in the same release
    return by_branch(v, [(19, 5, 1), (19, 4, 3), (19, 3, 6), (19, 2, 9), (19, 1, 9), (19, 0, 10), (18, 11, 13)], 2)


def bind_status(v):
    # CVE-2026-94300, ranges straight from the ISC advisory
    if (9, 11, 0) <= v <= (9, 18, 50):
        return "AFFECTED", "no fixed 9.18 build listed: move to 9.20.30+ or check with ISC"
    if (9, 20, 0) <= v < (9, 20, 30):
        return "AFFECTED", "upgrade to 9.20.30+"
    if (9, 21, 0) <= v < (9, 21, 27):
        return "AFFECTED", "upgrade to 9.21.27+"
    return "OK", ""


def check_bins(item, bins, flag, status_fn):
    if not bins:
        return [(item, "-", "-", "NOT FOUND", "")]
    rows = []
    for b in bins:
        v = ver(run(b, flag))
        status = status_fn(v) if v else ("UNKNOWN", "couldn't read version")
        rows.append((item, b, fmt(v) if v else "?", *status))
    return rows


def check_gitlab():
    path = "/opt/gitlab/embedded/service/gitlab-rails/VERSION"  # Omnibus installs
    if not os.path.exists(path):
        return [("GitLab", "-", "-", "NOT FOUND", "self-managed only; GitLab.com is already patched")]
    v = ver(open(path).read())
    status = gitlab_status(v) if v else ("UNKNOWN", "couldn't read version")
    return [("GitLab", path, fmt(v) if v else "?", *status)]


# Roots Red Hat says to blocklist (RHSB-2026-012); the cracked eMudhra intermediates chain to them.
# Matched by certificate bytes, not by name, so PEM bundles, Java keystores and NSS libraries all work.
EMUDHRA_ROOTS = {
    "emSign ECC Root CA - G3": ("AFFECTED", base64.b64decode("MIICTjCCAdOgAwIBAgIKPPYHqWhwDtqLhDAKBggqhkjOPQQDAzBrMQswCQYDVQQGEwJJTjETMBEGA1UECxMKZW1TaWduIFBLSTElMCMGA1UEChMcZU11ZGhyYSBUZWNobm9sb2dpZXMgTGltaXRlZDEgMB4GA1UEAxMXZW1TaWduIEVDQyBSb290IENBIC0gRzMwHhcNMTgwMjE4MTgzMDAwWhcNNDMwMjE4MTgzMDAwWjBrMQswCQYDVQQGEwJJTjETMBEGA1UECxMKZW1TaWduIFBLSTElMCMGA1UEChMcZU11ZGhyYSBUZWNobm9sb2dpZXMgTGltaXRlZDEgMB4GA1UEAxMXZW1TaWduIEVDQyBSb290IENBIC0gRzMwdjAQBgcqhkjOPQIBBgUrgQQAIgNiAAQjpQy4LRL1KPOxst3iAhKAnjlfSU2fySU0WXTsuwYc58Byr+iuL+FBVIcUqEqy6HyC5ltqtdyzdc6LBtCGI79G1Y4PPwT01xySfvalY8L1X44uT6EYGQIrMgqCZH0Wk9GjQjBAMB0GA1UdDgQWBBR8XQKEE9TMipuBzhccLikenEhjQjAOBgNVHQ8BAf8EBAMCAQYwDwYDVR0TAQH/BAUwAwEB/zAKBggqhkjOPQQDAwNpADBmAjEAvvNhzwIQHWSVB7gYboiFBS+DCBeQyh+KTOgNG3qxrdWBCUfvO6wIBHxcmbHtRwfSAjEAnbpV/KlK6O3t5nYBQnvI+GDZjVGLVTv7jHvrZQnD+JbNR6iC8hZVdyR+EhCVBCyj")),
    "AAA Certificate Services": ("REVIEW", base64.b64decode("MIIEMjCCAxqgAwIBAgIBATANBgkqhkiG9w0BAQUFADB7MQswCQYDVQQGEwJHQjEbMBkGA1UECAwSR3JlYXRlciBNYW5jaGVzdGVyMRAwDgYDVQQHDAdTYWxmb3JkMRowGAYDVQQKDBFDb21vZG8gQ0EgTGltaXRlZDEhMB8GA1UEAwwYQUFBIENlcnRpZmljYXRlIFNlcnZpY2VzMB4XDTA0MDEwMTAwMDAwMFoXDTI4MTIzMTIzNTk1OVowezELMAkGA1UEBhMCR0IxGzAZBgNVBAgMEkdyZWF0ZXIgTWFuY2hlc3RlcjEQMA4GA1UEBwwHU2FsZm9yZDEaMBgGA1UECgwRQ29tb2RvIENBIExpbWl0ZWQxITAfBgNVBAMMGEFBQSBDZXJ0aWZpY2F0ZSBTZXJ2aWNlczCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAL5AnfRu4ep2hxxNRUSOvkbIgwadwSr+GB+O5AL686tdUIoWMQuaBtDFcCLNSS1UY8y2bmhGC1Pqy0wkwLxyTurxFa70VJoSCsN6sjNg4tqJVfMiWPPe3M/vg4aijJRPn2jymJBGhCfHdr/jzDUsi14HZGWCwEiwqJH5YZ92IFCokcdmtet4YgNW8IoaE+oxox6gmf049vYnMlhvB/VruPsUK6+3qszWY19zjNoFmag4qMsXeDZRrOme9Hg6jc8P2ULimAyrL58OAd7vn5lJ8S3frHRNG5i1R8XlKdH5kBjHYpy+g8cmez6KJcfA3Z3mNWgQIJ2P2N7Sw4ScDV7oL8kCAwEAAaOBwDCBvTAdBgNVHQ4EFgQUoBEKIz6W8Qfs4q8p74Klf9AwpLQwDgYDVR0PAQH/BAQDAgEGMA8GA1UdEwEB/wQFMAMBAf8wewYDVR0fBHQwcjA4oDagNIYyaHR0cDovL2NybC5jb21vZG9jYS5jb20vQUFBQ2VydGlmaWNhdGVTZXJ2aWNlcy5jcmwwNqA0oDKGMGh0dHA6Ly9jcmwuY29tb2RvLm5ldC9BQUFDZXJ0aWZpY2F0ZVNlcnZpY2VzLmNybDANBgkqhkiG9w0BAQUFAAOCAQEACFb8AvCb6P+k+tZ7xkSAzk/ExfYAWMymtrwUSWgEdujm7l3sAg9g1o1QGE8mTgHj5rCl7r+8dFRBv/38ErjHT1r0iWAFf2C3BUrz9vHCv8S5dIa2LX1rzNLzRt0vxuBqw8M0Ayx9lt1awg6nCpnBBYurDC/zXDrPbDdVCYfeU0BsWO/8tqtlbgT2G9w84FoVxp7Z8VlIMCFlA2zs6SFz7JsDoeA3raAVGI/6ugLOpyypEBMs1OUIJqsil2D4kF501KKaU73yqWjgom7C12yxow+ev+to51byrvLjKzg6CYG1a4XXvi3tPxq3smPi9WIsgtRqAEFQ8TmDn5XpNpaYbg==")),
}
PEM = re.compile(rb"-----BEGIN CERTIFICATE-----(.+?)-----END CERTIFICATE-----", re.S)
BUNDLE_FILES = {"cacert.pem", "cert.pem", "ca-bundle.crt", "ca-certificates.crt", "cacerts"}

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


def roots_in(path):
    """Names of the eMudhra roots in a PEM bundle or a binary store (JKS/PKCS12 cacerts, libnssckbi)."""
    try:
        if os.path.getsize(path) > 50_000_000:
            return []
        data = open(path, "rb").read()
    except OSError:
        return []
    if b"-----BEGIN CERTIFICATE-----" in data:
        blocks = {b"".join(m.split()) for m in PEM.findall(data)}
        return [n for n, (_, der) in EMUDHRA_ROOTS.items() if base64.b64encode(der) in blocks]
    return [n for n, (_, der) in EMUDHRA_ROOTS.items() if der in data]


def fix_hint(path):
    p = path.lower()
    if "certifi" in p:
        return "pip install -U certifi once a release drops it"
    if "site-packages" in p:  # e.g. botocore ships its own bundle
        pkg = p.split("site-packages" + os.sep)[1].split(os.sep)[0]
        return f"upgrade the {pkg} Python package once it drops the root"
    if "cacerts" in p:
        return "update the JDK, or keytool -delete the alias"
    if "nss" in p:
        return "update Firefox/Thunderbird"
    return "OpenSSL/curl trust this bundle: update ca-certificates, or blocklist the root"


def root_note(name, hint):
    if EMUDHRA_ROOTS[name][0] == "REVIEW":
        return "Comodo root Red Hat suggests blocklisting; many Sectigo sites chain to it, test before removing. " + hint
    return hint


# From LiteLLM's incident report (Oct 21 2026)
BAD_LITELLM = "1.107.0"
LITELLM_CLEANUP = ("don't pip install first (any Python start re-runs it): delete cook.pth/cook.py/sitecustomize.py "
                   "from site-packages, kill the daemon holding /tmp/remote_code_loader.lock, rebuild the env pinned "
                   "to 1.106.2, rotate every credential the host could reach")
BAD_LITELLM_IMAGES = ("sha256:1bbcb1443bc9", "sha256:c00f9d92c427", "sha256:7b00e91cd2fe")
LOCKFILE = re.compile(r"(requirements.*\.txt|pyproject\.toml|uv\.lock|poetry\.lock|Pipfile\.lock)$")
SKIP = {"node_modules", ".git", ".Trash"}


def scan_files(roots):
    """One walk for: installed litellm (dist-info dirs, incl. venvs and caches), lockfiles pinning
    the bad build, LiteLLM malware files, and app CA bundles (certifi, JDKs) carrying the eMudhra roots."""
    roots = sorted({os.path.realpath(os.path.expanduser(r)) for r in roots})
    roots = [r for r in roots if not any(r.startswith(o + os.sep) for o in roots)]  # nested roots = duplicate rows
    rows, bundles = [], []
    for root in roots:
        for d, dirs, files in os.walk(root):
            dirs[:] = [x for x in dirs if x not in SKIP]
            if d == f"{HOME}/Library":  # huge on macOS; only its Python site-packages matter
                dirs[:] = [x for x in dirs if x == "Python"]
            for x in dirs:
                m = re.fullmatch(r"litellm-([\w.]+)\.(?:dist|egg)-info", x)
                if m:
                    bad = m[1] == BAD_LITELLM
                    rows.append(("LiteLLM", os.path.join(d, x), m[1], "AFFECTED" if bad else "OK", LITELLM_CLEANUP if bad else ""))
            for f in files:
                p = os.path.join(d, f)
                if f in BUNDLE_FILES:
                    bundles += [(name, p) for name in roots_in(p)]
                if "site-packages" in d and f in ("cook.pth", "cook.py"):
                    rows.append(("LiteLLM", p, "malware file", "AFFECTED", LITELLM_CLEANUP))
                # Python only auto-runs it from the top of site-packages; Homebrew ships a legit one there
                elif f == "sitecustomize.py" and os.path.basename(d) == "site-packages" and \
                        "created by Homebrew" not in open(p, errors="ignore").read(200):
                    rows.append(("LiteLLM", p, "possible malware", "REVIEW", "LiteLLM malware drops this; check it if you didn't add it"))
                if not LOCKFILE.search(f):
                    continue
                try:
                    text = open(p, errors="ignore").read()
                except OSError:
                    continue
                # ponytail: proximity regex, not a real lockfile parser; good enough for one pinned version
                if re.search(r"litellm.{0,80}?1\.107\.0", text, re.S | re.I):
                    rows.append(("LiteLLM", p, BAD_LITELLM, "AFFECTED", "lockfile pins the backdoored build: pin 1.106.2"))
    if os.path.exists("/tmp/remote_code_loader.lock"):
        rows.append(("LiteLLM", "/tmp/remote_code_loader.lock", "malware lock", "AFFECTED", "malware daemon may be running: " + LITELLM_CLEANUP))
    images = run("docker", "images", "--digests", "--format", "{{.Repository}}:{{.Tag}} {{.Digest}}")
    for line in images.splitlines():
        if line.split()[-1].startswith(BAD_LITELLM_IMAGES):
            rows.append(("LiteLLM", "docker", line, "AFFECTED", "backdoored image: remove it, rebuild from 1.106.2, rotate keys"))
    # every venv has its own certifi, so one summary row per root and fix instead of one per bundle
    groups = {}
    for name, p in bundles:
        groups.setdefault((name, fix_hint(p)), []).append(p)
    summary = [("eMudhra CA", f"{len(ps)} app CA bundles, e.g. {ps[0]}", name, EMUDHRA_ROOTS[name][0], root_note(name, hint))
               for (name, hint), ps in groups.items()]
    return (rows or [("LiteLLM", "-", "-", "NOT FOUND", "")]) + summary


def check_os_store():
    der = {n: d for n, (_, d) in EMUDHRA_ROOTS.items()}
    if sys.platform == "darwin":
        out = run("security", "find-certificate", "-a", "-Z", "/System/Library/Keychains/SystemRootCertificates.keychain",
                  "/Library/Keychains/System.keychain", f"{HOME}/Library/Keychains/login.keychain-db")
        found = [n for n, d in der.items() if hashlib.sha256(d).hexdigest().upper() in out]
        return [("eMudhra CA", "macOS Keychain", n, EMUDHRA_ROOTS[n][0],
                 root_note(n, "Safari and most Mac apps trust it; macOS may already distrust it, install pending updates"))
                for n in found] or [("eMudhra CA", "macOS Keychain", "-", "OK", "")]
    if sys.platform == "win32":
        # ponytail: untested on Windows. Root stores plus Disallowed, where Windows Update puts distrusted roots
        ps = ("Get-ChildItem Cert:\\LocalMachine\\Root,Cert:\\CurrentUser\\Root,Cert:\\LocalMachine\\Disallowed | "
              "% { $_.PSParentPath.Split('\\')[-1] + ' ' + $_.Thumbprint }")
        lines = run("powershell", "-NoProfile", "-Command", ps).upper().splitlines()
        rows = []
        for n, d in der.items():
            thumb = hashlib.sha1(d).hexdigest().upper()
            if f"DISALLOWED {thumb}" in lines:
                rows.append(("eMudhra CA", "Windows cert store", n, "OK", "already in the Disallowed store"))
            elif f"ROOT {thumb}" in lines:
                rows.append(("eMudhra CA", "Windows cert store", n, EMUDHRA_ROOTS[n][0], root_note(n, "run Windows Update, or move it to Disallowed")))
        return rows or [("eMudhra CA", "Windows cert store", "-", "OK", "not installed, though Windows can still fetch roots on demand")]
    return []  # Linux system trust is covered by the extracted bundles in STORES


def check_emudhra():
    rows = check_os_store()
    for p in sorted({os.path.realpath(p) for g in STORES for p in glob.glob(g)}):
        found = roots_in(p)
        rows += [("eMudhra CA", p, n, EMUDHRA_ROOTS[n][0], root_note(n, fix_hint(p))) for n in found] or [("eMudhra CA", p, "-", "OK", "")]
    return rows


STATUSES = ("AFFECTED", "REVIEW", "UNKNOWN", "OK", "NOT FOUND")


def html_report(rows, path):
    e = html.escape
    counts = "".join(f'<div class="stat {s.replace(" ", "")}"><b>{sum(r[3] == s for r in rows)}</b>{s.lower()}</div>' for s in STATUSES)
    body = "".join(
        f'<tr><td>{e(r[0])}</td><td><span class="pill {r[3].replace(" ", "")}">{e(r[3])}</span></td>'
        f'<td>{e(str(r[2]))}</td><td class="path">{e(str(r[1]))}</td><td>{e(r[4])}</td></tr>'
        for r in sorted(rows, key=lambda r: STATUSES.index(r[3])))
    when = datetime.datetime.now().strftime("%d %b %Y, %H:%M")
    open(path, "w").write(f"""<!doctype html><html><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1"><title>Security Inspector Report</title><style>
:root{{--bg:#fafaf9;--fg:#1c1917;--muted:#78716c;--card:#fff;--line:#e7e5e4;--bad:#b91c1c;--warn:#b45309;--ok:#15803d;--na:#a8a29e}}
@media (prefers-color-scheme:dark){{:root{{--bg:#1c1917;--fg:#f5f5f4;--muted:#a8a29e;--card:#292524;--line:#44403c;--bad:#f87171;--warn:#fbbf24;--ok:#4ade80;--na:#78716c}}}}
body{{margin:0;padding:32px 16px;background:var(--bg);color:var(--fg);font:14px/1.5 system-ui,sans-serif}}
main{{max-width:1200px;margin:auto}} h1{{margin:0;font-size:24px}} .sub{{color:var(--muted);margin:4px 0 24px}}
.stats{{display:flex;gap:12px;flex-wrap:wrap;margin-bottom:24px}}
.stat{{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:12px 18px;color:var(--muted)}}
.stat b{{display:block;font-size:26px;color:var(--fg)}} .stat.AFFECTED b{{color:var(--bad)}} .stat.REVIEW b{{color:var(--warn)}}
.wrap{{overflow-x:auto;background:var(--card);border:1px solid var(--line);border-radius:10px}}
table{{border-collapse:collapse;width:100%}} th,td{{text-align:left;padding:10px 12px;border-bottom:1px solid var(--line);vertical-align:top}}
th{{color:var(--muted);font-weight:500}} .path{{font:12px ui-monospace,monospace;word-break:break-all;color:var(--muted)}}
.pill{{font-size:11px;font-weight:600;padding:2px 8px;border-radius:99px;border:1px solid;white-space:nowrap}}
.AFFECTED{{color:var(--bad)}} .REVIEW,.UNKNOWN{{color:var(--warn)}} .OK{{color:var(--ok)}} .NOTFOUND{{color:var(--na)}}
</style></head><body><main><h1>Security Inspector</h1>
<p class="sub">{e(platform.node())} · {e(platform.platform())} · {when}</p><div class="stats">{counts}</div>
<div class="wrap"><table><tr><th>Item</th><th>Status</th><th>Version / root</th><th>Where</th><th>What to do</th></tr>{body}</table></div>
</main></body></html>""")


def main(argv):
    ap = argparse.ArgumentParser(description="Am I affected by the Oct 2026 PHP, Node.js, BIND, LiteLLM, GitLab and eMudhra issues?")
    ap.add_argument("dirs", nargs="*", help="search only these folders for Python envs, lockfiles and CA bundles")
    ap.add_argument("--html", metavar="FILE", help="also write an HTML report")
    args = ap.parse_args(argv)
    roots = args.dirs or [HOME, "/usr/local/lib", "/opt/homebrew/lib", *glob.glob("/usr/lib/python3*")]
    print(f"Scanning {', '.join(roots)} for Python envs, lockfiles and CA bundles, give it a minute...", file=sys.stderr)
    rows = (
        check_bins("PHP", binaries("php", "/opt/homebrew/opt/php*/bin/php", "/usr/local/opt/php*/bin/php", "/usr/bin/php[0-9]*"),
                   "-v", php_status)
        + check_bins("Node.js", binaries("node", "~/.nvm/versions/node/*/bin/node", "~/.volta/tools/image/node/*/bin/node",
                                         "~/.local/share/fnm/node-versions/*/installation/bin/node", "/opt/homebrew/opt/node*/bin/node"),
                     "-v", node_status)
        + check_bins("BIND", binaries("named", "/usr/sbin/named", "/opt/homebrew/opt/bind/sbin/named"), "-v", bind_status)
        + check_gitlab()
        + scan_files(roots)
        + check_emudhra()
    )
    widths = [max(len(str(r[i])) for r in rows) for i in range(4)]
    for r in rows:
        print("  ".join(str(c).ljust(w) for c, w in zip(r, widths)), r[4])
    if args.html:
        html_report(rows, args.html)
        print(f"Report written to {os.path.abspath(args.html)}", file=sys.stderr)
    return 1 if any(r[3] == "AFFECTED" for r in rows) else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
