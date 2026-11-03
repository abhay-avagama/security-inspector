import io
import os
import shutil
import subprocess
import sys
import tarfile
import tempfile

from secinspect import (ADVISORIES, AAA, CHROMIUM, INTERMEDIATES, MCP, ROOTS, agent_config_rows, by_branch, chain_accepts, check_mcp, env_rows, ssh_key_encrypted, unpinned, check_overrides, check_version,
                        chromium_version, distro_status, fix_for, installed, inspect_file, ver,
                        fix_hint, fix_plan, html_report, new_cves, nums, os_release, pem, roots_in, scan_files,
                        scan_image_tar, test_bundle, upstream, version_status)

PHP = [(8, 5, 12), (8, 4, 27), (8, 3, 36), (8, 2, 35)]
ADV = {a["name"]: a for a in ADVISORIES["versions"]}


def status(name, v):
    return version_status(ADV[name], v)[0]


def test_versions():
    assert by_branch((8, 3, 35), PHP, 2)[0] == "AFFECTED"
    assert by_branch((8, 1, 99), PHP, 2)[0] == "AFFECTED"  # end-of-life
    assert by_branch((8, 6, 0), PHP, 2)[0] == "UNKNOWN"
    assert status("PHP", (7, 4, 33)) == "AFFECTED"
    assert status("PHP", (8, 2, 35)) == "OK"
    assert "restart" in version_status(ADV["PHP"], (8, 5, 11))[1]
    assert status("Node.js", (26, 7, 0)) == "AFFECTED"
    assert status("Node.js", (20, 19, 2)) == "AFFECTED"  # EOL
    assert status("Node.js", (24, 22, 1)) == "OK"
    assert status("GitLab", (18, 11, 13)) == "OK"
    assert status("GitLab", (18, 5, 0)) == "AFFECTED"
    assert status("BIND", (9, 18, 50)) == "AFFECTED"
    assert status("BIND", (9, 20, 30)) == "OK"
    assert status("BIND", (9, 21, 26)) == "AFFECTED"


def test_ca():
    assert roots_in(b"# no labels\n" + pem(ROOTS[AAA])) == [AAA]
    assert roots_in(b"\xfe\xed\xfe\xed junk" + ROOTS[AAA] + b"junk") == [AAA]  # JKS-ish binary
    assert roots_in(pem(ROOTS[AAA][:-1] + b"x")) == []
    assert "ca-certificates" in fix_hint("/opt/homebrew/etc/ca-certificates/cert.pem")
    assert "certifi" in fix_hint("/x/site-packages/certifi/cacert.pem")
    assert "botocore" in fix_hint("/x/site-packages/botocore/cacert.pem")
    accepted = chain_accepts(pem(ROOTS[AAA]))
    if accepted is not None:  # needs openssl
        assert accepted == list(INTERMEDIATES), accepted
        assert chain_accepts(pem(ROOTS["emSign ECC Root CA - G3"])) == []


def test_overrides(monkeypatch=None):
    with tempfile.TemporaryDirectory() as d:
        bad = os.path.realpath(f"{d}/custom.pem")
        gone = os.path.realpath(f"{d}/gone.pem")
        open(bad, "wb").write(pem(ROOTS[AAA]))
        os.environ["REQUESTS_CA_BUNDLE"] = bad
        os.environ["SSL_CERT_FILE"] = gone  # points at a missing file
        try:
            rows = check_overrides()
        finally:
            del os.environ["REQUESTS_CA_BUNDLE"], os.environ["SSL_CERT_FILE"]
        by_path = {r[1].split(" (")[0]: r for r in rows}
        assert by_path[bad][3] == ("AFFECTED" if chain_accepts(pem(ROOTS[AAA])) else "REVIEW"), rows
        assert "REQUESTS_CA_BUNDLE" in by_path[bad][1]
        assert by_path[gone][3] == "REVIEW"  # missing bundle flagged, not silently skipped


def test_fix_plan():
    rows = [
        ("Node.js", "/Users/x/.nvm/versions/node/v18/bin/node", "18.0.0", "AFFECTED", "eol"),
        ("Node.js", "/Users/y/.nvm/versions/node/v20/bin/node", "20.0.0", "AFFECTED", "eol"),
        ("Node.js", "/opt/homebrew/Cellar/node/26.7.0/bin/node", "26.7.0", "AFFECTED", "upgrade"),
        ("eMudhra CA", "81 app CA bundles, e.g. /x/certifi/cacert.pem", "emSign", "AFFECTED", "certifi"),
        ("eMudhra CA", "macOS Keychain", "AAA", "REVIEW", "comodo"),
        ("LiteLLM", "/x/litellm-1.72.6.dist-info", "1.72.6", "OK", ""),  # OK rows produce no fix
    ]
    plan = fix_plan(rows)
    titles = {t for _, t, _, _, _ in plan}
    assert "Replace end-of-life Node versions under nvm" in titles
    assert "Upgrade Homebrew Node to a patched release" in titles
    assert plan[0][0] == "AFFECTED"  # affected sorted before review
    nvm = next(p for p in plan if "nvm" in p[1])
    assert nvm[3] == 2, nvm  # both nvm rows collapse into one job of count 2
    certifi = next(p for p in plan if "certifi" in p[1].lower())
    assert certifi[3] == 81, certifi  # "81 app CA bundles" parsed as count
    assert all(t != "" for _, t, _, _, _ in plan)  # no OK rows leaked in


def test_new_cves():
    items = [
        {"id": "CVE-2026-99999#2026-10-24T09:00:00.1Z", "date_modified": "2026-10-24T09:00:00.1Z"},  # newer
        {"id": "CVE-2026-109618", "date_modified": "2026-10-23T00:16:34.627Z"},  # older, already handled
        {"id": "CVE-2026-88888", "date_modified": "2026-10-23T12:00:00Z"},  # equal to watermark, not newer
        {"id": "CVE-2026-77777"},  # malformed (no date) -> skipped, must not raise
    ]
    assert new_cves(items, "2026-10-23T12:00:00Z") == ["CVE-2026-99999"]
    assert new_cves(items, "2026-10-25T00:00:00Z") == []  # watermark past everything
    updates = [
        {"id": "CVE-2026-109618#2026-10-26T00:00:00Z", "date_modified": "2026-10-26T00:00:00Z"},  # KEV update to a covered CVE
        {"id": "CVE-2023-3932#2026-10-28T00:00:00Z", "date_modified": "2026-10-28T00:00:00Z"},  # old CVE rescored
        {"id": "CVE-2025-11969#2026-11-02T00:00:00Z", "date_modified": "2026-11-02T00:00:00Z"},  # last year's id, new
    ]
    assert new_cves(updates, "2026-10-23T12:00:00Z", ["CVE-2026-109618"]) == ["CVE-2025-11969"]


def fake_venv(files):
    sp = "home/app/.venv/lib/site-packages"
    files.update({
        f"{sp}/litellm-1.107.0.dist-info/METADATA": b"Name: litellm",
        f"{sp}/cook.pth": b"",
        f"{sp}/certifi/cacert.pem": pem(ROOTS[AAA]),
        "home/app/uv.lock": b'[[package]]\nname = "litellm"\nversion = "1.107.0"\n',
        "other/.venv/lib/site-packages/litellm-1.106.2.dist-info/METADATA": b"Name: litellm",
    })
    return files


def expected(rows):
    got = sorted((r[0], r[3]) for r in rows if r[3] != "NOT FOUND")
    assert got == [("LiteLLM", "AFFECTED")] * 3 + [("LiteLLM", "OK"), ("eMudhra CA", "AFFECTED")], got


def test_scan_files():
    with tempfile.TemporaryDirectory() as d:
        for path, data in fake_venv({}).items():
            os.makedirs(os.path.dirname(f"{d}/{path}"), exist_ok=True)
            open(f"{d}/{path}", "wb").write(data)
        rows = scan_files([d, f"{d}/home"])  # nested root must not double-count
        expected(rows)
        assert rows[-1][1].startswith("1 app CA bundles"), rows[-1]
        html_report(rows, f"{d}/r.html")
        assert "cook.pth" in open(f"{d}/r.html").read()


def tar_of(files):
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as t:
        for name, data in files.items():
            info = tarfile.TarInfo(name)
            info.size = len(data)
            t.addfile(info, io.BytesIO(data))
    return buf.getvalue()


def test_docker_image():
    layer = tar_of(fake_venv({}))
    saved = tar_of({"manifest.json": b"[]", "abc123/layer.tar": layer})  # shape of `docker save`
    rows, bundles = scan_image_tar("myimage:latest", io.BytesIO(saved))
    assert all(r[1].startswith("myimage:latest:/") for r in rows), rows
    expected(rows + [("eMudhra CA", p, "", "AFFECTED", "") for p, _, _ in bundles])


def test_docker_oversized_member_skipped():
    import secinspect
    # a lockfile pinning the bad build, but larger than the read cap: metadata guard must skip it unread
    big = fake_venv({"home/app/requirements.txt": b"litellm==1.107.0\n" + b"#" * 200})
    saved = tar_of({"manifest.json": b"[]", "l/layer.tar": tar_of(big)})
    try:
        secinspect.MAX_READ = 50  # force the cap below the member size
        rows, _ = scan_image_tar("img:1", io.BytesIO(saved))
    finally:
        secinspect.MAX_READ = 50_000_000
    assert not any(r[2] == "1.107.0" and "requirements" in r[1] for r in rows), rows


def test_distro():
    # real dpkg/rpm ordering is exercised in containers; a numeric stand-in is enough for the decisions
    lt = lambda a, b: nums(a) < nums(b)
    assert installed("deb", []) == installed("rpm", []) == []
    DIST = {a["name"]: a for a in ADVISORIES["distro"]}
    assert os_release('ID=ubuntu\nVERSION_ID="24.04"') == "ubuntu:24.04"
    assert os_release('ID="rocky"\nID_LIKE="rhel centos fedora"\nVERSION_ID="9.6"') == "el:9"
    assert os_release('ID=debian\nVERSION_ID="12"') == "debian:12"
    assert os_release('ID=fedora\nID_LIKE=""\nVERSION_ID=41') is None
    assert upstream("1:9.6p1-3ubuntu13.5") == "9.6p1" and upstream("8.0.15") == "8.0.15"
    st = lambda name, rel, v, src="": distro_status(DIST[name], rel, v, src, lt)[0]
    # distro backport: same upstream base, compare the build
    assert st("nginx", "ubuntu:24.04", "1.24.0-2ubuntu7.5") == "AFFECTED"
    assert st("nginx", "ubuntu:24.04", "1.24.0-2ubuntu7.19") == "OK"
    # nginx.org build on the same box: upstream rule
    assert st("nginx", "ubuntu:24.04", "1.30.5-1~noble") == "AFFECTED"
    assert st("nginx", "ubuntu:24.04", "1.30.6-1~noble") == "OK"
    # no distro fix yet: say so, but a fixed vendor build is still OK
    assert "no fixed" in distro_status(DIST["nginx"], "debian:12", "1.22.1-9+deb12u10", "", lt)[1]
    assert st("nginx", "el:9", "1:1.31.7-1.el9.ngx") == "OK"
    # vendor-only software
    assert st("MongoDB", None, "8.0.31") == "AFFECTED" and st("MongoDB", "ubuntu:24.04", "8.0.32") == "OK"
    assert st("Plex Media Server", "debian:12", "1.42.9.1000-abc") == "AFFECTED"
    # kernels: flavour from the source package, unknown flavour is UNKNOWN, Ubuntu remote bug unfixed
    k = "Linux kernel (exploited)"
    assert st(k, "ubuntu:24.04", "6.8.0-87.88", "linux") == "AFFECTED"
    assert st(k, "ubuntu:24.04", "6.8.0-146.146", "linux") == "OK"
    assert st(k, "ubuntu:22.04", "6.8.0-124.124~22.04.1", "linux-hwe-6.8") == "AFFECTED"  # unfixed flavour
    assert st(k, "ubuntu:24.04", "6.8.0-1.1", "linux-lowlatency-weird") == "UNKNOWN"
    assert st(k, "debian:12", "6.1.158-1") == "AFFECTED" and st(k, "debian:12", "6.1.176-1") == "OK"
    assert st("Linux kernel (remote TCP)", "ubuntu:24.04", "6.8.0-146.146", "linux") == "AFFECTED"
    assert st("Linux kernel (remote TCP)", "el:9", "5.14.0-687.64.1.el9_8") == "OK"
    # Ubuntu's fix is only in -proposed: a booted proposed kernel counts, others get Ubuntu's install steps
    assert st("Linux kernel (remote TCP)", "ubuntu:24.04", "6.8.0-149.149", "linux") == "OK"
    note = distro_status(DIST["Linux kernel (remote TCP)"], "ubuntu:22.04", "5.15.0-198.208", "linux", lt)[1]
    assert "-proposed pocket" in note and "5.15.0-203.213" in note, note
    assert "--pocket proposed" in fix_for("Linux kernel (remote TCP)", "linux-image-5.15.0-198-generic (apt)", note)[1]
    aws = distro_status(DIST["Linux kernel (remote TCP)"], "ubuntu:24.04", "6.8.0-1066.69", "linux-aws", lt)[1]
    assert aws.startswith("no fixed") and "isn't listed yet" in aws, aws  # flavours not in Ubuntu's post
    # fix plan: one apt/dnf command per advisory, kernel reboots
    plan = fix_plan([("nginx", "nginx nginx-core (apt)", "1", "AFFECTED", ""), (k, "kernel-core (dnf)", "1", "AFFECTED", "")])
    assert any("apt install --only-upgrade nginx nginx-core" in p[2] for p in plan)
    assert any("reboot" in p[2] and "dnf" in p[2] for p in plan)
    plan = fix_plan([("nginx", "nginx (dnf)", "1", "AFFECTED", "no fixed el:9 package yet: ...")])
    assert plan[0][2] == DIST["nginx"]["mitigation"], plan


def test_web_apps():
    from secinspect import check_version
    ADV_WP = dict(ADV["WordPress"])
    with tempfile.TemporaryDirectory() as d:
        for site, v in (("old", "7.1.3"), ("new", "7.1.4"), ("ancient", "4.6")):
            os.makedirs(f"{d}/{site}/wp-includes")
            open(f"{d}/{site}/wp-includes/version.php", "w").write(f"<?php\n$wp_version = '{v}';\n")
        ADV_WP["version_files"] = [f"{d}/*/wp-includes/version.php"]
        got = {os.path.basename(r[1]): r[3] for r in check_version(ADV_WP)}
    assert got == {"old": "AFFECTED", "new": "OK", "ancient": "AFFECTED"}, got


def test_chrome():
    assert ver("Google Chrome for Testing 153.0.8010.12") == (153, 0, 8010, 12)
    assert ver("v24.22.1") == (24, 22, 1)
    assert status("Google Chrome / Chromium", (153, 0, 8010, 35)) == "AFFECTED"
    assert status("Google Chrome / Chromium", (155, 0, 8059, 39)) == "AFFECTED"  # Oct 27 critical fixes
    assert status("Google Chrome / Chromium", (156, 0, 8078, 73)) == "OK"
    assert version_status(CHROMIUM, (142, 0, 7444, 175))[0] == "AFFECTED"
    assert version_status(CHROMIUM, (156, 0, 8078, 47))[0] == "AFFECTED"  # Puppeteer 25.16.0's build
    assert version_status(CHROMIUM, (156, 0, 8078, 73))[0] == "OK"
    note = version_status(CHROMIUM, (154, 0, 1, 1))[1]
    assert ("106378" in note) == (sys.platform == "darwin"), note  # macOS-only range matches first there
    assert chromium_version("/x/.cache/puppeteer/chrome/mac_arm-142.0.7444.175") == (142, 0, 7444, 175)
    assert "puppeteer" in fix_for(CHROMIUM["name"], "/home/a/.cache/puppeteer/chrome/linux-140.0.1.2")[1]
    assert "chromiumSandbox: true" in fix_for(CHROMIUM["name"], "/home/a/.cache/ms-playwright/chromium-1234")[1]


def test_mcp():
    with tempfile.TemporaryDirectory() as d:
        cfg = os.path.join(d, ".mcp.json")
        data = b'{"mcpServers": {"b": {"args": ["-y", "@modelcontextprotocol/server-puppeteer"]},' \
               b' "g": {"args": ["@modelcontextprotocol/server-github"]}, "f": {"args": ["@modelcontextprotocol/server-filesystem"]}}}'
        rows, _ = inspect_file(cfg, lambda: data)
        assert [(r[2], r[3]) for r in rows] == [("server-github", "REVIEW"), ("server-puppeteer", "AFFECTED")], rows
        assert "remove the puppeteer" in fix_for(MCP["name"], cfg, rows[1][4])[0].lower()
        assert check_mcp(rows) == [] or all(r[1] != cfg for r in check_mcp(rows))
    assert check_mcp([])[-1][3] in ("NOT FOUND", "AFFECTED", "REVIEW")


def test_queue_nov3():
    rows = lambda path, data: [(r[0], r[2], r[3]) for r in inspect_file(path, lambda: data)[0]]
    # python-jose: dist-info uses an underscore; every release through 3.5.0 is affected
    assert rows("/v/site-packages/python_jose-3.3.0.dist-info/METADATA", b"") == [("python-jose", "3.3.0", "REVIEW")]
    assert rows("/p/requirements.txt", b"python-jose[cryptography]==3.5.0\n") == [("python-jose", "3.5.0", "REVIEW")]
    assert rows("/p/requirements.txt", b"pyjwt==2.9.0\n") == []
    # @fastify/http-proxy in each lockfile format; 11.6.6 is fixed, ^ranges in specs are ignored
    lock = b'{"packages": {"": {"dependencies": {"@fastify/http-proxy": "^11.0.0"}},' \
           b' "node_modules/@fastify/http-proxy": {"version": "11.6.5", "resolved": "x"}}}'
    assert rows("/p/package-lock.json", lock) == [("@fastify/http-proxy", "11.6.5", "AFFECTED")]
    assert rows("/p/package-lock.json", lock.replace(b"11.6.5", b"11.6.6")) == []
    assert rows("/p/pnpm-lock.yaml", b"packages:\n  '@fastify/http-proxy@10.0.1':\n") == [("@fastify/http-proxy", "10.0.1", "AFFECTED")]
    assert rows("/p/yarn.lock", b'\n"@fastify/http-proxy@^11.0.0":\n  version "11.2.0"\n') == [("@fastify/http-proxy", "11.2.0", "AFFECTED")]
    assert rows("/p/bun.lock", b'"@fastify/http-proxy": ["@fastify/http-proxy@8.4.0", ""]') == []  # before 9.0.0
    # WordPress plugins and FreeRDP: ranges compared with nums(), so s2Member's 260927 works
    assert status("WordPress: s2Member", (260927,)) == "AFFECTED" and status("WordPress: s2Member", (261017,)) == "OK"
    assert status("WordPress: Ultra Addons for Contact Form 7", (3, 5, 57)) == "OK"
    assert status("FreeRDP", (3, 32, 1)) == "AFFECTED" and status("FreeRDP", (3, 32, 2)) == "OK"
    with tempfile.TemporaryDirectory() as d:
        for slug, head in (("acf-extended", "Plugin Name: Advanced Custom Fields: Extended\n * Version: 0.9.2.5"),
                           ("acf-extended-pro", "Plugin Name: Advanced Custom Fields: Extended PRO\n * Version: 0.9.2.6")):
            os.makedirs(f"{d}/site/wp-content/plugins/{slug}")
            open(f"{d}/site/wp-content/plugins/{slug}/acf-extended.php", "w").write(f"<?php\n/*\n{head}\n*/")
        acf = dict(ADV["WordPress: ACF Extended PRO"], version_files=[f"{d}/site/wp-content/plugins/acf-extended*/acf-extended*.php"])
        assert [r[2:4] for r in check_version(acf)] == [("0.9.2.6", "AFFECTED")]  # the free plugin is skipped
        cwp = dict(ADV["Control Web Panel"], present_paths=[d])
        assert check_version(cwp)[0][3] == "REVIEW"
    assert fix_for("python-jose", "/p/requirements.txt")[0].startswith("Move off python-jose")


def test_postgres():
    assert status("PostgreSQL server", (16, 10)) == "AFFECTED"
    assert status("PostgreSQL server", (16, 15)) == "OK"
    assert status("PostgreSQL server", (13, 22)) == "AFFECTED"  # end-of-life
    assert status("PostgreSQL client (psql, pg_dump)", (18, 6)) == "OK"
    assert version_status(ADV["pgAdmin 4"], (9, 18))[0] == "REVIEW"
    with tempfile.TemporaryDirectory() as d:
        exe = os.path.join(d, "postgres")
        open(exe, "w").write("#!/bin/sh\necho 'postgres (PostgreSQL) 17.6 (Homebrew)'\n")
        os.chmod(exe, 0o755)
        row = check_version(dict(ADV["PostgreSQL server"], binary="no-such-binary", globs=[exe]))[0]
        assert row[2:4] == ("17.6", "AFFECTED"), row
        open(os.path.join(d, "psqlodbcw.so"), "w").write("")
        assert check_version(dict(ADV["psqlODBC"], present_paths=[d + "/psqlodbc*.so"]))[0][3] == "REVIEW"
    rows = [(r[0], r[2], r[3]) for r in inspect_file("/v/site-packages/pgadmin4-9.18.dist-info/METADATA", lambda: b"")[0]]
    assert rows == [("pgAdmin 4 (pip)", "9.18", "REVIEW")], rows


def test_agent_setup():
    assert unpinned("npx", ["-y", "@playwright/mcp@latest"]) == "@playwright/mcp@latest"
    assert unpinned("npx", ["-y", "@playwright/mcp"]) == "@playwright/mcp"
    assert unpinned("npx", ["-y", "@playwright/mcp@0.0.84"]) is None
    assert unpinned("/usr/local/bin/npx", ["server-x@1.2.3", "--port", "1"]) is None
    assert unpinned("uvx", ["mcp-server-fetch"]) == "mcp-server-fetch"
    assert unpinned("uvx", ["--from", "mcp-server-fetch==1.0", "mcp-server-fetch"]) is None
    assert unpinned("node", ["server.js"]) is None
    cfg = b'{"projects": {"/p": {"mcpServers": {"pw": {"command": "npx", "args": ["@playwright/mcp@latest"]}}}},' \
          b' "permissions": {"defaultMode": "bypassPermissions", "allow": ["Bash", "Read"]}}'
    got = sorted((r[0], r[2]) for r in agent_config_rows("/h/.claude.json", cfg))
    assert got == [("AI agent: permissions", "allow Bash"), ("AI agent: permissions", "bypassPermissions"),
                   ("AI agent: unpinned MCP servers", "@playwright/mcp@latest")], got
    codex = b'approval_policy = "never"\nsandbox_mode = "danger-full-access"\n'
    if sys.version_info >= (3, 11):
        assert [r[2] for r in agent_config_rows("/h/.codex/config.toml", codex)] == ["never/danger-full-access"]
    assert agent_config_rows("/h/.mcp.json", b"{not json") == []
    assert agent_config_rows("/h/.claude/plugins/marketplaces/x/.mcp.json", cfg) == []
    with tempfile.TemporaryDirectory() as d:
        key = os.path.join(d, "k")
        if shutil.which("ssh-keygen") and subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", key], capture_output=True).returncode == 0:
            assert not ssh_key_encrypted(open(key).read())
            subprocess.run(["ssh-keygen", "-q", "-p", "-P", "", "-N", "pw", "-f", key], capture_output=True, check=True)
            assert ssh_key_encrypted(open(key).read())
        assert [r[2] for r in env_rows(d, [".claude"], [".env", ".env.example", "app.py"])] == [".env"]
        assert env_rows(d, [], [".env"]) == []  # no agent here
        os.makedirs(os.path.join(d, ".claude"))
        open(os.path.join(d, ".claude", "settings.json"), "w").write('{"permissions": {"deny": ["Read(./.env*)"]}}')
        assert env_rows(d, [".claude"], [".env"]) == []  # already denied
    assert fix_for("AI agent: secrets in reach", "/Users/a/.ssh/id_ed25519")[1].startswith("ssh-keygen -p")


if __name__ == "__main__":
    test_agent_setup()
    test_postgres()
    test_queue_nov3()
    test_chrome()
    test_mcp()
    test_distro()
    test_web_apps()
    test_versions()
    test_ca()
    test_overrides()
    test_fix_plan()
    test_new_cves()
    test_scan_files()
    test_docker_image()
    test_docker_oversized_member_skipped()
    print("ok")
