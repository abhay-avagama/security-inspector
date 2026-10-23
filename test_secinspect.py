import io
import os
import tarfile
import tempfile

from secinspect import (ADVISORIES, AAA, INTERMEDIATES, ROOTS, by_branch, chain_accepts, check_overrides, fix_hint,
                        fix_plan, html_report, new_cves, pem, roots_in, scan_files, scan_image_tar, test_bundle,
                        version_status)

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
    got = sorted((r[0], r[3]) for r in rows)
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


if __name__ == "__main__":
    test_versions()
    test_ca()
    test_overrides()
    test_fix_plan()
    test_new_cves()
    test_scan_files()
    test_docker_image()
    test_docker_oversized_member_skipped()
    print("ok")
