import base64
import os
import tempfile
import textwrap

from secinspect import (EMUDHRA_ROOTS, bind_status, by_branch, gitlab_status, html_report, node_status,
                        php_status, roots_in, scan_files, ver)

PHP = [(8, 5, 12), (8, 4, 27), (8, 3, 36), (8, 2, 35)]
EMSIGN = EMUDHRA_ROOTS["emSign ECC Root CA - G3"][1]


def pem(der):
    return "-----BEGIN CERTIFICATE-----\n" + "\n".join(textwrap.wrap(base64.b64encode(der).decode(), 64)) + "\n-----END CERTIFICATE-----\n"


def test_versions():
    assert ver("PHP 8.3.6 (cli)") == (8, 3, 6)
    assert ver("v26.7.0") == (26, 7, 0)
    assert by_branch((8, 3, 35), PHP, 2)[0] == "AFFECTED"
    assert by_branch((8, 3, 36), PHP, 2)[0] == "OK"
    assert by_branch((8, 1, 99), PHP, 2)[0] == "AFFECTED"  # end-of-life
    assert by_branch((8, 6, 0), PHP, 2)[0] == "UNKNOWN"
    assert php_status((7, 4, 33))[0] == "AFFECTED"
    assert php_status((8, 2, 35))[0] == "OK"
    assert php_status((8, 5, 11))[0] == "AFFECTED"
    assert node_status((26, 7, 0))[0] == "AFFECTED"
    assert node_status((20, 19, 2))[0] == "AFFECTED"  # EOL
    assert node_status((24, 22, 1))[0] == "OK"
    assert gitlab_status((18, 11, 13))[0] == "OK"
    assert gitlab_status((18, 5, 0))[0] == "AFFECTED"
    assert bind_status((9, 18, 50))[0] == "AFFECTED"
    assert bind_status((9, 20, 30))[0] == "OK"
    assert bind_status((9, 21, 26))[0] == "AFFECTED"


def test_roots_in():
    with tempfile.TemporaryDirectory() as d:
        open(f"{d}/bundle.pem", "w").write("# no labels here\n" + pem(EMSIGN))
        open(f"{d}/cacerts", "wb").write(b"\xfe\xed\xfe\xed junk" + EMSIGN + b"junk")  # JKS-ish binary
        open(f"{d}/clean.pem", "w").write(pem(EMSIGN[:-1] + b"x"))
        assert roots_in(f"{d}/bundle.pem") == ["emSign ECC Root CA - G3"]
        assert roots_in(f"{d}/cacerts") == ["emSign ECC Root CA - G3"]
        assert roots_in(f"{d}/clean.pem") == []


def test_scan_files():
    with tempfile.TemporaryDirectory() as d:
        sp = f"{d}/a/.venv/lib/site-packages"
        os.makedirs(f"{sp}/litellm-1.107.0.dist-info")
        os.makedirs(f"{d}/b/.venv/lib/site-packages/litellm-1.106.2.dist-info")
        open(f"{sp}/cook.pth", "w").write("")
        open(f"{d}/uv.lock", "w").write('[[package]]\nname = "litellm"\nversion = "1.107.0"\n')
        os.makedirs(f"{sp}/certifi")
        open(f"{sp}/certifi/cacert.pem", "w").write(pem(EMSIGN))
        rows = scan_files([d, f"{d}/a"])  # nested root must not double-count
        status = sorted((r[0], r[3]) for r in rows)
        assert status == [("LiteLLM", "AFFECTED")] * 3 + [("LiteLLM", "OK"), ("eMudhra CA", "AFFECTED")], status
        assert rows[-1][1].startswith("1 app CA bundles"), rows[-1]
        html_report(rows, f"{d}/r.html")
        assert "cook.pth" in open(f"{d}/r.html").read()


if __name__ == "__main__":
    test_versions()
    test_roots_in()
    test_scan_files()
    print("ok")
