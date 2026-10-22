# Security Inspector

Am I affected? One Python file that checks your machine for the October 2026 PHP, Node.js, BIND,
LiteLLM, GitLab and eMudhra issues and tells you what to do about each one.

No dependencies, nothing sent anywhere. Python 3.8+ on macOS or Linux (Windows partly, see below).

```
python3 secinspect.py                       # whole machine
python3 secinspect.py ~/work ~/clients      # only search these folders for envs and bundles
python3 secinspect.py --html report.html    # also write an HTML report
```

Exit code is `1` if anything is affected, so it can fail a CI job.

## What it checks

| Issue | How |
|---|---|
| **PHP** CVE-2026-109618 / 109619 (PHP2Shell) | `php -v` for every PHP on PATH and in Homebrew. Fixed in 8.5.12 / 8.4.27 / 8.3.36 / 8.2.35; older branches are affected with no fix. |
| **Node.js** Oct 21 2026 release (10 CVEs incl. Brotli RCE) | Every `node` on PATH, nvm, Volta, fnm and Homebrew. Fixed in 26.12.1 / 24.22.1 / 22.23.4; end-of-life lines are always affected. |
| **BIND 9** CVE-2026-94300 | `named -v` against ISC's affected ranges. |
| **GitLab** CVE-2026-110264 + 11 more | Self-managed Omnibus version file. GitLab.com and Dedicated are already patched. |
| **LiteLLM** 1.107.0 backdoor | Installed copies in every venv, lockfiles pinning 1.107.0, the malware's `cook.pth` / `cook.py` / `sitecustomize.py`, `/tmp/remote_code_loader.lock`, and the bad Docker image digests. |
| **eMudhra CA** (RHSB-2026-012) | Looks for `emSign ECC Root CA - G3` and the Comodo `AAA Certificate Services` root by certificate bytes in: macOS Keychain, Windows Root/Disallowed stores, OpenSSL/curl bundles (`/etc/ssl`, `/etc/pki`, Homebrew), Java `cacerts`, Firefox/Thunderbird NSS, and app bundles found under the scanned folders (certifi, botocore and friends). |

Updating your browser only fixes your browser. OpenSSL, curl, Python, Java and anything else with
its own CA bundle keeps trusting the root until that bundle is updated, which is why the eMudhra
check looks in so many places.

## Not covered (yet)

- Chrome's own root store (Chrome updates itself; check `chrome://version`)
- Perl `Mozilla::CA`, Go binaries with embedded roots, files inside Docker images
- GitLab installs on other machines, or GitLab running in Docker
- The Windows store check has not been tested on Windows yet

## Sources

- PHP: [CVE-2026-109618](https://nvd.nist.gov/vuln/detail/cve-2026-109618), [CVE-2026-109619](https://nvd.nist.gov/vuln/detail/cve-2026-109619)
- [Node.js October 2026 security releases](https://nodejs.org/en/blog/vulnerability/october-2026-security-releases)
- [ISC CVE-2026-94300](https://kb.isc.org/docs/cve-2026-94300)
- [LiteLLM incident report](https://docs.litellm.ai/blog/security-incident-oct-21-2026)
- [GitLab 19.5.1 patch release](https://docs.gitlab.com/releases/patches/patch-release-gitlab-19-5-1-released/)
- [Red Hat RHSB-2026-012](https://access.redhat.com/security/vulnerabilities/RHSB-2026-012)

## Tests

```
python3 test_secinspect.py
```

MIT licensed.
