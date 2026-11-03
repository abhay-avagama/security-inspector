# Am I affected?

One Python file that checks your machine for exploited Chrome bugs, the stale browsers Puppeteer and
Playwright leave behind, the archived Puppeteer MCP server, and the October 2026 PHP, Node.js, BIND,
LiteLLM, GitLab and eMudhra issues and tells you what to do about each one. On a Linux VPS it also
checks the kernel and the usual server software (nginx, Apache, MariaDB, MongoDB, WordPress and
more) for the bugs being exploited right now.

No dependencies, and nothing about your machine is sent anywhere. The only network call is an
optional read-only check of the public cve.now feed (see Staying current; disable with
`--no-update-check`). Python 3.8+ on macOS or Linux (Windows partly, see below).

Quickest way, without cloning:

```
curl -fsSL https://amiaffected.now/run | sh                 # options go after: sh -s -- --html report.html
```

Or from a clone:

```
python3 secinspect.py                       # whole machine
python3 secinspect.py ~/work ~/clients      # only search these folders for envs and bundles
python3 secinspect.py --docker              # also look inside every local Docker image
python3 secinspect.py --html report.html    # also write an HTML report
python3 secinspect.py --no-update-check      # don't phone cve.now (offline/CI)
```

Exit code is `1` if anything is affected, so it can fail a CI job.

## Staying current

On every run (unless `--no-update-check` or `SECINSPECT_NO_UPDATE_CHECK` is set) the tool does a
read-only GET of the public [cve.now](https://cve.now) feed for PHP, Node.js and GitLab and prints a
one-line notice to stderr if any CVE there is newer than the `checked` watermark in
[`advisories.json`](advisories.json) — a hint that the bundled data (and the tool's checks) may be
stale. Nothing about your machine is sent, it only reads the feed; any network error is ignored so
an offline scan still works, and it never changes the exit code. BIND, LiteLLM and eMudhra aren't
version-feed technologies, so they aren't tracked this way — refresh them from the vendor advisory.

## What it checks

| Issue | How |
|---|---|
| **Chrome / Chromium** CVE-2026-87491, CVE-2026-85046 (CISA KEV); on macOS also [CVE-2026-106378](https://pwn.ai/blog/chrome-escape) (GPU sandbox escape) | `--version` of Google Chrome and Chromium in /Applications, /usr/bin and snap. Fixed in 153.0.8010.36, and 155.0.8059.39 on macOS; relaunch after updating. |
| **Puppeteer / Playwright browsers** | Every Chromium in `~/.cache/puppeteer`, `~/.cache/ms-playwright` and `~/Library/Caches/ms-playwright` (and `$PUPPETEER_CACHE_DIR` / `$PLAYWRIGHT_BROWSERS_PATH`). They never update themselves, so builds before 153.0.8010.36 (155.0.8059.39 on macOS) are flagged. The version comes from the folder name or Info.plist where possible. |
| **Archived MCP servers** | `.mcp.json`, `mcp.json`, `claude_desktop_config.json`, `~/.claude.json` and the Claude, VS Code, Cursor, Windsurf, Gemini and Codex configs. `@modelcontextprotocol/server-puppeteer` is affected (prompt injection can start any program, and [no fix is coming](https://www.helpnetsecurity.com/2026/11/03/mcphantom-deprecated-mcp-servers/)); the other archived reference servers are flagged for review. |
| **PHP** CVE-2026-109618 / 109619 (PHP2Shell) | `php -v` for every PHP on PATH and in Homebrew. Fixed in 8.5.12 / 8.4.27 / 8.3.36 / 8.2.35; older branches are affected with no fix. |
| **Node.js** Oct 21 2026 release (10 CVEs incl. Brotli RCE) | Every `node` on PATH, nvm, Volta, fnm and Homebrew. Fixed in 26.12.1 / 24.22.1 / 22.23.4; end-of-life lines are always affected. |
| **BIND 9** CVE-2026-94300 | `named -v` against ISC's affected ranges. |
| **GitLab** CVE-2026-110264 + 11 more | Self-managed Omnibus version file. GitLab.com and Dedicated are already patched. |
| **LiteLLM** 1.107.0 backdoor | Installed copies in every venv, lockfiles pinning 1.107.0, the malware's `cook.pth` / `cook.py` / `sitecustomize.py`, `/tmp/remote_code_loader.lock`, and the bad Docker image digests. |
| **eMudhra CA** (RHSB-2026-012) | Tests whether each trust store would accept the cracked eMudhra intermediates. See below. |

With `--docker`, every local image is streamed through `docker save` and the same file checks run
on each layer (LiteLLM, malware files, lockfiles, CA bundles), without starting a container.

## Servers (Ubuntu, Debian, RHEL family)

On a VPS most software comes from apt or dnf, and the distros fix bugs without changing the
upstream version: a patched Ubuntu nginx still says 1.24.0. So for these the tool reads
`/etc/os-release`, asks `dpkg` or `rpm` what is installed, and compares it with the distro's own
fixed build for that release (Ubuntu 22.04 / 24.04 / 26.04, Debian 12 / 13, RHEL / AlmaLinux /
Rocky 9 / 10), letting `dpkg` and `rpm` decide which version is newer. Packages from a vendor
repo (nginx.org, MariaDB, MongoDB, Plex) carry a different upstream version and are checked
against the upstream fixes instead.

| Issue | How |
|---|---|
| **Linux kernel**: CVE-2026-46300, CVE-2026-53266, CVE-2025-39964, CVE-2025-39682 (all CISA KEV) | The *running* kernel, matched to its flavour (generic, HWE, KVM, AWS, Azure, GCP, Oracle). A fix only counts after a reboot. |
| **Linux kernel**: CVE-2026-98432 (CVSS 9.8, remote over IPv4 TCP) | Same. Ubuntu has announced the fix but not shipped it yet. |
| **nginx** CVE-2026-15176 and 4 more | Distro or nginx.org package. Fixed upstream in 1.30.6 / 1.31.7. |
| **Apache httpd** 2.4.69 fixes (CVE-2026-57941 mod_http2 and 4 more) | `apache2` / `httpd`, plus `mod_http2` on RHEL-family systems, where it is a separate package. |
| **MariaDB** CVE-2026-85746 and 4 more | Distro or MariaDB repo package. |
| **MongoDB** CVE-2026-82067 (authorization can end up off) and 4 more | `mongodb-org-server`. |
| **Brotli** CVE-2026-111497 (CISA KEV) | The system library that web servers, curl and PHP use. |
| **Plex**, **Zammad** (CISA KEV) | Their vendor packages. |
| **WordPress** CVE-2026-87902 (CISA KEV), CVE-2026-119977 | `wp-includes/version.php` under `/var/www`, `/srv` and `~/public_html`. |
| **Nextcloud** built-in Collabora CODE, CVE-2026-110447 (CISA KEV) | The `richdocumentscode` app in the same web roots. |

The fix plan gives the `apt` or `dnf` command for each one, and says when a distro hasn't shipped a
fix yet and what to do in the meantime.

## The eMudhra check

Several eMudhra intermediates (`EM DV/EV/OV TLS CA - G3B/G3C`) had keys small enough to crack.
In May 2025 they were cross-signed by Sectigo's `AAA Certificate Services` root, which is in
almost every trust store. Updating your browser only fixes your browser.

So for every store it finds, the tool runs the real test instead of looking for a name:

- **PEM bundles** (OpenSSL, curl, Python certifi, botocore, vendored bundles, Linux system
  bundles): `openssl verify` of the cross-signed intermediates against the bundle. OpenSSL doesn't
  check revocation by default, so if the bundle trusts the AAA root, the cracked chain verifies.
- **macOS Keychain**: `security verify-cert`, which does check revocation. Up-to-date macOS
  reports the intermediates as revoked.
- **Java `cacerts`, Firefox NSS, Windows Root store**: checked for the roots by certificate bytes.
  Firefox also blocks the intermediates through OneCRL; Windows CryptoAPI accepts the chain unless
  revocation checking is on.

Don't just delete the AAA root. Many legitimate Sectigo sites still chain to it.

### Package managers and custom bundles

Anything that fetches over TLS trusts one of these bundles, so the exposure is wider than browsers:
pip/uv/poetry use `certifi`, npm/pnpm/yarn use Node's built-in store (upgrade Node to fix it),
Homebrew and `git`/`curl` use the system OpenSSL bundle, and Go/cargo/apt/dnf use the system roots.
The tool covers all of these through the bundle and version checks above.

A custom bundle can also be wired in through an env var or config, replacing the system store for
that tool — so a machine can look clean while its real trust anchor is still compromised. The tool
reads `SSL_CERT_FILE`, `CURL_CA_BUNDLE`, `NODE_EXTRA_CA_CERTS`, `REQUESTS_CA_BUNDLE`, `AWS_CA_BUNDLE`,
`GIT_SSL_CAINFO`, `PIP_CERT`, `DENO_CERT`, `CARGO_HTTP_CAINFO`, and the `cafile`/`cert`/`sslCAInfo`
config of npm, pip, git and yarn, then runs the same chain test on whatever bundle they point at.
Once a fix ships, the usual patch is to update `ca-certificates` / `certifi` / the JDK and let these
tools pick it up, rather than maintaining a hand-edited bundle.

## Adding an advisory

Everything the checks need lives in [`advisories.json`](advisories.json): fixed versions per
branch (or explicit affected ranges), bad package versions, malware file names, image digests,
roots and intermediates (base64 DER). A new Node or PHP release, another backdoored PyPI package
or another cracked intermediate is a data change, so send a pull request with a link to the
advisory in `source`.

## Not covered (yet)

- Chrome's own root store (Chrome updates itself; check `chrome://version`)
- Perl `Mozilla::CA`, Go binaries with embedded roots
- Docker layers compressed with zstd, and files deleted in a later layer are still reported
- GitLab installs on other machines
- The Windows store check has not been tested on Windows yet
- Server checks: other distros (Fedora, Arch, Alpine, SUSE), software in Docker containers, and
  MySQL (its one high Server CVE this quarter needs a database login and doesn't run code)
- Rocky Linux builds are assumed to match RHEL's; AlmaLinux sometimes ships an earlier fixed build
  of its own, which shows up as affected

## Tests

```
python3 test_secinspect.py
```

Built and maintained by [Avagama Consulting](https://avagama.co), who also do fixed-scope
[security reviews](https://avagama.co/services/) of agents, MCP servers and the machines they run on.
MIT licensed.

## Security

Found a problem with the tool itself? See [SECURITY.md](SECURITY.md).
