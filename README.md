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
| **Chrome / Chromium** CVE-2026-87491, CVE-2026-85046 (CISA KEV); on macOS also [CVE-2026-106378](https://pwn.ai/blog/chrome-escape) (GPU sandbox escape) | `--version` of Google Chrome and Chromium in /Applications, /usr/bin and snap. Fixed in 153.0.8010.36, and 155.0.8059.39 on macOS; the four critical bugs from 27 Oct 2026 (CVE-2026-118306, 118331, 118348, 118344) need 156.0.8078.73. Relaunch after updating. |
| **Puppeteer / Playwright browsers** | Every Chromium in `~/.cache/puppeteer`, `~/.cache/ms-playwright` and `~/Library/Caches/ms-playwright` (and `$PUPPETEER_CACHE_DIR` / `$PLAYWRIGHT_BROWSERS_PATH`). They never update themselves, so builds before 156.0.8078.73 are flagged. The latest Playwright (1.64.1, Chromium 156.0.8078.4) and Puppeteer (25.16.0, 156.0.8078.47) are still behind, and Playwright launches Chromium with the sandbox off by default, so the fix is to run them on your installed Chrome: `channel: 'chrome'`, plus `chromiumSandbox: true` in Playwright. The version comes from the folder name or Info.plist where possible. |
| **Archived MCP servers** | `.mcp.json`, `mcp.json`, `claude_desktop_config.json`, `~/.claude.json` and the Claude, VS Code, Cursor, Windsurf, Gemini and Codex configs. `@modelcontextprotocol/server-puppeteer` is affected (prompt injection can start any program, and [no fix is coming](https://www.helpnetsecurity.com/2026/11/03/mcphantom-deprecated-mcp-servers/)); the other archived reference servers are flagged for review. |
| **PHP** CVE-2026-109618 / 109619 (PHP2Shell) | `php -v` for every PHP on PATH and in Homebrew. Fixed in 8.5.12 / 8.4.27 / 8.3.36 / 8.2.35; older branches are affected with no fix. |
| **Node.js** Oct 21 2026 release (10 CVEs incl. Brotli RCE) | Every `node` on PATH, nvm, Volta, fnm and Homebrew. Fixed in 26.12.1 / 24.22.1 / 22.23.4; end-of-life lines are always affected. |
| **BIND 9** CVE-2026-94300 | `named -v` against ISC's affected ranges. |
| **GitLab** CVE-2026-110264 + 11 more | Self-managed Omnibus version file. GitLab.com and Dedicated are already patched. |
| **LiteLLM** 1.107.0 backdoor | Installed copies in every venv, lockfiles pinning 1.107.0, the malware's `cook.pth` / `cook.py` / `sitecustomize.py`, `/tmp/remote_code_loader.lock`, and the bad Docker image digests. |
| **python-jose** CVE-2026-120459 (empty HMAC key accepted) | Installed copies in every venv and lockfiles. Every release through 3.5.0 is affected and there's no fix, so it's flagged for review: make sure HMAC keys can't be empty, or move to PyJWT / joserfc. |
| **@fastify/http-proxy** CVE-2026-120213 | Resolved versions in `package-lock.json`, `pnpm-lock.yaml`, `yarn.lock` and `bun.lock`. 9.0.0 to 11.6.5 affected, fixed in 11.6.6. |
| **FreeRDP** CVE-2026-121392 | `--version` of xfreerdp / sdl-freerdp on PATH, Homebrew and `/usr/bin`. Fixed in 3.32.2; distro builds may carry a backported fix. |
| **PostgreSQL** Aug 2026 release (CVE-2026-16239, CVE-2026-14669 and 22 more; client: CVE-2026-19385, CVE-2026-18408) | `postgres --version` and `psql --version` in Debian/Ubuntu (`/usr/lib/postgresql/*`), PGDG (`/usr/pgsql-*`), Homebrew and Postgres.app. Fixed in 18.6 / 17.11 / 16.15 / 15.19 / 14.24; 13 and older are end-of-life. |
| **psqlODBC** CVE-2026-120057 to 120067 | Flags the installed driver library for review: fixed in 18.00.0006, distro packages may lag. |
| **pgAdmin 4** CVE-2026-116249 to 116252 | The macOS app's version and pip installs. Fixes are merged after 9.18 but not released yet, so 9.18 and older are flagged for review. |
| **eMudhra CA** (RHSB-2026-012) | Tests whether each trust store would accept the cracked eMudhra intermediates. See below. |

With `--docker`, every local image is streamed through `docker save` and the same file checks run
on each layer (LiteLLM, malware files, lockfiles, CA bundles), without starting a container.

## AI agent setup

Coding agents (Claude Code, Codex, Cursor, Gemini) and their MCP servers run as you, so anything they
can be tricked into doing by a prompt injection runs with your files and keys. These are
configuration findings, not CVEs, so they're REVIEW, never AFFECTED, and don't change the exit code.

| Check | How |
|---|---|
| **Unpinned MCP servers** | Servers in `.mcp.json`, `mcp.json`, `~/.claude.json`, Claude Desktop, Cursor, VS Code and Codex configs that start with `npx` / `bunx` / `pnpm dlx` / `uvx` and no version or `@latest`. Plugin catalogs you haven't installed are skipped. |
| **Agent permissions** | Claude Code `permissions.defaultMode: bypassPermissions` or an allow rule for all of `Bash`; Codex `approval_policy = "never"` or `sandbox_mode = "danger-full-access"`. |
| **Cursor extension backdoor** ([Cursor's notice](https://cursor.com/blog/claude-code-extension-security-notice)) | AFFECTED if any trace of the tampered `Anthropic.claude-code` 2.1.312 / 2.1.313 is on disk: a `svc-telemetry` key in `~/.ssh/authorized_keys`, `~/.config/.smt` / `.smtk`, `~/Library/LaunchAgents/com.apple.sysmond.plist`, `.stk_*` in the temp folder, the `@reboot` crontab entry, or the bad versions in `~/.cursor/extensions`. Uninstalling the extension doesn't remove the backdoor. |
| **SSH keys without a passphrase** | Every private key in `~/.ssh`, read for its encryption header only. |
| **`.env` files an agent can read** | `.env*` files (not `.example` / `.sample` / `.template`) in folders with `CLAUDE.md`, `AGENTS.md`, `GEMINI.md`, `.mcp.json` or a `.claude` / `.cursor` / `.codex` / `.gemini` folder, unless a Claude Code `permissions.deny` rule covers `.env`. Only the path is reported. |

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
| **Linux kernel**: CVE-2026-98432 (CVSS 9.8, remote over IPv4 TCP) | Same. On Ubuntu the fixed generic kernels (5.15.0-203.213 / 6.8.0-149.149 / 7.0.0-43.43) are [in -proposed](https://ubuntu.com/blog/fixes-available-in-proposed-pocket-for-cve-2026-98432) so far: a booted proposed kernel counts as fixed, and the fix plan gives Ubuntu's steps to install it. Cloud and HWE flavours aren't listed yet. |
| **nginx** CVE-2026-15176 and 4 more | Distro or nginx.org package. Fixed upstream in 1.30.6 / 1.31.7. |
| **Apache httpd** 2.4.69 fixes (CVE-2026-57941 mod_http2 and 4 more) | `apache2` / `httpd`, plus `mod_http2` on RHEL-family systems, where it is a separate package. |
| **MariaDB** CVE-2026-85746 and 4 more | Distro or MariaDB repo package. |
| **MongoDB** CVE-2026-82067 (authorization can end up off) and 4 more | `mongodb-org-server`. |
| **Brotli** CVE-2026-111497 (CISA KEV) | The system library that web servers, curl and PHP use. |
| **Plex**, **Zammad** (CISA KEV) | Their vendor packages. |
| **WordPress** CVE-2026-87902 (CISA KEV), CVE-2026-119977 | `wp-includes/version.php` under `/var/www`, `/srv` and `~/public_html`. |
| **WordPress plugins**: ACF Extended PRO (CVE-2026-120534), s2Member (CVE-2026-86596), Ultra Addons for CF7 (CVE-2026-102435), BuddyPress XProfile Image Field (CVE-2026-120518) | The plugin's `Version:` header in `wp-content/plugins/` under the same web roots. BuddyPress XProfile Image Field has no fix and is gone from wordpress.org: delete it. |
| **Control Web Panel** CVE-2026-77876, CVE-2026-73696 | Flags `/usr/local/cwpsrv` for review: CWP doesn't keep a version file we can trust, so confirm the panel shows 1.29+. |
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
