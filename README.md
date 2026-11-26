# Am I affected?

One Python file that checks your machine for exploited Chrome bugs, the stale browsers Puppeteer and
Playwright leave behind, the archived Puppeteer MCP server, and the October 2026 PHP, Node.js, BIND,
LiteLLM, GitLab and eMudhra issues and tells you what to do about each one. On a Linux VPS it also
checks the kernel and the usual server software (nginx, Apache, MariaDB, MongoDB, WordPress and
more) for the bugs being exploited right now. On Ubuntu, RHEL, AlmaLinux, Rocky and Oracle Linux it
also checks every installed package against the vendor's own security notices, exploited ones first.

No dependencies, and nothing about your machine is sent anywhere. The only network calls are
read-only downloads of public files: the cve.now feed, your distro vendor's security notices and
CISA's list of exploited CVEs (see Staying current; `--no-update-check` uses the last copies only).
Python 3.8+ on macOS or Linux (Windows partly, see below).

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
python3 secinspect.py --no-update-check      # no downloads: use the last copies (offline/CI)
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
| **Chrome / Chromium** CVE-2026-87491, CVE-2026-85046 (CISA KEV); on macOS also [CVE-2026-106378](https://pwn.ai/blog/chrome-escape) (GPU sandbox escape) | `--version` of Google Chrome and Chromium in /Applications, /usr/bin and snap. Fixed in 153.0.8010.36, and 155.0.8059.39 on macOS; the four critical bugs from 27 Oct 2026 (CVE-2026-118306, 118331, 118348, 118344) need 156.0.8078.73. The 3 Nov release fixes 196 more (33 critical), and the 9 Nov release, 157.0.8103.50, fixes CVE-2026-125350 (XML, exploited in the wild). The 11 Nov release, 157.0.8103.78, fixes 83 more (none known exploited). Chrome 158 (17 Nov, 158.0.8127.36) fixes 204 more, 6 critical, and 158.0.8127.88 (23 Nov) fixes CVE-2026-134401 (critical, runs code outside the sandbox, not known exploited) and is the minimum. Relaunch after updating. |
| **macOS** [CVE-2026-86950](https://support.apple.com/en-us/149228) (exploited, CoreGraphics) | `sw_vers -productVersion`. Fixed in Tahoe 26.7.1 and Sequoia 15.8.1; Golden Gate 27 isn't affected. Sonoma 14 and older get no more fixes, so they're flagged. Update in System Settings > General > Software Update. |
| **Firefox** | Version from `application.ini` (macOS apps, /usr/lib, /opt, snap, flatpak), so Firefox isn't started. Flagged before 159.0.1 (167 high-impact bugs fixed on 27 Oct, one more on 3 Nov), ESR 153.6 and ESR 115.44; ESR 140 and older get no more fixes. |
| **Edge and Brave** | `--version` of Microsoft Edge and Brave (macOS apps, /usr/bin, /opt, snap). CVE-2026-125350, exploited in Chrome, is in both: Brave fixed it in Release 1.99.56 and Beta 1.100.52, Microsoft in desktop Edge 157.0.4341.46. Chrome's 11 Nov fixes need Brave 1.99.57 and Edge 157.0.4341.57; Chrome 158's need Brave 1.100.58 and Edge 158.0.4370.33; the 23 Nov fix (CVE-2026-134401) needs Brave 1.100.59 and Edge 158.0.4370.45. Microsoft doesn't name the Chromium build in each Edge release, so Edge's are matched by date. |
| **Electron apps** | VS Code, Cursor, Slack, Postman, Claude and other apps carry their own Chromium. The Electron and Chromium versions are read from the app's binary without starting it (macOS `/Applications`, `~/Applications`; Linux apps under /opt, /usr/lib, /usr/share, snap and `~/.local/share`). Electron backports Chrome's fixes only to its newest three majors (43 to 45 now), so an app on an older Electron is flagged: update it, and if it is already current, its maker ships an unsupported Electron. |
| **Puppeteer / Playwright browsers** | Every Chromium in `~/.cache/puppeteer`, `~/.cache/ms-playwright` and `~/Library/Caches/ms-playwright` (and `$PUPPETEER_CACHE_DIR` / `$PLAYWRIGHT_BROWSERS_PATH`). They never update themselves, so builds before 157.0.8103.50 are flagged. Puppeteer (25.16.0, Chromium 156.0.8078.47) is still behind; Playwright 1.65.0 ships 158.0.8127.18 but launches Chromium with the sandbox off by default, so the fix is to run them on your installed Chrome: `channel: 'chrome'`, plus `chromiumSandbox: true` in Playwright. The version comes from the folder name or Info.plist where possible. |
| **Archived MCP servers** | `.mcp.json`, `mcp.json`, `claude_desktop_config.json`, `~/.claude.json` and the Claude, VS Code, Cursor, Windsurf, Gemini and Codex configs. `@modelcontextprotocol/server-puppeteer` is affected (prompt injection can start any program, and [no fix is coming](https://www.helpnetsecurity.com/2026/11/03/mcphantom-deprecated-mcp-servers/)); the other archived reference servers are flagged for review. |
| **PHP** CVE-2026-109618 / 109619 (PHP2Shell); the 19 Nov 2026 security releases (17 CVEs, the worst CVE-2026-129289, FPM request smuggling) | `php -v` for every PHP on PATH and in Homebrew, outside `/usr/bin`. Fixed in 8.5.13 / 8.4.28 / 8.3.37 / 8.2.36 (8.6.0 has the fixes); 8.1 and older are affected with no fix. PHP installed with apt or dnf is judged by its package build instead, see [Servers](#servers-ubuntu-debian-rhel-family). |
| **Python** CVE-2026-115557 (the ssl module trusted the cracked eMudhra intermediates), CVE-2026-114583 | `--version` of every Python you installed: pyenv, uv, Homebrew, python.org, asdf, conda. Fixed in 3.15.2 / 3.14.10 / 3.13.18 / 3.12.16 / 3.11.18; 3.10 and older get no fixes. Copies in `/usr/bin` and `/bin` are skipped, because distros patch them without changing the version; the vendor notices check those. |
| **Ruby** Regexp and String memory bugs (18 Nov 2026), Onigmo regexp bugs (CVE-2026-97229 on CISA KEV) | `--version` of rbenv, rvm, chruby, asdf, mise and Homebrew Rubies (the distro's `/usr/bin/ruby` gets backported fixes, so it's skipped). Fixed in 4.0.10, 3.4.13 and 3.3.14; 3.2 is end of life. |
| **Git** CVE-2026-111760 and five more (3 Nov 2026) | `git --version` for Homebrew's and Apple's Git (Command Line Tools and Xcode). Cloning a malicious repository with `--recurse-submodules` can run its code. Fixed in 2.56.1 / 2.55.1 / 2.54.1 / 2.53.1 / 2.52.1 / 2.51.3 / 2.50.2; nothing below 2.50 got the fix. |
| **curl** CVE-2026-92392 | `curl --version` for curl you installed yourself (Homebrew, `/usr/local`), since macOS and distros patch their own. 8.12.0 to 8.22.0 can use freed memory during an HTTP/2 upload to a malicious server; fixed in 8.23.0 (and 8.20.2, 8.16.2, 8.14.3). |
| **Java** October 2026 patch update, and the eMudhra fixes CVE-2026-91403 / 114820 | `java -version` for every JDK in `/Library/Java`, `~/Library/Java`, SDKMAN, Homebrew and `/usr/lib/jvm`. Flagged below 27.0.1 / 25.0.5 / 21.0.13 / 17.0.21 / 11.0.33 / 8u511; other lines are end-of-life. The later eMudhra fix is numbered per vendor (Oracle .0.3, Corretto .0.10/.0.11), so the check stops at the shared October versions and says to get it. |
| **Docker Desktop** CVE-2026-98432 | The version in `Docker.app`'s Info.plist (macOS). A 9.8-rated bug in the TCP code of the kernel inside Docker Desktop's VM, fixed in 4.98.0. |
| **FrankenPHP** CVE-2026-128014 to 128027 and 17 more fixed in 1.13.5 | `frankenphp version` on PATH, `/usr/local/bin`, `/usr/bin` and `~/.local/bin`. Below 1.13.5 is flagged: the worst bug lets `php_server` run an uploaded non-PHP file as PHP. Docker images under old tags weren't rebuilt when PHP, Go and Alpine were fixed, so pull and rebuild those too. |
| **End of life** (any CVE, including the next one) | Python, Node.js, PHP, PostgreSQL, GitLab and macOS found above, plus the Linux release in `/etc/os-release` (Ubuntu, Debian, RHEL, AlmaLinux, Rocky). A branch past its end-of-life date is flagged for review even when no CVE applies yet, because it won't get the fix for the next one; a branch ending within 90 days gets a note. Dates come from [endoflife.date](https://endoflife.date), kept in `advisories.json` so they're signed with everything else and nothing is fetched at run time. |
| **Mac settings** | `fdesetup status` (FileVault), `spctl --status` (Gatekeeper), `csrutil status` (SIP), the application firewall, and the Software Update keys for security responses and system files. Each one that is off is flagged for review with how to turn it on. Also every program listening on a port other machines can reach (`lsof`), leaving out Apple's own. In `--watch`, a new one shows up as NEW. |
| **Linux automatic updates** | `unattended-upgrades` on Debian and Ubuntu, `dnf-automatic` on the RHEL family: flagged for review when security updates wait for someone to install them. |
| **Linux server hardening** | Whether a firewall is on (ufw's own `ENABLED=yes`, or firewalld / nftables running), Docker ports published on `0.0.0.0` past it (Docker writes its own iptables rules), and in `sshd_config` as sshd reads it (first value wins, `Include` files in place, `Match` blocks left out) password login and `PermitRootLogin yes`. Each one is REVIEW with how to change it. |
| **Listening on a Linux server** | Every program taking connections from other machines (`ss -ltnp`), sshd left out. A database or a Docker-published port on `0.0.0.0` is the usual surprise. Run as root to see which program owns each port; without it, other users' ports show as "a program run by another user". In `--watch`, a new one shows up as NEW. |
| **Node.js** Nov 11 2026 release (15 CVEs, incl. HTTPS memory leaks of TLS private keys and HTTP/2 crashes) | Every `node` on PATH, nvm, Volta, fnm and Homebrew. Fixed in 26.13.1 / 24.22.3 / 22.23.5; end-of-life lines are always affected. |
| **BIND 9** CVE-2026-94300 | `named -v` against ISC's affected ranges. |
| **GitLab** 25 Nov release (13 CVEs, medium and low), CVE-2026-132825 (critical, bundled Ruby, 20 Nov), the 16 Nov release (37 CVEs), CVE-2026-105437 (critical, bundled git), CVE-2026-110264 | Self-managed Omnibus version file: below 19.6.2 / 19.5.9 / 19.4.11 is flagged. 19.3 and older only got the Ruby, Git and GPGME backports (19.3.10 down to 18.11.15), not GitLab's own fixes, so they stay flagged. GitLab.com and Dedicated are already patched. |
| **LiteLLM** 1.107.0 backdoor | Installed copies in every venv, lockfiles pinning 1.107.0, the malware's `cook.pth` / `cook.py` / `sitecustomize.py`, `/tmp/remote_code_loader.lock`, and the bad Docker image digests. Also **CVE-2026-40217** (CISA KEV): from 1.81.8 to 1.83.10 the proxy's `/guardrails/test_custom_code` runs code for anyone with the admin key, so installed copies and lockfiles below 1.83.11 are flagged. |
| **python-jose** CVE-2026-120459 (empty HMAC key accepted) | Installed copies in every venv and lockfiles. Every release through 3.5.0 is affected and there's no fix, so it's flagged for review: make sure HMAC keys can't be empty, or move to PyJWT / joserfc. |
| **Ruby on Rails** CVE-2026-126082, CVE-2026-126186 and 19 more (4 Nov 2026) | `actionpack` pinned in `Gemfile.lock`, and installed gems (`specifications/actionpack-*.gemspec`, including `/var/lib/gems`). Every Rails gem shares one version. Fixed in 8.1.4.1 and 8.0.5.2 (8.0's support has ended); 7.2 and older get no fix. Gemfile.lock files also go to OSV with `--osv`. |
| **Log4Shell** CVE-2021-44228, CVE-2021-45046 (CISA KEV), CVE-2021-45105, CVE-2021-44832; **Spring4Shell** CVE-2022-22965 (CISA KEV) | `log4j-core` and `spring-beans` jars by file name (`~/.m2`, `~/.gradle`), by `META-INF/maven/.../pom.properties` (Debian's unversioned `/usr/share/java/log4j-core.jar`, shaded vendor jars), and bundled in `.war`/`.ear`/Spring Boot jars (`WEB-INF/lib`, `BOOT-INF/lib`), in the home folder, `/usr/share/java`, `/var/lib/tomcat*`, `/opt/tomcat*`, `/var/www`, `/srv` and Docker image layers. Log4j is fixed in 2.17.1 (2.12.4 on Java 7, 2.3.2 on Java 6); Spring in 5.3.18 / 5.2.20, flagged for review since it needs a WAR on Tomcat with JDK 9+. `pom.xml` and Gradle files aren't read. |
| **Apache Roller** CVE-2026-129448 (CISA KEV, exploited), CVE-2026-82384 | `roller.war` (or any war) by its `META-INF/maven/org.apache.roller/roller-webapp/pom.properties`, in the same places as Log4j. 4.0.0 to 6.1.5 is flagged: XML-RPC runs code for anyone before it checks the login. Fixed in 6.1.6; until then set `enabledForExtensions` to false in `WEB-INF/web.xml` (turning XML-RPC off in the admin page is not enough). An unpacked webapp folder without its war isn't read. |
| **GPUStack** CVE-2026-102895 (CISA KEV), CVE-2026-102894 and 14 more | Installed copies (`site-packages`) and lockfile pins below 2.3.1. Before 2.2.0 a request that looks local is treated as the admin, and that bug is exploited; later releases fix a SAML login bypass and more authorization bugs. After upgrading, rotate its API keys, worker tokens and cloud credentials. |
| **@fastify/http-proxy** CVE-2026-120213 | Resolved versions in `package-lock.json`, `pnpm-lock.yaml`, `yarn.lock` and `bun.lock`. 9.0.0 to 11.6.5 affected, fixed in 11.6.6. |
| **FreeRDP** CVE-2026-121392 | `--version` of xfreerdp / sdl-freerdp on PATH, Homebrew and `/usr/bin`. Fixed in 3.32.2; distro builds may carry a backported fix. |
| **PostgreSQL** Nov 2026 release (53 CVEs, most of them code execution by a user who can create objects; client: pg_dump, pg_restore, vacuumdb, reindexdb) and the Aug 2026 one | `postgres --version` and `psql --version` in Debian/Ubuntu (`/usr/lib/postgresql/*`), PGDG (`/usr/pgsql-*`), Homebrew and Postgres.app. Fixed in 18.7 / 17.12 / 16.16 / 15.20 / 14.25; 14.25 is the last release of 14, and 13 and older are end-of-life. |
| **psqlODBC** CVE-2026-120057 to 120067 | Flags the installed driver library for review: fixed in 18.00.0006, distro packages may lag. |
| **pgAdmin 4** CVE-2026-116249 to 116252 | The macOS app's version and pip installs. Fixes are merged after 9.18 but not released yet, so 9.18 and older are flagged for review. |
| **eMudhra CA** (RHSB-2026-012) | Tests whether each trust store would accept the cracked eMudhra intermediates. See below. |

With `--docker`, every local image is streamed through `docker save` and the same file checks run
on each layer (LiteLLM, malware files, lockfiles, CA bundles), without starting a container.

## GitHub Action

Check every push for backdoored or vulnerable pinned packages (Python and npm lockfiles), archived or
unpinned MCP servers, risky agent skills and `.env` files in agent folders:

```yaml
- uses: actions/checkout@v4
- uses: abhay-avagama/security-inspector@v1
  with:
    fail-on: affected   # or: review, never
```

It runs with `--files-only`, so only the repository is judged, not the runner's own Chrome or Node. It uses
the action's pinned copy of the tool (no `curl | sh`), writes a summary on the run page, and sends nothing
anywhere. `@v1` moves to each tested release, so new advisories arrive without changing your workflow.
Inputs: `path` (default `.`), `fail-on`, `docker: true` to also check images built earlier in the job,
`html` for a report file.

## AI agent setup

Coding agents (Claude Code, Codex, Cursor, Gemini) and their MCP servers run as you, so anything they
can be tricked into doing by a prompt injection runs with your files and keys. These are
configuration findings, not CVEs, so they're REVIEW, never AFFECTED, and don't change the exit code.

| Check | How |
|---|---|
| **Unpinned MCP servers** | Servers in `.mcp.json`, `mcp.json`, `~/.claude.json`, Claude Desktop, Cursor, VS Code and Codex configs that start with `npx` / `bunx` / `pnpm dlx` / `uvx` and no version or `@latest`. Plugin catalogs you haven't installed are skipped. |
| **Agent permissions** | Claude Code `permissions.defaultMode: bypassPermissions` or an allow rule for all of `Bash`; Codex `approval_policy = "never"` or `sandbox_mode = "danger-full-access"`. |
| **Skills** | Every folder with a `SKILL.md` under `~/.claude/skills`, `~/.claude/plugins/cache`, `~/.codex/skills`, `~/.agents/skills`, `~/.openclaw` and projects: hidden instructions (quoted warnings and test fixtures skipped), invisible Unicode, `curl \| sh`, programs downloaded and made runnable, compiled binaries, password-protected zips, and in scripts: credential reads, persistence, decode-and-run. `allowed-tools` covering all of `Bash`. AFFECTED for authors and skills [Snyk's ToxicSkills research](https://snyk.io/blog/toxicskills-malicious-ai-agent-skills-clawhub/) confirmed malicious; everything else is REVIEW, and a clean result means nothing obvious, not safe. Plugin catalogs (`plugins/marketplaces`) are skipped. |
| **Hooks** | Commands in plugin `hooks.json` files and `~/.claude/settings.json` that run automatically, listed with the events that trigger them. |
| **Skill changes** (opt-in) | With `--skills-baseline FILE`, a SHA-256 of every file in every installed skill is kept in FILE, and the next run lists new skills and changed files since the last one. FILE is the only thing written, and only because you named it. |
| **Cursor extension backdoor** ([Cursor's notice](https://cursor.com/blog/claude-code-extension-security-notice)) | AFFECTED if any trace of the tampered `Anthropic.claude-code` 2.1.312 / 2.1.313 is on disk: a `svc-telemetry` key in `~/.ssh/authorized_keys`, `~/.config/.smt` / `.smtk`, `~/Library/LaunchAgents/com.apple.sysmond.plist`, `.stk_*` in the temp folder, the `@reboot` crontab entry, or the bad versions in `~/.cursor/extensions`. Uninstalling the extension doesn't remove the backdoor. |
| **SSH keys without a passphrase** | Every private key in `~/.ssh`, read for its encryption header only. |
| **`.env` files an agent can read** | `.env*` files (not `.example` / `.sample` / `.template`) in folders with `CLAUDE.md`, `AGENTS.md`, `GEMINI.md`, `.mcp.json` or a `.claude` / `.cursor` / `.codex` / `.gemini` folder, unless a Claude Code `permissions.deny` rule covers `.env`. Only the path is reported. |

## Watch a server, or your Mac

Run it every few hours and hear about it only when something changes and hear about it only when something changes: a new affected package, a new
kernel bug, or a fix that landed. A quiet day prints and sends nothing.

```sh
curl -fsSL https://amiaffected.now/run | sudo sh -s -- --install
sudo crontab -e
# every 6 hours: take the signed update if there is one, compare with last time, post changes to Slack
0 */6 * * * python3 /opt/amiaffected/secinspect.py --update; python3 /opt/amiaffected/secinspect.py --watch /opt/amiaffected/watch.json --notify https://hooks.slack.com/services/...
```

`--notify URL` posts `{"text": ..., "content": ...}`, which Slack, Teams and Discord webhooks all read.
`--mail ADDRESS` sends through the server's own `sendmail`. The first run reports everything it found;
after that only NEW and FIXED lines. These two flags are the only way findings leave the machine, and
only to the place you name.

On a Mac, `--install` (without sudo) also writes a LaunchAgent, `~/Library/LaunchAgents/now.amiaffected.watch.plist`,
that takes the signed update and runs `--watch --desktop` every 6 hours; `--desktop` shows the change as a
notification (`notify-send` on Linux desktops). It isn't started for you: `--install` prints the
`launchctl bootstrap` line to start it and the `bootout` line to stop it. Give Python Full Disk Access in
System Settings > Privacy & Security, or a background run can't read Documents, Desktop or Downloads.

When the fix for an affected package reaches the machine's own package sources (your distro's, or a
vendor repository you added), watch mode says so once: `PATCH  nginx -> nginx 1.24.0-2ubuntu7.19: run
--fix to apply it`. It reads the package lists as they are, so keep `apt-daily` or `dnf-makecache`
running; it never refreshes or installs anything from cron.

## Install it, with signed updates

The one-liner fetches a fresh copy every time, from the same site as the data, and runs it only if
`secinspect.py` and `advisories.json` match our release key (it needs `ssh-keygen` from OpenSSH 8.1 or
newer; without one it says the signature wasn't checked). The line under the table names the release
that produced the result. [SECURITY.md](SECURITY.md#checking-what-you-were-served) has the ways to
check what you were served, including a public log we don't control. That suits a quick check. For a server you watch from cron, or before running `--fix` as root, install a copy that
only takes updates you can check came from us:

```sh
curl -fsSL https://amiaffected.now/run | sudo sh -s -- --install    # or without sudo, into ~/.local/share/amiaffected
```

`--install` puts `secinspect.py` and `advisories.json` in `/opt/amiaffected` and pins our release key
there. It prints the key's fingerprint, which should be:

```
SHA256:J2gtbuBTYxZRpDwEsKM6owYkY38bCClyuybzmeCu01U
```

From then on, `--update` downloads the new release and its signatures (`secinspect.py.sig`,
`advisories.json.sig`) and checks them with `ssh-keygen -Y verify` against the pinned key (OpenSSH 8.1 or newer; on minimal
images install `openssh-client`). It swaps the
files in only if both match, the signed `advisories.json` names this exact `secinspect.py` (by its
SHA-256), and the release isn't older than what's installed. So an old release served again is refused,
and so is an older signed script slipped in beside new signed data. If anything fails, nothing changes and it says why. Installs, updates and
refusals all go into the audit log below. The key that signs releases is kept offline, never on the
site, in GitHub or in CI, so someone who takes over the site can change the files but can't sign them.

## Apply the fixes, with your approval

```sh
sudo python3 /opt/amiaffected/secinspect.py --fix                # Linux, after --install (see above)
python3 ~/.local/share/amiaffected/secinspect.py --fix           # macOS: Homebrew won't run as root
```

`--fix` runs only from the installed copy, and first checks that its `secinspect.py` and
`advisories.json` still match their signatures. If either was edited after install, it refuses, logs
why, and tells you to run `--update`. So whatever decides what gets upgraded came from a signed release.

`--fix` scans, then offers the update for each affected package that apt, dnf or Homebrew can install,
whether it comes from your distro or from a vendor repository you added (nginx.org, PGDG, MySQL,
Google's Chrome repo). For each one it shows the installed and the new version and the exact command,
and runs it only if you type `yes` at the terminal. Then it checks again and says whether the finding
cleared. Restarts (nginx, PHP-FPM, a database) are left to you and shown as the next step.

- **What runs.** The commands are written in `secinspect.py`, using the package names your package
  manager reports. Nothing from `advisories.json` is ever run: it only decides which packages need an update.
- **Where the patch comes from.** Only from the package sources this machine already trusts, with
  their own signatures. We never ship a patch.
- **When it isn't offered.** If the newest version in your sources still doesn't fix the bug, it says
  so instead of updating. Kernels (they need a reboot), apps that update themselves, and anything
  installed by hand (nvm, tarballs) stay in the fix plan for you to do.
- **Audit log.** Every step (the scan, the plan, each approval or skip, the command, its exit code and
  the re-check) is one line in `/var/log/amiaffected/audit.jsonl` as root, or
  `~/.local/state/amiaffected/audit.jsonl` otherwise (`--audit-log FILE` to choose). Each line holds the
  hash of the one before, plus the hashes of the `secinspect.py` and `advisories.json` that made the
  decision. `--verify-log` says which line was edited, added or removed. If the log doesn't check out,
  `--fix` changes nothing. It stays on the machine.

## Every dependency, against OSV (opt-in)

```sh
curl -fsSL https://amiaffected.now/run | sh -s -- --osv ~/work
```

`--osv` checks every package pinned in the lockfiles it finds (`package-lock.json`, `pnpm-lock.yaml`, `yarn.lock`,
`bun.lock`, `requirements*.txt` pins, `poetry.lock`, `uv.lock`, `Pipfile.lock`, `Cargo.lock`, `go.sum`) and every installed
Python package against [OSV.dev](https://osv.dev), Google's open vulnerability database. It is off by default because
it sends the package names and versions to `api.osv.dev` (it says how many before it does); nothing else about the machine
is sent. Critical and high findings are AFFECTED, the rest REVIEW, each with the version that fixes it. It works with
`--files-only` too, so a CI job can check a repository's dependencies.

## Every installed package, against the vendor's notices

The hand-picked checks above cover what's being exploited right now. On top of that, on a Linux
server the tool lists every installed package (`dpkg` or `rpm`) and matches the list against the
security notices your distro vendor publishes, downloaded and kept on the machine:

| Distro | Notices | From |
|---|---|---|
| Ubuntu (every release Canonical publishes) | USN | `security-metadata.canonical.com` |
| Debian 11, 12, 13 | CVE, DSA | `www.debian.org/security/oval` |
| RHEL 8, 9 | RHSA | `security.access.redhat.com` |
| AlmaLinux 8, 9, 10 | ALSA | `security.almalinux.org` |
| Rocky Linux 8, 9 | RHSA (see below) | `security.access.redhat.com` |
| Oracle Linux 8, 9, 10 | ELSA | `linux.oracle.com` |

There's one row per source package with a pending fix: the version to update to, the notices, and
how serious they are. A package with a CVE on [CISA's exploited list](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)
comes first and is AFFECTED, and so are Critical and High (Important) notices. Medium and Low ones
are REVIEW, so they don't fail a CI job, but `--fix` offers them too. Debian rates no severity, so
there only an exploited CVE makes a row AFFECTED. When a hand-picked check above is already AFFECTED
for the same package, the vendor's notices go into that row instead of a second one.

- **Nothing is sent.** These are plain downloads of public files, refreshed every 6 hours and kept in
  `/var/cache/amiaffected` (or `~/.cache/amiaffected`). The package list stays on the machine.
- **Each notice's conditions are checked, not just a version number.** Package version, release and
  architecture are tested against what's installed. A condition the tool can't judge (a kernel
  notice tied to the running kernel, a module stream, a FIPS build) counts as not met, so it can miss
  a notice but won't invent one. The running-kernel check above covers exploited kernel bugs.
- **Checked against the package manager.** What it flags matched the package manager's own list of
  security updates: Ubuntu 22.04 with old packages installed 13 of 13 (`apt`), Ubuntu 24.04 5 of 5,
  AlmaLinux 9 4 of 4, Oracle Linux 9 3 of 3, RHEL 9 0 of 0 (`dnf updateinfo --security`). On Rocky 9.3
  it found all 57, plus 6 fixes Rocky ships but its own metadata doesn't mark as security updates.
  On Debian 12.0 it found every package `apt` would upgrade from the security archive except tzdata
  (time zone data, no CVE), with glibc first for CVE-2023-4911. Debian's file lists 61,000 CVEs, so
  reading it takes about 10 seconds; the others take 1 to 3.
- **Rocky uses Red Hat's notices.** Rocky's own notices file stopped being updated in 2024, and Rocky
  rebuilds RHEL with the same package versions, so Red Hat's data fits it exactly.
- **Not covered yet:** RHEL 10 and Rocky 10 (Red Hat no longer publishes this format for
  10), and CentOS Stream, which publishes no security notices at all. These say UNKNOWN or nothing,
  rather than guess.

## Servers (Ubuntu, Debian, RHEL family)

On a VPS most software comes from apt or dnf, and the distros fix bugs without changing the
upstream version: a patched Ubuntu nginx still says 1.24.0. So for these the tool reads
`/etc/os-release`, asks `dpkg` or `rpm` what is installed, and compares it with the distro's own
fixed build for that release (Ubuntu 22.04 / 24.04 / 26.04, Debian 12 / 13, RHEL / AlmaLinux /
Rocky 9 / 10), letting `dpkg` and `rpm` decide which version is newer. Packages from a vendor
repo (nginx.org, MariaDB, MongoDB, Plex) carry a different upstream version and are checked
against the upstream fixes instead. The same goes for Homebrew, on a Mac or Linuxbrew: nginx,
httpd, MariaDB, MongoDB (`mongodb-community`) and Brotli installed with `brew` are checked against the
upstream fixes, and `--fix` offers `brew upgrade` for them.

| Issue | How |
|---|---|
| **Linux kernel**: CVE-2026-46300, CVE-2026-53266, CVE-2025-39964, CVE-2025-39682 (all CISA KEV) | The *running* kernel, matched to its flavour (generic, HWE, KVM, AWS, Azure, GCP, Oracle). A fix only counts after a reboot. |
| **Linux kernel**: CVE-2026-98432 (CVSS 9.8, remote over IPv4 TCP) | Same. On Ubuntu the fixed generic kernels (5.15.0-203.213 / 6.8.0-149.149 / 7.0.0-43.43) are [in -proposed](https://ubuntu.com/blog/fixes-available-in-proposed-pocket-for-cve-2026-98432) so far: a booted proposed kernel counts as fixed, and the fix plan gives Ubuntu's steps to install it. Cloud and HWE flavours aren't listed yet. |
| **PHP** from apt or dnf: PHP2Shell and the 19 Nov 2026 releases | `php8.x-cli`, `-fpm`, `-common` and `libapache2-mod-php8.x`, or `php-cli` / `php-fpm` on the RHEL family. Ubuntu, Debian and RHEL backport fixes without changing the version (Ubuntu 24.04's patched PHP is still 8.3.6), so the distro's fixed build decides. deb.sury.org, Remi and RHEL module streams carry upstream versions and are judged by those. |
| **nginx** CVE-2026-15176 and 4 more | Distro or nginx.org package. Fixed upstream in 1.30.6 / 1.31.7. |
| **Apache httpd** 2.4.69 fixes (CVE-2026-57941 mod_http2 and 4 more) | `apache2` / `httpd`, plus `mod_http2` on RHEL-family systems, where it is a separate package. |
| **MariaDB** CVE-2026-85746 and 4 more | Distro or MariaDB repo package. |
| **MySQL** Oracle's October 2026 Critical Patch Update (98 fixes, 29 without a login) | Distro, Oracle repo (`mysql-community-server`) or Homebrew package. Fixed in 8.4.13 and 9.7.4; Ubuntu 22.04/24.04 backport into 8.0.46 (`…ubuntu0.2x.04.5`). Oracle's own 8.0 builds are end of life. |
| **MySQL** Oracle's 17 Nov 2026 patch update: CVE-2026-114952 (9.1, client programs, no login needed) and 5 more | Same packages plus the client ones. 8.4.13, 9.7.4 and 26.10 are affected and no public or distro fix exists yet, so every MySQL is flagged for review with the mitigation: keep 3306 to the hosts that need it and don't point the client programs at servers you don't control. |
| **MongoDB** CVE-2026-82067 (authorization can end up off) and 4 more | `mongodb-org-server`. |
| **Brotli** CVE-2026-111497 (CISA KEV) | The system library that web servers, curl and PHP use. |
| **Plex**, **Zammad** (CISA KEV) | Their vendor packages. |
| **WordPress** CVE-2026-87902, CVE-2026-119977 (both CISA KEV) | `wp-includes/version.php` under `/var/www`, `/srv` and `~/public_html`. |
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
advisory in `source`. Each release is signed by the maintainer before it goes out
(`ssh-keygen -Y sign -f ~/.ssh/amiaffected_signing -n amiaffected secinspect.py advisories.json`),
and CI fails if a `.sig` doesn't match its file. Every 6 hours a scheduled job also checks the files
the site is serving and opens an issue if they don't verify.

The same job looks for CVEs the tool doesn't check yet and opens a `queue` issue for each: newly
exploited ones from CISA's KEV list, new ones in the cve.now feed for every tech already tracked, and
zero-days, which are bugs the vendor's own release notes say are exploited (Chrome Releases, Apple
security releases, Mozilla advisories). Zero-days often reach KEV days later, so they get a
`zero-day` label and go to the top of the queue.

## Not covered (yet)

- Chrome's own root store (Chrome updates itself; check `chrome://version`)
- Settings on Windows
- The OpenSSH client (its latest fixes have no CVEs) and the OpenSSL command line (it doesn't say which library your apps load)
- Opera, Vivaldi and Arc (their own version numbers don't say which Chromium fixes they carry), and Electron apps on Windows
- Perl `Mozilla::CA`, Go binaries with embedded roots
- Docker layers compressed with zstd, and files deleted in a later layer are still reported
- GitLab installs on other machines
- The Windows store check has not been tested on Windows yet
- Server checks: other distros (Fedora, Arch, Alpine, SUSE) and software in Docker containers
- Rocky Linux builds are assumed to match RHEL's; AlmaLinux sometimes ships an earlier fixed build
  of its own, which shows up as affected

## Tests

```
python3 test_secinspect.py
```

Built and maintained by [Avagama Consulting](https://avagama.co), who also do fixed-scope
[security reviews](https://avagama.co/services/) of agents, MCP servers and the machines they run on.
MIT licensed.

## Changelog

Every check and when it went live: [amiaffected.now/changelog](https://amiaffected.now/changelog/) ([RSS](https://amiaffected.now/changelog.xml)). Agent skills, MCP servers and extensions named in public as malicious or unsafe: [amiaffected.now/watchlist](https://amiaffected.now/watchlist/), generated from `advisories.json` by the same script. Add an entry to `changelog.json` with each change and run `python3 changelog.py`; CI fails if the page is out of date.

## Security

Found a problem with the tool itself? See [SECURITY.md](SECURITY.md).
