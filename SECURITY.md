# Security policy

## Reporting a problem

Found a security bug in Am I affected? Please don't open a public issue. Report it privately instead:

- on GitHub: the **Security** tab of this repository, then **Report a vulnerability**, or
- by email to [info@avagama.co](mailto:info@avagama.co) with "Security: Am I affected?" in the subject.

Tell us what you ran, on which OS, and what happened. We'll reply, keep you posted until it's fixed, and credit you in the commit if you'd like that.

## What counts

- `secinspect.py`, `advisories.json`, the `run` installer and the amiaffected.now site.
- A result that says a machine is safe when it isn't (a missed install, a wrong fixed version, an advisory we got wrong). For a tool like this, a false "OK" is a security bug. If the mistake is in public advisory data, a normal issue is fine too.

## What the tool does on your machine

So you can check it before you run it:

- It reads files under your home folder (or the folders you name), and system trust stores.
- It runs `--version` (or `-v`) on the programs it checks, `dpkg-query` / `rpm` on Linux servers, and `openssl` (plus `security` on macOS) to test CA bundles. With `--docker` it also runs `docker images` and `docker save`, and reads the images without starting them.
- It writes nothing except short-lived temporary files for those tests, the `--html` report if you ask for one, and the skill fingerprint file if you pass `--skills-baseline FILE`. Both go only where you name them.
- Its only network requests are read-only downloads of public files: the [cve.now](https://cve.now) feed (to warn when its advisory data is out of date), the distro vendor's security notices (Canonical, Red Hat, AlmaLinux, Rocky, Oracle) and CISA's list of exploited CVEs. Nothing about your machine is sent, including the package list. `--no-update-check` uses the last downloaded copies only.
- The one exception is watch mode, and only when you ask: `--watch FILE --notify URL` posts the changed findings (item, path, status) to the webhook you name, and `--mail ADDRESS` emails them through your own `sendmail`. Without those flags nothing is sent.
- `curl -fsSL https://amiaffected.now/run | sh` downloads `secinspect.py`, `advisories.json` and their signatures from this repository's GitHub Pages site into a temporary folder, checks both files against the release key, runs them only if they match and deletes the folder. Read [`run`](run) first if you prefer, or clone the repository and run `python3 secinspect.py` yourself.

## Checking what you were served

- **The release key.** Every release of `secinspect.py` and `advisories.json` is signed with one key, kept offline by the maintainer, never on the site, in GitHub or in CI. Its fingerprint is `SHA256:J2gtbuBTYxZRpDwEsKM6owYkY38bCClyuybzmeCu01U`. The same key is written in `run`, in `secinspect.py` (`SIGNING_KEY`) and here; if they ever differ, don't run it and tell us.
- **`run` checks before it runs.** It verifies both files with `ssh-keygen -Y verify` and refuses to start if either doesn't match. On a machine with no `ssh-keygen`, or OpenSSH older than 8.1, it can't check; it says so and runs.
- **Every result names its release.** The line under the table, and the top of the HTML report, give the release date, the hash of `secinspect.py` and whether the files match the release key.
- **A public log we don't control.** On each release, CI records the hashes of `secinspect.py`, `advisories.json` and `run` in Sigstore's public transparency log through GitHub's artifact attestations. To check a file you downloaded: `gh attestation verify secinspect.py --repo abhay-avagama/security-inspector`.
- **The limit.** `run` comes from the same site as the files, so someone who took over the site could serve a `run` without the check. To rule that out, check `run` itself against the log before running it:

  ```sh
  curl -fsSL https://amiaffected.now/run -o run && gh attestation verify run --repo abhay-avagama/security-inspector && sh run
  ```
