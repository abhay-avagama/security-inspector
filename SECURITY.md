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
- Its only network request is a read-only GET of the public [cve.now](https://cve.now) feed, to warn when its advisory data is out of date. Nothing about your machine is sent. `--no-update-check` turns it off.
- `curl -fsSL https://amiaffected.now/run | sh` downloads `secinspect.py` and `advisories.json` from this repository's GitHub Pages site into a temporary folder, runs them and deletes the folder. Read [`run`](run) first if you prefer, or clone the repository and run `python3 secinspect.py` yourself.
