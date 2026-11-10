#!/bin/sh
# Sign and push a release:  sh .github/sign-release.sh
#   Checks the release is ready, signs secinspect.py + advisories.json with your offline key
#   (asks for its passphrase), verifies the signatures, commits them and pushes after you say yes.
# Install the guard that stops any unsigned push (yours, Claude's or the marketing agent's):
#   sh .github/sign-release.sh --install-hook
set -e
cd "$(git rev-parse --show-toplevel)"
KEY="$HOME/.ssh/amiaffected_signing"

if [ "$1" = "--install-hook" ]; then
  cp .github/pre-push .git/hooks/pre-push && chmod +x .git/hooks/pre-push
  echo "Installed .git/hooks/pre-push: pushes whose release files aren't signed are refused."
  exit 0
fi

[ "$(git branch --show-current)" = main ] || { echo "Not on main."; exit 1; }
git diff --quiet HEAD -- secinspect.py advisories.json || { echo "secinspect.py or advisories.json has uncommitted changes: commit them first."; exit 1; }
git fetch -q origin
git merge-base --is-ancestor origin/main HEAD || { echo "origin/main has commits you don't have: git pull --rebase first."; exit 1; }
python3 changelog.py --check || { echo "Run python3 changelog.py, commit what it changes, then run this again."; exit 1; }
python3 test_secinspect.py >/dev/null 2>&1 || { echo "Tests fail: python3 test_secinspect.py"; exit 1; }

if python3 -c "import sys, secinspect as s; sys.exit(0 if s.release_signed('.') else 1)"; then
  echo "Release files are already signed."
else
  [ -f "$KEY" ] || { echo "No signing key at $KEY"; exit 1; }
  ssh-keygen -Y sign -f "$KEY" -n amiaffected secinspect.py advisories.json
  python3 -c "import sys, secinspect as s; sys.exit(0 if s.release_signed('.') else 1)" \
    || { echo "The new signatures don't verify against the key pinned in secinspect.py. Nothing committed."; exit 1; }
  git add secinspect.py.sig advisories.json.sig
  git commit -q -m "Sign release"
  echo "Signed and committed."
fi

if [ -z "$(git --no-pager log --oneline origin/main..HEAD)" ]; then
  echo "Nothing to push."; exit 0
fi
echo; echo "About to push:"; git --no-pager log --oneline origin/main..HEAD
printf "Push to GitHub? [y/N] "; read -r a
[ "$a" = y ] || [ "$a" = Y ] || { echo "Not pushed."; exit 0; }
git push
