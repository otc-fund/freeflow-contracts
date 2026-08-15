#!/bin/sh
# Install the tracked hooks in scripts/hooks/ into this checkout's hook directory.
#
# Run once after cloning:
#     ./freeflow-contracts/scripts/install-git-hooks.sh
#
# LAYOUT NOTE — this repo is not shaped the way you would guess. The git root of
# a normal checkout is the PARENT of freeflow-contracts/, because the GitHub repo
# publishes freeflow-contracts/ as a top-level directory. So:
#   * the hooks SOURCE is resolved relative to this script, not to the git root;
#   * the hooks DESTINATION comes from `git rev-parse --git-dir`, not from
#     "<toplevel>/.git" — which also keeps this correct inside a linked worktree,
#     where .git is a file rather than a directory.

set -e

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
HOOKS_SRC="$SCRIPT_DIR/hooks"

if [ ! -d "$HOOKS_SRC" ]; then
    echo "install-git-hooks: $HOOKS_SRC not found."
    exit 1
fi

GIT_DIR=$(git rev-parse --git-dir 2>/dev/null) || {
    echo "install-git-hooks: not inside a git repository."
    exit 1
}
HOOKS_DST="$GIT_DIR/hooks"
mkdir -p "$HOOKS_DST"

for hook in "$HOOKS_SRC"/*; do
    [ -f "$hook" ] || continue
    name=$(basename "$hook")
    cp "$hook" "$HOOKS_DST/$name"
    chmod +x "$HOOKS_DST/$name"
    echo "installed: $HOOKS_DST/$name"
done

if ! command -v gitleaks >/dev/null 2>&1; then
    echo ""
    echo "install-git-hooks: hooks are in place, but gitleaks is NOT on PATH."
    echo "The pre-commit hook fails closed, so commits will be blocked until you"
    echo "install it:"
    echo "  Windows:  winget install gitleaks   (or drop gitleaks.exe on PATH)"
    echo "  macOS:    brew install gitleaks"
    echo "  Linux:    https://github.com/gitleaks/gitleaks#installation"
    exit 1
fi

echo ""
echo "install-git-hooks: OK — gitleaks $(gitleaks version) on PATH."
