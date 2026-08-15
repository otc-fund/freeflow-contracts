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

# Honour core.hooksPath if the repo sets one — installing into .git/hooks while
# git is reading somewhere else means the hooks silently never run.
#
# This is not hypothetical: this repo had core.hooksPath set to an ABSOLUTE path
# pointing at the git dir's previous location. When the repository was re-rooted
# the path went stale, git found no hooks there, and commits stopped being
# scanned with no error of any kind. An absolute hooksPath also breaks on every
# fresh clone. If one is configured here, say so loudly.
CONFIGURED=$(git config --get core.hooksPath || true)
if [ -n "$CONFIGURED" ]; then
    HOOKS_DST="$CONFIGURED"
    echo "install-git-hooks: core.hooksPath is set to '$CONFIGURED' — installing there."
    case "$CONFIGURED" in
        /*|[A-Za-z]:[/\\]*)
            echo "  WARNING: that is an ABSOLUTE path. It will break if this repo is"
            echo "           moved or cloned, and hooks then fail SILENTLY. Consider:"
            echo "               git config --unset core.hooksPath"
            ;;
    esac
else
    HOOKS_DST="$GIT_DIR/hooks"
fi
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
