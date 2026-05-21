#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
#  FreeFlow Solana Programs — Deployment Script
#  Deploys staking, rewards, and registry programs to devnet or mainnet.
#
#  Usage:
#    ./deploy.sh devnet        # Deploy to devnet (safe, uses test $FLOW)
#    ./deploy.sh mainnet-beta  # Deploy to mainnet (real $FLOW — irreversible)
#    ./deploy.sh localnet      # Deploy to local test validator
#    ./deploy.sh upgrade devnet staking  # Upgrade one program on devnet
#
#  Requirements:
#    - Solana CLI: sh -c "$(curl -sSfL https://release.anza.xyz/stable/install)"
#    - Anchor CLI: cargo install --git https://github.com/coral-xyz/anchor anchor-cli
#    - Funded wallet at ~/.config/solana/id.json
# ─────────────────────────────────────────────────────────────────────────────
set -euo pipefail

CLUSTER="${1:-devnet}"
ACTION="${2:-deploy}"   # deploy | upgrade | verify
TARGET="${3:-all}"      # all | staking | rewards | registry

PROGRAMS=(staking rewards registry)
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# ── Colours ────────────────────────────────────────────────────────────────────
GREEN='\033[0;32m'; CYAN='\033[0;36m'; YELLOW='\033[0;33m'; RED='\033[0;31m'; RESET='\033[0m'
info()  { echo -e "${CYAN}[INFO]${RESET}  $*"; }
ok()    { echo -e "${GREEN}[ OK ]${RESET}  $*"; }
warn()  { echo -e "${YELLOW}[WARN]${RESET}  $*"; }
fatal() { echo -e "${RED}[FAIL]${RESET}  $*"; exit 1; }

# ── Preflight checks ───────────────────────────────────────────────────────────
info "FreeFlow program deployment — cluster: $CLUSTER, action: $ACTION"

command -v solana &>/dev/null || fatal "Solana CLI not found. Install from https://release.anza.xyz"
command -v anchor  &>/dev/null || fatal "Anchor CLI not found. Run: cargo install anchor-cli"

# Set cluster.
solana config set --url "$CLUSTER" >/dev/null

# Check wallet balance.
WALLET="$(solana config get keypair | awk '{print $2}')"
BALANCE="$(solana balance --lamports | awk '{print $1}')"
info "Wallet: $WALLET"
info "Balance: $(echo "scale=4; $BALANCE/1000000000" | bc) SOL"

if [[ "$CLUSTER" == "mainnet-beta" ]]; then
    echo ""
    warn "⚠️  MAINNET DEPLOYMENT — This uses real money and is irreversible."
    warn "   Ensure you have reviewed and audited all programs before proceeding."
    read -rp "   Type 'DEPLOY MAINNET' to confirm: " CONFIRM
    [[ "$CONFIRM" == "DEPLOY MAINNET" ]] || fatal "Mainnet deployment cancelled."
fi

# Minimum SOL for deployment (rough estimate: 2 SOL per program for rent + fees).
MIN_SOL=6000000000  # 6 SOL in lamports
if [[ "$BALANCE" -lt "$MIN_SOL" ]]; then
    fatal "Insufficient balance. Need ~6 SOL, have $(echo "scale=4; $BALANCE/1000000000" | bc) SOL"
fi

# ── Build ──────────────────────────────────────────────────────────────────────
info "Building programs with anchor build..."
cd "$SCRIPT_DIR"
anchor build 2>&1 | tail -20

ok "Build successful"

# ── Deploy or Upgrade ──────────────────────────────────────────────────────────

deploy_program() {
    local name="$1"
    local so_path="target/deploy/freeflow_${name}_program.so"
    local keypair="target/deploy/freeflow_${name}_program-keypair.json"

    if [[ ! -f "$so_path" ]]; then
        warn "Binary not found: $so_path — skipping $name"
        return
    fi

    info "Deploying freeflow-$name..."

    if [[ "$ACTION" == "upgrade" ]]; then
        # Upgrade an already-deployed program (requires upgrade authority).
        solana program deploy \
            --program-id "$keypair" \
            --upgrade-authority "$WALLET" \
            "$so_path"
    else
        # Fresh deploy — use the generated keypair as program ID.
        solana program deploy \
            --keypair "$keypair" \
            "$so_path"
    fi

    PROGRAM_ID="$(solana program show --output json "$(solana-keygen pubkey "$keypair")" | python3 -c "import sys,json; print(json.load(sys.stdin)['programId'])" 2>/dev/null || solana-keygen pubkey "$keypair")"
    ok "$name deployed: $PROGRAM_ID"
    echo "FREEFLOW_${name^^}_PROGRAM_ID=$PROGRAM_ID" >> "$SCRIPT_DIR/.env.$CLUSTER"
}

# ── Main deployment loop ───────────────────────────────────────────────────────

# Clear env file for fresh deployment.
[[ "$ACTION" == "deploy" ]] && > "$SCRIPT_DIR/.env.$CLUSTER"

if [[ "$TARGET" == "all" ]]; then
    for prog in "${PROGRAMS[@]}"; do
        deploy_program "$prog"
    done
else
    deploy_program "$TARGET"
fi

# ── Post-deployment verification ──────────────────────────────────────────────

info "Verifying deployed programs..."
for prog in "${PROGRAMS[@]}"; do
    KEYPAIR="target/deploy/freeflow_${prog}_program-keypair.json"
    [[ -f "$KEYPAIR" ]] || continue
    PROG_ID="$(solana-keygen pubkey "$KEYPAIR")"
    STATUS="$(solana program show "$PROG_ID" 2>/dev/null | grep "Upgradeable" || echo "unknown")"
    ok "$prog ($PROG_ID): $STATUS"
done

# ── Run integration tests ──────────────────────────────────────────────────────
if [[ "$CLUSTER" == "localnet" || "$CLUSTER" == "devnet" ]]; then
    info "Running integration tests against $CLUSTER..."
    anchor test --skip-build --provider.cluster "$CLUSTER" 2>&1 | tail -30
    ok "Tests passed"
fi

echo ""
ok "Deployment complete!"
echo ""
echo "  Program IDs written to: .env.$CLUSTER"
echo "  Update freeflow.toml with these program IDs."
cat "$SCRIPT_DIR/.env.$CLUSTER" 2>/dev/null || true
