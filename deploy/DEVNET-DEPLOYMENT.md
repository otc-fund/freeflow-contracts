# Devnet Deployment Record

**Date:** 2026-04-28 (initial) / 2026-05-30 (rewards-v2)  
**Network:** Solana Devnet  
**Solana CLI:** 1.18.26  
**Anchor:** 0.30.1  
**Platform-tools:** v1.41 (cargo 1.75.0 / rustc 1.75.0)  
**Deployer wallet:** `~/.config/solana/id.json`

---

## Deployed Programs

| Program | Program ID | Status |
|---------|-----------|--------|
| repflow_token | `8K4GhPEQ1yy9vdTaMPTL83G5qr5ZHZiBm2VBQ58jJs5w` | Upgraded |
| staking | `7N1JRX3LY3goVAZCyaJyH7kpZ3kboZvh3jteDmCq6Dz4` | Upgraded |
| rewards | `2yeVew5qq5jf5zuoqiE2svVLRE9HTN6J2GfB9LopdM1C` | Upgraded |
| registry | `HkMhMoEv7U8VowyVsCCk9pZDkWwp18ei1BZ3Fif94DCE` | Upgraded |
| user_escrow | `7PzcA2sNDzrvhTNLFScWZuNKS4g7jCCghsowZA9RsZ26` | New deploy |
| rewards_v2 | `26pFEqpZYeG5xxmAMc74ZsANo6Kdduf5HYq5qk7Y34eT` | New deploy (2026-05-30) |

All programs verified `Executable: true` via `solana program show <program-id>`.

---

## Build Command

```bash
cd freeflow-contracts

# Regenerate lockfile after any Cargo.toml change, then downgrade to v3
cargo generate-lockfile
sed -i 's/^version = 4$/version = 3/' Cargo.lock

# Build all programs
cargo build-sbf -- --locked
```

Compiled `.so` artifacts land in:
```
target/deploy/
  repflow_token.so
  staking.so
  rewards.so
  registry.so
  user_escrow.so
  freeflow_rewards_v2.so   # rewards-v2 (Merkle-committed claims, 3-phase flow)
```

---

## Deploy / Upgrade Procedure

### New program (first-time deploy)

```bash
# Generate a keypair for the program (once only)
solana-keygen new -o deploy/user_escrow-keypair.json --no-bip39-passphrase

# Fund deployer if needed
solana airdrop 5

# Deploy
solana program deploy \
  --program-id deploy/user_escrow-keypair.json \
  target/deploy/user_escrow.so
```

### Upgrade existing program

Existing programs may have grown since their last deploy.  
If the new binary is larger than the on-chain account, extend first:

```bash
# Extend buffer — add bytes beyond what the binary needs (safety margin)
solana program extend <PROGRAM_ID> <EXTRA_BYTES>

# Upgrade
solana program deploy \
  --program-id <PROGRAM_ID> \
  target/deploy/<program>.so
```

**Extensions applied this deployment:**

| Program | Extension |
|---------|-----------|
| repflow_token | +40,000 bytes |
| rewards | +170,000 bytes |
| staking | +8,000 bytes |
| registry | +8,000 bytes |

### Verify after deploy

```bash
solana program show <PROGRAM_ID>
# Expect: Executable: true
```

---

## Anchor.toml devnet section

```toml
[programs.devnet]
repflow_token = "8K4GhPEQ1yy9vdTaMPTL83G5qr5ZHZiBm2VBQ58jJs5w"
staking       = "7N1JRX3LY3goVAZCyaJyH7kpZ3kboZvh3jteDmCq6Dz4"
rewards       = "2yeVew5qq5jf5zuoqiE2svVLRE9HTN6J2GfB9LopdM1C"
registry      = "HkMhMoEv7U8VowyVsCCk9pZDkWwp18ei1BZ3Fif94DCE"
user_escrow   = "7PzcA2sNDzrvhTNLFScWZuNKS4g7jCCghsowZA9RsZ26"
rewards_v2    = "26pFEqpZYeG5xxmAMc74ZsANo6Kdduf5HYq5qk7Y34eT"
```

---

## Git Push (Windows / credential issue)

The Windows Credential Manager requires a GUI prompt, which blocks
non-interactive terminals. Workaround: embed credentials directly in the
remote URL for a one-shot push.

```bash
git remote set-url origin https://<TOKEN>@github.com/otc-fund/freeflow-contracts.git
git push origin main
# Then restore the clean URL
git remote set-url origin https://github.com/otc-fund/freeflow-contracts.git
```

The token can be read from `~/.git-credentials` (line format:
`https://<user>:<token>@github.com`).
