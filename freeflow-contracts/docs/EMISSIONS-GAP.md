# FreeFlow — Emissions Gap Analysis

> **Date:** 2026-05-24
> **Scope:** Reward rate accuracy, claim emissions, on-chain vs documented vs target
> **Data source:** `relay-monitor.jsonl` (poll #1, 2026-05-24T00:30:00Z), on-chain RewardRatesAccount PDA, sidecar source, rewards program source
> **Constraint:** DOCUMENT ONLY — DO NOT TOUCH CODE

---

## Executive Summary

There are **two separate reward calculation paths** and they disagree by 1000x:

1. **On-chain PDA (`RewardRatesAccount`)** says: routing=1,000,000/MB, uptime=10,000,000,000/hr
2. **`process_claim()` hardcoded constants** say: routing=1,000/MB, uptime=10,000,000/hr

`process_claim()` **ignores the on-chain PDA entirely** and uses hardcoded values that are 1000x lower than what the PDA stores. The sidecar reads from the PDA for display (`/v1/rates`), but the actual reward calculation uses the constants.

The repflow `/100` is a **basis points converter** (100 bps = 1.0x), not a reward-reducing divisor — it cancels out completely for Active tier relays.

DreamHost emits **~0.04 FLOW/day** vs a target of ~240 FLOW/day from uptime alone at 10 FLOW/hr — roughly **6000x below target**.

---

## E1: On-Chain PDA vs Hardcoded Constants — 1000x Disconnect

### The two reward paths

**Path A: `process_claim()` (disc=0, ClaimRewards)** — the legacy path used by the sidecar:
```rust
// rewards/lib.rs:2422-2424 — HARDCODED
const BASE_ROUTING_PER_MB:   u64 = 1_000;
const BASE_SEEDING_PER_MB:   u64 = 2_000;
const BASE_UPTIME_PER_HOUR:  u64 = 10_000_000;
```
This function **never reads** the `RewardRatesAccount` PDA.

**Path B: `process_claim_usage()` (disc=2, ClaimUsage)** — the new usage-escrow path:
Does not calculate lamport rewards at all — escrows $FLOW from user charges into `PendingClaimsStore`. The on-chain `RewardRatesAccount` PDA is read only for `flow_price_cents` to compute stake requirements (line 2910-2923), not for reward amounts.

### What this means in practice

| Rate | On-chain PDA | Hardcoded constant | Ratio |
|------|-------------|-------------------|-------|
| Routing | 1,000,000/MB | 1,000/MB | **1000x** |
| Seeding | 2,000,000/MB | 2,000/MB | **1000x** |
| Uptime | 10,000,000,000/hr | 10,000,000/hr | **1000x** |

The PDA rates are **displayed by the sidecar** at `GET /v1/rates` but **never applied to actual reward calculations**. Relays see one set of rates on the dashboard and get paid at a different set.

### Actual rewards per claim (Active tier, multiplier=1.0)

For 1 GB routed: `1024 MB × 1,000 = 1,024,000 base units = 0.001 FLOW`
For 1 hr uptime: `1 × 10,000,000 = 10,000,000 base units = 0.01 FLOW`

**Target:** 1 FLOW/GB routing, 10 FLOW/hr uptime
**Actual:** 0.001 FLOW/GB routing, 0.01 FLOW/hr uptime (when uptime hits)

Routing: **1000x below target**. Uptime: **1000x below target** (before the integer division bug).

### The repflow `/100` is NOT a divisor

The `/100` in the formula is a **basis points converter**:
```rust
routing_reward = routing_mb × BASE_ROUTING_PER_MB × multiplier_bps / 100
```

For Active tier (`multiplier_bps = 100`): `× 100 / 100 = × 1.0` — cancels out, no reduction.
For Newcomer (`multiplier_bps = 90`): `× 90 / 100 = × 0.9` — 10% penalty.
For Icon (`multiplier_bps = 150`): `× 150 / 100 = × 1.5` — 50% bonus.

This is correct behavior — it's how you express 0.9x to 1.5x multipliers in integer math. The `/100` does NOT compress rewards; it converts "basis points" to a real multiplier.

---

## E2: Integer Division Zeroes Out Uptime Rewards

**Bug:** `calculate_reward()` at `rewards/lib.rs:2427`:
```rust
let uptime_hrs = uptime_seconds / 3600;  // integer division
```

The sidecar claims approximately every hour. The period window is `[now - 3600, now]` (`handlers.rs:324`). In practice, `uptime_seconds` is typically 3500-3650 — which means:

- If `uptime_seconds = 3599` → `uptime_hrs = 0` → **zero uptime reward** (should be 10 FLOW)
- If `uptime_seconds = 3600` → `uptime_hrs = 1` → **10 FLOW** (correct rate)

**Result:** Roughly 50% of claims get zero uptime credit. This is a coin flip based on exact timing. The rate itself is correct at 10 FLOW/hr — the bug is that it only fires ~50% of the time.

### DreamHost actual emissions

From `relay-monitor.jsonl`:
- Total claimed: **0.7358 FLOW** over **19 claims** over **16.8 days**
- Average: **0.0387 FLOW/day** or **~40M base units/day**
- Per claim: **~38.7M base units** (~0.0387 FLOW)

At the target of 10 FLOW/hr uptime alone, DreamHost should earn **~240 FLOW/day** (24 hr × 10 FLOW). It's earning **0.04 FLOW/day** total.

**Emissions are ~6000x below target.**

---

## E3: No `flow_price_cents` Set

The `flow_price_cents` field in the RewardRatesAccount PDA is **0**. This field is used by the sidecar to convert FLOW amounts to USD cents for display and for dynamic stake/bond calculations.

Impact:
- `compute_challenger_bond()` returns default 50 FLOW (since price=0 triggers default)
- `compute_min_stake()` returns default 100 FLOW
- No way to adjust stake requirements based on actual FLOW price

---

## E4: No $FLOW Supply Cap Enforcement

**Fact:** 99,000,000 FLOW not yet minted (from user). Total supply cap is 100,000,000 FLOW.

**Current supply:** `human_supply: 100000008` with `decimals: 9` (from `relay-monitor.jsonl`) = **0.100000008 FLOW** on-chain.

**Relays mint $FLOW through claims.** There is no program-level daily mint cap on $FLOW — the only limit is the total supply cap of 100M. The `MAX_DAILY_MINT = 200` in `repflow-token/src/state.rs:88` is a **per-user** daily limit for repFlow, not $FLOW.

If rates were corrected to 10 FLOW/hr × 2 relays × 24 hr = 480 FLOW/day, it would take ~208,333 days to exhaust the remaining 99M supply — not a practical concern.

---

## E5: No Rate Adjustment Mechanism

**The operational gap:** Even if the correct rates are known, there's no way to change them.

| Component | Capability |
|-----------|-----------|
| On-chain program | `UpdateRewardRates` (disc=17) exists, requires foundation signature |
| Sidecar | `encode_update_reward_rates()` exists, can build the transaction |
| Foundation | **No endpoint** to call it |
| Admin | No CLI subcommand, no HTTP route |

To fix rates today, you would need to:
1. Manually build the `UpdateRewardRates` instruction
2. Sign it with the foundation delegate key
3. Submit it via Solana RPC

There's no tooling for this. No script, no endpoint, no CLI.

---

## E6: RepFlow Multiplier — Correct Behavior

The reward formula uses basis points for tier differentiation:
```rust
routing_reward = routing_mb × BASE_ROUTING_PER_MB × multiplier_bps / 100
```

The `/100` is simply how you convert "100 bps = 1.0x" to an integer multiplier. It is **not** a reward-reducing divisor:

| Tier | multiplier_bps | Final multiplier | Effect |
|------|---------------|-----------------|--------|
| Newcomer | 90 | 90/100 = 0.9x | 10% penalty |
| Active | 100 | 100/100 = 1.0x | Baseline (cancels out) |
| Trusted | 110 | 110/100 = 1.1x | 10% bonus |
| Veteran | 130 | 130/100 = 1.3x | 30% bonus |
| Legend | 140 | 140/100 = 1.4x | 40% bonus |
| Icon | 150 | 150/100 = 1.5x | 50% bonus |

This is correct. The confusion arose because the document previously characterized `/100` as a reward-reducing divisor — it is not. For Active tier (the baseline), `× 100 / 100 = × 1` with zero effect.

---

## E7: Cashback Component Unused

The reward formula includes a `cashback` term:
```rust
total_reward = routing_reward + uptime_reward + cashback
```

But `cashback` is never populated in any claim path. It's always zero. Dead code.

---

## Summary: Emissions vs Target

| Metric | Target | Actual (DreamHost) | Gap |
|--------|--------|-------------------|-----|
| Routing reward | 1 FLOW/GB | 0.001 FLOW/GB | **1000x low** |
| Uptime reward | 10 FLOW/hr | 0.01 FLOW/hr (when it fires) | **1000x low + integer division halves it** |
| Total daily | ~241 FLOW/day (1 GB routing + 240 hr uptime) | ~0.04 FLOW/day | **~6000x low** |
| $FLOW minted | 0.1 FLOW on-chain | 0.1 FLOW | Consistent with low emissions |

**Root causes:**
1. `process_claim()` uses hardcoded constants (1,000/MB routing, 10,000,000/hr uptime) that are 1000x below target — it never reads the on-chain RewardRatesAccount PDA
2. Integer division `uptime_seconds / 3600` zeroes out ~50% of uptime rewards on top of the 1000x shortfall
3. On-chain PDA rates are displayed by sidecar but never applied to actual reward calculations
4. No operational path to fix either the hardcoded constants or the PDA rates (F1 in FOUNDATION-GAPS.md)
5. No $FLOW daily mint cap exists — only the 100M total supply cap (repFlow's `MAX_DAILY_MINT = 200` is per-user, per-day, unrelated to $FLOW)
