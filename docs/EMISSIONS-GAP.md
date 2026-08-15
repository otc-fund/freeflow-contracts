# FreeFlow — Emissions Gap Analysis

> **Date:** 2026-05-24
> **Scope:** Reward rate accuracy, claim emissions, on-chain vs documented vs target
> **Data source:** `relay-monitor.jsonl` (poll #1, 2026-05-24T00:30:00Z), on-chain RewardRatesAccount PDA, sidecar source, rewards program source
> **Updated:** 2026-05-26 — E1 (constants + PDA wiring), E2 (integer division), E7 (cashback) all resolved in-code. E3 (flow_price_cents) code-ready, not yet initialized on-chain. E5 (rate adjustment) on-chain instruction exists; foundation endpoint still missing. E4 (supply cap) still open but not practically concerning.

---

## Resolved Since Original Audit

| Date | Gap | What changed | Evidence |
|------|-----|-------------|----------|
| 2026-05-26 | E1 | Constants bumped to target rates; `calculate_reward()` now reads from `RewardRatesAccount` PDA when supplied; fallback to constants for backward compat | `rewards/lib.rs:2426-2428` (BASE_ROUTING_PER_MB=1_000_000), `lib.rs:2602-2626` (PDA read with fallback) |
| 2026-05-26 | E2 | Multiply-then-divide preserves sub-hour precision: `(uptime_seconds × uptime_per_hour) / 3600` | `rewards/lib.rs:2456-2458` |
| 2026-05-26 | E7 | Cashback now live in `calculate_reward()`: per-tier percentages (2%–12%), tracked on `RewardAccount.total_cashback_earned` | `rewards/lib.rs:2446-2478`, tests at `lib.rs:6136` |

---

---

## Executive Summary

There are **two separate reward calculation paths** and they disagree by 1000x:

1. **On-chain PDA (`RewardRatesAccount`)** says: routing=1,000,000/MB, uptime=10,000,000,000/hr
2. **`process_claim()` hardcoded constants** say: routing=1,000/MB, uptime=10,000,000/hr

`process_claim()` **ignores the on-chain PDA entirely** and uses hardcoded values that are 1000x lower than what the PDA stores. The sidecar reads from the PDA for display (`/v1/rates`), but the actual reward calculation uses the constants.

The repflow `/100` is a **basis points converter** (100 bps = 1.0x), not a reward-reducing divisor — it cancels out completely for Active tier relays.

DreamHost emits **~0.04 FLOW/day** vs a target of ~240 FLOW/day from uptime alone at 10 FLOW/hr — roughly **6000x below target**.

---

## E1: On-Chain PDA vs Hardcoded Constants — 1000x Disconnect **RESOLVED (2026-05-26)**

### ~~The two reward paths~~

**~~Path A: `process_claim()` (disc=0, ClaimRewards)~~** — ~~the legacy path used by the sidecar~~:

**FIXED:** Constants at `rewards/lib.rs:2426-2428` are now `BASE_ROUTING_PER_MB = 1_000_000`, `BASE_SEEDING_PER_MB = 2_000_000`, `BASE_UPTIME_PER_HOUR = 10_000_000_000` — matching the on-chain PDA values.

**FIXED:** `ClaimRewards` handler (`lib.rs:2602-2626`) accepts `RewardRatesAccount` PDA as optional account[2]. When present and valid, reads rates from PDA. Falls back to BASE constants only when PDA is absent or unparseable — backward compatible.

**FIXED:** `calculate_reward()` now accepts `routing_per_mb`, `seeding_per_mb`, `uptime_per_hour` as parameters (line 2437-2439), sourced from the PDA at call time.

### What this means now

| Rate | On-chain PDA | Hardcoded constant | Status |
|------|-------------|-------------------|--------|
| Routing | 1,000,000/MB | 1,000,000/MB | **MATCH** |
| Seeding | 2,000,000/MB | 2,000,000/MB | **MATCH** |
| Uptime | 10,000,000,000/hr | 10,000,000,000/hr | **MATCH** |

PDA rates are used when supplied. Fallback constants are identical — no more discrepancy.

### ~~Actual rewards per claim (Active tier, pre-fix)~~ (HISTORICAL)

> **Note:** Pre-fix figures below. Post-fix: rates match target.

For 1 GB routed (pre-fix): `1024 MB × 1,000 = 1,024,000 base units = 0.001 FLOW`
For 1 hr uptime (pre-fix): `1 × 10,000,000 = 10,000,000 base units = 0.01 FLOW` (when integer division didn't zero it)

**Target:** 1 FLOW/GB routing, 10 FLOW/hr uptime
**Actual (pre-fix):** 0.001 FLOW/GB routing, 0.01 FLOW/hr uptime — both 1000x low
**Actual (post-fix):** 1 FLOW/GB routing, 10 FLOW/hr uptime — constants match target. PDA values used when supplied.

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

## E2: Integer Division Zeroes Out Uptime Rewards **RESOLVED (2026-05-26)**

**FIXED:** `calculate_reward()` at `rewards/lib.rs:2456-2458`:
```rust
// Old: (uptime_seconds / 3600) * uptime_per_hour → 0 for 3599 s
// New: (uptime_seconds * uptime_per_hour) / 3600  → ≈ uptime_per_hour for 3599 s
let uptime_base = uptime_seconds
    .saturating_mul(uptime_per_hour)
    .saturating_div(3600);
```

Multiply-then-divide preserves sub-hour precision. For `uptime_seconds = 3599`:
- **Old:** `3599 / 3600 = 0` → zero uptime reward
- **New:** `3599 × 10_000_000_000 / 3600 = 9_997_222_222` → ~10 FLOW (correct)

### ~~DreamHost actual emissions~~ (HISTORICAL — pre-fix data)

> **Note:** The figures below reflect emissions under the old 1000x-low constants. After the E1/E2 fixes (2026-05-26), per-claim emissions should increase ~1000x.

From `relay-monitor.jsonl`:
- Total claimed: **0.7358 FLOW** over **19 claims** over **16.8 days**
- Average: **0.0387 FLOW/day** or **~40M base units/day**
- Per claim: **~38.7M base units** (~0.0387 FLOW)

At the corrected rate of 10 FLOW/hr uptime alone, DreamHost should earn **~240 FLOW/day** (24 hr × 10 FLOW). Pre-fix emissions were **0.04 FLOW/day** total.

**Pre-fix emissions were ~6000x below target. Post-fix: should be ~1x target (pending on-chain initialization and deployment).**

---

## E3: No `flow_price_cents` Set **PARTIALLY RESOLVED**

**FIXED (in-code):** The `flow_price_cents` field exists on `RewardRatesAccount` (line 1527). `UpdateRewardRates` can set it (`lib.rs:4483`). `compute_challenger_bond()` and `compute_min_stake()` use it for dynamic stake/bond calculations, falling back to defaults (50 FLOW challenger bond, 100 FLOW min stake) when `flow_price_cents = 0`.

**STILL OPEN:** The PDA has not been initialized on-chain with a non-zero `flow_price_cents` value (no deployment yet). The code path is ready; the operational act of calling `InitializeRewardRates` with a real price hasn't happened.

---

## E4: No $FLOW Supply Cap Enforcement

**Fact:** 99,000,000 FLOW not yet minted (from user). Total supply cap is 100,000,000 FLOW.

**Current supply:** `human_supply: 100000008` with `decimals: 9` (from `relay-monitor.jsonl`) = **0.100000008 FLOW** on-chain.

**Relays mint $FLOW through claims.** There is no program-level daily mint cap on $FLOW — the only limit is the total supply cap of 100M. The `MAX_DAILY_MINT = 200` in `repflow-token/src/state.rs:88` is a **per-user** daily limit for repFlow, not $FLOW.

If rates were corrected to 10 FLOW/hr × 2 relays × 24 hr = 480 FLOW/day, it would take ~208,333 days to exhaust the remaining 99M supply — not a practical concern.

---

## E5: No Rate Adjustment Mechanism **PARTIALLY RESOLVED**

| Component | Status |
|-----------|--------|
| On-chain program | `UpdateRewardRates` (disc=17) exists at `rewards/lib.rs:4433-4494`, requires Foundation signature — **RESOLVED** |
| Sidecar | `encode_update_reward_rates()` exists in `sidecar/src/solana.rs` — **RESOLVED** |
| Foundation | **STILL OPEN** — no endpoint to call it |
| Admin | No CLI subcommand, no HTTP route — **STILL OPEN** |

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

## E7: Cashback Component **RESOLVED (2026-05-26)**

The reward formula now includes cashback in the calculation at `rewards/lib.rs:2446-2478`:
```rust
let cashback_pct   = repflow_tier.cashback_percent();
// ...
let cashback = routing_reward
    .saturating_add(seeding_reward)
    .saturating_mul(cashback_pct)
    .saturating_div(100);
```

Per-tier cashback percentages:
| Tier | Cashback |
|------|----------|
| Newcomer | 2% |
| Active | 5% |
| Trusted | 7% |
| Veteran | 7% |
| Legend | 10% |
| Icon | 12% |

`total_cashback_earned` is tracked on `RewardAccount` (line 2414) and accumulated per claim (line 2724). Tests at `lib.rs:6136` (`cashback_is_included_in_total`).

---

## Summary: Emissions vs Target

| Metric | Target | Actual (DreamHost, pre-fix) | Actual (Post-fix, expected) | Gap (pre) | Gap (post) |
|--------|--------|-----------|---------------------------|-----------|------------|
| Routing reward | 1 FLOW/GB | 0.001 FLOW/GB | 1 FLOW/GB | **1000x low** | **MATCH** |
| Uptime reward | 10 FLOW/hr | 0.01 FLOW/hr (when it fires) | 10 FLOW/hr (all claims) | **1000x low + int div** | **MATCH** |
| Total daily | ~241 FLOW/day | ~0.04 FLOW/day | ~241 FLOW/day | **~6000x low** | **MATCH** |
| $FLOW minted | 0.1 FLOW on-chain | 0.1 FLOW | TBD (needs deployment) | — | — |

**Root causes (all resolved in-code as of 2026-05-26):**
1. ~~`process_claim()` uses hardcoded constants 1000x below target~~ → **FIXED**: constants bumped to 1_000_000/MB routing, 2_000_000/MB seeding, 10_000_000_000/hr uptime. PDA now read when supplied (`lib.rs:2602-2626`).
2. ~~Integer division `uptime_seconds / 3600` zeroes out ~50% of uptime rewards~~ → **FIXED**: multiply-then-divide `(uptime_seconds × uptime_per_hour) / 3600` preserves sub-hour precision (`lib.rs:2456-2458`).
3. ~~On-chain PDA rates never applied to actual reward calculations~~ → **FIXED**: `calculate_reward()` now takes rate params from PDA.
4. ~~No operational path to fix constants or PDA rates~~ → **PARTIALLY FIXED**: on-chain `UpdateRewardRates` exists (disc=17). Foundation endpoint still missing (F1 in FOUNDATION-GAPS.md).
5. ~~No $FLOW daily mint cap~~ → **STILL OPEN**: only the 100M total supply cap exists. Not practically concerning at current scale (~208K days to exhaust remaining supply).

**Remaining action items:**
- [ ] Deploy corrected programs to devnet/mainnet (constants + PDA wiring are in-code but not yet on-chain)
- [ ] Initialize `RewardRatesAccount` PDA with correct rates (including non-zero `flow_price_cents` — E3)
- [ ] Add Foundation endpoint for `UpdateRewardRates` (F1 in FOUNDATION-GAPS.md)
- [ ] Verify post-fix emissions match target via relay monitoring
