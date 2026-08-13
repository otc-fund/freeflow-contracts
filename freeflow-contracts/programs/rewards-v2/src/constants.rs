//! Rewards-v2 program constants.
//!
//! # Governance tiers
//!
//! - **Tier A** — `RewardRatesAccount` PDA: `routing_per_mb`, `seeding_per_mb`,
//!   `uptime_per_hour`, `flow_price_cents`.  Foundation updates via on-chain tx;
//!   relays pick up changes at next epoch via sidecar `/v1/relay/rates`.
//!
//! - **Tier B** — `FoundationConfig` PDA: `trial_enabled` (live kill switch).
//!   See `SetTrialEnabled` (disc=6).
//!
//! - **Tier C** — Constants below marked `[GOVERNANCE CANDIDATE]` are hardcoded
//!   today but could move to `FoundationConfig` in a future upgrade.
//!   See `docs/FOUNDATION-GOVERNANCE.md` for the migration plan.

use solana_program::pubkey::Pubkey;

/// Classic SPL Token program (`TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA`).
///
/// $FLOW is a **classic** SPL mint, not Token-2022 — the live mint
/// `7w6YxBZmXMZfuS4PJCwDmY5hX98RrpnR7xNEV9Ugwzxc` and the foundation's token
/// account are both owned by this program. Deriving the foundation ATA with
/// the Token-2022 id instead would produce an address that does not exist.
pub const SPL_TOKEN_PROGRAM_ID: Pubkey = Pubkey::new_from_array([
    6, 221, 246, 225, 215, 101, 161, 147, 217, 203, 225, 70, 206, 235, 121, 172,
    28, 180, 133, 237, 95, 91, 55, 145, 58, 140, 245, 133, 126, 255, 0, 169,
]);

/// Associated Token Account program (`ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL`).
///
/// Used only to *derive* the expected foundation treasury address in
/// `process_claim_relay_uptime_ix`; the program is never CPI'd into.
pub const ASSOCIATED_TOKEN_PROGRAM_ID: Pubkey = Pubkey::new_from_array([
    140, 151, 37, 143, 78, 36, 137, 241, 187, 61, 16, 41, 20, 142, 13, 131,
    11, 90, 19, 153, 218, 255, 16, 132, 4, 142, 123, 216, 219, 233, 248, 89,
]);

/// Foundation wallet whose ATA receives the 30% treasury split
/// (`8SL4dhnXU9tjvsbwfkVzQbfV99wGnVZBECoiuwrdbaJk`).
///
/// Used by `require_foundation_treasury` to pin `reward_treasury` at the three
/// mint sinks that do NOT carry `foundation_config` in their account lists:
/// `ReleaseClaim`, `ClaimPendingRewards`, and `ReleaseTrialClaim`. Hardcoding
/// keeps those pins free of a wire change (SECURITY-FIXES-PLAN.md §H-1, D3).
///
/// **This is a SECOND source of truth.** `process_claim_relay_uptime_ix`
/// derives the same wallet from `foundation_config.wallet` instead, precisely
/// so a rotation needs no program upgrade. If the foundation wallet is ever
/// rotated and this constant is not updated in the same release, uptime pays
/// the new treasury and every release pays the old one — silently.
///
/// That divergence is not left to vigilance: `ReleaseTrialClaim` is the one
/// handler holding both, and it asserts they are equal
/// (`RewardsError::InvalidTreasuryAccount`). A rotation therefore fails loudly
/// on the next trial release instead of quietly misrouting the 30%.
///
/// The permanent fix is one source of truth — either add `foundation_config`
/// to the two paid sinks (a wire change at both) or land the treasury set
/// (`docs/superpowers/plans/2026-07-31-treasury-set.md`).
pub const FOUNDATION_PUBKEY: Pubkey = Pubkey::new_from_array([
    110, 126, 226, 5, 207, 4, 113, 108, 159, 133, 215, 194, 173, 220, 77, 27,
    22, 144, 172, 176, 41, 96, 65, 31, 110, 88, 150, 233, 171, 99, 37, 89,
]);

/// repFlow-token program (`8K4GhPEQ1yy9vdTaMPTL83G5qr5ZHZiBm2VBQ58jJs5w`).
///
/// The authentic deployed repflow-token program — matches `Anchor.toml` and the
/// program's own `declare_id!`. Used to bind `relay_repflow_user` in the repFlow
/// gate and the dispute slash: the account's owner must be this program and its
/// address must be the canonical `[b"repflow_user", wallet]` PDA.
///
/// MUST be this hardcoded constant — never a caller-supplied program account —
/// or the PDA derivation could be redirected to an attacker-controlled program.
pub const REPFLOW_PROGRAM_ID: Pubkey =
    solana_program::pubkey!("8K4GhPEQ1yy9vdTaMPTL83G5qr5ZHZiBm2VBQ58jJs5w");

/// Seconds per epoch (12 hours).
pub const EPOCH_SECS: u64 = 43_200;

/// Dispute window duration (7 days).
pub const DISPUTE_WINDOW_SECS: i64 = 7 * 24 * 3600;

/// Minimum relay repFlow balance required to mint $FLOW rewards.
///
/// [GOVERNANCE CANDIDATE — Tier C] Move to `FoundationConfig.min_relay_repflow`.
pub const MIN_RELAY_REPFLOW: u64 = 2_001;

/// Tiered slashing amounts (repFlow burned per offense).
///
/// [GOVERNANCE CANDIDATE — Tier C] Move to `FoundationConfig.slash_first_offense`
/// and `FoundationConfig.slash_second_offense`.
/// Third+ offense is always 100% of relay's repFlow balance (not configurable).
pub const SLASH_FIRST_OFFENSE:  u64 = 500;
pub const SLASH_SECOND_OFFENSE: u64 = 1_000;

/// $FLOW reward rate: 1 $FLOW per GB (1_073_741_824 bytes).
/// Used for repFlow bandwidth minting — NOT for the $FLOW mint amount.
pub const BYTES_PER_FLOW: u64 = 1_073_741_824;

/// $FLOW mint decimal places.
///
/// $FLOW uses 9 decimal places (same as SOL/lamports).
/// 1 $FLOW = 1_000_000_000 base units.
/// All on-chain mint_to amounts are in base units.
pub const FLOW_DECIMALS: u32 = 9;

/// Base units per $FLOW (10^FLOW_DECIMALS = 10^9).
///
/// Analogous to LAMPORTS_PER_SOL.  All on-chain mint amounts use this unit.
pub const BASE_UNITS_PER_FLOW: u64 = 1_000_000_000;

/// Decimal megabyte divisor for routing-rate math (1 MB = 1_000_000 bytes).
/// 1 GB = 1000 MB ⇒ routing_per_mb=1_000_000 base units ⇒ 1 $FLOW/GB. (Spec OI-5/Option A.)
pub const MB_DIVISOR: u64 = 1_000_000;

/// RewardRatesAccount defaults (base units).
pub const DEFAULT_ROUTING_PER_MB:  u64 = 1_000_000;       // 1 $FLOW/GB
pub const DEFAULT_SEEDING_PER_MB:  u64 = 2_000_000;       // 2 $FLOW/GB
pub const DEFAULT_UPTIME_PER_HOUR: u64 = 10_000_000_000;  // 10 $FLOW/hr

/// 70% split to relay, 30% to foundation.
pub const RELAY_SPLIT_PCT:      u64 = 70;
pub const FOUNDATION_SPLIT_PCT: u64 = 30;

/// Free trial cap per user: 10 GB in bytes.
pub const FREE_TRIAL_BYTES: u64 = 10_737_418_240;

/// Free trial duration: 30 days.
pub const FREE_TRIAL_DURATION_SECS: u64 = 2_592_000;

/// Max trial $FLOW minted per relay per epoch.
///
/// = 100 $FLOW × BASE_UNITS_PER_FLOW = 100_000_000_000 base units.
/// Prevents a relay from fabricating unlimited trial claims in a single epoch.
///
/// Basis: a relay routing the full 10 GB trial bandwidth earns ≈ 40 $FLOW
/// (at $0.025/FLOW rate).  The 100 $FLOW cap allows 2.5× headroom.
pub const MAX_TRIAL_MINT_PER_RELAY_PER_EPOCH: u64 = 100 * BASE_UNITS_PER_FLOW; // 100 $FLOW

/// Absolute per-epoch ceiling on claimable uptime, in hours.
///
/// Twice the 12h FixedUtc cycle, so a relay that misses one cycle can still
/// claim what it earned. Required *alongside* the elapsed-time clamp: elapsed
/// alone bounds time passed, not time served, so a relay offline for 30 days
/// would otherwise claim 720 hours it never served.
pub const MAX_UPTIME_HOURS_PER_EPOCH: u64 = 24;

/// The reward_rates PDA is mandatory on CommitClaim.
///
/// Was false during rollout, which made the rate ceiling optional: a relay
/// sending a 3-account CommitClaim skipped enforcement entirely and
/// total_amount was unbounded. All relays pass the account, so this is safe.
pub const REWARD_RATES_REQUIRED: bool = true;
