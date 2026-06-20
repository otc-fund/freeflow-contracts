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
