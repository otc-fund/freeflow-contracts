//! Rewards-v2 program constants.

/// Seconds per epoch (12 hours).
pub const EPOCH_SECS: u64 = 43_200;

/// Dispute window duration (7 days).
pub const DISPUTE_WINDOW_SECS: i64 = 7 * 24 * 3600;

/// Minimum relay repFlow balance required to mint $FLOW rewards.
pub const MIN_RELAY_REPFLOW: u64 = 2_001;

/// Tiered slashing amounts (repFlow burned per offense).
pub const SLASH_FIRST_OFFENSE:  u64 = 500;
pub const SLASH_SECOND_OFFENSE: u64 = 1_000;
// Third+ offense: burn 100% of relay's repFlow balance.

/// $FLOW reward rate: 1 $FLOW per GB (1_073_741_824 bytes).
pub const BYTES_PER_FLOW: u64 = 1_073_741_824;

/// 70% split to relay, 30% to foundation.
pub const RELAY_SPLIT_PCT:      u64 = 70;
pub const FOUNDATION_SPLIT_PCT: u64 = 30;

/// Free trial cap per user: 10 GB in bytes.
pub const FREE_TRIAL_BYTES: u64 = 10_737_418_240;

/// Free trial duration: 30 days.
pub const FREE_TRIAL_DURATION_SECS: u64 = 2_592_000;

/// Max trial $FLOW minted per relay per epoch (prevents unlimited fake trial abuse).
pub const MAX_TRIAL_MINT_PER_RELAY_PER_EPOCH: u64 = 100_000_000;
