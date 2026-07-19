//! Rewards-v2 PDA and instruction data structures.
//! Full implementation in Task 2.

use borsh::{BorshDeserialize, BorshSerialize};
use solana_program::pubkey::Pubkey;

// ── ClaimCommitment PDA ─────────────────────────────────────────────────────
// Seeds: [b"claim_commitment", relay_pubkey, claim_epoch.to_le_bytes()]

#[derive(BorshSerialize, BorshDeserialize, Debug, Clone, PartialEq, Eq)]
pub struct ClaimCommitment {
    pub relay_pubkey:    [u8; 32],
    pub claim_epoch:     u64,
    pub merkle_root:     [u8; 32],
    pub client_count:    u32,
    /// Derived: total_bytes · routing_per_mb / MB_DIVISOR.
    /// The ONLY budget releases are checked against.
    pub bandwidth_amount: u64,
    /// Derived: clamped uptime_hours · uptime_per_hour.
    /// Consumed solely by ClaimRelayUptime; never drawn on by releases.
    pub uptime_amount:   u64,
    pub total_bytes:     u64,
    /// Post-clamp hours actually credited.
    pub uptime_hours:    u64,
    /// Rate pinned at commit. An epoch spans three transactions over up to
    /// seven days; re-reading the live rate would let a mid-epoch governance
    /// change desync the cumulative checks.
    pub routing_per_mb:  u64,
    pub uptime_per_hour: u64,
    pub committed_at:    i64,
    pub uptime_paid:     bool,
    pub reserved_count:  u32,
    pub released_count:  u32,
    pub released_amount: u64,
    pub released_bytes:  u64,
    pub status:          ClaimCommitmentStatus,
    pub dispute_deadline: i64,
    pub bump:            u8,
}

pub const CLAIM_COMMITMENT_SIZE: usize =
    32 + 8 + 32 + 4      // relay, epoch, root, client_count
    + 8 + 8              // bandwidth_amount, uptime_amount
    + 8 + 8              // total_bytes, uptime_hours
    + 8 + 8 + 8 + 1      // routing_per_mb, uptime_per_hour, committed_at, uptime_paid
    + 4 + 4 + 8 + 8      // reserved/released counts and totals
    + 1 + 8 + 1;         // status, dispute_deadline, bump

#[derive(BorshSerialize, BorshDeserialize, Debug, Clone, PartialEq, Eq)]
pub enum ClaimCommitmentStatus {
    Active,     // Within dispute window. Reserves allowed, releases not.
    Releasing,  // Dispute window expired. Relay is releasing individual claims.
    Complete,   // All claims released.
    Disputed,   // Under active dispute. Release paused.
}

// ── ReserveBatchEntry ───────────────────────────────────────────────────────

#[derive(BorshSerialize, BorshDeserialize, Debug, Clone)]
pub struct ReserveBatchEntry {
    pub client_pubkey:    [u8; 32],
    pub highest_seq:      u64,
    pub amount:           u64,
    pub bytes:            u64,
    pub merkle_leaf_hash: [u8; 32],
    pub session_id:       [u8; 16],
    pub record_count:     u32,
}

// ── ClientReleaseOnChain ────────────────────────────────────────────────────

#[derive(BorshSerialize, BorshDeserialize, Debug, Clone)]
pub struct ClientReleaseOnChain {
    pub client_pubkey:    [u8; 32],
    pub session_id:       [u8; 16],
    pub batch_nonce:      u64,
    pub total_amount:     u64,
    pub total_bytes:      u64,
    pub merkle_proof:     Vec<[u8; 32]>,
    pub client_signature: [u8; 64],
    pub device_uuid:      [u8; 16],
    pub record_count:     u32,
}

// ── RelayReputation PDA ─────────────────────────────────────────────────────
// Seeds: [b"relay_reputation", relay_pubkey]

#[derive(BorshSerialize, BorshDeserialize, Debug, Clone, PartialEq, Eq)]
pub struct RelayReputation {
    pub relay:            [u8; 32],
    pub slash_count:      u32,
    pub lifetime_slashed: u64,
    pub bump:             u8,
}

pub const RELAY_REPUTATION_SIZE: usize = 32 + 4 + 8 + 1;

// ── ClaimableBalance PDA ────────────────────────────────────────────────────
// Seeds: [b"claimable_balance", relay_pubkey, claim_epoch.to_le_bytes()]

#[derive(BorshSerialize, BorshDeserialize, Debug, Clone, PartialEq, Eq)]
pub struct ClaimableBalance {
    pub relay:              [u8; 32],
    pub claim_epoch:        u64,
    pub pending_relay_flow: u64,
    pub pending_treasury:   u64,
    pub pending_repflow:    u64,
    pub status:             ClaimableBalanceStatus,
    pub bump:               u8,
}

pub const CLAIMABLE_BALANCE_SIZE: usize = 32 + 8 + 8 + 8 + 8 + 1 + 1;

#[derive(BorshSerialize, BorshDeserialize, Debug, Clone, PartialEq, Eq)]
pub enum ClaimableBalanceStatus {
    Pending,  // Waiting for relay to reach 2001 repFlow
    Claimed,  // Successfully claimed and minted
    Slashed,  // Relay was slashed before claiming — amounts lost
}

// ── UserRelayClaimState PDA ─────────────────────────────────────────────────
// Seeds: [b"claim_state", user_pubkey, relay_pubkey]

#[derive(BorshSerialize, BorshDeserialize, Debug, Clone)]
pub struct UserRelayClaimState {
    pub user:                [u8; 32],
    pub relay:               [u8; 32],
    pub last_claimed_seq:    u64,
    pub total_claimed_bytes: u64,
    pub last_claim_slot:     u64,
    pub last_release_epoch:  u64,
    pub bump:                u8,
}

pub const USER_RELAY_CLAIM_STATE_SIZE: usize = 32 + 32 + 8 + 8 + 8 + 8 + 1;

// ── FoundationConfig PDA ────────────────────────────────────────────────────
// Seeds: [b"foundation_config"]

#[derive(BorshSerialize, BorshDeserialize, Debug, Clone, PartialEq, Eq)]
pub struct FoundationConfig {
    pub foundation_wallet: [u8; 32],
    pub trial_enabled:     bool,
    /// Kill switch for relay uptime rewards.
    ///
    /// Separate from the rate because zero is unrepresentable in the rate
    /// encoding: UpdateRewardRates treats uptime_per_hour == 0 as "keep
    /// existing", so zeroing the rate silently no-ops.
    pub uptime_enabled:    bool,
    pub bump:              u8,
}

pub const FOUNDATION_CONFIG_SIZE: usize = 32 + 1 + 1 + 1;

// ── RewardRatesAccount PDA ──────────────────────────────────────────────────
// Seeds: [b"reward_rates"]. Foundation-governed; authority == FoundationConfig.foundation_wallet.

#[derive(BorshSerialize, BorshDeserialize, Debug, Clone, PartialEq, Eq)]
pub struct RewardRatesAccount {
    pub authority:        [u8; 32],
    pub routing_per_mb:   u64,
    pub seeding_per_mb:   u64,
    pub uptime_per_hour:  u64,
    pub flow_price_cents: u64,
    pub last_updated:     i64,
    pub change_count:     u64,
    pub bump:             u8,
}

pub const REWARD_RATES_SIZE: usize = 32 + 8 + 8 + 8 + 8 + 8 + 8 + 1; // = 81
const _: () = assert!(REWARD_RATES_SIZE == 81);

// ── TrialMintCap PDA ────────────────────────────────────────────────────────
// Seeds: [b"trial_mint_cap", relay_pubkey, epoch_le]
// Per-relay-per-epoch cap: a fresh PDA each epoch so the minted_so_far counter
// resets every epoch. Seed must match the off-chain clients' derivation.

#[derive(BorshSerialize, BorshDeserialize, Debug, Clone, PartialEq, Eq)]
pub struct TrialMintCap {
    pub relay:          [u8; 32],
    pub epoch:          u64,
    pub minted_so_far:  u64,
    pub bump:           u8,
}

pub const TRIAL_MINT_CAP_SIZE: usize = 32 + 8 + 8 + 1;

// ── TrialUsage PDA ──────────────────────────────────────────────────────────
// Seeds: [b"trial_usage", user_pubkey]

#[derive(BorshSerialize, BorshDeserialize, Debug, Clone)]
pub struct TrialUsage {
    pub user_pubkey:   [u8; 32],
    pub used_bytes:    u64,
    pub claimed_bytes: u64,
    pub device_uuid:   [u8; 16],
    pub first_seen_ts: u64,
    pub last_usage_ts: u64,
    pub expires_at:    u64,
    pub cap_bytes:     u64,
    pub bump:          u8,
}

pub const TRIAL_USAGE_SIZE: usize = 32 + 8 + 8 + 16 + 8 + 8 + 8 + 8 + 1;

// ── Reservation PDA ─────────────────────────────────────────────────────────
// Seeds: [b"reservation", user_pubkey]

#[derive(BorshSerialize, BorshDeserialize, Debug, Clone)]
pub struct Reservation {
    pub user:     [u8; 32],
    pub reserved: u64,
    pub bump:     u8,
}

pub const RESERVATION_SIZE: usize = 32 + 8 + 1;

// ── RepFlowUser (read-only mirror for balance check) ────────────────────────
// Mirrors the Anchor-serialized repflow_user account from repflow-token program.
// Only the fields we need for the repFlow balance gate check.
// Anchor accounts have an 8-byte discriminator prefix — skip when reading manually.

#[derive(BorshSerialize, BorshDeserialize, Debug, Clone)]
pub struct RepFlowUser {
    pub wallet:         Pubkey,
    pub balance:        u64,
    pub lifetime_earned: u64,
    pub daily_minted:   u64,
    pub daily_window_start: i64,
    pub last_earned_at: i64,
    pub tier_override:  u8,
    pub bump:           u8,
    pub last_slash_at:  i64,
}

// ── RelayClaimMeta PDA ──────────────────────────────────────────────────────
// Seeds: [b"relay_meta", relay_wallet].
//
// Holds the monotonic timestamp of a relay's most recent CommitClaim, used to
// clamp uptime_hours to real elapsed time.
//
// Deliberately NOT read from a caller-supplied previous commitment: a
// ClaimCommitment is seeded by (relay, epoch), so a caller could pass an
// arbitrarily old epoch and manufacture a large elapsed window. A monotonic
// per-relay record cannot be chosen by the caller.

#[derive(BorshSerialize, BorshDeserialize, Debug, Clone, PartialEq, Eq)]
pub struct RelayClaimMeta {
    pub relay:             [u8; 32],
    pub last_committed_at: i64,
    pub bump:              u8,
}

pub const RELAY_CLAIM_META_SIZE: usize = 32 + 8 + 1;

#[cfg(test)]
mod claim_commitment_tests {
    use super::*;

    fn sample() -> ClaimCommitment {
        ClaimCommitment {
            relay_pubkey:     [1u8; 32],
            claim_epoch:      42,
            merkle_root:      [2u8; 32],
            client_count:     3,
            bandwidth_amount: 5_000_000_000,
            uptime_amount:    120_000_000_000,
            total_bytes:      5_000_000_000,
            uptime_hours:     12,
            routing_per_mb:   1_000_000,
            uptime_per_hour:  10_000_000_000,
            committed_at:     1_700_000_000,
            uptime_paid:      false,
            reserved_count:   0,
            released_count:   0,
            released_amount:  0,
            released_bytes:   0,
            status:           ClaimCommitmentStatus::Active,
            dispute_deadline: 1_700_604_800,
            bump:             255,
        }
    }

    #[test]
    fn size_matches_serialised_length() {
        let bytes = borsh::to_vec(&sample()).expect("serialise");
        assert_eq!(bytes.len(), CLAIM_COMMITMENT_SIZE);
    }

    #[test]
    fn budgets_are_separate_fields() {
        // Regression: a single conflated total_amount let releases (bandwidth
        // only) draw on the uptime allowance.
        let c = sample();
        assert_ne!(c.bandwidth_amount, c.uptime_amount);
        assert_eq!(c.released_amount, 0);
    }
}

#[cfg(test)]
mod relay_claim_meta_tests {
    use super::*;

    #[test]
    fn size_matches_serialised_length() {
        let m = RelayClaimMeta { relay: [7u8; 32], last_committed_at: 1_700_000_000, bump: 254 };
        let bytes = borsh::to_vec(&m).expect("serialise");
        assert_eq!(bytes.len(), RELAY_CLAIM_META_SIZE, "SIZE must match Borsh length");
    }

    #[test]
    fn roundtrips() {
        let m = RelayClaimMeta { relay: [3u8; 32], last_committed_at: -1, bump: 1 };
        let bytes = borsh::to_vec(&m).expect("serialise");
        let back = RelayClaimMeta::try_from_slice(&bytes).expect("deserialise");
        assert_eq!(back, m);
    }
}

#[cfg(test)]
mod foundation_config_tests {
    use super::*;

    #[test]
    fn size_matches_serialised_length() {
        let fc = FoundationConfig {
            foundation_wallet: [9u8; 32],
            trial_enabled:     true,
            uptime_enabled:    true,
            bump:              255,
        };
        assert_eq!(borsh::to_vec(&fc).expect("serialise").len(), FOUNDATION_CONFIG_SIZE);
    }

    #[test]
    fn grew_by_one_byte() {
        // Existing on-chain account is 34 bytes; the realloc in
        // process_set_uptime_enabled_ix exists because of this.
        assert_eq!(FOUNDATION_CONFIG_SIZE, 35);
    }
}
