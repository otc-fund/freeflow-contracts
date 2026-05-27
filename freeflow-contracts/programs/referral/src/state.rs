//! On-chain PDA account structs for the referral program.
//!
//! All structs use raw Borsh (no Anchor discriminator), following the staking
//! program pattern. SIZE = borsh-serialized byte count; account allocation =
//! exactly SIZE bytes (see system_instruction::create_account calls).

use borsh::{BorshDeserialize, BorshSerialize};

// ─── ReferralConfig ───────────────────────────────────────────────────────────

/// Singleton program configuration PDA.
///
/// PDA seeds: [b"referral_config"]
///
/// Stores reward basis points, per-claim cap, minimum purchase threshold,
/// the foundation authority key, and the SPL token vault that receives
/// auto-funded referral cuts.
#[derive(BorshSerialize, BorshDeserialize, Debug, Clone)]
pub struct ReferralConfig {
    /// Reward rate in basis points (100 bps = 1%). Max 3000 (30%).
    pub reward_bps:            u16,
    /// Maximum reward per referral in $FLOW lamports (9 decimals).
    pub max_reward_lamports:   u64,
    /// Minimum purchase amount to qualify for a referral reward.
    pub min_purchase_lamports: u64,
    /// Foundation authority — only this key can call UpdateReferralConfig.
    pub authority:             [u8; 32],
    /// SPL token vault pubkey that receives the referral cut on each purchase.
    pub rewards_pool_vault:    [u8; 32],
    pub bump:                  u8,
    pub _padding:              [u8; 3],
}

impl ReferralConfig {
    /// Borsh-serialized struct size (no discriminant prefix).
    /// 2 + 8 + 8 + 32 + 32 + 1 + 3 = 86
    pub const SIZE: usize = 2 + 8 + 8 + 32 + 32 + 1 + 3; // = 86
}

// ─── ReferralCode ─────────────────────────────────────────────────────────────

/// Per-code PDA, one per referral code string.
///
/// PDA seeds: [b"referral_code", code_hash]
///
/// Created and claimed simultaneously by the referrer via RegisterReferralCode.
/// Ownership is first-come, first-served.
#[derive(BorshSerialize, BorshDeserialize, Debug, Clone)]
pub struct ReferralCode {
    /// SHA-256 of the uppercased code string (case-insensitive matching).
    pub code_hash:  [u8; 32],
    /// Referrer's public key (who registered/claimed this code).
    pub referrer:   [u8; 32],
    /// Unix timestamp when the code was registered.
    pub created_at: i64,
    /// Whether this code has been claimed by a referrer.
    pub is_claimed: bool,
    pub bump:       u8,
    pub _padding:   [u8; 6],
}

impl ReferralCode {
    /// Borsh-serialized struct size.
    /// 32 + 32 + 8 + 1 + 1 + 6 = 80
    pub const SIZE: usize = 32 + 32 + 8 + 1 + 1 + 6; // = 80
}

// ─── ReferralRecord ───────────────────────────────────────────────────────────

/// Per-purchase referral record PDA.
///
/// PDA seeds: [b"referral_record", referrer_pubkey, client_pubkey, sequence_le_bytes]
///
/// Created by RecordReferral after each qualifying purchase.
/// The sequence number comes from ReferrerBalance.next_sequence (monotonically
/// increasing per referrer), ensuring each purchase gets a unique PDA.
#[derive(BorshSerialize, BorshDeserialize, Debug, Clone)]
pub struct ReferralRecord {
    pub referrer:        [u8; 32],
    pub client:          [u8; 32],
    pub purchase_amount: u64,
    pub reward_lamports: u64,
    pub code_hash:       [u8; 32],
    pub timestamp:       i64,
    pub sequence:        u32,
    pub bump:            u8,
    pub _padding:        [u8; 3],
}

impl ReferralRecord {
    /// Borsh-serialized struct size.
    /// 32 + 32 + 8 + 8 + 32 + 8 + 4 + 1 + 3 = 128
    pub const SIZE: usize = 32 + 32 + 8 + 8 + 32 + 8 + 4 + 1 + 3; // = 128
}

// ─── ReferrerBalance ─────────────────────────────────────────────────────────

/// Per-referrer cumulative balance PDA.
///
/// PDA seeds: [b"referrer_balance", referrer_pubkey]
///
/// Tracks total rewards earned and claimed. next_sequence is the nonce used
/// for deriving each unique ReferralRecord PDA. Created on first RecordReferral
/// for a given referrer.
///
/// Invariant: total_earned >= total_claimed (enforced by ClaimReferralReward).
#[derive(BorshSerialize, BorshDeserialize, Debug, Clone)]
pub struct ReferrerBalance {
    pub referrer:       [u8; 32],
    pub total_earned:   u64,
    pub total_claimed:  u64,
    pub referral_count: u32,
    pub next_sequence:  u32,
    pub bump:           u8,
    pub _padding:       [u8; 7],
}

impl ReferrerBalance {
    /// Borsh-serialized struct size.
    /// 32 + 8 + 8 + 4 + 4 + 1 + 7 = 64
    pub const SIZE: usize = 32 + 8 + 8 + 4 + 4 + 1 + 7; // = 64
}

// ─── RewardsPool ─────────────────────────────────────────────────────────────

/// Pool accounting PDA — tracks total auto-funded deposits and lifetime claims.
///
/// PDA seeds: [b"rewards_pool"]
///
/// The actual $FLOW is stored in a separate SPL token vault account
/// (ReferralConfig.rewards_pool_vault). This PDA only tracks accounting
/// totals for observability.
#[derive(BorshSerialize, BorshDeserialize, Debug, Clone)]
pub struct RewardsPool {
    /// PDA bump for the vault token account (optional — 0 if not used).
    pub vault_bump:       u8,
    /// Lifetime $FLOW deposited (auto-funded cuts + DepositRewardsPool calls).
    pub total_deposited:  u64,
    /// Lifetime $FLOW distributed via ClaimReferralReward.
    pub total_distributed: u64,
    pub bump:             u8,
    pub _padding:         [u8; 6],
}

impl RewardsPool {
    /// Borsh-serialized struct size.
    /// 1 + 8 + 8 + 1 + 6 = 24
    pub const SIZE: usize = 1 + 8 + 8 + 1 + 6; // = 24
}
