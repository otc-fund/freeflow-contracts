//! On-chain account state for the repFlow token program.

use anchor_lang::prelude::*;

/// Global program configuration — controls minters, burners and emergency pause.
///
/// PDA seeds: [b"repflow_config"]
#[account]
#[derive(Debug)]
pub struct RepFlowConfig {
    /// Admin authority (can update minters/burners and toggle pause).
    pub admin:          Pubkey,
    /// List of authorised minter public keys (up to 9 for 5-of-9 multisig).
    pub minters:        [Pubkey; 9],
    /// Number of active minters.
    pub minter_count:   u8,
    /// List of authorised burner public keys (up to 9).
    pub burners:        [Pubkey; 9],
    /// Number of active burners.
    pub burner_count:   u8,
    /// Emergency pause flag — when true, all mint/burn operations are suspended.
    pub paused:         bool,
    /// Total repFlow minted across all users (cumulative).
    pub total_minted:   u64,
    /// Total repFlow burned via slashing (cumulative).
    pub total_burned:   u64,
    /// Unix timestamp of last config update.
    pub updated_at:     i64,
    /// PDA bump seed.
    pub bump:           u8,
}

impl RepFlowConfig {
    pub const SIZE: usize = 32 + (32 * 9) + 1 + (32 * 9) + 1 + 1 + 8 + 8 + 8 + 1 + 64;

    pub fn is_minter(&self, key: &Pubkey) -> bool {
        self.minters[..self.minter_count as usize].contains(key)
    }

    pub fn is_burner(&self, key: &Pubkey) -> bool {
        self.burners[..self.burner_count as usize].contains(key)
    }
}

/// Per-user reputation account — tracks earnings, tier and slash history.
///
/// PDA seeds: [b"repflow_user", wallet_pubkey]
#[account]
#[derive(Debug)]
pub struct RepFlowUser {
    /// User's wallet public key.
    pub wallet:              Pubkey,
    /// Current repFlow balance (in base units, 1 repFlow = 1 unit).
    pub balance:             u64,
    /// Lifetime repFlow earned (never decreases).
    pub lifetime_earned:     u64,
    /// Total repFlow slashed from this account.
    pub lifetime_slashed:    u64,
    /// repFlow minted today (resets at UTC midnight). Used for rate limiting.
    pub daily_minted:        u64,
    /// Unix timestamp of the start of the current daily window.
    pub daily_window_start:  i64,
    /// Number of times this account has been slashed.
    pub slash_count:         u32,
    /// Unix timestamp of last repFlow earned.
    pub last_earned_at:      i64,
    /// Bitmap of completed one-time earning milestones.
    pub milestones_claimed:  u64,
    /// PDA bump seed.
    pub bump:                u8,
}

impl RepFlowUser {
    pub const SIZE: usize = 32 + 8 + 8 + 8 + 8 + 8 + 4 + 8 + 8 + 1 + 32;

    pub const MAX_DAILY_MINT: u64 = 100_000;
    pub const SECS_PER_DAY:   i64 = 86_400;

    /// Compute the current repFlow tier from balance.
    pub fn tier(&self) -> RepFlowTierCode {
        RepFlowTierCode::from_balance(self.balance)
    }

    /// Governance voting power (1-11 votes).
    pub fn voting_power(&self) -> u64 {
        self.tier().voting_power()
    }

    /// Reset daily mint window if it has expired.
    pub fn refresh_daily_window(&mut self, now: i64) {
        if now - self.daily_window_start >= Self::SECS_PER_DAY {
            self.daily_minted       = 0;
            self.daily_window_start = now;
        }
    }

    /// Check a milestone bit.
    pub fn has_milestone(&self, bit: u8) -> bool {
        self.milestones_claimed & (1 << bit) != 0
    }

    /// Set a milestone bit.
    pub fn set_milestone(&mut self, bit: u8) {
        self.milestones_claimed |= 1 << bit;
    }
}

/// Lightweight on-chain tier code — avoids importing the full Rust enum
/// into the Solana program (keeps the binary small).
#[derive(Debug, Clone, Copy, PartialEq, Eq, AnchorSerialize, AnchorDeserialize)]
pub enum RepFlowTierCode {
    Newcomer  = 0,
    Active    = 1,
    Trusted   = 2,
    Veteran   = 3,
    Legend    = 4,
    Icon      = 5,
}

impl RepFlowTierCode {
    pub fn from_balance(balance: u64) -> Self {
        match balance {
            0..=1_000          => Self::Newcomer,
            1_001..=5_000      => Self::Active,
            5_001..=10_000     => Self::Trusted,
            10_001..=25_000    => Self::Veteran,
            25_001..=50_000    => Self::Legend,
            _                  => Self::Icon,
        }
    }

    pub fn voting_power(self) -> u64 {
        match self {
            Self::Newcomer => 1,
            Self::Active   => 2,
            Self::Trusted  => 6,
            Self::Veteran  => 11,
            Self::Legend   => 11,
            Self::Icon     => 11,
        }
    }

    pub fn reward_multiplier_bps(self) -> u64 {
        // Basis points — 100 = 1.0x, 150 = 1.5x, 90 = 0.9x
        match self {
            Self::Newcomer => 90,
            Self::Active   => 100,
            Self::Trusted  => 110,
            Self::Veteran  => 130,
            Self::Legend   => 140,
            Self::Icon     => 150,
        }
    }
}

/// Pending slash record — stores evidence and enforces the 72-hour appeal window.
///
/// PDA seeds: [b"slash_record", wallet_pubkey, &slash_id.to_le_bytes()]
#[account]
#[derive(Debug)]
pub struct SlashRecord {
    /// Target user wallet.
    pub wallet:           Pubkey,
    /// Amount of repFlow to slash.
    pub slash_amount:     u64,
    /// Slash offense code (matches RepFlowSlashingOffense discriminant).
    pub offense_code:     u8,
    /// SHA-256 hash of off-chain evidence (stored for audit trail).
    pub evidence_hash:    [u8; 32],
    /// Unix timestamp when the slash was proposed.
    pub proposed_at:      i64,
    /// Unix timestamp when the appeal window closes (proposed_at + 72h).
    pub appeal_deadline:  i64,
    /// Whether the appeal window has been waived by the user.
    pub appeal_waived:    bool,
    /// Whether the slash has been executed.
    pub executed:         bool,
    /// Proposer's public key (for accountability).
    pub proposer:         Pubkey,
    /// PDA bump.
    pub bump:             u8,
}

impl SlashRecord {
    pub const SIZE: usize = 32 + 8 + 1 + 32 + 8 + 8 + 1 + 1 + 32 + 1 + 32;
    pub const APPEAL_WINDOW_SECS: i64 = 72 * 3600; // 72 hours
}
