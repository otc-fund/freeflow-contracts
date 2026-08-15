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
    /// The repFlow SPL Token-2022 mint address. Set once at initialisation.
    pub mint:           Pubkey,
    /// List of authorised minter public keys (up to 5 for 3-of-5 multisig).
    pub minters:        [Pubkey; 5],
    /// Number of active minters.
    pub minter_count:   u8,
    /// List of authorised burner public keys (up to 5 for 3-of-5 multisig).
    pub burners:        [Pubkey; 5],
    /// Number of active burners.
    pub burner_count:   u8,
    /// Emergency pause flag — when true, all mint/burn operations are suspended.
    pub paused:         bool,
    /// Unix timestamp of last config update.
    pub updated_at:     i64,
    /// PDA bump seed.
    pub bump:           u8,
}

impl RepFlowConfig {
    // admin(32) + mint(32) + minters(32*5) + minter_count(1) + burners(32*5) + burner_count(1)
    // + paused(1) + updated_at(8) + bump(1) + padding(56)
    // PDA-only: global counters (total_minted/total_burned/max_supply) removed —
    // per-user earns must not contend on this shared config account.
    pub const SIZE: usize = 32 + 32 + (32 * 5) + 1 + (32 * 5) + 1 + 1 + 8 + 1 + 56;

    pub fn is_minter(&self, key: &Pubkey) -> bool {
        self.minters[..self.minter_count as usize].contains(key)
    }

    pub fn is_burner(&self, key: &Pubkey) -> bool {
        self.burners[..self.burner_count as usize].contains(key)
    }
}

/// Earning activity codes for repFlow minting.
///
/// Used by `mint_repflow`, `mint_repflow_from_rewards`, and `claim_daily_uptime_repflow`
/// to identify the source of earned repFlow in events and sub-limit enforcement.
#[derive(Debug, Clone, Copy, PartialEq, Eq, AnchorSerialize, AnchorDeserialize)]
pub enum RepFlowEarningActivity {
    /// Relay uptime contribution. Max 50 repFlow/day sub-limit.
    Uptime     = 1,
    /// Bandwidth routed: 1 repFlow per GB. Counts toward 200/day total cap.
    Bandwidth  = 2,
    /// 1 repFlow per 1 $FLOW escrowed (client path — separate from relay earning).
    Escrow     = 3,
    /// Governance discretionary award (community contribution).
    Community  = 4,
    /// Code contribution reward.
    Code       = 5,
    /// Challenger won a dispute (earns repFlow for policing the network).
    DisputeWin = 6,
}

impl RepFlowEarningActivity {
    /// Parse an activity code byte into the enum.  Returns `None` for unknown codes.
    pub fn try_from_code(code: u8) -> Option<Self> {
        match code {
            1 => Some(Self::Uptime),
            2 => Some(Self::Bandwidth),
            3 => Some(Self::Escrow),
            4 => Some(Self::Community),
            5 => Some(Self::Code),
            6 => Some(Self::DisputeWin),
            _ => None,
        }
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
    /// Uptime repFlow minted today (sub-limit tracker).
    ///
    /// Resets with `daily_minted` when the daily window rolls over.
    /// Enforces the 50/day uptime sub-limit — `uptime_daily_minted` ≤ 50 per window.
    ///
    /// **Backward compat:** field is appended after `bump`. Existing accounts (initialized
    /// before this field was added) have zero bytes at this position in the PDA, so
    /// Borsh deserializes the value as 0, which is the correct default.
    pub uptime_daily_minted: u64,
}

impl RepFlowUser {
    // wallet(32) + balance(8) + lifetime_earned(8) + lifetime_slashed(8)
    // + daily_minted(8) + daily_window_start(8) + slash_count(4) + last_earned_at(8)
    // + milestones_claimed(8) + bump(1) + uptime_daily_minted(8) + padding(24)
    // = 125 bytes (unchanged — absorbed 8 bytes from the 32-byte trailing padding)
    pub const SIZE: usize = 32 + 8 + 8 + 8 + 8 + 8 + 4 + 8 + 8 + 1 + 8 + 24;

    /// On-chain hard cap: 200 repFlow per user per 24-hour window.
    pub const MAX_DAILY_MINT: u64  = 200;
    /// Uptime sub-limit: at most 50 of the 200 daily cap can come from uptime.
    pub const MAX_DAILY_UPTIME: u64 = 50;
    pub const SECS_PER_DAY:    i64 = 86_400;

    /// Compute the current repFlow tier from balance.
    pub fn tier(&self) -> RepFlowTierCode {
        RepFlowTierCode::from_balance(self.balance)
    }

    /// Governance voting power (1-11 votes).
    pub fn voting_power(&self) -> u64 {
        self.tier().voting_power()
    }

    /// Reset daily mint window when the UTC date bucket rolls over.
    ///
    /// Also resets `uptime_daily_minted` so the 50/day uptime sub-limit renews each window.
    ///
    /// The window is a **fixed UTC day bucket** (`now / 86_400`), not an elapsed-time
    /// check against the previous mint. An elapsed check re-anchors `daily_window_start`
    /// to the mint timestamp, so a caller minting on a 24h period can never accumulate
    /// the full 86_400s: transaction latency and `Clock` drift make the on-chain delta
    /// land just short, the window never rolls, and every subsequent uptime claim fails
    /// with `UptimeDailyCapExceeded`. Bucketing is immune to both, and matches the
    /// `date_bucket` convention already used by `submit_proof_of_service`.
    ///
    /// `daily_window_start` keeps its timestamp representation (no layout change).
    /// Accounts written under the old elapsed scheme roll over on their next call,
    /// since a stale timestamp always falls in an earlier bucket.
    pub fn refresh_daily_window(&mut self, now: i64) {
        if now / Self::SECS_PER_DAY != self.daily_window_start / Self::SECS_PER_DAY {
            self.daily_minted        = 0;
            self.uptime_daily_minted = 0;
            self.daily_window_start  = now;
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

/// Proof-of-Service attestation — submitted by relay sidecar, consumed by uptime claim.
///
/// Proves a relay served real client traffic in a given day. Tied to a daily bucket
/// so replay across days is impossible and a consumed attestation cannot be reused.
///
/// PDA seeds: [b"proof_of_service", relay_pubkey, &date_bucket.to_le_bytes()]
/// where date_bucket = Clock::get()?.unix_timestamp / 86_400
#[account]
#[derive(Debug)]
pub struct ProofOfService {
    /// Relay wallet pubkey that submitted this attestation.
    pub relay_pubkey:  [u8; 32],
    /// Number of unique client sessions served in the period.
    pub client_count:  u32,
    /// Total bytes routed to clients in the period.
    pub bytes_routed:  u64,
    /// Unix timestamp of measurement period start.
    pub period_start:  i64,
    /// Unix timestamp of measurement period end.
    pub period_end:    i64,
    /// Unix timestamp when this attestation was submitted on-chain.
    pub submitted_at:  i64,
    /// True if this attestation has been consumed by a repFlow uptime claim.
    /// A consumed PDA cannot be overwritten (VULN-2).
    pub consumed:      bool,
    /// PDA bump seed.
    pub bump:          u8,
}

impl ProofOfService {
    // relay_pubkey(32) + client_count(4) + bytes_routed(8) + period_start(8)
    // + period_end(8) + submitted_at(8) + consumed(1) + bump(1) = 70 bytes
    pub const SIZE: usize = 32 + 4 + 8 + 8 + 8 + 8 + 1 + 1;

    // Byte offsets within the Anchor account data (after 8-byte discriminator).
    pub const OFFSET_RELAY_PUBKEY:  usize = 8;        // [8..40]
    pub const OFFSET_CLIENT_COUNT:  usize = 8 + 32;   // [40..44]
    pub const OFFSET_BYTES_ROUTED:  usize = 8 + 36;   // [44..52]
    pub const OFFSET_SUBMITTED_AT:  usize = 8 + 60;   // [68..76]
    pub const OFFSET_CONSUMED:      usize = 8 + 68;   // [76]

    pub const TOTAL_SIZE: usize = 8 + Self::SIZE; // discriminator + fields
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

/// Client reputation — separate from RepFlowUser (clients track different signals).
/// PDA: ["client_rep", wallet]
#[account]
#[derive(Debug)]
pub struct ClientRep {
    pub wallet:             Pubkey,   // 32
    pub balance:            u64,      // 8  — earned client repFlow
    pub lifetime_earned:    u64,      // 8
    pub lifetime_slashed:   u64,      // 8
    pub disputes_won:       u32,      // 4
    pub disputes_lost:      u32,      // 4
    pub last_active_at:     i64,      // 8
    pub daily_minted:       u64,      // 8  — per-user rate limit (no global counter)
    pub daily_window_start: i64,      // 8
    pub bump:               u8,       // 1
    pub _reserved:          [u8; 64], // 64 — headroom, avoid future realloc
}

impl ClientRep {
    // 32+8+8+8+4+4+8+8+8+1+64 = 153
    pub const SIZE: usize = 153;
    pub const MAX_DAILY_MINT: u64 = 200;

    /// Reset the daily-minted counter when the UTC date bucket rolls over.
    ///
    /// Uses the same fixed-bucket scheme as [`RepFlowUser::refresh_daily_window`] —
    /// see there for why an elapsed-time check starves callers on a 24h period.
    pub fn refresh_daily_window(&mut self, now: i64) {
        if now / RepFlowUser::SECS_PER_DAY != self.daily_window_start / RepFlowUser::SECS_PER_DAY {
            self.daily_minted = 0;
            self.daily_window_start = now;
        }
    }

    /// Tier derived from balance — reuses the relay tier curve for now.
    /// A client-specific curve can replace this when client repFlow is built.
    pub fn tier(&self) -> RepFlowTierCode {
        RepFlowTierCode::from_balance(self.balance)
    }
}

#[cfg(test)]
mod daily_window_tests {
    use super::*;

    fn user(window_start: i64, uptime_minted: u64) -> RepFlowUser {
        RepFlowUser {
            wallet:              Pubkey::default(),
            balance:             0,
            lifetime_earned:     0,
            lifetime_slashed:    0,
            daily_minted:        uptime_minted,
            daily_window_start:  window_start,
            slash_count:         0,
            last_earned_at:      0,
            milestones_claimed:  0,
            bump:                0,
            uptime_daily_minted: uptime_minted,
        }
    }

    /// Regression: a relay claiming on a 24h period lands a few seconds *short*
    /// of 86_400 on-chain (tx latency + Clock drift). The old elapsed-time check
    /// refused to roll the window, leaving uptime_daily_minted pinned at 50 so
    /// every subsequent claim failed with UptimeDailyCapExceeded.
    #[test]
    fn rolls_over_when_next_day_arrives_slightly_under_86400s() {
        // 86_400 = midnight UTC. Mint at 00:00:10, next attempt 86_395s later
        // (00:00:05 the following day) - 5s short of a full day elapsed.
        let first  = 86_400 + 10;
        let second = first + 86_395;
        assert!(second - first < 86_400, "precondition: under a full day elapsed");

        let mut u = user(first, 50);
        u.refresh_daily_window(second);

        assert_eq!(u.uptime_daily_minted, 0, "uptime sub-limit must renew on the new UTC day");
        assert_eq!(u.daily_minted, 0, "daily cap must renew on the new UTC day");
        assert_eq!(u.daily_window_start, second);
    }

    /// The cap must still hold within a single UTC day, even after >23h elapsed.
    #[test]
    fn does_not_roll_over_within_the_same_utc_day() {
        let first  = 86_400;           // 00:00:00
        let second = first + 86_399;   // 23:59:59 same day
        let mut u = user(first, 50);
        u.refresh_daily_window(second);

        assert_eq!(u.uptime_daily_minted, 50, "same UTC day - cap must not renew");
        assert_eq!(u.daily_window_start, first, "anchor must not move within a day");
    }

    /// Accounts written under the old elapsed scheme carry a stale timestamp;
    /// it always falls in an earlier bucket, so they roll over on first touch.
    #[test]
    fn legacy_account_with_stale_anchor_rolls_over() {
        let mut u = user(1_700_000_000, 50);
        u.refresh_daily_window(1_700_000_000 + 10 * 86_400);
        assert_eq!(u.uptime_daily_minted, 0);
    }

    /// ClientRep shares the bucket scheme.
    #[test]
    fn client_rep_rolls_over_on_new_utc_day() {
        let mut c = ClientRep {
            wallet: Pubkey::default(), balance: 0, lifetime_earned: 0,
            lifetime_slashed: 0, disputes_won: 0, disputes_lost: 0,
            last_active_at: 0, daily_minted: 200,
            daily_window_start: 86_400 + 10, bump: 0, _reserved: [0u8; 64],
        };
        c.refresh_daily_window(86_400 + 10 + 86_395);
        assert_eq!(c.daily_minted, 0);
    }
}
