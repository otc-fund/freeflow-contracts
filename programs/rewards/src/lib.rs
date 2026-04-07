//! FreeFlow Rewards Program (Solana on-chain).
//!
//! Reward formula (repFlow-based, replacing old tier multipliers):
//!   routing_reward = routing_mb × BASE_ROUTING_PER_MB × repflow_multiplier_bps / 100
//!   seeding_reward = seeding_mb × BASE_SEEDING_PER_MB × repflow_multiplier_bps / 100
//!   uptime_reward  = uptime_hrs × BASE_UPTIME_PER_HOUR
//!   cashback       = (routing + seeding) × repflow_cashback_pct / 100
//!   total          = routing + seeding + uptime + cashback
//!
//! repFlow multipliers (replaces old Professional/Lightweight/Mobile tiers):
//!   Newcomer   (0–1K repFlow):     0.9×  — small penalty for unproven nodes
//!   Active     (1K–5K):            1.0×  — baseline
//!   Trusted    (5K–10K):           1.1×
//!   Veteran    (10K–25K):          1.3×
//!   Legend     (25K–50K):          1.4×
//!   Icon       (50K+ repFlow):     1.5×  — maximum
//!
//! Instructions:
//!   0x00  ClaimRewards  — relay submits signed claim, receives $FLOW
//!   0x01  RecordBytes   — oracle posts verified byte counters on-chain

use borsh::{BorshDeserialize, BorshSerialize};
use solana_program::{
    account_info::{next_account_info, AccountInfo},
    clock::Clock,
    entrypoint,
    entrypoint::ProgramResult,
    msg,
    program_error::ProgramError,
    pubkey::Pubkey,
    sysvar::Sysvar,
};

solana_program::declare_id!("REWDxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx");

entrypoint!(process_instruction);

pub fn process_instruction(
    program_id: &Pubkey,
    accounts:   &[AccountInfo],
    input:      &[u8],
) -> ProgramResult {
    let ix = RewardsInstruction::try_from_slice(input)
        .map_err(|_| ProgramError::InvalidInstructionData)?;

    match ix {
        RewardsInstruction::ClaimRewards {
            period_start, period_end,
            bytes_routed, bytes_seeded, uptime_seconds,
            repflow_balance,
        } => process_claim(
            program_id, accounts,
            period_start, period_end,
            bytes_routed, bytes_seeded, uptime_seconds,
            repflow_balance,
        ),
        RewardsInstruction::RecordBytes { relay_pubkey, bytes_routed, bytes_seeded } => {
            process_record_bytes(program_id, accounts, relay_pubkey, bytes_routed, bytes_seeded)
        }
    }
}

// ── Instructions ─────────────────────────────────────────────────────────────

#[derive(BorshSerialize, BorshDeserialize, Debug)]
pub enum RewardsInstruction {
    ClaimRewards {
        period_start:    i64,
        period_end:      i64,
        bytes_routed:    u64,
        bytes_seeded:    u64,
        uptime_seconds:  u64,
        /// repFlow balance, oracle-attested at claim time.
        /// In production: replaced by CPI to repflow-token program.
        repflow_balance: u64,
    },
    RecordBytes {
        relay_pubkey: [u8; 32],
        bytes_routed: u64,
        bytes_seeded: u64,
    },
}

// ── repFlow tier (on-chain copy — canonical source is repflow-token program) ──

/// repFlow tier determines reward multipliers and cashback.
/// Mirrors freeflow-relay-runtime/src/repflow/tiers.rs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RepFlowTier {
    Newcomer = 0,  // 0–1,000
    Active   = 1,  // 1,001–5,000
    Trusted  = 2,  // 5,001–10,000
    Veteran  = 3,  // 10,001–25,000
    Legend   = 4,  // 25,001–50,000
    Icon     = 5,  // 50,001+
}

impl RepFlowTier {
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

    /// Reward multiplier in basis points (100 = 1.0×).
    pub fn reward_multiplier_bps(self) -> u64 {
        match self {
            Self::Newcomer => 90,
            Self::Active   => 100,
            Self::Trusted  => 110,
            Self::Veteran  => 130,
            Self::Legend   => 140,
            Self::Icon     => 150,
        }
    }

    /// Cashback percentage on routing + seeding rewards (2%–12%).
    pub fn cashback_percent(self) -> u64 {
        match self {
            Self::Newcomer => 2,
            Self::Active   => 3,
            Self::Trusted  => 5,
            Self::Veteran  => 7,
            Self::Legend   => 10,
            Self::Icon     => 12,
        }
    }
}

// ── On-chain reward account ───────────────────────────────────────────────────

#[derive(BorshSerialize, BorshDeserialize, Debug, Clone)]
pub struct RewardAccount {
    pub relay_wallet:           [u8; 32],
    pub total_lamports_claimed: u64,
    pub total_bytes_routed:     u64,
    pub total_bytes_seeded:     u64,
    pub total_uptime_seconds:   u64,
    pub last_claim_ts:          i64,
    pub claim_count:            u64,
    /// DEPRECATED — kept for backwards compat with existing accounts.
    /// Was: 0=Mobile, 1=Lightweight, 2=Professional.
    /// Going forward use repflow_tier instead.
    pub tier:                   u8,
    pub bump:                   u8,
    // ── repFlow fields (added in v2) ──────────────────────────────────────
    /// repFlow balance at the time of last claim (oracle-attested).
    pub repflow_balance:        u64,
    /// repFlow tier code at last claim (0=Newcomer … 5=Icon).
    pub repflow_tier:           u8,
    /// Lifetime cashback earned through repFlow tier bonuses.
    pub total_cashback_earned:  u64,
}

impl RewardAccount {
    pub const SIZE: usize =
        32 + 8 + 8 + 8 + 8 + 8 + 8 + 1 + 1  // original fields
        + 8 + 1 + 8;                           // repFlow fields

    const BASE_ROUTING_PER_MB:   u64 = 1_000;       // lamports per MB routed
    const BASE_SEEDING_PER_MB:   u64 = 2_000;       // lamports per MB seeded
    const BASE_UPTIME_PER_HOUR:  u64 = 10_000_000;  // lamports per hour uptime
    const MIN_CLAIM_INTERVAL:    i64 = 86_400;       // 24 hours

    /// Calculate pending reward using repFlow-based multipliers and cashback.
    ///
    /// This replaces the old Professional/Lightweight/Mobile tier system.
    pub fn calculate_reward(
        &self,
        bytes_routed:    u64,
        bytes_seeded:    u64,
        uptime_seconds:  u64,
        repflow_balance: u64,
    ) -> u64 {
        let routing_mb = bytes_routed   / (1024 * 1024);
        let seeding_mb = bytes_seeded   / (1024 * 1024);
        let uptime_hrs = uptime_seconds / 3600;

        // Derive repFlow tier from oracle-attested balance.
        let repflow_tier   = RepFlowTier::from_balance(repflow_balance);
        let multiplier_bps = repflow_tier.reward_multiplier_bps();
        let cashback_pct   = repflow_tier.cashback_percent();

        // Base amounts (before repFlow multiplier).
        let routing_base = routing_mb * Self::BASE_ROUTING_PER_MB;
        let seeding_base = seeding_mb * Self::BASE_SEEDING_PER_MB;
        let uptime_base  = uptime_hrs * Self::BASE_UPTIME_PER_HOUR;

        // Apply repFlow multiplier to routing and seeding (not uptime).
        let routing_reward = routing_base * multiplier_bps / 100;
        let seeding_reward = seeding_base * multiplier_bps / 100;

        // Cashback: percentage of post-multiplier routing + seeding.
        let cashback = (routing_reward + seeding_reward) * cashback_pct / 100;

        // Total: multiplied routing + multiplied seeding + flat uptime + cashback.
        routing_reward
            .saturating_add(seeding_reward)
            .saturating_add(uptime_base)
            .saturating_add(cashback)
    }
}

// ── Instruction processors ────────────────────────────────────────────────────

#[allow(clippy::too_many_arguments)]
fn process_claim(
    program_id:      &Pubkey,
    accounts:        &[AccountInfo],
    period_start:    i64,
    period_end:      i64,
    bytes_routed:    u64,
    bytes_seeded:    u64,
    uptime_seconds:  u64,
    repflow_balance: u64,
) -> ProgramResult {
    let accounts_iter  = &mut accounts.iter();
    let relay_wallet   = next_account_info(accounts_iter)?;
    let reward_account = next_account_info(accounts_iter)?;

    if !relay_wallet.is_signer {
        return Err(ProgramError::MissingRequiredSignature);
    }

    let clock = Clock::get()?;

    let mut state = if reward_account.data_len() >= RewardAccount::SIZE
        && reward_account.lamports() > 0
    {
        let data = reward_account.try_borrow_data()?;
        RewardAccount::try_from_slice(&data)
            .map_err(|_| ProgramError::InvalidAccountData)?
    } else {
        let repflow_tier = RepFlowTier::from_balance(repflow_balance) as u8;
        RewardAccount {
            relay_wallet:           relay_wallet.key.to_bytes(),
            total_lamports_claimed: 0,
            total_bytes_routed:     0,
            total_bytes_seeded:     0,
            total_uptime_seconds:   0,
            last_claim_ts:          0,
            claim_count:            0,
            tier:                   1, // DEPRECATED — default Lightweight for compat
            bump:                   0,
            repflow_balance,
            repflow_tier,
            total_cashback_earned:  0,
        }
    };

    // Enforce 24-hour claim interval.
    if state.last_claim_ts > 0 {
        let elapsed = clock.unix_timestamp - state.last_claim_ts;
        if elapsed < RewardAccount::MIN_CLAIM_INTERVAL {
            msg!("Claim too soon: {}s elapsed, need {}s", elapsed, RewardAccount::MIN_CLAIM_INTERVAL);
            return Err(ProgramError::InvalidInstructionData);
        }
    }

    // Calculate reward using repFlow-based multipliers.
    let reward = state.calculate_reward(bytes_routed, bytes_seeded, uptime_seconds, repflow_balance);
    if reward == 0 {
        msg!("No rewards to claim");
        return Err(ProgramError::InvalidInstructionData);
    }

    // Compute cashback component for on-chain tracking.
    let repflow_tier  = RepFlowTier::from_balance(repflow_balance);
    let cashback_pct  = repflow_tier.cashback_percent();
    let routing_mb    = bytes_routed / (1024 * 1024);
    let seeding_mb    = bytes_seeded / (1024 * 1024);
    let routing_r     = routing_mb * RewardAccount::BASE_ROUTING_PER_MB
        * repflow_tier.reward_multiplier_bps() / 100;
    let seeding_r     = seeding_mb * RewardAccount::BASE_SEEDING_PER_MB
        * repflow_tier.reward_multiplier_bps() / 100;
    let cashback      = (routing_r + seeding_r) * cashback_pct / 100;

    // Update state.
    state.total_lamports_claimed =
        state.total_lamports_claimed.saturating_add(reward);
    state.total_bytes_routed     =
        state.total_bytes_routed.saturating_add(bytes_routed);
    state.total_bytes_seeded     =
        state.total_bytes_seeded.saturating_add(bytes_seeded);
    state.total_uptime_seconds   =
        state.total_uptime_seconds.saturating_add(uptime_seconds);
    state.last_claim_ts          = clock.unix_timestamp;
    state.claim_count            = state.claim_count.saturating_add(1);
    state.repflow_balance        = repflow_balance;
    state.repflow_tier           = repflow_tier as u8;
    state.total_cashback_earned  =
        state.total_cashback_earned.saturating_add(cashback);

    let mut data = reward_account.try_borrow_mut_data()?;
    state.serialize(&mut &mut data[..])?;

    msg!(
        "Rewards claimed: {} lamports (repFlow={} tier={:?} mult={}bps cashback={}%)",
        reward, repflow_balance, repflow_tier,
        repflow_tier.reward_multiplier_bps(),
        repflow_tier.cashback_percent()
    );

    Ok(())
}

fn process_record_bytes(
    _program_id:  &Pubkey,
    accounts:     &[AccountInfo],
    relay_pubkey: [u8; 32],
    bytes_routed: u64,
    bytes_seeded: u64,
) -> ProgramResult {
    let accounts_iter = &mut accounts.iter();
    let oracle        = next_account_info(accounts_iter)?;

    if !oracle.is_signer {
        return Err(ProgramError::MissingRequiredSignature);
    }

    msg!(
        "Bytes recorded for relay {:?}: routed={} seeded={}",
        &relay_pubkey[..4], bytes_routed, bytes_seeded
    );
    Ok(())
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_account(repflow_balance: u64) -> RewardAccount {
        let repflow_tier = RepFlowTier::from_balance(repflow_balance) as u8;
        RewardAccount {
            relay_wallet:           [0u8; 32],
            total_lamports_claimed: 0,
            total_bytes_routed:     0,
            total_bytes_seeded:     0,
            total_uptime_seconds:   0,
            last_claim_ts:          0,
            claim_count:            0,
            tier:                   1, // deprecated
            bump:                   0,
            repflow_balance,
            repflow_tier,
            total_cashback_earned:  0,
        }
    }

    #[test]
    fn newcomer_gets_penalty_multiplier() {
        let tier = RepFlowTier::from_balance(500);
        assert_eq!(tier.reward_multiplier_bps(), 90,  "Newcomer: 0.9×");
        assert_eq!(tier.cashback_percent(),       2,   "Newcomer: 2% cashback");
    }

    #[test]
    fn icon_gets_max_multiplier() {
        let tier = RepFlowTier::from_balance(100_000);
        assert_eq!(tier.reward_multiplier_bps(), 150, "Icon: 1.5×");
        assert_eq!(tier.cashback_percent(),      12,  "Icon: 12% cashback");
    }

    #[test]
    fn active_tier_is_baseline() {
        let tier = RepFlowTier::from_balance(2_000);
        assert_eq!(tier.reward_multiplier_bps(), 100, "Active: 1.0× (no change)");
    }

    #[test]
    fn icon_earns_more_than_newcomer() {
        let bytes  = 100 * 1024 * 1024 * 1024_u64;
        let uptime = 3600_u64;

        let icon    = make_account(100_000);
        let newcomer = make_account(0);

        let icon_r    = icon.calculate_reward(bytes, bytes, uptime, 100_000);
        let newc_r    = newcomer.calculate_reward(bytes, bytes, uptime, 0);

        assert!(icon_r > newc_r, "Icon ({icon_r}) must earn more than Newcomer ({newc_r})");

        // Icon gets 1.5× + 12% cashback; Newcomer gets 0.9× + 2% cashback.
        let ratio = icon_r as f64 / newc_r as f64;
        assert!(ratio > 1.5, "Icon/Newcomer ratio must exceed 1.5× (got {ratio:.2}×)");
    }

    #[test]
    fn cashback_is_included_in_total() {
        let routing_mb = 1024u64;     // 1 GB
        let bytes      = routing_mb * 1024 * 1024;

        // Icon tier: 1.5× multiplier, 12% cashback
        let icon   = make_account(100_000);
        let total  = icon.calculate_reward(bytes, 0, 0, 100_000);

        let base       = routing_mb * RewardAccount::BASE_ROUTING_PER_MB;
        let multiplied = base * 150 / 100;  // 1.5×
        let cashback   = multiplied * 12 / 100;
        let expected   = multiplied + cashback;

        assert_eq!(total, expected,
            "Total ({total}) must equal multiplied ({multiplied}) + cashback ({cashback})");
    }

    #[test]
    fn uptime_reward_not_multiplied() {
        // Uptime reward is flat — not affected by repFlow multiplier.
        let uptime_hrs = 24u64;
        let uptime_s   = uptime_hrs * 3600;

        let icon    = make_account(100_000);
        let newcomer = make_account(0);

        let uptime_expected = uptime_hrs * RewardAccount::BASE_UPTIME_PER_HOUR;

        // Both accounts, zero bytes: total should equal uptime_base
        let icon_uptime    = icon.calculate_reward(0, 0, uptime_s, 100_000);
        let newc_uptime    = newcomer.calculate_reward(0, 0, uptime_s, 0);

        assert_eq!(icon_uptime, uptime_expected, "Icon uptime must not be multiplied");
        assert_eq!(newc_uptime, uptime_expected, "Newcomer uptime must not be multiplied");
    }

    #[test]
    fn rewards_calculation_with_repflow_veteran() {
        // 1 GB routed, Veteran tier (1.3× multiplier, 7% cashback)
        let routing_mb  = 1024u64;
        let bytes_routed = routing_mb * 1024 * 1024;
        let repflow_bal = 15_000; // Veteran

        let acct    = make_account(repflow_bal);
        let total   = acct.calculate_reward(bytes_routed, 0, 0, repflow_bal);

        let base     = routing_mb * RewardAccount::BASE_ROUTING_PER_MB;
        let mult     = base * 130 / 100; // 1.3×
        let cashback = mult * 7 / 100;   // 7%
        let expected = mult + cashback;

        assert_eq!(total, expected);
    }

    #[test]
    fn zero_activity_zero_reward() {
        let acct = make_account(5_000);
        assert_eq!(acct.calculate_reward(0, 0, 0, 5_000), 0);
    }

    #[test]
    fn tier_boundaries_correct() {
        let cases = [
            (0,          RepFlowTier::Newcomer),
            (1_000,      RepFlowTier::Newcomer),
            (1_001,      RepFlowTier::Active),
            (5_000,      RepFlowTier::Active),
            (5_001,      RepFlowTier::Trusted),
            (10_000,     RepFlowTier::Trusted),
            (10_001,     RepFlowTier::Veteran),
            (25_000,     RepFlowTier::Veteran),
            (25_001,     RepFlowTier::Legend),
            (50_000,     RepFlowTier::Legend),
            (50_001,     RepFlowTier::Icon),
            (u64::MAX,   RepFlowTier::Icon),
        ];
        for (bal, expected) in cases {
            assert_eq!(RepFlowTier::from_balance(bal), expected,
                "balance={bal} → expected {expected:?}");
        }
    }
}
