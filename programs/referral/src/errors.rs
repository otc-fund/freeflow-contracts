//! Custom error types for the referral program.

use solana_program::program_error::ProgramError;

#[derive(Debug, PartialEq, Eq)]
pub enum ReferralError {
    ConfigAlreadyInitialized,       // 0
    InvalidAuthority,               // 1
    CodeAlreadyClaimed,             // 2
    CodeNotClaimed,                 // 3
    InvalidReferralCode,            // 4
    RewardBpsTooHigh,               // 5
    NoRewardsToClaim,               // 6
    InsufficientPoolFunds,          // 7
    InvalidPurchaseProof,           // 8
    SequenceMismatch,               // 9
    InvalidMaxReward,               // 10
    Overflow,                       // 11
    PurchaseBelowMinimum,           // 12
    InvalidRewardAmount,            // 13 — M-5: transferred_reward != calculated reward
    InvalidPoolVault,               // 14 — H-1: pool_vault doesn't match config.rewards_pool_vault
    InvalidReferralConfigOwner,     // 15 — C-2: referral_config not owned by referral program
    InvalidReferralConfigSize,      // 16 — C-2: referral_config data too small
    InvalidReferralConfigAuthority, // 17 — C-2: config authority doesn't match expected
    ReviewPeriodNotExpired,         // 18 — reserved for future auto-release guard
    ClaimAlreadyExecuted,           // 19
    InvalidClaimStatus,             // 20
    ReviewDeadlinePassed,           // 21 — M-1: foundation acted after 48h window closed
}

impl From<ReferralError> for ProgramError {
    fn from(e: ReferralError) -> Self {
        ProgramError::Custom(e as u32)
    }
}
