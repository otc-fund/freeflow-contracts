//! Custom error types for the referral program.

use solana_program::program_error::ProgramError;

#[derive(Debug, PartialEq, Eq)]
pub enum ReferralError {
    ConfigAlreadyInitialized, // 0
    InvalidAuthority,         // 1
    CodeAlreadyClaimed,       // 2
    CodeNotClaimed,           // 3
    InvalidReferralCode,      // 4
    RewardBpsTooHigh,         // 5
    NoRewardsToClaim,         // 6
    InsufficientPoolFunds,    // 7
    InvalidPurchaseProof,     // 8
    SequenceMismatch,         // 9
    InvalidMaxReward,         // 10
    Overflow,                 // 11
    PurchaseBelowMinimum,     // 12
}

impl From<ReferralError> for ProgramError {
    fn from(e: ReferralError) -> Self {
        ProgramError::Custom(e as u32)
    }
}
