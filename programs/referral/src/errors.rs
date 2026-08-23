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
    InvalidReferralConfigAuthority, // 17 — reserved: config.authority != an expected key.
                                    //      Unused in this program. `user-escrow` 6009 already
                                    //      means exactly that, so it is NOT reused for the
                                    //      address check below — same name, same audit, two
                                    //      different failures would be a trap.
    ReviewPeriodNotExpired,         // 18 — reserved for future auto-release guard
    ClaimAlreadyExecuted,           // 19
    InvalidClaimStatus,             // 20
    ReviewDeadlinePassed,           // 21 — M-1: foundation acted after 48h window closed
    InvalidReferralConfigAddress,   // 22 — M-2: referral_config is not the canonical
                                    //      [b"referral_config"] PDA. Deliberately distinct
                                    //      from 15 so a test asserting the owner branch can
                                    //      never be satisfied by the address branch, or the
                                    //      other way round.
    InvalidReferrerAta,             // 23 — Task 4: the ApproveClaim payout destination is not
                                    //      the canonical ATA of `claim_request.referrer`.
                                    //      Its own code, not `InvalidAuthority` (1): that one
                                    //      already means "the signer is not the foundation",
                                    //      and a shared code makes the test unable to say
                                    //      which check rejected the transaction.
}

impl From<ReferralError> for ProgramError {
    fn from(e: ReferralError) -> Self {
        ProgramError::Custom(e as u32)
    }
}
