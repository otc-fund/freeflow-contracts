//! Rewards-v2 error codes.

use borsh::{BorshDeserialize, BorshSerialize};
use solana_program::program_error::ProgramError;

#[derive(BorshSerialize, BorshDeserialize, Debug, Clone, PartialEq, Eq)]
#[borsh(use_discriminant = true)]
#[repr(u32)]
pub enum RewardsError {
    // Legacy codes (preserved for reference):
    Unauthorized              = 0,
    InvalidProgramId          = 1,
    InvalidAccountData        = 2,
    InsufficientFunds         = 3,
    AccountNotFound           = 4,
    InvalidInstruction        = 5,
    ArithmeticOverflow        = 6,
    InvalidMerkleRoot         = 7,
    DisputeAlreadyResolved    = 8,
    BondInsufficient          = 9,
    ClaimExpired              = 10,
    RateLimitExceeded         = 11,
    InvalidSignature          = 12,
    EscrowInsufficient        = 13,
    ReplayDetected            = 14,
    TransactionTooLarge       = 15,
    SequenceOutOfOrder        = 16,
    InvalidBatch              = 17,

    // Merkle-committed claim codes:
    MerkleProofInvalid         = 18,
    BatchSignatureInvalid      = 19,
    EpochAlreadyCommitted      = 20,
    DisputeWindowActive        = 21,
    DisputeNotFound            = 22,
    ClaimCommitmentNotFound    = 23,
    EpochComplete              = 24,
    ReserveBatchFailed         = 25,
    EpochNotCommitted          = 26,
    SeqAlreadyAdvanced         = 27,
    DisputeWindowExpired       = 28,
    RepFlowGateNotMet          = 29,
    ClaimableBalanceNotFound   = 30,
    SlashFailed                = 31,
    CpiFailed                  = 32,

    // Trial codes:
    TrialExpired               = 33,
    TrialCapExceeded           = 34,
    NoEscrowOrTrial            = 35,
    TrialUsageNotFound         = 36,
    ClientSignatureInvalid     = 37,
    TrialDisabled              = 38,
    TrialMintCapExceeded       = 39,
    AlreadyReleased            = 40,
    ReleaseExceedsCommitment   = 41,
    ReserveExceedsCommitment   = 42,
    NoClaimHistory             = 43,

    // Reward-rate authority codes:
    /// CommitClaim's total_amount exceeds rate × usage ceiling.
    RateCeilingExceeded            = 44,
    /// UpdateRewardRates called before InitializeRewardRates.
    RewardRatesNotInitialized      = 45,
    /// InitializeRewardRates called on an existing PDA.
    RewardRatesAlreadyInitialized  = 46,

    /// Uptime rewards are disabled by the foundation kill switch.
    UptimeRewardsDisabled          = 47,
    /// ClaimRelayUptime already ran for this epoch.
    UptimeAlreadyPaid              = 48,
    /// relay_meta account is not the expected PDA.
    RelayMetaInvalid               = 49,

    /// `reward_treasury` is not the foundation wallet's associated token
    /// account for the mint being paid. Appended — never renumber the
    /// variants above: deployed off-chain code maps these by number.
    InvalidTreasuryAccount         = 50,
}

impl From<RewardsError> for ProgramError {
    fn from(e: RewardsError) -> Self {
        ProgramError::Custom(e as u32)
    }
}
