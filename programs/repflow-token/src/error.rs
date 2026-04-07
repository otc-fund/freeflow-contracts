//! Custom error types for the repFlow token program.

use anchor_lang::prelude::*;

#[error_code]
pub enum RepFlowError {
    /// repFlow is non-transferable (soulbound). All transfers are rejected.
    #[msg("repFlow is non-transferable — it cannot be bought, sold, or traded")]
    NonTransferable,

    /// The calling account is not an authorised minter.
    #[msg("Caller is not an authorised minter")]
    UnauthorizedMinter,

    /// The calling account is not an authorised burner.
    #[msg("Caller is not an authorised burner")]
    UnauthorizedBurner,

    /// Mint amount exceeds the per-user daily rate limit.
    #[msg("Mint amount exceeds daily rate limit (100,000 repFlow per user per day)")]
    DailyRateLimitExceeded,

    /// The mint authority config account does not match the program.
    #[msg("Invalid authority config account")]
    InvalidAuthorityConfig,

    /// Slashing amount exceeds the account's current balance.
    #[msg("Slash amount exceeds current repFlow balance")]
    InsufficientBalanceForSlash,

    /// The appeal window for a slash is still open.
    #[msg("Appeal window is still open — wait 72 hours before executing slash")]
    AppealWindowOpen,

    /// The provided evidence hash does not match the slash record.
    #[msg("Evidence hash mismatch — slash record may have been tampered")]
    EvidenceHashMismatch,

    /// Emergency pause is active — all operations suspended.
    #[msg("Program is paused for emergency maintenance")]
    ProgramPaused,

    /// Arithmetic overflow in reward or slash calculation.
    #[msg("Arithmetic overflow in calculation")]
    Overflow,
}
