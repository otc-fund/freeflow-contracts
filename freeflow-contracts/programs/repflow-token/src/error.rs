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
    #[msg("Mint amount exceeds daily rate limit (200 repFlow per user per day)")]
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

    /// M-03: The provided user token account does not belong to the slashed user.
    #[msg("user_ata does not belong to the slashed user wallet")]
    InvalidAta,

    /// F1-H7: The provided slash_id is not the next sequential ID for this user.
    /// slash_id must equal the user's current slash_count to prevent gaps/replays.
    #[msg("slash_id must equal user's current slash_count (sequential enforcement)")]
    InvalidSlashId,

    /// The CPI caller's rewards_authority PDA does not match the expected rewards program PDA.
    /// Only the rewards program can call `mint_repflow_from_rewards`.
    #[msg("Caller is not the authorized rewards program CPI authority")]
    UnauthorizedRewardsCPI,

    /// Uptime repFlow minting would exceed the 50/day sub-limit for this user.
    /// Uptime contributes at most 50 of the 200 daily cap.
    #[msg("Uptime repFlow mint would exceed 50/day sub-limit")]
    UptimeDailyCapExceeded,

    /// Unknown earning activity code passed to mint_repflow_from_rewards.
    /// Valid codes: 1=Uptime, 2=Bandwidth, 6=DisputeWin.
    #[msg("Unknown activity code — valid codes: 1=Uptime, 2=Bandwidth, 6=DisputeWin")]
    InvalidActivityCode,

    /// C-2: The ExtraAccountMetaList PDA for the transfer hook has not been initialized.
    ///
    /// Until this PDA exists the SPL Token-2022 runtime cannot locate the hook's
    /// account list, which means the transfer hook is inactive and repFlow is freely
    /// transferable — defeating the soulbound property.
    ///
    /// Fix: call `initialize_extra_account_meta_list` before any mint operation.
    #[msg("Transfer hook ExtraAccountMetaList not initialized — repFlow is not yet soulbound")]
    TransferHookNotInitialized,
}
