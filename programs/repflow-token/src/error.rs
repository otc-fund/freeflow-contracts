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

    /// The mint account provided does not match the mint recorded in the config.
    #[msg("Mint account does not match the repFlow config mint")]
    InvalidMint,

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

    // ── Stage 2: Proof-of-Service ──────────────────────────────────────────────

    /// The Proof-of-Service PDA address does not match the expected derivation, or
    /// the relay_pubkey field does not match the relay_wallet signer.
    ///
    /// Expected seeds: [b"proof_of_service", relay_wallet, &date_bucket.to_le_bytes()]
    /// where date_bucket = on-chain unix_timestamp / 86_400.
    #[msg("Proof-of-Service PDA address mismatch or wrong relay")]
    InvalidProofOfService,

    /// The Proof-of-Service attestation was submitted more than 48 hours ago.
    ///
    /// Submit a fresh attestation for today's date bucket before claiming.
    #[msg("Proof-of-Service attestation too old (submitted > 48h ago)")]
    ProofOfServiceTooOld,

    /// The Proof-of-Service attestation records zero unique client sessions.
    ///
    /// The relay must have served at least one client session to claim uptime repFlow.
    #[msg("Proof-of-Service: no client sessions recorded")]
    NoClientSessions,

    /// The Proof-of-Service attestation records zero bytes routed.
    ///
    /// The relay must have routed traffic to claim uptime repFlow.
    #[msg("Proof-of-Service: no traffic routed")]
    NoTrafficRouted,

    /// The Proof-of-Service attestation has already been consumed by a previous claim.
    ///
    /// A consumed PDA cannot be reused. Submit a new attestation for the next day bucket.
    #[msg("Proof-of-Service attestation already consumed")]
    ProofOfServiceConsumed,

    /// Proof-of-Service period_end must be strictly after period_start.
    #[msg("Proof-of-Service period_end must be after period_start")]
    InvalidPeriod,

    /// Proof-of-Service period_end is more than 1 hour in the future.
    ///
    /// Relays must submit attestations for already-elapsed time windows, not future windows.
    /// A 1-hour tolerance is allowed for clock skew between the relay and the chain.
    #[msg("Proof-of-Service period_end is too far in the future (max 1h clock skew)")]
    PeriodInFuture,

    /// Proof-of-Service period_start is more than 24 hours in the past.
    ///
    /// Only attestations from the current 24-hour window are accepted.
    #[msg("Proof-of-Service period_start is too old (> 24h ago)")]
    PeriodTooOld,

    // ── Reachability attestation (deadweight-relay gate) ───────────────────────

    /// No valid foundation-signed reachability attestation for today's date bucket
    /// was found in the transaction. The relay's sidecar must fetch a fresh
    /// attestation (the foundation only signs for relays it has actively probed as
    /// reachable from the internet) and submit it as an Ed25519SigVerify
    /// instruction alongside the claim.
    #[msg("relay not proven reachable by foundation attestation")]
    Unreachable,
}
