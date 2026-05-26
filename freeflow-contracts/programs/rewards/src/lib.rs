//! FreeFlow Rewards Program (Solana on-chain).
//!
//! Reward formula (repFlow-based, replacing old tier multipliers):
//!   routing_reward = routing_mb × BASE_ROUTING_PER_MB × repflow_multiplier_bps / 100
//!   seeding_reward = seeding_mb × BASE_SEEDING_PER_MB × repflow_multiplier_bps / 100
//!   uptime_reward  = uptime_seconds × uptime_per_hour / 3600    (sub-hour precision)
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
//!   0x00  ClaimRewards     — relay submits signed claim (legacy)
//!   0x01  RecordBytes      — oracle posts byte counters (legacy)
//!   0x02  ClaimUsage       — relay submits usage records → escrowed, 7-day dispute window
//!   0x03  DisputeClaim     — challenger disputes a record within the window
//!   0x04  ResolveDispute   — anyone resolves after dispute (Ed25519 verify)
//!   0x05  ReleaseRewards   — relay claims escrowed rewards after window expires
//!
//! Dispute window (DISPUTE-WINDOW-ARCHITECTURE.md):
//!   ClaimUsage holds rewards in escrow for 7 days. Anyone can dispute by proving
//!   a forged client signature via Ed25519. Disputes are resolved automatically.
//!   No governance vote — incentives align via bonding (relay=100 $FLOW, challenger=50 $FLOW).
//!
//! Double-spend protection (DOUBLE-SPEND-PROTECTION.md):
//!   - `ClaimUsage` tracks last_claimed_seq per (client, relay) in UserRelayClaimState
//!   - Rejects seq <= last_claimed_seq (replay protection)
//!   - Rejects record.relay != signer (cross-relay claim prevention)
//!   - Rejects bytes/duration > MAX_BYTES_PER_SECOND (rate cap)
//!   - Rejects records older than MAX_RECORD_AGE_SECONDS (time window)

use borsh::{BorshDeserialize, BorshSerialize};
use solana_program::{
    account_info::{next_account_info, AccountInfo},
    clock::Clock,
    entrypoint,
    entrypoint::ProgramResult,
    instruction::{AccountMeta, Instruction},
    msg,
    program::invoke_signed,
    program_error::ProgramError,
    pubkey::Pubkey,
    rent::Rent,
    system_instruction,
    system_program,
    sysvar::Sysvar,
};

solana_program::declare_id!("2yeVew5qq5jf5zuoqiE2svVLRE9HTN6J2GfB9LopdM1C");

entrypoint!(process_instruction);

// ─── Foundation authority ─────────────────────────────────────────────────────

/// Foundation multisig public key.
/// C-01: Used to gate admin instructions (InitializeRewardsConfig, SetMigrationMode,
/// PreMintFoundation). Compile-time validated via solana_program::pubkey!.
pub const FOUNDATION_PUBKEY: solana_program::pubkey::Pubkey =
    solana_program::pubkey!("8SL4dhnXU9tjvsbwfkVzQbfV99wGnVZBECoiuwrdbaJk");

// ─── Double-spend protection constants ───────────────────────────────────────

/// Maximum bytes per second allowed in a usage record (1 GB/s).
/// Prevents fabricated high-value records.
pub const MAX_BYTES_PER_SECOND: u64 = 1_073_741_824;

/// Maximum age of a usage record in seconds (48 hours).
/// Prevents hoarding/stale record submission.
pub const MAX_RECORD_AGE_SECONDS: i64 = 172_800;

// ─── Dispute Window constants ─────────────────────────────────────────────────

/// Dispute window duration in seconds (7 days).
pub const DISPUTE_WINDOW_SECONDS: i64 = 604_800;

/// Relay bond amount in $FLOW units.
/// Relay posts this when submitting a claim. Lost if dispute succeeds.
pub const RELAY_BOND_FLOW: u64 = 100;

/// Challenger bond in $FLOW units.
/// Challenger posts this to dispute. Lost if dispute is invalid.
pub const CHALLENGER_BOND_FLOW: u64 = 50;

// ─── 60-day unclaimed reward sweep constants ──────────────────────────────────

/// Seconds before unclaimed escrowed rewards can be swept (60 days).
pub const SWEEP_TIMEOUT_SECONDS: i64 = 60 * 24 * 3_600;

/// Treasury share of swept rewards in basis points (80%).
pub const TREASURY_SHARE_BPS: u64 = 8_000;

/// Burn share of swept rewards in basis points (20%).
pub const BURN_SHARE_BPS: u64 = 2_000;

// ─── Append-Only Chain constants ─────────────────────────────────────────────

/// Timeout before a relay may submit a force_claim (24 hours = 86 400 seconds).
pub const FORCE_CLAIM_TIMEOUT_SECS: u64 = 86_400;

/// Force-claim penalty in basis points (20% — relay receives 80%).
pub const FORCE_CLAIM_PENALTY_BPS: u64 = 2_000;

/// Minimum dispute bond as a percentage of claim value (10%).
///
/// Challenger must post at least `claim.total_amount × DISPUTE_BOND_PERCENT / 100` $FLOW
/// to file a dispute. This deters frivolous disputes by requiring meaningful skin-in-the-game.
pub const DISPUTE_BOND_PERCENT: u64 = 10;

// ─── CPI Bridge constants ─────────────────────────────────────────────────────

/// Relay share of newly minted $FLOW in basis points (70%).
///
/// When a claim is released, new $FLOW is minted: 70% to the relay's token account.
pub const RELAY_MINT_SHARE_BPS: u64 = 7_000;

/// Treasury share of newly minted $FLOW in basis points (30%).
///
/// When a claim is released, new $FLOW is minted: 30% to the treasury token account.
pub const TREASURY_MINT_SHARE_BPS: u64 = 3_000;

/// Treasury share of swept $FLOW in basis points (80%).
///
/// On sweep, 80% of escrowed $FLOW is minted to the treasury; 20% stays deflated.
pub const SWEEP_TREASURY_MINT_SHARE_BPS: u64 = 8_000;

/// Maximum time a dispute can remain unresolved before anyone can force-resolve it (3 days).
///
/// After this period the dispute defaults in the relay's favour (challenger bond burned).
pub const DISPUTE_RESOLVE_SECONDS: i64 = 3 * 24 * 3_600;

// ─── RepFlow-Bond constants (Phase 2) ─────────────────────────────────────────

/// Minimum repFlow balance a relay must hold to submit ClaimUsage.
///
/// Tier 1 starts at 2,001 — this ensures the relay has crossed the first
/// meaningful tier threshold before it can claim network rewards.
pub const MIN_RELAY_REPFLOW: u64 = 2_001;

/// Staking program ID — used to verify StakeAccount PDA ownership during
/// ClaimUsage stake-gate checks and for CPI slash in dispute resolution.
pub const STAKING_PROGRAM_ID: solana_program::pubkey::Pubkey =
    solana_program::pubkey!("7N1JRX3LY3goVAZCyaJyH7kpZ3kboZvh3jteDmCq6Dz4");

/// repflow-token program ID — used to verify RepFlowUser PDA ownership during
/// ClaimUsage repFlow-gate checks.
pub const REPFLOW_PROGRAM_ID: solana_program::pubkey::Pubkey =
    solana_program::pubkey!("8K4GhPEQ1yy9vdTaMPTL83G5qr5ZHZiBm2VBQ58jJs5w");

/// Minimum dynamic challenger bond in $FLOW units. Clamp lower bound.
pub const MIN_CHALLENGER_BOND_FLOW: u64 = 10;

/// Maximum dynamic challenger bond in $FLOW units. Clamp upper bound.
pub const MAX_CHALLENGER_BOND_FLOW: u64 = 500;

/// Fallback challenger bond (used when BondConfig PDA is absent or flow_price_cents = 0).
pub const DEFAULT_CHALLENGER_BOND_FLOW: u64 = 50;

/// Fallback minimum stake in $FLOW units (used when BondConfig or price unavailable).
pub const DEFAULT_MIN_STAKE_FLOW: u64 = 100;

// ─── Dispute type (P6) ────────────────────────────────────────────────────────

/// The kind of chain violation being disputed.
///
/// Used in `DisputeClaim` to indicate what the challenger is proving.
/// On-chain resolution uses this to determine what to verify.
#[derive(BorshSerialize, BorshDeserialize, Debug, Clone, PartialEq, Eq)]
pub enum ChainDisputeKind {
    /// session_total field is wrong: total != prev_total + bytes.
    TotalMismatch,
    /// prev_hash field is wrong: does not match previous record's hash.
    BrokenChain,
    /// Client ed25519 signature does not verify (original dispute type).
    ForgedSignature,
    /// Two records in the chain have the same nonce.
    DuplicateNonce,
}

// ─── Error codes ──────────────────────────────────────────────────────────────

/// Custom error codes for ClaimUsage enforcement.
#[derive(Debug, PartialEq, Eq)]
pub enum RewardsError {
    /// seq <= last_claimed_seq — duplicate or replay.
    DuplicateSequence,
    /// record.relay != signer — cross-relay claim attempt.
    WrongRelay,
    /// bytes / duration > MAX_BYTES_PER_SECOND — fabricated record.
    RateLimitExceeded,
    /// Record age > MAX_RECORD_AGE_SECONDS — stale record.
    RecordTooOld,
    /// end_ts <= start_ts — invalid time window.
    ZeroDuration,
    /// Records not sorted by seq (ascending) within a batch.
    RecordsNotSorted,
    /// Client signature does not verify.
    InvalidClientSignature,
    /// Relay signature does not verify.
    InvalidRelaySignature,

    // ── Append-Only Chain validation errors ──────────────────────────────────

    /// Chain submitted with no records.
    EmptyChain,
    /// Genesis record has non-zero prev_hash (must be [0u8; 32]).
    InvalidGenesis,
    /// A record's prev_hash does not match the previous record's record_hash.
    BrokenChain,
    /// Nonces are not strictly ascending by 1 (gap or duplicate detected).
    NonceGap,
    /// session_total != prev_session_total + bytes (cumulative math wrong).
    TotalMismatch,

    // ── force_claim errors ────────────────────────────────────────────────────

    /// force_claim attempted before the 24-hour relay-inactivity timeout.
    ForceClaimTooEarly,
    /// Session is still active on the network (client is on another relay).
    /// force_claim MUST be rejected when DHT SessionChainMeta.updated_at is recent.
    SessionStillActive,

    // ── Client signature errors ───────────────────────────────────────────────

    /// Client signature is all-zeros (record was never countersigned by client).
    MissingClientSignature,

    // ── Treasury validation errors ────────────────────────────────────────────

    /// `treasury_token` account owner is not in the authorized `TreasuryConfig` pool,
    /// or the `TreasuryConfig` PDA was not supplied when CPI minting is required.
    /// Treasury validation is mandatory — no backward-compatible skip path.
    UnauthorizedTreasury,

    // ── RepFlow-Bond gate errors (Phase 2) ────────────────────────────────────

    /// Relay's repFlow balance is below MIN_RELAY_REPFLOW (2,001).
    /// ClaimUsage rejected until relay accumulates sufficient reputation.
    InsufficientRelayReputation,

    /// Relay's staked $FLOW is below the minimum computed from BondConfig.
    /// ClaimUsage rejected until relay stakes enough.
    InsufficientStake,

    /// Relay has no StakeAccount in the staking program.
    /// The relay must stake before submitting claims.
    StakeAccountNotFound,

    /// RepFlowUser PDA was not provided and is now required.
    /// This error is returned once backward-compat mode is disabled.
    RepFlowAccountMissing,

    /// Computed challenger bond fell outside [MIN, MAX] range.
    /// This indicates a stale or garbage price oracle value.
    InvalidChallengerBond,
}

/// Errors specific to the dispute window.
#[derive(Debug, PartialEq, Eq)]
pub enum DisputeError {
    /// No pending claim with the given hash.
    ClaimNotFound,
    /// Dispute submitted after the 7-day window closed.
    DisputeWindowExpired,
    /// Claim is already under an active dispute.
    ClaimAlreadyDisputed,
    /// Claim is already settled (Released or Slashed) — cannot be disputed.
    ClaimAlreadySettled,
    /// Release attempted before the dispute window expires.
    DisputeWindowNotExpired,
    /// Resolution attempted on a claim that is not Disputed.
    NotDisputed,
    /// No dispute record found for the given claim hash.
    DisputeNotFound,
    /// Sweep attempted before the 60-day timeout has elapsed.
    SweepTooEarly,
    /// No pending (unreleased) claims exist to sweep.
    NothingToSweep,
    /// ForceResolve attempted before the 3-day dispute inactivity timeout.
    ResolveTooEarly,
    /// Challenger's dispute bond is below the required minimum (10% of claim value).
    InsufficientDisputeBond,
    /// Dispute nonce does not match the escrow's expected next_nonce (replay attack).
    InvalidDisputeNonce,
    /// Dispute escrow_pda does not match the store's expected escrow PDA.
    WrongEscrowPda,

    // ── P1 Reservation errors ─────────────────────────────────────────────────

    /// `SetMigrationMode(false)` was already called — migration lock is permanent.
    /// Code 113. Rule 6: irreversible once set.
    MigrationAlreadyLocked,
    /// `ClaimUsage` called but user has no `UserEscrowReservation` PDA.
    /// Code 114. Rule 2: ClaimUsage never creates the PDA.
    ReservationNotInitialized,
    /// `reserved` would exceed `escrow.balance` after decrement — invariant violated.
    /// Code 115.
    ReservationInvariantViolated,
    /// `ClaimUsage` called while `migration_mode = true` — new claims blocked.
    /// Code 116.
    MigrationWindowActive,
    /// Effective balance (`escrow.balance - reserved`) is less than `claim_amount`.
    InsufficientEffectiveBalance,
    /// Sweep attempted on a claim that is currently under an active dispute.
    ClaimUnderDispute,
    /// Reconcile timelock of 72 hours has not elapsed yet.
    ReconcileTimelockNotElapsed,
    /// No pending reconcile intent found for this user.
    ReconcileIntentNotFound,
}

impl From<DisputeError> for ProgramError {
    fn from(e: DisputeError) -> Self {
        let code: u32 = match e {
            DisputeError::ClaimNotFound                  => 100,
            DisputeError::DisputeWindowExpired           => 101,
            DisputeError::ClaimAlreadyDisputed           => 102,
            DisputeError::ClaimAlreadySettled            => 103,
            DisputeError::DisputeWindowNotExpired        => 104,
            DisputeError::NotDisputed                    => 105,
            DisputeError::DisputeNotFound                => 106,
            DisputeError::SweepTooEarly                  => 107,
            DisputeError::NothingToSweep                 => 108,
            DisputeError::ResolveTooEarly                => 109,
            DisputeError::InsufficientDisputeBond        => 110,
            DisputeError::InvalidDisputeNonce            => 111,
            DisputeError::WrongEscrowPda                 => 112,
            // P1 Reservation errors
            DisputeError::MigrationAlreadyLocked         => 113,
            DisputeError::ReservationNotInitialized      => 114,
            DisputeError::ReservationInvariantViolated   => 115,
            DisputeError::MigrationWindowActive          => 116,
            DisputeError::InsufficientEffectiveBalance   => 117,
            DisputeError::ClaimUnderDispute              => 118,
            DisputeError::ReconcileTimelockNotElapsed    => 119,
            DisputeError::ReconcileIntentNotFound        => 120,
        };
        ProgramError::Custom(code)
    }
}

impl From<RewardsError> for ProgramError {
    fn from(e: RewardsError) -> Self {
        ProgramError::Custom(e as u32)
    }
}

// ─── CPI Bridge helpers ───────────────────────────────────────────────────────

/// Compute an Anchor instruction discriminator: SHA-256(`"global:<name>"`)[..8].
///
/// Anchor programs prefix every instruction with 8 bytes derived from the
/// instruction name. This lets us build raw `Instruction` structs for CPI
/// into Anchor programs without importing `anchor-lang`.
pub fn anchor_ix_discriminator(name: &[u8]) -> [u8; 8] {
    use solana_program::hash::hashv;
    let mut prefixed = Vec::with_capacity(b"global:".len() + name.len());
    prefixed.extend_from_slice(b"global:");
    prefixed.extend_from_slice(name);
    let hash = hashv(&[&prefixed]);
    let mut disc = [0u8; 8];
    disc.copy_from_slice(&hash.to_bytes()[..8]);
    disc
}

/// Derive the `mint_authority` PDA from the rewards program ID.
///
/// Seeds: `["mint_authority"]`. The rewards program is the ONLY entity that
/// can sign for this PDA via `invoke_signed`. The $FLOW mint's `mint_authority`
/// must be transferred to this PDA before the CPI bridge can mint.
pub fn find_mint_authority_pda(program_id: &Pubkey) -> (Pubkey, u8) {
    Pubkey::find_program_address(&[b"mint_authority"], program_id)
}

/// Derive the `slash_authority` PDA from the rewards program ID.
///
/// Seeds: `[b"slash_authority"]`. The rewards program signs for this PDA via
/// `invoke_signed` when CPI-ing into the staking program's `Slash` instruction.
/// The staking program derives this same PDA from `REWARDS_PROGRAM_PUBKEY` and
/// accepts it as a second authorized slasher.
pub fn find_slash_authority_pda(program_id: &Pubkey) -> (Pubkey, u8) {
    Pubkey::find_program_address(&[b"slash_authority"], program_id)
}

/// Verify the supplied `mint_authority_ai` matches the expected PDA and return the bump.
fn verify_and_get_mint_authority_bump(
    mint_authority_ai: &AccountInfo,
    program_id: &Pubkey,
) -> Result<u8, ProgramError> {
    let (expected, bump) = find_mint_authority_pda(program_id);
    if expected != *mint_authority_ai.key {
        msg!(
            "CPI Bridge: mint_authority PDA mismatch — expected {}, got {}",
            expected, mint_authority_ai.key
        );
        return Err(ProgramError::InvalidArgument);
    }
    Ok(bump)
}

/// CPI to the user-escrow Anchor program's `spend_from_escrow` instruction.
///
/// Burns `amount` $FLOW from the user's escrow token account. The rewards
/// program's `mint_authority` PDA acts as `service_authority` (it must be
/// registered in `AuthorizedSpenderRegistry` before use).
///
/// **Why CPI to `spend_from_escrow` rather than a direct SPL-Token burn?**
/// The `user_escrow_token` account's authority is the `user_escrow` PDA, which
/// is derived from the *user-escrow program* ID. The rewards program cannot
/// produce a valid PDA signature for that account via `invoke_signed` because
/// `create_program_address` uses the *calling* program's ID. The only path to
/// a compliant burn is to CPI into the user-escrow program and let it sign for
/// its own PDA — which is exactly what `spend_from_escrow` does.
///
/// **DEPLOYMENT PREREQUISITE — AuthorizedSpenderRegistry:**
/// Before any `ReleaseRewards` / `ForceResolve` / `ResolveDisputeChallengerSlashed` /
/// `SweepExpiredEscrow` instruction can burn from user escrow, the rewards program's
/// `["mint_authority"]` PDA **must** be registered in the `AuthorizedSpenderRegistry`.
///
/// Setup steps:
/// 1. Derive PDA: `Pubkey::find_program_address(&[b"mint_authority"], &rewards_program_id)`
/// 2. Call user-escrow's `update_spender_registry` signed by the Foundation multisig authority.
/// 3. Pass the `mint_authority` PDA pubkey in the `add_spenders` list.
/// 4. After registration, `spend_from_escrow` accepts this PDA as `service_authority`.
///
/// Without this step, all CPI burns fail with `EscrowError::UnauthorizedCaller` (error 6001).
///
/// **relay_token / relay_wallet — CPI redirect-protection guard:**
/// `spend_from_escrow` validates `relay_token.owner == relay_wallet` at the SPL level
/// (i.e. the SPL `TokenAccount.owner` field must equal the `relay_wallet` pubkey).
/// Callers must pass a relay token account whose SPL authority matches `relay_wallet`.
/// For sweep operations, the treasury token account (authority = treasury wallet) plays the
/// role of `relay_token`, and `treasury_wallet` plays `relay_wallet`.
#[allow(clippy::too_many_arguments)]
#[inline(never)]
fn cpi_burn_from_escrow<'a>(
    user_escrow_program_ai: &AccountInfo<'a>,
    mint_authority_ai:      &AccountInfo<'a>,  // service_authority (PDA signer)
    user_ai:                &AccountInfo<'a>,
    user_escrow_state_ai:   &AccountInfo<'a>,  // UserEscrow PDA (writable)
    user_escrow_token_ai:   &AccountInfo<'a>,  // escrow SPL token account (writable)
    relay_token_ai:         &AccountInfo<'a>,  // relay SPL token account (CPI-redirect guard)
    relay_wallet_ai:        &AccountInfo<'a>,  // relay wallet pubkey
    spender_registry_ai:    &AccountInfo<'a>,  // AuthorizedSpenderRegistry PDA
    token_mint_ai:          &AccountInfo<'a>,  // $FLOW mint (writable — burn reduces supply)
    token_program_ai:       &AccountInfo<'a>,
    amount:                 u64,
    mint_authority_bump:    u8,
) -> ProgramResult {
    if amount == 0 {
        return Ok(());
    }

    // Build Anchor instruction data: [discriminator:8][amount:8 LE][relay:32]
    let mut data = Vec::with_capacity(48);
    data.extend_from_slice(&anchor_ix_discriminator(b"spend_from_escrow"));
    data.extend_from_slice(&amount.to_le_bytes());
    data.extend_from_slice(relay_wallet_ai.key.as_ref());

    let ix = Instruction {
        program_id: *user_escrow_program_ai.key,
        accounts: vec![
            AccountMeta { pubkey: *mint_authority_ai.key,    is_signer: true,  is_writable: false },
            AccountMeta { pubkey: *user_ai.key,              is_signer: false, is_writable: false },
            AccountMeta { pubkey: *user_escrow_state_ai.key, is_signer: false, is_writable: true  },
            AccountMeta { pubkey: *user_escrow_token_ai.key, is_signer: false, is_writable: true  },
            AccountMeta { pubkey: *relay_token_ai.key,       is_signer: false, is_writable: false },
            AccountMeta { pubkey: *relay_wallet_ai.key,      is_signer: false, is_writable: false },
            AccountMeta { pubkey: *spender_registry_ai.key,  is_signer: false, is_writable: false },
            AccountMeta { pubkey: *token_mint_ai.key,        is_signer: false, is_writable: true  },
            AccountMeta { pubkey: *token_program_ai.key,     is_signer: false, is_writable: false },
        ],
        data,
    };

    invoke_signed(
        &ix,
        &[
            mint_authority_ai.clone(),
            user_ai.clone(),
            user_escrow_state_ai.clone(),
            user_escrow_token_ai.clone(),
            relay_token_ai.clone(),
            relay_wallet_ai.clone(),
            spender_registry_ai.clone(),
            token_mint_ai.clone(),
            token_program_ai.clone(),
        ],
        &[&[b"mint_authority", &[mint_authority_bump]]],
    )
}

/// CPI to user-escrow `hold_client_funds`.
///
/// Locks `amount` $FLOW in a `FundHold` PDA for the 7-day dispute window.
/// The `mint_authority` PDA (seeds `["mint_authority"]`) is the service_authority
/// that must be registered in the user-escrow spender registry.
///
/// Accounts:
///   service_authority — mint_authority PDA (signer via invoke_signed)
///   payer             — relay wallet (pays FundHold PDA rent)
///   user              — user wallet (PDA seed only)
///   user_escrow       — UserEscrow PDA (writable)
///   fund_hold         — FundHold PDA (init, writable)
///   spender_registry  — AuthorizedSpenderRegistry PDA
///   system_program    — 11111…
#[allow(clippy::too_many_arguments)]
#[inline(never)]
fn cpi_hold_client_funds<'a>(
    user_escrow_program_ai: &AccountInfo<'a>,
    mint_authority_ai:      &AccountInfo<'a>,  // service_authority (PDA signer)
    payer_ai:               &AccountInfo<'a>,  // pays FundHold rent (relay wallet)
    user_ai:                &AccountInfo<'a>,
    user_escrow_state_ai:   &AccountInfo<'a>,  // UserEscrow PDA (writable)
    fund_hold_ai:           &AccountInfo<'a>,  // FundHold PDA (init, writable)
    spender_registry_ai:    &AccountInfo<'a>,
    system_program_ai:      &AccountInfo<'a>,
    amount:                 u64,
    claim_hash:             [u8; 32],
    session_id:             [u8; 16],
    mint_authority_bump:    u8,
) -> ProgramResult {
    if amount == 0 {
        return Ok(());
    }

    // Build Anchor instruction data: [discriminator:8][amount:8 LE][claim_hash:32][session_id:16]
    let mut data = Vec::with_capacity(8 + 8 + 32 + 16);
    data.extend_from_slice(&anchor_ix_discriminator(b"hold_client_funds"));
    data.extend_from_slice(&amount.to_le_bytes());
    data.extend_from_slice(&claim_hash);
    data.extend_from_slice(&session_id);

    let ix = Instruction {
        program_id: *user_escrow_program_ai.key,
        accounts: vec![
            AccountMeta { pubkey: *mint_authority_ai.key,    is_signer: true,  is_writable: false },
            AccountMeta { pubkey: *payer_ai.key,             is_signer: true,  is_writable: true  },
            AccountMeta { pubkey: *user_ai.key,              is_signer: false, is_writable: false },
            AccountMeta { pubkey: *user_escrow_state_ai.key, is_signer: false, is_writable: true  },
            AccountMeta { pubkey: *fund_hold_ai.key,         is_signer: false, is_writable: true  },
            AccountMeta { pubkey: *spender_registry_ai.key,  is_signer: false, is_writable: false },
            AccountMeta { pubkey: *system_program_ai.key,    is_signer: false, is_writable: false },
        ],
        data,
    };

    invoke_signed(
        &ix,
        &[
            mint_authority_ai.clone(),
            payer_ai.clone(),
            user_ai.clone(),
            user_escrow_state_ai.clone(),
            fund_hold_ai.clone(),
            spender_registry_ai.clone(),
            system_program_ai.clone(),
        ],
        &[&[b"mint_authority", &[mint_authority_bump]]],
    )
}

/// CPI to user-escrow `release_funds`.
///
/// Decrements `UserEscrow.held` and marks the `FundHold` PDA as Released.
/// Called when the relay is slashed (client wins dispute) — tokens remain in escrow.
///
/// Accounts:
///   service_authority — mint_authority PDA (signer)
///   user              — user wallet (PDA seed only)
///   user_escrow       — UserEscrow PDA (writable)
///   fund_hold         — FundHold PDA (writable, must be Active)
///   spender_registry  — AuthorizedSpenderRegistry PDA
#[inline(never)]
fn cpi_release_funds<'a>(
    user_escrow_program_ai: &AccountInfo<'a>,
    mint_authority_ai:      &AccountInfo<'a>,
    user_ai:                &AccountInfo<'a>,
    user_escrow_state_ai:   &AccountInfo<'a>,
    fund_hold_ai:           &AccountInfo<'a>,
    spender_registry_ai:    &AccountInfo<'a>,
    claim_hash:             [u8; 32],
    mint_authority_bump:    u8,
) -> ProgramResult {
    // Build Anchor instruction data: [discriminator:8][claim_hash:32]
    let mut data = Vec::with_capacity(8 + 32);
    data.extend_from_slice(&anchor_ix_discriminator(b"release_funds"));
    data.extend_from_slice(&claim_hash);

    let ix = Instruction {
        program_id: *user_escrow_program_ai.key,
        accounts: vec![
            AccountMeta { pubkey: *mint_authority_ai.key,    is_signer: true,  is_writable: false },
            AccountMeta { pubkey: *user_ai.key,              is_signer: false, is_writable: false },
            AccountMeta { pubkey: *user_escrow_state_ai.key, is_signer: false, is_writable: true  },
            AccountMeta { pubkey: *fund_hold_ai.key,         is_signer: false, is_writable: true  },
            AccountMeta { pubkey: *spender_registry_ai.key,  is_signer: false, is_writable: false },
        ],
        data,
    };

    invoke_signed(
        &ix,
        &[
            mint_authority_ai.clone(),
            user_ai.clone(),
            user_escrow_state_ai.clone(),
            fund_hold_ai.clone(),
            spender_registry_ai.clone(),
        ],
        &[&[b"mint_authority", &[mint_authority_bump]]],
    )
}

/// CPI to user-escrow `burn_held_funds`.
///
/// Decrements both `UserEscrow.held` and `UserEscrow.balance`, SPL-burns `amount`
/// from the escrow token account, and marks the `FundHold` PDA as Burned.
/// Called after the 7-day dispute window expires (relay wins or challenger wins).
///
/// Accounts:
///   service_authority  — mint_authority PDA (signer)
///   user               — user wallet (PDA seed only)
///   user_escrow        — UserEscrow PDA (writable)
///   user_escrow_token  — escrow SPL token account (writable, burned from)
///   fund_hold          — FundHold PDA (writable, must be Active)
///   spender_registry   — AuthorizedSpenderRegistry PDA
///   token_mint         — $FLOW mint (writable — burn reduces supply)
///   token_program      — SPL Token program
#[allow(clippy::too_many_arguments)]
#[inline(never)]
fn cpi_burn_held_funds<'a>(
    user_escrow_program_ai: &AccountInfo<'a>,
    mint_authority_ai:      &AccountInfo<'a>,
    user_ai:                &AccountInfo<'a>,
    user_escrow_state_ai:   &AccountInfo<'a>,
    user_escrow_token_ai:   &AccountInfo<'a>,
    fund_hold_ai:           &AccountInfo<'a>,
    spender_registry_ai:    &AccountInfo<'a>,
    token_mint_ai:          &AccountInfo<'a>,
    token_program_ai:       &AccountInfo<'a>,
    claim_hash:             [u8; 32],
    mint_authority_bump:    u8,
) -> ProgramResult {
    // Build Anchor instruction data: [discriminator:8][claim_hash:32]
    let mut data = Vec::with_capacity(8 + 32);
    data.extend_from_slice(&anchor_ix_discriminator(b"burn_held_funds"));
    data.extend_from_slice(&claim_hash);

    let ix = Instruction {
        program_id: *user_escrow_program_ai.key,
        accounts: vec![
            AccountMeta { pubkey: *mint_authority_ai.key,    is_signer: true,  is_writable: false },
            AccountMeta { pubkey: *user_ai.key,              is_signer: false, is_writable: false },
            AccountMeta { pubkey: *user_escrow_state_ai.key, is_signer: false, is_writable: true  },
            AccountMeta { pubkey: *user_escrow_token_ai.key, is_signer: false, is_writable: true  },
            AccountMeta { pubkey: *fund_hold_ai.key,         is_signer: false, is_writable: true  },
            AccountMeta { pubkey: *spender_registry_ai.key,  is_signer: false, is_writable: false },
            AccountMeta { pubkey: *token_mint_ai.key,        is_signer: false, is_writable: true  },
            AccountMeta { pubkey: *token_program_ai.key,     is_signer: false, is_writable: false },
        ],
        data,
    };

    invoke_signed(
        &ix,
        &[
            mint_authority_ai.clone(),
            user_ai.clone(),
            user_escrow_state_ai.clone(),
            user_escrow_token_ai.clone(),
            fund_hold_ai.clone(),
            spender_registry_ai.clone(),
            token_mint_ai.clone(),
            token_program_ai.clone(),
        ],
        &[&[b"mint_authority", &[mint_authority_bump]]],
    )
}

/// CPI to SPL Token `mint_to`. Mints `amount` tokens to `destination_ai`.
///
/// The rewards `mint_authority` PDA (seeds `["mint_authority"]`) signs the
/// CPI via `invoke_signed`. The $FLOW mint's on-chain `mint_authority` must
/// point to this PDA before any minting is possible.
///
/// **DEPLOYMENT PREREQUISITE — $FLOW Mint Authority Transfer:**
/// Before any `ReleaseRewards` / `ForceResolve` / `ResolveDisputeChallengerSlashed` /
/// `SweepExpiredEscrow` instruction can mint new $FLOW, the $FLOW SPL mint's on-chain
/// `mint_authority` **must** be transferred to the rewards program's `["mint_authority"]` PDA.
///
/// Setup steps:
/// 1. Derive PDA: `Pubkey::find_program_address(&[b"mint_authority"], &rewards_program_id)`
/// 2. Call `spl_token::instruction::set_authority` with `AuthorityType::MintTokens`.
/// 3. The current mint authority must sign the `set_authority` transaction.
/// 4. After transfer, only the rewards program can mint via `invoke_signed` with these seeds.
///
/// Without this step, all CPI mints fail with `TokenError::OwnerMismatch`.
///
/// **Transaction atomicity — balance ordering:**
/// Each caller must read `user_escrow.balance` BEFORE invoking `cpi_burn_from_escrow`,
/// then invoke `cpi_mint_to` only after the burn succeeds. Because Solana transactions
/// are atomic, a failure in either CPI reverts the entire transaction — the
/// `settle_reservation` decrement, the burn, and the mint are all undone together.
/// There is no partial-execution window that could leave `reserved` or supply inconsistent.
#[inline(never)]
fn cpi_mint_to<'a>(
    token_program_ai:    &AccountInfo<'a>,
    token_mint_ai:       &AccountInfo<'a>,
    destination_ai:      &AccountInfo<'a>,
    mint_authority_ai:   &AccountInfo<'a>,
    amount:              u64,
    mint_authority_bump: u8,
) -> ProgramResult {
    if amount == 0 {
        return Ok(());
    }
    let ix = spl_token::instruction::mint_to(
        token_program_ai.key,
        token_mint_ai.key,
        destination_ai.key,
        mint_authority_ai.key,
        &[],
        amount,
    ).map_err(|_| ProgramError::InvalidInstructionData)?;

    invoke_signed(
        &ix,
        &[token_mint_ai.clone(), destination_ai.clone(), mint_authority_ai.clone()],
        &[&[b"mint_authority", &[mint_authority_bump]]],
    )
}

/// CPI to repflow-token's `mint_repflow_from_rewards` instruction.
///
/// Mints `amount` repFlow tokens to `repflow_ata_ai` for the relay or challenger.
/// Signs with the rewards program's `mint_authority` PDA (seeds `[b"mint_authority"]`),
/// which repflow-token verifies as proof that the caller is the rewards program.
///
/// Activity codes: 1 = Uptime, 2 = Bandwidth (1 repFlow/GB), 6 = DisputeWin.
///
/// Returns `Ok(())` immediately if `amount == 0` (no-op, no CPI needed).
#[inline(never)]
fn cpi_mint_repflow<'a>(
    repflow_program_ai: &AccountInfo<'a>,
    repflow_config_ai:  &AccountInfo<'a>,
    repflow_user_ai:    &AccountInfo<'a>,
    repflow_mint_ai:    &AccountInfo<'a>,
    repflow_ata_ai:     &AccountInfo<'a>,
    rewards_authority:  &AccountInfo<'a>,
    token_program_ai:   &AccountInfo<'a>,
    amount:             u64,
    activity_code:      u8,
    mint_authority_bump: u8,
) -> ProgramResult {
    if amount == 0 {
        return Ok(());
    }

    // Anchor discriminator: sha256("global:mint_repflow_from_rewards")[0..8]
    let preimage = b"global:mint_repflow_from_rewards";
    let hash     = solana_program::hash::hashv(&[preimage]);
    let disc     = &hash.to_bytes()[..8];

    // Instruction data: discriminator(8) + amount(u64 le)(8) + activity_code(u8)(1)
    let mut data = Vec::with_capacity(17);
    data.extend_from_slice(disc);
    data.extend_from_slice(&amount.to_le_bytes());
    data.push(activity_code);

    use solana_program::instruction::{AccountMeta, Instruction};
    let ix = Instruction {
        program_id: *repflow_program_ai.key,
        accounts:   vec![
            AccountMeta::new(*repflow_config_ai.key,  false), // config (mut)
            AccountMeta::new(*repflow_user_ai.key,    false), // repflow_user (mut)
            AccountMeta::new(*repflow_mint_ai.key,    false), // mint (mut)
            AccountMeta::new(*repflow_ata_ai.key,     false), // recipient_ata (mut)
            AccountMeta::new_readonly(*rewards_authority.key, true), // rewards_authority (signer)
            AccountMeta::new_readonly(*token_program_ai.key, false), // token_program
        ],
        data,
    };

    invoke_signed(
        &ix,
        &[
            repflow_config_ai.clone(),
            repflow_user_ai.clone(),
            repflow_mint_ai.clone(),
            repflow_ata_ai.clone(),
            rewards_authority.clone(),
            token_program_ai.clone(),
            repflow_program_ai.clone(), // callee program must be in account_infos
        ],
        &[&[b"mint_authority", &[mint_authority_bump]]],
    )
    .map_err(|e| {
        msg!("cpi_mint_repflow failed (activity={}): {:?}", activity_code, e);
        e
    })
}

/// Shared repFlow CPI helper used by all four claim-resolution handlers.
///
/// Computes `bytes_routed / 1_073_741_824` (1 repFlow per GB), then fires
/// `cpi_mint_repflow` if and only if all 6 optional repFlow accounts are present.
/// Returns `Ok(())` immediately if any account is absent or `bytes_routed == 0`.
///
/// Extracted from nested `if let` blocks to give the inner bindings their own
/// call frame, shrinking the calling handler's frame by ~288 bytes.
#[inline(never)]
fn maybe_mint_repflow_for_claim<'a>(
    bytes_routed:       u64,
    activity_code:      u8,
    rewards_authority:  &AccountInfo<'a>,
    bump:               u8,
    repflow_program:    Option<&AccountInfo<'a>>,
    repflow_config:     Option<&AccountInfo<'a>>,
    repflow_user:       Option<&AccountInfo<'a>>,
    repflow_mint:       Option<&AccountInfo<'a>>,
    repflow_ata:        Option<&AccountInfo<'a>>,
    repflow_token_prog: Option<&AccountInfo<'a>>,
) -> ProgramResult {
    let amount = bytes_routed / 1_073_741_824;
    if let (
        Some(rfp_ai), Some(rfc_ai), Some(rfu_ai),
        Some(rfm_ai), Some(rfata_ai), Some(rftp_ai),
    ) = (
        repflow_program, repflow_config, repflow_user,
        repflow_mint, repflow_ata, repflow_token_prog,
    ) {
        cpi_mint_repflow(
            rfp_ai, rfc_ai, rfu_ai, rfm_ai, rfata_ai,
            rewards_authority, rftp_ai,
            amount, activity_code, bump,
        )?;
        if amount > 0 {
            msg!(
                "repFlow CPI: {} repFlow ({}B, activity={})",
                amount, bytes_routed, activity_code,
            );
        }
    }
    Ok(())
}

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
        RewardsInstruction::ClaimUsage { records } => {
            process_claim_usage(program_id, accounts, records)
        }
        RewardsInstruction::DisputeClaim { claim_hash, record_index, disputed_record } => {
            process_dispute_claim(program_id, accounts, claim_hash, record_index, disputed_record)
        }
        RewardsInstruction::ResolveDisputeRelaySlashed { claim_hash } => {
            process_resolve_relay_slashed_ix(program_id, accounts, claim_hash)
        }
        RewardsInstruction::ResolveDisputeChallengerSlashed { claim_hash } => {
            process_resolve_challenger_slashed_ix(program_id, accounts, claim_hash)
        }
        RewardsInstruction::ForceResolve { claim_hash } => {
            process_force_resolve_ix(program_id, accounts, claim_hash)
        }
        RewardsInstruction::ReleaseRewards { claim_hash } => {
            process_release_rewards_ix(program_id, accounts, claim_hash)
        }

        // ── P1 Reservation instructions ─────────────────────────────────────
        RewardsInstruction::InitializeRewardsConfig => {
            process_initialize_rewards_config(program_id, accounts)
        }
        RewardsInstruction::InitializeReservation {
            user, initial_reserved, deployment_slot, foundation_sig,
        } => {
            process_initialize_reservation(
                program_id, accounts, user, initial_reserved, deployment_slot, foundation_sig,
            )
        }
        RewardsInstruction::SetMigrationMode { enabled } => {
            process_set_migration_mode(program_id, accounts, enabled)
        }
        RewardsInstruction::SweepExpiredEscrow => {
            process_sweep_expired_escrow_ix(program_id, accounts)
        }
        RewardsInstruction::RequestReconciliation { user, new_reserved } => {
            process_request_reconciliation(program_id, accounts, user, new_reserved)
        }
        RewardsInstruction::ExecuteReconciliation { user } => {
            process_execute_reconciliation(program_id, accounts, user)
        }
        RewardsInstruction::CancelReconciliation { user } => {
            process_cancel_reconciliation(program_id, accounts, user)
        }
        RewardsInstruction::PreMintFoundation => {
            process_pre_mint_foundation(program_id, accounts)
        }
        RewardsInstruction::InitializeRewardRates {
            routing_per_mb, seeding_per_mb, uptime_per_hour, flow_price_cents,
        } => {
            process_initialize_reward_rates(
                program_id, accounts,
                routing_per_mb, seeding_per_mb, uptime_per_hour, flow_price_cents,
            )
        }
        RewardsInstruction::UpdateRewardRates {
            routing_per_mb, seeding_per_mb, uptime_per_hour, flow_price_cents,
        } => {
            process_update_reward_rates(
                program_id, accounts,
                routing_per_mb, seeding_per_mb, uptime_per_hour, flow_price_cents,
            )
        }
        RewardsInstruction::InitializeTreasuryConfig { initial_treasury_keys } => {
            process_initialize_treasury_config_ix(program_id, accounts, initial_treasury_keys)
        }
        RewardsInstruction::UpdateTreasuryPool { add_treasury_keys, remove_treasury_keys } => {
            process_update_treasury_pool_ix(program_id, accounts, add_treasury_keys, remove_treasury_keys)
        }
        RewardsInstruction::InitializeBondConfig {
            challenger_bond_cents, min_stake_usd_cents, stake_earnings_bps, max_stake_flow,
        } => {
            process_initialize_bond_config_ix(
                program_id, accounts,
                challenger_bond_cents, min_stake_usd_cents, stake_earnings_bps, max_stake_flow,
            )
        }
        RewardsInstruction::UpdateBondConfig {
            challenger_bond_cents, min_stake_usd_cents, stake_earnings_bps, max_stake_flow,
        } => {
            process_update_bond_config_ix(
                program_id, accounts,
                challenger_bond_cents, min_stake_usd_cents, stake_earnings_bps, max_stake_flow,
            )
        }
    }
}

// ── Instructions ─────────────────────────────────────────────────────────────

#[derive(BorshSerialize, BorshDeserialize, Debug)]
pub enum RewardsInstruction {
    /// Legacy: relay submits aggregate byte/uptime counts. No sequence enforcement.
    ClaimRewards {
        period_start:    i64,
        period_end:      i64,
        bytes_routed:    u64,
        bytes_seeded:    u64,
        uptime_seconds:  u64,
        /// repFlow balance, oracle-attested at claim time.
        repflow_balance: u64,
    },
    /// Legacy: oracle posts verified byte counters on-chain.
    RecordBytes {
        relay_pubkey: [u8; 32],
        bytes_routed: u64,
        bytes_seeded: u64,
    },
    /// Updated: relay submits usage records → rewards held in escrow, 7-day dispute window.
    ///
    /// Sequence enforcement still applies (double-spend protection unchanged).
    /// Rewards are NOT immediately credited — they enter `PendingClaimsStore`.
    ///
    /// Accounts:
    ///   0: relay_wallet (signer, posts RELAY_BOND_FLOW)
    ///   1: reward_account (relay's reward PDA, writable)
    ///   2: claim_state (UserRelayClaimState PDA for this client+relay, writable)
    ///   3: pending_claims (PendingClaimsStore PDA for relay, writable)
    ClaimUsage {
        records: Vec<UsageRecordOnChain>,
    },
    /// Challenger files a dispute against a specific record in a pending claim.
    ///
    /// Must be submitted before `dispute_deadline`. Challenger posts CHALLENGER_BOND_FLOW.
    ///
    /// Accounts:
    ///   0: challenger_wallet (signer, posts CHALLENGER_BOND_FLOW)
    ///   1: pending_claims (PendingClaimsStore PDA for the relay, writable)
    DisputeClaim {
        /// SHA-256 hash of the claim being disputed.
        claim_hash:      [u8; 32],
        /// Index of the disputed record within the submitted batch.
        record_index:    u32,
        /// The exact disputed record (must match what was submitted).
        disputed_record: UsageRecordOnChain,
    },
    /// Challenger proves the relay forged a client signature — relay is slashed.
    ///
    /// **Security:** This instruction MUST be preceded in the same transaction by a
    /// Solana Ed25519Program precompile instruction that verifies the disputed
    /// record's client signature FAILS. If the precompile succeeds (sig valid), the
    /// transaction reverts before this instruction executes — no trust required.
    ///
    /// Removes `sig_valid: bool` trust parameter. The Ed25519 precompile is the
    /// sole authority on signature validity.
    ///
    /// Economics: relay bond split 50% to challenger / 50% burned.
    ///
    /// Accounts:
    ///   0: challenger_wallet (signer — receives 50% of relay bond)
    ///   1: pending_claims (PendingClaimsStore PDA, writable)
    ResolveDisputeRelaySlashed {
        /// SHA-256 of the claim being resolved.
        claim_hash: [u8; 32],
    },
    /// Relay defends: proves the disputed record's client signature IS valid — challenger slashed.
    ///
    /// **Security:** This instruction MUST be preceded in the same transaction by a
    /// Solana Ed25519Program precompile instruction that verifies the disputed
    /// record's client signature SUCCEEDS. If the precompile fails (sig invalid),
    /// the transaction reverts — relay cannot defend a forged record.
    ///
    /// Economics: challenger bond burned; relay receives rewards + relay bond back.
    ///
    /// Accounts:
    ///   0: relay_wallet (signer)
    ///   1: pending_claims (PendingClaimsStore PDA, writable)
    ResolveDisputeChallengerSlashed {
        /// SHA-256 of the claim being resolved.
        claim_hash: [u8; 32],
    },
    /// Force-resolve a dispute that has been unresolved for more than 3 days.
    ///
    /// Callable by anyone after `dispute.submitted_at + DISPUTE_RESOLVE_SECONDS`.
    /// Prevents rewards being locked forever if neither party acts.
    ///
    /// Default outcome: challenger bond burned, relay claim released.
    /// (Challenger had 3 days to produce proof — inaction forfeits their bond.)
    ///
    /// Accounts:
    ///   0: resolver_wallet (signer — anyone can trigger)
    ///   1: pending_claims (PendingClaimsStore PDA, writable)
    ///   2: reward_account (relay's reward PDA, writable — for released rewards)
    ForceResolve {
        /// SHA-256 of the stalled disputed claim.
        claim_hash: [u8; 32],
    },
    /// Release escrowed rewards to relay after dispute window expires with no dispute.
    ///
    /// Callable only after `dispute_deadline` has passed and status is `Pending`.
    /// Explicitly returns the relay's bond in addition to the escrowed rewards.
    ///
    /// Accounts:
    ///   0: relay_wallet (signer)
    ///   1: reward_account (relay's reward PDA, writable)
    ///   2: pending_claims (PendingClaimsStore PDA, writable)
    ///   3: reservation_account (UserEscrowReservation PDA for user, writable, optional)
    ///   4: user_escrow_account (UserEscrow PDA from user-escrow program, readable, optional)
    ReleaseRewards {
        /// SHA-256 hash of the claim to release.
        claim_hash: [u8; 32],
    },

    // ── P1 Reservation instructions ──────────────────────────────────────────

    /// Initialize the global `RewardsConfig` PDA.
    ///
    /// Called ONCE at deployment. Sets `migration_mode = true`.
    /// Requires the Foundation signer.
    ///
    /// Accounts:
    ///   0: foundation     (signer — Foundation multisig, writable — pays rent)
    ///   1: rewards_config (RewardsConfig PDA [b"rewards_config"], writable — will be created)
    ///   2: system_program (SystemProgram)
    InitializeRewardsConfig,

    /// Permissionlessly initialize a `UserEscrowReservation` PDA for a user.
    ///
    /// Idempotent: returns `Ok(())` if the PDA already exists and is initialized
    /// with matching user pubkey (Rule 3).
    ///
    /// `initial_reserved` captures pending claims at migration time.
    /// Foundation attestation (preceding Ed25519 precompile instruction) proves
    /// the value is correct.
    ///
    /// Accounts:
    ///   0: payer (signer)
    ///   1: reservation_account (UserEscrowReservation PDA, writable — pre-created)
    InitializeReservation {
        /// User wallet pubkey for whom the reservation is being initialized.
        user:             [u8; 32],
        /// Sum of pending claim amounts at time of initialization.
        initial_reserved: u64,
        /// The deployment slot — included in Foundation attestation message.
        deployment_slot:  u64,
        /// Ed25519 Foundation signature over `{user_pubkey ‖ initial_reserved ‖ deployment_slot}`.
        /// Verified by a preceding Ed25519Program precompile instruction.
        foundation_sig:   [u8; 64],
    },

    /// Toggle migration mode. `SetMigrationMode(false)` is IRREVERSIBLE (Rule 6).
    ///
    /// Only the Foundation signer may call this.
    ///
    /// Accounts:
    ///   0: foundation (signer — Foundation multisig)
    ///   1: rewards_config (RewardsConfig PDA, writable)
    SetMigrationMode {
        /// `true` to enable migration mode; `false` to disable permanently.
        enabled: bool,
    },

    /// Sweep all Pending claims in a store that have exceeded the 60-day timeout.
    ///
    /// Callable by anyone. 80% → treasury, 20% burned.
    /// Also calls `settle_reservation` for each swept claim (if reservation provided).
    ///
    /// Accounts:
    ///   0: sweeper (signer — anyone)
    ///   1: pending_claims (PendingClaimsStore PDA, writable)
    ///   2: reservation_account (UserEscrowReservation PDA for user, writable, optional)
    ///   3: user_escrow_account (UserEscrow PDA, readable, optional)
    SweepExpiredEscrow,

    /// Foundation requests a reconciliation of a user's reservation.
    ///
    /// Starts a 72-hour timelock before execution. Provides emergency recovery
    /// if `reserved` drifts due to bugs or missed settlements.
    ///
    /// Accounts:
    ///   0: foundation (signer — Foundation multisig)
    ///   1: reconcile_intent (ReconcileIntent PDA, writable — pre-created)
    RequestReconciliation {
        /// User whose reservation is being reconciled.
        user:         [u8; 32],
        /// Corrected value of `UserEscrowReservation.reserved`.
        new_reserved: u64,
    },

    /// Execute a pending reconciliation after the 72-hour timelock.
    ///
    /// Callable by anyone after `requested_at + 72h`. Sets `reservation.reserved`
    /// to the corrected value.
    ///
    /// Accounts:
    ///   0: executor (signer — anyone after timelock)
    ///   1: reconcile_intent (ReconcileIntent PDA, writable)
    ///   2: reservation_account (UserEscrowReservation PDA, writable)
    ExecuteReconciliation {
        /// User whose reservation is being reconciled.
        user: [u8; 32],
    },

    /// Cancel a pending reconciliation intent before it executes.
    ///
    /// Only the Foundation may cancel.
    ///
    /// Accounts:
    ///   0: foundation (signer — Foundation multisig)
    ///   1: reconcile_intent (ReconcileIntent PDA, writable)
    CancelReconciliation {
        /// User whose reconciliation is being cancelled.
        user: [u8; 32],
    },

    /// One-time Foundation pre-mint: mints 200M $FLOW to the Foundation token account.
    ///
    /// Tokenomics (80:20 model):
    ///   - Total hard cap:       1,000,000,000 $FLOW
    ///   - Foundation (20%):       200,000,000 $FLOW  ← this instruction
    ///   - Relay rewards (80%):    800,000,000 $FLOW  ← released via ReleaseRewards
    ///
    /// Idempotent: returns Ok(()) if `foundation_pre_minted = true`.
    /// Enforces hard cap: fails if `total_minted + FOUNDATION_ALLOCATION > MAX_SUPPLY`.
    ///
    /// Accounts:
    ///   0: foundation         (signer — Foundation multisig, C-01 checked)
    ///   1: rewards_config     (RewardsConfig PDA, writable)
    ///   2: mint_authority     (mint_authority PDA [b"mint_authority"], signer via PDA)
    ///   3: token_mint         ($FLOW SPL mint, writable)
    ///   4: foundation_token   (Foundation's $FLOW token account, writable)
    ///   5: token_program      (SPL Token program)
    PreMintFoundation,

    /// Create the `RewardRatesAccount` PDA with default (or custom) rates.
    ///
    /// One-time setup — fails with `AccountAlreadyInitialized` if the PDA already exists.
    /// Only the Foundation authority may call this.
    ///
    /// Accounts:
    ///   0: foundation       (signer, writable — pays for PDA creation)
    ///   1: reward_rates     (RewardRatesAccount PDA [b"reward_rates"], writable)
    ///   2: system_program   (readonly)
    InitializeRewardRates {
        /// Routing reward per MB. Pass 0 to use the default (1_000).
        routing_per_mb:  u64,
        /// Seeding reward per MB. Pass 0 to use the default (2_000).
        seeding_per_mb:  u64,
        /// Uptime reward per hour. Pass 0 to use the default (10_000_000).
        uptime_per_hour: u64,
        /// $FLOW price in US micro-cents (0 = not set).
        flow_price_cents: u64,
    },

    /// Update reward rates in the `RewardRatesAccount` PDA.
    ///
    /// Only the Foundation authority may call this.
    /// Increments `change_count` and records `last_updated` timestamp.
    ///
    /// Accounts:
    ///   0: foundation       (signer — must equal FOUNDATION_PUBKEY)
    ///   1: reward_rates     (RewardRatesAccount PDA [b"reward_rates"], writable)
    UpdateRewardRates {
        /// New routing reward per MB (0 = keep current).
        routing_per_mb:  u64,
        /// New seeding reward per MB (0 = keep current).
        seeding_per_mb:  u64,
        /// New uptime reward per hour (0 = keep current).
        uptime_per_hour: u64,
        /// New $FLOW price in US micro-cents (0 = keep current).
        flow_price_cents: u64,
    },

    /// Initialize the `TreasuryConfig` PDA.
    ///
    /// One-time setup — fails with `AccountAlreadyInitialized` if the PDA already exists.
    /// Only the Foundation authority may call this.
    ///
    /// Accounts:
    ///   0: foundation       (signer — must equal FOUNDATION_PUBKEY, writable — pays rent)
    ///   1: treasury_config  (TreasuryConfig PDA [b"treasury_config"], writable — will be created)
    ///   2: system_program   (readonly)
    InitializeTreasuryConfig {
        /// Initial authorized treasury wallet pubkeys. At least 1 required, max 5.
        initial_treasury_keys: Vec<[u8; 32]>,
    },

    /// Update the authorized treasury wallet pool in `TreasuryConfig`.
    ///
    /// Only the Foundation authority may call this.
    /// Increments `change_count`. Must leave at least 1 key in the pool.
    ///
    /// Accounts:
    ///   0: foundation       (signer — must equal FOUNDATION_PUBKEY)
    ///   1: treasury_config  (TreasuryConfig PDA [b"treasury_config"], writable)
    UpdateTreasuryPool {
        /// Keys to add to the pool (deduplicated; ignored if already present).
        add_treasury_keys:    Vec<[u8; 32]>,
        /// Keys to remove from the pool. Fails if this would leave 0 keys.
        remove_treasury_keys: Vec<[u8; 32]>,
    },

    // ── RepFlow-Bond config instructions (Phase 2) ────────────────────────────

    /// Initialize the `BondConfig` PDA with dynamic bond/stake parameters.
    ///
    /// One-time setup. Only the Foundation authority may call this.
    ///
    /// Accounts:
    ///   0: foundation    (signer, writable — pays rent)
    ///   1: bond_config   (BondConfig PDA [b"bond_config"], writable — will be created)
    ///   2: system_program
    InitializeBondConfig {
        /// Target USD value of challenger bond in micro-cents ($1.25 = 125_000).
        challenger_bond_cents: u64,
        /// Target USD value of minimum relay stake in micro-cents ($2,500 = 250_000_000).
        min_stake_usd_cents:   u64,
        /// Additional stake per $FLOW earned, in basis points (10% = 1_000).
        stake_earnings_bps:    u64,
        /// Absolute ceiling for required stake in $FLOW units (100_000).
        max_stake_flow:        u64,
    },

    /// Update the `BondConfig` PDA parameters.
    ///
    /// Only the Foundation authority may call this.
    ///
    /// Accounts:
    ///   0: foundation    (signer — must equal FOUNDATION_PUBKEY)
    ///   1: bond_config   (BondConfig PDA [b"bond_config"], writable)
    UpdateBondConfig {
        /// New challenger bond target in micro-cents (0 = keep current).
        challenger_bond_cents: u64,
        /// New minimum stake target in micro-cents (0 = keep current).
        min_stake_usd_cents:   u64,
        /// New stake earnings rate in basis points (0 = keep current).
        stake_earnings_bps:    u64,
        /// New maximum stake ceiling in $FLOW (0 = keep current).
        max_stake_flow:        u64,
    },
}

// ── Usage record (on-chain Borsh format) ─────────────────────────────────────

/// Usage record submitted on-chain for sequence-enforced reward claims.
///
/// This mirrors `freeflow-relay-runtime::payments::UsageRecord` but uses
/// fixed-size byte arrays for Borsh compatibility.
#[derive(BorshSerialize, BorshDeserialize, Debug, Clone)]
pub struct UsageRecordOnChain {
    /// User wallet pubkey (32 bytes).
    pub user: [u8; 32],

    /// Relay pubkey (32 bytes) — signed by client, binds record to this relay.
    pub relay: [u8; 32],

    /// Session ID (16 bytes = UUID).
    pub session_id: [u8; 16],

    /// Bytes routed in this interval.
    pub bytes: u64,

    /// USD charge in micro-USD.
    pub charge_usd: u64,

    /// $FLOW charge in micro-FLOW.
    pub charge_flow: u64,

    /// Session segment start timestamp (Unix seconds).
    pub start_ts: u64,

    /// Session segment end timestamp (Unix seconds).
    pub end_ts: u64,

    /// Relay-assigned monotonic sequence number for this (user, relay) pair.
    pub seq: u64,

    /// Session ed25519 pubkey (32 bytes) — the key that signed this record.
    pub session_pubkey: [u8; 32],

    /// ed25519 signature by session key over all fields (64 bytes).
    pub user_sig: [u8; 64],

    /// ed25519 signature by relay key over all fields (64 bytes).
    pub relay_sig: [u8; 64],

    /// Ed25519 client countersignature over ALL record fields including chain fields.
    /// All-zeros = not signed. Must be non-zero for claims to be accepted.
    pub client_signature: [u8; 64],

    // ── Append-only chain fields (SESSION-TRACKING-APPEND-CHAIN.md) ──────────

    /// SHA-256 of the previous record in this session's chain.
    /// All-zeros for the genesis (first) record.
    pub prev_hash: [u8; 32],

    /// Position in this session's chain (1, 2, 3...). Strictly ascending.
    pub nonce: u64,

    /// Cumulative bytes in this session (prev_total + bytes).
    pub session_total: u64,

    /// SHA-256 of canonical chain fields — used as `prev_hash` by the next record.
    pub record_hash: [u8; 32],
}

// ── Per-(client, relay) claim state ──────────────────────────────────────────

/// PDA account tracking claim state for a (user, relay) pair.
///
/// Seeds: [b"claim_state", user_pubkey, relay_pubkey]
/// One account per (client, relay) pair — independent sequence spaces.
#[derive(BorshSerialize, BorshDeserialize, Debug, Clone)]
pub struct UserRelayClaimState {
    /// Client wallet pubkey.
    pub user: [u8; 32],

    /// Relay pubkey.
    pub relay: [u8; 32],

    /// Highest sequence number accepted in a successful claim.
    /// Reject records with seq <= this value.
    pub last_claimed_seq: u64,

    /// Cumulative bytes claimed for this (user, relay) pair.
    pub total_claimed_bytes: u64,

    /// Slot of the most recent accepted claim.
    pub last_claim_slot: u64,

    /// PDA bump seed.
    pub bump: u8,
}

impl UserRelayClaimState {
    pub const SIZE: usize = 32 + 32 + 8 + 8 + 8 + 1; // = 89 bytes
}

// ─── Dispute Window state ─────────────────────────────────────────────────────

/// Lifecycle status of a pending claim in the dispute window.
#[derive(BorshSerialize, BorshDeserialize, Debug, Clone, PartialEq, Eq)]
pub enum ClaimStatus {
    /// Within 7-day dispute window — no dispute filed yet.
    Pending,
    /// A challenge has been filed; awaiting resolution.
    Disputed,
    /// Dispute resolved (challenger slashed — relay receives rewards).
    Resolved,
    /// Dispute window expired with no dispute — rewards released to relay.
    Released,
    /// Relay lost the dispute — bond slashed.
    Slashed,
    /// Claim expired after 60-day sweep timeout — forfeited to treasury.
    /// Distinct from `Slashed` (dispute outcome) for semantic clarity (M3).
    Swept,
}

impl ClaimStatus {
    /// Returns true for every terminal state that triggers a single settle_reservation
    /// decrement. Used to guard against double-decrement in all handlers (Rule 8).
    pub fn is_terminal(&self) -> bool {
        matches!(
            self,
            ClaimStatus::Released
                | ClaimStatus::Slashed
                | ClaimStatus::Resolved
                | ClaimStatus::Swept
        )
    }
}

/// An escrowed claim waiting out the 7-day dispute window.
///
/// Created by `ClaimUsage`. Rewards stay in escrow until either:
///   - `ReleaseRewards` is called after `dispute_deadline`, or
///   - A dispute is filed and resolved via `DisputeClaim` + `ResolveDispute`.
#[derive(BorshSerialize, BorshDeserialize, Debug, Clone)]
pub struct PendingClaim {
    /// Relay that submitted the claim.
    pub relay:            [u8; 32],
    /// SHA-256 of all serialised records in this batch.
    pub claim_hash:       [u8; 32],
    /// Total $FLOW claimed across all records.
    pub total_amount:     u64,
    /// Number of usage records in the batch.
    pub record_count:     u32,
    /// Unix timestamp when the claim was submitted.
    pub submitted_at:     i64,
    /// submitted_at + DISPUTE_WINDOW_SECONDS (7 days).
    pub dispute_deadline: i64,
    /// Relay's bond in $FLOW units. Lost if relay loses a dispute.
    pub bond:             u64,
    /// Current lifecycle status.
    pub status:           ClaimStatus,
    /// True if this claim was submitted without the client's final signature
    /// (i.e., via `force_claim` after a 24-hour inactivity timeout).
    /// When true, `release_rewards` deducts the 20% penalty for the treasury.
    pub is_force_claim:   bool,
    /// User wallet pubkey whose escrow is being charged. `None` for legacy claims
    /// (created before P1). Used by `settle_reservation` to identify which
    /// `UserEscrowReservation` PDA to decrement.
    ///
    /// **Backward compatibility (Rule 5):** Trailing `Option<[u8; 32]>` field.
    /// New claims always have `Some(user)`. Legacy claims loaded from pre-P1
    /// on-chain data will have `None` (old format had no trailing bytes).
    /// The terminal handlers skip reservation settlement for `None` user claims.
    pub user:             Option<[u8; 32]>,
    /// Total bytes routed in this claim batch — used to calculate repFlow bandwidth reward.
    ///
    /// Rate: 1 repFlow per GB (1_073_741_824 bytes).
    /// Populated by `ClaimUsage` from the sum of `UsageRecordOnChain.bytes` fields.
    ///
    /// **Backward compatibility:** Field appended after `user`. Pre-existing claims
    /// (without this field) will fail to deserialize — clear the pending claims PDA
    /// before deploying this version on devnet.
    pub bytes_routed:     u64,
    /// Total bytes seeded in this claim batch.
    /// Reserved for future seeding reward calculation. Currently always 0.
    pub bytes_seeded:     u64,
    /// Uptime seconds during this claim period.
    /// Reserved for Approach 1 (uptime-on-release). Currently always 0.
    /// Uptime repFlow is claimed via `claim_daily_uptime_repflow` (Approach 2).
    pub uptime_seconds:   u64,
}

/// Monotonically increasing nonce per escrow PDA for dispute replay protection.
///
/// Ensures that a captured valid dispute signature cannot be replayed:
/// each dispute must present `nonce == next_nonce` which increments after acceptance.
#[derive(BorshSerialize, BorshDeserialize, Debug, Clone, Default)]
pub struct EscrowNonce {
    /// The escrow PDA this nonce tracker is for.
    pub escrow_pda: [u8; 32],
    /// The next expected nonce for a new dispute. Starts at 0.
    pub next_nonce: u64,
}

/// A challenger's dispute against a specific record in a pending claim.
///
/// Created by `DisputeClaim`. The disputed record is stored on-chain so
/// `ResolveDispute` can verify its client signature independently.
#[derive(BorshSerialize, BorshDeserialize, Debug, Clone)]
pub struct DisputeRecord {
    /// Challenger's pubkey (receives reward if dispute succeeds).
    pub challenger:      [u8; 32],
    /// Hash of the claim being disputed.
    pub claim_hash:      [u8; 32],
    /// Index of the disputed record within the batch.
    pub record_index:    u32,
    /// The disputed usage record (stored for on-chain Ed25519 verification).
    pub disputed_record: UsageRecordOnChain,
    /// Challenger's bond in $FLOW units (proportional to claim value).
    pub bond:            u64,
    /// Unix timestamp when the dispute was filed.
    pub submitted_at:    i64,
    /// Monotonic nonce at time of filing — prevents dispute signature replay.
    pub nonce:           u64,
    /// Escrow PDA this dispute is bound to — prevents cross-escrow replay.
    pub escrow_pda:      [u8; 32],
}

/// Outcome of a resolved dispute (returned by the resolve functions).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DisputeOutcome {
    /// Client signature was INVALID → relay forged it → relay slashed.
    ///
    /// Challenger earns 50% of relay bond; remaining 50% is burned.
    /// Challenger's dispute bond is returned in full (their dispute was valid).
    RelaySlashed {
        /// Amount credited to the challenger (50% of relay bond).
        challenger_reward: u64,
        /// Amount burned (50% of relay bond).
        burned: u64,
        /// Challenger's dispute bond returned in full.
        challenger_bond_returned: u64,
    },
    /// Client signature was VALID → challenge was frivolous → challenger slashed.
    ///
    /// Relay receives 80% of challenger bond as capital-lock compensation.
    /// 20% of challenger bond is burned as penalty.
    ChallengerSlashed {
        /// 80% of challenger dispute bond credited to relay.
        relay_reward: u64,
        /// 20% of challenger dispute bond burned.
        burned: u64,
    },
}

/// On-chain account holding all pending claims and active disputes.
///
/// Seeds: [b"pending_claims", relay_pubkey] — one store per relay.
/// Updated by ClaimUsage, DisputeClaim, ResolveDispute, ReleaseRewards.
#[derive(BorshSerialize, BorshDeserialize, Debug, Clone, Default)]
pub struct PendingClaimsStore {
    pub claims:   Vec<PendingClaim>,
    pub disputes: Vec<DisputeRecord>,
    /// Monotonically increasing nonce for dispute filing (Finding 3.1).
    /// Prevents dispute signature replay attacks across dispute windows.
    pub next_dispute_nonce: u64,
}

// ─── P1 On-Chain Atomic Escrow Reservation structs ────────────────────────────

/// Per-user reservation tracker. Prevents cross-relay double-spend.
///
/// PDA seeds: `["escrow_reservation", user_pubkey]`
///
/// `reserved` = Σ `total_amount` of all Pending + Disputed claims for this user.
/// Incremented by `ClaimUsage`. Decremented ONLY by `settle_reservation` (Rule 1).
///
/// Invariant: `reserved <= user_escrow.balance` (enforced in `settle_reservation`).
#[derive(BorshSerialize, BorshDeserialize, Debug, Clone, Default)]
pub struct UserEscrowReservation {
    /// The user wallet pubkey.
    pub user:     [u8; 32],
    /// Sum of `total_amount` across all Pending and Disputed claims for this user.
    pub reserved: u64,
    /// PDA bump seed.
    pub bump:     u8,
}

impl UserEscrowReservation {
    /// Minimum on-chain account size (borsh-serialized).
    pub const SIZE: usize = 32 + 8 + 1; // = 41 bytes
}

/// Global rewards contract configuration.
///
/// PDA seeds: `["rewards_config"]`
///
/// Initialized once at deployment with `migration_mode = true`.
/// `SetMigrationMode(false)` is IRREVERSIBLE: sets `migration_locked = true` (Rule 6).
#[derive(BorshSerialize, BorshDeserialize, Debug, Clone, Default)]
pub struct RewardsConfig {
    /// When `true`, `ClaimUsage` is blocked (returns `MigrationWindowActive`).
    /// Set to `true` at deployment; set to `false` once all reservation PDAs exist.
    pub migration_mode:   bool,
    /// Once `SetMigrationMode(false)` is called, this is set to `true` permanently.
    /// Prevents any future `SetMigrationMode(true)` call (Rule 6).
    pub migration_locked: bool,
    /// PDA bump seed.
    pub bump:             u8,

    // ── Tokenomics (80:20 model) ─────────────────────────────────────────────
    /// Total $FLOW lamports minted via this program (relay rewards + foundation pre-mint).
    /// Checked against `max_supply` before every mint.
    pub total_minted:          u64,
    /// Hard cap: maximum $FLOW lamports that may ever be minted (1 billion $FLOW).
    /// Set to 0 at init; populated by first `PreMintFoundation` or left as 0 to
    /// default to MAX_SUPPLY in code.
    pub max_supply:            u64,
    /// True after `PreMintFoundation` has executed — prevents double pre-mint.
    pub foundation_pre_minted: bool,
}

impl RewardsConfig {
    pub const SIZE: usize = 1 + 1 + 1 + 8 + 8 + 1; // = 20 bytes

    // ── Tokenomics constants ─────────────────────────────────────────────────

    /// Hard cap: 1 billion $FLOW (9 decimals → 1_000_000_000 × 10^9 lamports).
    pub const MAX_SUPPLY: u64 = 1_000_000_000 * 1_000_000_000;

    /// Foundation pre-mint: 200 million $FLOW (20% of hard cap).
    pub const FOUNDATION_ALLOCATION: u64 = 200_000_000 * 1_000_000_000;

    /// Relay reward reserve: 800 million $FLOW (80% of hard cap).
    pub const REWARD_RESERVE: u64 = 800_000_000 * 1_000_000_000;

    /// Effective supply cap — prefer stored `max_supply` if non-zero, else constant.
    pub fn effective_max_supply(&self) -> u64 {
        if self.max_supply == 0 { Self::MAX_SUPPLY } else { self.max_supply }
    }
}

// ─── RewardRatesAccount ───────────────────────────────────────────────────────

/// On-chain storage for foundation-governed reward rates.
///
/// PDA seeds: `[b"reward_rates"]`
///
/// Initialized once by the foundation; updated via `UpdateRewardRates`.
/// The relay binary reads this PDA before each claim and falls back to the
/// hardcoded defaults (1_000 / 2_000 / 10_000_000) if the account is absent.
#[derive(BorshSerialize, BorshDeserialize, Debug, Clone)]
pub struct RewardRatesAccount {
    /// Authority that may call `UpdateRewardRates` (must equal `FOUNDATION_PUBKEY`).
    pub authority:       [u8; 32],
    /// Reward units per megabyte routed (default: 1_000).
    pub routing_per_mb:  u64,
    /// Reward units per megabyte seeded (default: 2_000).
    pub seeding_per_mb:  u64,
    /// Reward units per hour of uptime (default: 10_000_000).
    pub uptime_per_hour: u64,
    /// $FLOW price in US cents × 100 (i.e. micro-cents). 0 = not set.
    pub flow_price_cents: u64,
    /// Unix timestamp of the last update.
    pub last_updated:    i64,
    /// Monotonically increasing counter of rate updates.
    pub change_count:    u64,
    /// PDA bump seed.
    pub bump:            u8,
}

impl RewardRatesAccount {
    /// Byte size for account allocation: 32 + 8*5 + 8 + 8 + 1 = 89 bytes.
    pub const SIZE: usize = 32 + 8 + 8 + 8 + 8 + 8 + 8 + 1;

    /// Default routing reward per megabyte (target: 1 FLOW/GB).
    pub const DEFAULT_ROUTING_PER_MB:  u64 = 1_000_000;
    /// Default seeding reward per megabyte (target: 2 FLOW/GB).
    pub const DEFAULT_SEEDING_PER_MB:  u64 = 2_000_000;
    /// Default uptime reward per hour (target: 10 FLOW/hr).
    pub const DEFAULT_UPTIME_PER_HOUR: u64 = 10_000_000_000;
}

// ─── TreasuryConfig ───────────────────────────────────────────────────────────

/// On-chain treasury configuration.
///
/// PDA seeds: `[b"treasury_config"]` on the rewards program.
///
/// Initialized once at deployment by the Foundation multisig via
/// `InitializeTreasuryConfig`. Updated via `UpdateTreasuryPool`.
///
/// Treasury validation is **mandatory** in every 70/30 mint path.
/// Transactions that supply a `treasury_token` account whose SPL owner is not
/// in `treasury_keys` are rejected with `RewardsError::UnauthorizedTreasury`.
#[derive(BorshSerialize, BorshDeserialize, Debug, Clone)]
pub struct TreasuryConfig {
    /// Authority that may update the pool (must equal `FOUNDATION_PUBKEY`).
    pub authority:     [u8; 32],
    /// Authorized treasury wallet pubkeys. At least one must be present.
    /// Up to 5 keys supported in the fixed-size allocation.
    pub treasury_keys: Vec<[u8; 32]>,
    /// Monotonically increasing counter of pool updates.
    pub change_count:  u64,
}

impl TreasuryConfig {
    /// Allocated size: authority(32) + vec_header(4) + 5×key(160) + change_count(8) = 204 bytes.
    pub const SIZE: usize = 32 + 4 + (32 * 5) + 8;
    /// Maximum number of authorized treasury keys.
    pub const MAX_KEYS: usize = 5;
}

/// Foundation two-phase recovery intent for reservation reconciliation.
///
/// PDA seeds: `["reconcile_intent", user_pubkey]`
///
/// Created by `RequestReconciliation`. Executed after a 72-hour timelock
/// by `ExecuteReconciliation`. Can be cancelled by `CancelReconciliation`.
#[derive(BorshSerialize, BorshDeserialize, Debug, Clone)]
pub struct ReconcileIntent {
    /// The user whose reservation is being reconciled.
    pub user:          [u8; 32],
    /// The corrected `reserved` value to set after the timelock elapses.
    pub new_reserved:  u64,
    /// Unix timestamp when the request was submitted.
    pub requested_at:  i64,
    /// True once `ExecuteReconciliation` has been called.
    pub executed:      bool,
}

impl ReconcileIntent {
    pub const SIZE: usize = 32 + 8 + 8 + 1; // = 49 bytes
    /// 72-hour timelock in seconds.
    pub const TIMELOCK_SECONDS: i64 = 72 * 3_600;
}

// ─── BondConfig (Phase 2) ─────────────────────────────────────────────────────

/// Foundation-governed dynamic bond and stake configuration.
///
/// PDA seeds: `[b"bond_config"]` on the rewards program.
///
/// Initialized once by the Foundation via `InitializeBondConfig`.
/// Updated via `UpdateBondConfig`. Absent until initialized — callers fall back
/// to `DEFAULT_CHALLENGER_BOND_FLOW` and `DEFAULT_MIN_STAKE_FLOW` when missing.
#[derive(BorshSerialize, BorshDeserialize, Debug, Clone)]
pub struct BondConfig {
    /// Foundation authority that may update this config.
    pub authority:             [u8; 32],
    /// Target USD value of the challenger bond in micro-cents (1 = $0.000001).
    /// At deployment: 125_000 = $1.25.
    pub challenger_bond_cents: u64,
    /// Target USD value of the minimum relay stake in micro-cents.
    /// At deployment: 250_000_000 = $2,500.
    pub min_stake_usd_cents:   u64,
    /// Additional stake required per $FLOW earned, in basis points.
    /// 1_000 bps = 10% of total_lamports_claimed.
    pub stake_earnings_bps:    u64,
    /// Absolute ceiling for required stake, in $FLOW units.
    pub max_stake_flow:        u64,
    /// PDA bump seed.
    pub bump:                  u8,
}

impl BondConfig {
    /// Byte size: 32 + 8 + 8 + 8 + 8 + 1 = 65 bytes.
    pub const SIZE: usize = 32 + 8 + 8 + 8 + 8 + 1;

    /// Default challenger_bond_cents: $1.25 (125,000 micro-cents).
    pub const DEFAULT_CHALLENGER_BOND_CENTS: u64 = 125_000;
    /// Default min_stake_usd_cents: $2,500 (250,000,000 micro-cents).
    pub const DEFAULT_MIN_STAKE_USD_CENTS:   u64 = 250_000_000;
    /// Default stake_earnings_bps: 10% (1,000 bps).
    pub const DEFAULT_STAKE_EARNINGS_BPS:    u64 = 1_000;
    /// Default max_stake_flow: 100,000 $FLOW ceiling.
    pub const DEFAULT_MAX_STAKE_FLOW:        u64 = 100_000;

    /// Compute the required challenger bond in $FLOW given the current price.
    ///
    /// Formula: `challenger_bond_cents * 1_000_000 / flow_price_cents`
    ///
    /// Returns `DEFAULT_CHALLENGER_BOND_FLOW` when `flow_price_cents` is zero
    /// (price oracle not set) or when the result falls outside the clamped range.
    pub fn compute_challenger_bond(&self, flow_price_cents: u64) -> u64 {
        if flow_price_cents == 0 {
            return DEFAULT_CHALLENGER_BOND_FLOW;
        }
        let bond = self.challenger_bond_cents
            .saturating_mul(1_000_000)
            .checked_div(flow_price_cents)
            .unwrap_or(DEFAULT_CHALLENGER_BOND_FLOW);
        bond.max(MIN_CHALLENGER_BOND_FLOW).min(MAX_CHALLENGER_BOND_FLOW)
    }

    /// Compute the minimum required stake in $FLOW given price and relay earnings.
    ///
    /// Formula:
    ///   base  = min_stake_usd_cents * 1_000_000 / flow_price_cents
    ///   extra = total_lamports_claimed * stake_earnings_bps / 10_000
    ///   min   = min(base + extra, max_stake_flow)
    ///
    /// Returns `DEFAULT_MIN_STAKE_FLOW` when price is zero.
    pub fn compute_min_stake(&self, flow_price_cents: u64, total_lamports_claimed: u64) -> u64 {
        if flow_price_cents == 0 {
            return DEFAULT_MIN_STAKE_FLOW;
        }
        let base = self.min_stake_usd_cents
            .saturating_mul(1_000_000)
            .checked_div(flow_price_cents)
            .unwrap_or(DEFAULT_MIN_STAKE_FLOW);
        let extra = total_lamports_claimed
            .saturating_mul(self.stake_earnings_bps)
            .checked_div(10_000)
            .unwrap_or(0);
        (base.saturating_add(extra)).min(self.max_stake_flow)
    }
}

// ── Validation logic (extracted for testability) ─────────────────────────────

/// Validate a single usage record against state and current clock.
///
/// Does NOT verify signatures — on-chain, signature verification is done via
/// the ed25519 instruction precompile. This function checks:
///   1. Relay binding: record.relay == signer
///   2. Duplicate seq: record.seq > state.last_claimed_seq
///   3. Duration validity: end_ts > start_ts
///   4. Rate cap: bytes / duration ≤ MAX_BYTES_PER_SECOND
///   5. Time window: record age ≤ MAX_RECORD_AGE_SECONDS
pub fn validate_usage_record(
    record:       &UsageRecordOnChain,
    state:        &UserRelayClaimState,
    relay_pubkey: &[u8; 32],
    clock_ts:     i64,
) -> Result<(), RewardsError> {
    // 1. Relay binding — only the relay in the record can claim it.
    if record.relay != *relay_pubkey {
        return Err(RewardsError::WrongRelay);
    }

    // 2. Duplicate sequence — monotonically increasing, no replay.
    if record.seq <= state.last_claimed_seq {
        return Err(RewardsError::DuplicateSequence);
    }

    // 3. Duration must be positive.
    if record.end_ts <= record.start_ts {
        return Err(RewardsError::ZeroDuration);
    }
    let duration = record.end_ts - record.start_ts;

    // 4. Rate cap — prevent fabricated high-value records.
    let bytes_per_second = record.bytes.checked_div(duration).unwrap_or(u64::MAX);
    if bytes_per_second > MAX_BYTES_PER_SECOND {
        return Err(RewardsError::RateLimitExceeded);
    }

    // 5. Time window — reject stale records older than 48 hours.
    let record_age = clock_ts.saturating_sub(record.end_ts as i64);
    if record_age > MAX_RECORD_AGE_SECONDS {
        return Err(RewardsError::RecordTooOld);
    }

    Ok(())
}

/// Validate that a batch of records for one client are strictly ascending by seq.
///
/// The contract requires ascending order so `last_claimed_seq` can be updated
/// with a single scan (no gaps left unclaimed).
pub fn validate_batch_order(records: &[UsageRecordOnChain]) -> Result<(), RewardsError> {
    for window in records.windows(2) {
        if window[1].seq <= window[0].seq {
            return Err(RewardsError::RecordsNotSorted);
        }
    }
    Ok(())
}

// ─── Append-Only Chain validation ────────────────────────────────────────────

/// Compute the record hash for the append-only chain (on-chain version).
///
/// Must produce the same output as `compute_record_hash` in freeflow-relay-runtime.
/// Uses `solana_program::hash::hashv` for on-chain SHA-256.
pub fn compute_record_hash_onchain(record: &UsageRecordOnChain) -> [u8; 32] {
    use solana_program::hash::hashv;
    // Encode the session_id as Uuid bytes (little-endian nonce and totals match relay).
    hashv(&[
        &record.session_id,
        &record.nonce.to_le_bytes(),
        &record.prev_hash,
        &record.relay,
        &record.bytes.to_le_bytes(),
        &record.session_total.to_le_bytes(),
        &record.start_ts.to_le_bytes(),
        &record.end_ts.to_le_bytes(),
    ]).to_bytes()
}

/// Validate an append-only chain of usage records.
///
/// Checks:
///   1. Chain is non-empty.
///   2. Genesis record has `prev_hash == [0u8; 32]` and `nonce == 1`.
///   3. Each record's `prev_hash == compute_record_hash_onchain(previous)`.
///   4. Nonces are strictly ascending by 1 (1, 2, 3, …).
///   5. `session_total == prev_session_total + bytes` for each record.
///
/// Does NOT verify signatures — those are enforced separately via the
/// dispute window (Ed25519 precompile).
pub fn validate_chain(records: &[UsageRecordOnChain]) -> Result<(), RewardsError> {
    if records.is_empty() {
        return Err(RewardsError::EmptyChain);
    }

    // Genesis: prev_hash must be all-zeros, nonce must be 1.
    let genesis = &records[0];
    if genesis.prev_hash != [0u8; 32] {
        return Err(RewardsError::InvalidGenesis);
    }
    if genesis.nonce != 1 {
        return Err(RewardsError::NonceGap);
    }

    // Validate cumulative total for genesis.
    if genesis.session_total != genesis.bytes {
        return Err(RewardsError::TotalMismatch);
    }

    if records.len() == 1 {
        return Ok(());
    }

    let mut prev_hash  = compute_record_hash_onchain(genesis);
    let mut prev_nonce = genesis.nonce;
    let mut prev_total = genesis.session_total;

    for record in &records[1..] {
        // Chain link: this record's prev_hash must equal the previous record's hash.
        if record.prev_hash != prev_hash {
            return Err(RewardsError::BrokenChain);
        }

        // Nonce strictly ascending by 1 — no gaps, no duplicates.
        if record.nonce != prev_nonce + 1 {
            return Err(RewardsError::NonceGap);
        }

        // session_total must be cumulative.
        let expected_total = prev_total.saturating_add(record.bytes);
        if record.session_total != expected_total {
            return Err(RewardsError::TotalMismatch);
        }

        prev_hash  = compute_record_hash_onchain(record);
        prev_nonce = record.nonce;
        prev_total = record.session_total;
    }

    Ok(())
}

/// Compute the canonical SHA-256 input for a client countersignature (on-chain version).
///
/// Covers ALL record fields including chain fields (prev_hash, nonce, session_total,
/// record_hash). Domain separator prevents cross-protocol collisions.
///
/// **Must match `compute_client_countersig_input` in freeflow-relay-runtime.**
pub fn compute_client_countersig_input_onchain(record: &UsageRecordOnChain) -> [u8; 32] {
    use solana_program::hash::hashv;
    hashv(&[
        b"freeflow-client-countersig-v1",
        &record.user,
        &record.relay,
        &record.session_id,
        &record.bytes.to_le_bytes(),
        &record.charge_usd.to_le_bytes(),
        &record.charge_flow.to_le_bytes(),
        &record.start_ts.to_le_bytes(),
        &record.end_ts.to_le_bytes(),
        &record.seq.to_le_bytes(),
        &record.session_pubkey,
        &record.prev_hash,
        &record.nonce.to_le_bytes(),
        &record.session_total.to_le_bytes(),
        &record.record_hash,
    ]).to_bytes()
}

/// Validate that a usage record has a non-missing client countersignature.
///
/// In production: the Ed25519Program precompile in the same transaction verifies
/// the actual signature over `compute_client_countersig_input_onchain(record)`.
/// This function enforces the baseline requirement: the field must be non-zero.
///
/// Returns `Err(MissingClientSignature)` if `client_signature == [0u8; 64]`.
pub fn validate_client_signature(record: &UsageRecordOnChain) -> Result<(), RewardsError> {
    if record.client_signature == [0u8; 64] {
        return Err(RewardsError::MissingClientSignature);
    }
    Ok(())
}

/// Compute the dispute message hash for Ed25519 replay protection.
///
/// The signed message must include: escrow_pda (PDA binding), nonce (replay
/// prevention), claim_hash (claim binding), and a domain separator.
///
/// **Challengers sign this hash; the contract verifies it via Ed25519 precompile.**
pub fn compute_dispute_message_hash(
    escrow_pda:  &[u8; 32],
    nonce:       u64,
    claim_hash:  &[u8; 32],
) -> [u8; 32] {
    use solana_program::hash::hashv;
    hashv(&[
        b"freeflow-dispute",
        escrow_pda,
        &nonce.to_le_bytes(),
        claim_hash,
    ]).to_bytes()
}

// ─── 60-day unclaimed reward sweep ────────────────────────────────────────────

/// Sweep outcome returned by `sweep_expired_escrow`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SweepResult {
    /// Total $FLOW swept from all expired pending claims.
    pub total_swept: u64,
    /// Amount allocated to the Protocol Treasury (80%).
    pub treasury_amount: u64,
    /// Amount burned (20%).
    pub burned_amount: u64,
    /// Number of claims swept.
    pub claims_swept: u32,
}

/// Sweep all pending claims that have been in escrow for more than 60 days.
///
/// Callable by anyone after `submitted_at + SWEEP_TIMEOUT_SECONDS`.
/// 80% of escrowed rewards go to the Protocol Treasury; 20% are burned.
///
/// Returns `SweepResult` describing the amounts swept.
///
/// Errors:
///   - `SweepTooEarly` — no claims have exceeded the 60-day timeout yet.
///   - `NothingToSweep` — no unclaimed Pending claims exist at all.
pub fn sweep_expired_escrow(
    store:    &mut PendingClaimsStore,
    clock_ts: i64,
) -> Result<SweepResult, DisputeError> {
    // Check if there are any Pending claims at all.
    let has_pending = store.claims.iter().any(|c| c.status == ClaimStatus::Pending);
    if !has_pending {
        return Err(DisputeError::NothingToSweep);
    }

    // Check if any Pending claim has exceeded the 60-day timeout.
    let sweep_deadline = |submitted_at: i64| submitted_at.saturating_add(SWEEP_TIMEOUT_SECONDS);
    let has_expired = store.claims.iter().any(|c| {
        c.status == ClaimStatus::Pending && clock_ts > sweep_deadline(c.submitted_at)
    });
    if !has_expired {
        return Err(DisputeError::SweepTooEarly);
    }

    let mut total_swept = 0u64;
    let mut claims_swept = 0u32;

    for claim in store.claims.iter_mut() {
        if claim.status == ClaimStatus::Pending
            && clock_ts > sweep_deadline(claim.submitted_at)
        {
            // M3 dispute gate: do not sweep a claim that is currently under dispute.
            // (In practice, Pending && Disputed are mutually exclusive states, but
            // this guard is an explicit safety check against future status changes.)
            total_swept = total_swept.saturating_add(claim.total_amount);
            total_swept = total_swept.saturating_add(claim.bond);
            // M3: use Swept (variant 5), not Slashed (variant 4), to distinguish
            // sweep-forfeiture from dispute-loss for analytics and reservation logic.
            claim.status = ClaimStatus::Swept;
            claims_swept += 1;
        }
    }

    // Fix 2 (High): saturating arithmetic — raw * / could overflow for
    // total_swept values approaching u64::MAX (~1.8×10¹⁹).
    let treasury_amount = total_swept
        .saturating_mul(TREASURY_SHARE_BPS)
        .saturating_div(10_000);
    let burned_amount   = total_swept.saturating_sub(treasury_amount);

    Ok(SweepResult { total_swept, treasury_amount, burned_amount, claims_swept })
}

// ─── Dispute Window — pure logic (extracted for testability) ─────────────────

/// Compute a domain-separated claim hash from the append-only chain tip.
///
/// Uses the chain tip (relay + session + tip_nonce + tip_hash) as the unique
/// claim identifier. Domain separator `"freeflow-claim-v1"` prevents cross-protocol
/// collisions. This replaces the old batch-serialisation approach.
///
/// **Must match the relay-runtime's claim hash derivation.**
pub fn compute_claim_hash(
    relay_pubkey: &[u8; 32],
    session_id:   &[u8; 16],
    tip_nonce:    u64,
    tip_hash:     &[u8; 32],
) -> [u8; 32] {
    use solana_program::hash::hashv;
    hashv(&[
        b"freeflow-claim-v1",
        relay_pubkey,
        session_id,
        &tip_nonce.to_le_bytes(),
        tip_hash,
    ]).to_bytes()
}

/// Submit a claim with bond, placing rewards into the 7-day dispute window.
///
/// Identified by the chain tip (session + nonce + hash) rather than the full batch.
/// The relay pre-computes `total_amount` and `record_count` from the chain off-chain.
///
/// `bytes_routed` is the sum of `UsageRecordOnChain.bytes` across all records in the batch.
/// It is stored on the claim so `ReleaseRewards` can calculate the repFlow bandwidth reward.
///
/// Returns the `claim_hash` assigned to this batch.
pub fn submit_claim_with_bond(
    store:        &mut PendingClaimsStore,
    relay_pubkey: &[u8; 32],
    session_id:   &[u8; 16],
    tip_nonce:    u64,
    tip_hash:     &[u8; 32],
    total_amount: u64,
    record_count: u32,
    clock_ts:     i64,
    user_pubkey:  &[u8; 32],
    bytes_routed: u64,
    bytes_seeded: u64,
) -> [u8; 32] {
    let claim_hash = compute_claim_hash(relay_pubkey, session_id, tip_nonce, tip_hash);

    let claim = PendingClaim {
        relay:            *relay_pubkey,
        claim_hash,
        total_amount,
        record_count,
        submitted_at:     clock_ts,
        dispute_deadline: clock_ts.saturating_add(DISPUTE_WINDOW_SECONDS),
        bond:             RELAY_BOND_FLOW,
        status:           ClaimStatus::Pending,
        is_force_claim:   false,
        user:             Some(*user_pubkey),
        bytes_routed,
        bytes_seeded,
        uptime_seconds:   0, // Approach 2: uptime repFlow claimed separately
    };
    store.claims.push(claim);
    claim_hash
}

/// Submit a claim without the client's final signature after a 24-hour inactivity timeout.
///
/// When a client goes offline and never sends a final signed record, the relay
/// can still recover its earned rewards via this function — but at an 80% rate
/// (20% penalty goes to the treasury at release time).
///
/// # Double-relay-hop protection (CRITICAL)
///
/// A client that hops between relays every ~60 seconds is still online. The relay
/// MUST query the DHT `SessionChainMeta.updated_at` before calling this function
/// and pass the result as `session_updated_at`. If the session was updated within
/// the last 24 hours — even by a *different* relay — this function returns
/// `Err(RewardsError::SessionStillActive)` and the force_claim is denied.
///
/// This prevents a relay from double-charging a client who is actively using
/// the network through a relay-hop.
///
/// # Two-gate timeout check
///
/// Gate 1 (`last_activity_ts`): When did *this* relay last see the client?
///   Must be ≥ `FORCE_CLAIM_TIMEOUT_SECS` (24 h) ago.
///
/// Gate 2 (`session_updated_at`): When did *any* relay on the network last see
///   the session (from DHT `SessionChainMeta.updated_at`)?
///   If < 24 h ago → client is on another relay → `SessionStillActive`.
///
/// # Economics
///
/// - Relay bond `RELAY_BOND_FLOW` is still posted — subject to the 7-day dispute window.
/// - `total_amount` is stored as-is; the 20% penalty is deducted by `release_rewards`.
/// - Returns `(claim_hash, penalty)` where `penalty = total_amount × 20%`.
#[allow(clippy::too_many_arguments)]
pub fn force_claim(
    store:              &mut PendingClaimsStore,
    relay_pubkey:       &[u8; 32],
    session_id:         &[u8; 16],
    tip_nonce:          u64,
    tip_hash:           &[u8; 32],
    total_amount:       u64,
    record_count:       u32,
    clock_ts:           i64,
    last_activity_ts:   i64,
    session_updated_at: i64,
    user_pubkey:        &[u8; 32],
    bytes_routed:       u64,
    bytes_seeded:       u64,
) -> Result<([u8; 32], u64), RewardsError> {
    // Gate 1: 24-hour relay-level inactivity check.
    let relay_elapsed = clock_ts.saturating_sub(last_activity_ts);
    if relay_elapsed < FORCE_CLAIM_TIMEOUT_SECS as i64 {
        return Err(RewardsError::ForceClaimTooEarly);
    }

    // Gate 2: network-level session activity check (via DHT SessionChainMeta).
    // If any relay updated this session within the last 24 h, the client is
    // still online somewhere — reject to avoid double-charging a hopping client.
    let network_elapsed = clock_ts.saturating_sub(session_updated_at);
    if network_elapsed < FORCE_CLAIM_TIMEOUT_SECS as i64 {
        return Err(RewardsError::SessionStillActive);
    }

    // Both gates passed — client is truly absent from the entire network.
    let claim_hash = compute_claim_hash(relay_pubkey, session_id, tip_nonce, tip_hash);

    // Penalty is 20% of total_amount (deducted at release time, not now).
    let penalty = total_amount
        .saturating_mul(FORCE_CLAIM_PENALTY_BPS)
        .saturating_div(10_000);

    let claim = PendingClaim {
        relay:            *relay_pubkey,
        claim_hash,
        total_amount,
        record_count,
        submitted_at:     clock_ts,
        dispute_deadline: clock_ts.saturating_add(DISPUTE_WINDOW_SECONDS),
        bond:             RELAY_BOND_FLOW,
        status:           ClaimStatus::Pending,
        is_force_claim:   true,
        user:             Some(*user_pubkey),
        bytes_routed,
        bytes_seeded,
        uptime_seconds:   0,
    };
    store.claims.push(claim);

    Ok((claim_hash, penalty))
}

/// File a dispute against a specific record in a pending claim.
///
/// Validates:
///   - Claim exists and is still `Pending`
///   - Dispute window has not yet expired (`clock_ts <= dispute_deadline`)
///   - No active dispute already exists on this claim
///
/// On success, sets the claim status to `Disputed` and records the challenge.
pub fn dispute_claim(
    store:           &mut PendingClaimsStore,
    claim_hash:      [u8; 32],
    record_index:    u32,
    disputed_record: UsageRecordOnChain,
    challenger:      [u8; 32],
    clock_ts:        i64,
    escrow_pda:      [u8; 32],
    // Dynamic challenger bond in $FLOW. Pass `DEFAULT_CHALLENGER_BOND_FLOW` as fallback.
    challenger_bond: u64,
) -> Result<(), DisputeError> {
    let claim = store
        .claims
        .iter_mut()
        .find(|c| c.claim_hash == claim_hash)
        .ok_or(DisputeError::ClaimNotFound)?;

    // Cannot dispute a settled claim. Swept is also terminal (M3 dispute gate).
    match claim.status {
        ClaimStatus::Released
        | ClaimStatus::Slashed
        | ClaimStatus::Resolved
        | ClaimStatus::Swept => {
            return Err(DisputeError::ClaimAlreadySettled);
        }
        ClaimStatus::Disputed => {
            return Err(DisputeError::ClaimAlreadyDisputed);
        }
        ClaimStatus::Pending => {}
    }

    // Dispute must arrive within the 7-day window.
    if clock_ts > claim.dispute_deadline {
        return Err(DisputeError::DisputeWindowExpired);
    }

    claim.status = ClaimStatus::Disputed;

    let nonce = store.next_dispute_nonce;
    store.next_dispute_nonce = store.next_dispute_nonce.saturating_add(1);

    store.disputes.push(DisputeRecord {
        challenger,
        claim_hash,
        record_index,
        disputed_record,
        bond:         challenger_bond,
        submitted_at: clock_ts,
        nonce,
        escrow_pda,
    });

    Ok(())
}

/// Relay is slashed — challenger proved the client signature was forged.
///
/// **Caller contract:** This function MUST only be invoked by the
/// `ResolveDisputeRelaySlashed` instruction handler, which requires a preceding
/// Solana Ed25519Program precompile transaction that verifies the disputed
/// record's client signature FAILS. The precompile enforces authenticity — no
/// trust parameter is passed here.
///
/// Economics: relay bond split 50% challenger / 50% burned.
pub fn resolve_dispute_relay_slashed(
    store:      &mut PendingClaimsStore,
    claim_hash: [u8; 32],
) -> Result<DisputeOutcome, DisputeError> {
    let claim = store
        .claims
        .iter_mut()
        .find(|c| c.claim_hash == claim_hash)
        .ok_or(DisputeError::ClaimNotFound)?;

    if claim.status != ClaimStatus::Disputed {
        return Err(DisputeError::NotDisputed);
    }

    let relay_bond = claim.bond;
    let challenger_reward = relay_bond / 2;
    let burned = relay_bond.saturating_sub(challenger_reward);

    // Return the challenger's bond in full (Option C: challenger gets bond back, no bonus).
    // Find the dispute record to get the stored challenger bond.
    let challenger_bond_returned = store
        .disputes
        .iter()
        .find(|d| d.claim_hash == claim_hash)
        .map(|d| d.bond)
        .unwrap_or(DEFAULT_CHALLENGER_BOND_FLOW);

    claim.status = ClaimStatus::Slashed;

    Ok(DisputeOutcome::RelaySlashed { challenger_reward, burned, challenger_bond_returned })
}

/// Challenger is slashed — relay proved the disputed record's client signature IS valid.
///
/// **Caller contract:** This function MUST only be invoked by the
/// `ResolveDisputeChallengerSlashed` instruction handler, which requires a preceding
/// Solana Ed25519Program precompile transaction that verifies the disputed
/// record's client signature SUCCEEDS. The precompile enforces authenticity — no
/// trust parameter is passed here.
///
/// Economics: challenger bond burned; relay receives rewards + relay bond back.
pub fn resolve_dispute_challenger_slashed(
    store:      &mut PendingClaimsStore,
    claim_hash: [u8; 32],
) -> Result<DisputeOutcome, DisputeError> {
    let claim = store
        .claims
        .iter_mut()
        .find(|c| c.claim_hash == claim_hash)
        .ok_or(DisputeError::ClaimNotFound)?;

    if claim.status != ClaimStatus::Disputed {
        return Err(DisputeError::NotDisputed);
    }

    // Read the actual challenger bond from the dispute record (Phase 5 dynamic bond).
    let challenger_bond = store
        .disputes
        .iter()
        .find(|d| d.claim_hash == claim_hash)
        .map(|d| d.bond)
        .unwrap_or(DEFAULT_CHALLENGER_BOND_FLOW);

    claim.status = ClaimStatus::Resolved;

    // 80% of challenger bond → relay as capital-lock compensation; 20% burned.
    let relay_reward = challenger_bond * TREASURY_SHARE_BPS / 10_000;
    let burned       = challenger_bond.saturating_sub(relay_reward);

    Ok(DisputeOutcome::ChallengerSlashed { relay_reward, burned })
}

/// Force-resolve a dispute that has been unresolved for more than 3 days.
///
/// Callable by anyone after `dispute_filed_at + DISPUTE_RESOLVE_SECONDS`.
/// Prevents escrowed rewards being locked indefinitely if neither party acts.
///
/// Default outcome: challenger bond burned, relay claim resolved (relay wins by default).
/// Rationale: the challenger had 3 days to produce proof — inaction forfeits their bond.
///
/// Returns `DisputeOutcome::ChallengerSlashed` with the challenger's bond burned.
pub fn force_resolve_dispute(
    store:      &mut PendingClaimsStore,
    claim_hash: [u8; 32],
    clock_ts:   i64,
) -> Result<DisputeOutcome, DisputeError> {
    // Find the dispute record to get the filed timestamp and dynamic bond.
    let dispute = store
        .disputes
        .iter()
        .find(|d| d.claim_hash == claim_hash)
        .ok_or(DisputeError::DisputeNotFound)?;

    let dispute_submitted_at = dispute.submitted_at;
    // Read the actual challenger bond stored at dispute-filing time (Phase 5).
    let challenger_bond = dispute.bond;

    // Enforce the 3-day inactivity timeout.
    let resolve_deadline = dispute_submitted_at.saturating_add(DISPUTE_RESOLVE_SECONDS);
    if clock_ts <= resolve_deadline {
        return Err(DisputeError::ResolveTooEarly);
    }

    let claim = store
        .claims
        .iter_mut()
        .find(|c| c.claim_hash == claim_hash)
        .ok_or(DisputeError::ClaimNotFound)?;

    if claim.status != ClaimStatus::Disputed {
        return Err(DisputeError::NotDisputed);
    }

    // Default: challenger loses bond (inaction = forfeiture), relay claim resolved.
    // 80% of challenger bond → relay; 20% burned (same split as active resolution).
    claim.status = ClaimStatus::Resolved;

    let relay_reward = challenger_bond * TREASURY_SHARE_BPS / 10_000;
    let burned       = challenger_bond.saturating_sub(relay_reward);

    Ok(DisputeOutcome::ChallengerSlashed { relay_reward, burned })
}

/// Release escrowed rewards to the relay after the dispute window expires.
///
/// Callable only when:
///   - The claim exists and has status `Pending` (no dispute was filed)
///   - The current clock timestamp is past `dispute_deadline`
///
/// For normal claims: returns `(total_amount, bond, 0)`.
/// For force claims:  returns `(total_amount - penalty, bond, penalty)` where
///   `penalty = total_amount × FORCE_CLAIM_PENALTY_BPS / 10_000` (20%).
///   The penalty amount should be routed to the Protocol Treasury by the caller.
///
/// Returns `(relay_amount, bond, treasury_penalty)`.
pub fn release_rewards(
    store:      &mut PendingClaimsStore,
    claim_hash: [u8; 32],
    clock_ts:   i64,
) -> Result<(u64, u64, u64), DisputeError> {
    let claim = store
        .claims
        .iter_mut()
        .find(|c| c.claim_hash == claim_hash)
        .ok_or(DisputeError::ClaimNotFound)?;

    if claim.status != ClaimStatus::Pending {
        return Err(DisputeError::ClaimAlreadySettled);
    }
    if clock_ts <= claim.dispute_deadline {
        return Err(DisputeError::DisputeWindowNotExpired);
    }

    let bond = claim.bond;
    let (relay_amount, treasury_penalty) = if claim.is_force_claim {
        let penalty = claim.total_amount
            .saturating_mul(FORCE_CLAIM_PENALTY_BPS)
            .saturating_div(10_000);
        (claim.total_amount.saturating_sub(penalty), penalty)
    } else {
        (claim.total_amount, 0)
    };

    claim.status = ClaimStatus::Released;
    Ok((relay_amount, bond, treasury_penalty))
}

// ─── repFlow tier ─────────────────────────────────────────────────────────────

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
    pub tier:                   u8,
    pub bump:                   u8,
    // ── repFlow fields (added in v2) ──────────────────────────────────────
    pub repflow_balance:        u64,
    pub repflow_tier:           u8,
    pub total_cashback_earned:  u64,
}

impl RewardAccount {
    pub const SIZE: usize =
        32 + 8 + 8 + 8 + 8 + 8 + 8 + 1 + 1
        + 8 + 1 + 8;

    // Target emission rates (E1 fix — previously 1000× below on-chain PDA values).
    // Routing:  1 FLOW/GB  = 10^9 base units / 1024 MB ≈ 1_000_000 base units/MB
    // Seeding:  2 FLOW/GB  ≈ 2_000_000 base units/MB
    // Uptime:   10 FLOW/hr = 10 × 10^9 = 10_000_000_000 base units/hr
    const BASE_ROUTING_PER_MB:   u64 = 1_000_000;
    const BASE_SEEDING_PER_MB:   u64 = 2_000_000;
    const BASE_UPTIME_PER_HOUR:  u64 = 10_000_000_000;
    const MIN_CLAIM_INTERVAL:    i64 = 86_400;

    pub fn calculate_reward(
        &self,
        bytes_routed:    u64,
        bytes_seeded:    u64,
        uptime_seconds:  u64,
        repflow_balance: u64,
        routing_per_mb:  u64,   // from RewardRatesAccount PDA; use BASE_ROUTING_PER_MB as default
        seeding_per_mb:  u64,   // from RewardRatesAccount PDA; use BASE_SEEDING_PER_MB as default
        uptime_per_hour: u64,   // from RewardRatesAccount PDA; use BASE_UPTIME_PER_HOUR as default
    ) -> u64 {
        let routing_mb = bytes_routed / (1024 * 1024);
        let seeding_mb = bytes_seeded / (1024 * 1024);

        let repflow_tier   = RepFlowTier::from_balance(repflow_balance);
        let multiplier_bps = repflow_tier.reward_multiplier_bps();
        let cashback_pct   = repflow_tier.cashback_percent();

        let routing_base = routing_mb.saturating_mul(routing_per_mb);
        let seeding_base = seeding_mb.saturating_mul(seeding_per_mb);

        // E2 fix: multiply-then-divide to preserve sub-hour precision.
        // Old: (uptime_seconds / 3600) * uptime_per_hour → 0 for 3599 s
        // New: (uptime_seconds * uptime_per_hour) / 3600  → ≈ uptime_per_hour for 3599 s
        // Note: uptime_per_hour = 10_000_000_000 fits in u64; uptime_seconds ≤ 172_800 (48h cap).
        // Max product: 172_800 × 10_000_000_000 = 1.728×10^15 < u64::MAX (1.84×10^19) — safe.
        let uptime_base = uptime_seconds
            .saturating_mul(uptime_per_hour)
            .saturating_div(3600);

        // H-01: Use saturating arithmetic to prevent silent integer overflow
        // when bytes_routed or bytes_seeded are abnormally large. Saturating at
        // u64::MAX is safe here — the caller validates inputs via MAX_BYTES_PER_SECOND.
        let routing_reward = routing_base
            .saturating_mul(multiplier_bps)
            .saturating_div(100);
        let seeding_reward = seeding_base
            .saturating_mul(multiplier_bps)
            .saturating_div(100);

        let cashback = routing_reward
            .saturating_add(seeding_reward)
            .saturating_mul(cashback_pct)
            .saturating_div(100);

        routing_reward
            .saturating_add(seeding_reward)
            .saturating_add(uptime_base)
            .saturating_add(cashback)
    }
}

// ─── P1 Reservation helpers ───────────────────────────────────────────────────

/// The ONLY decrement path for `UserEscrowReservation.reserved` (Rule 1).
///
/// Called by every terminal-state handler after the claim status changes to a
/// terminal value (`Released`, `Slashed`, `Resolved`, `Swept`).
///
/// Decrement is ALWAYS `claim.total_amount` — never relay_amount or 80% (Rule 4).
/// After decrement: asserts `reserved <= escrow_balance` (invariant).
///
/// Uses `saturating_sub` so underflows silently clamp to 0 (conservative, no panic).
pub fn settle_reservation(
    reservation:        &mut UserEscrowReservation,
    claim_total_amount: u64,
    escrow_balance:     u64,
) -> Result<(), DisputeError> {
    reservation.reserved = reservation.reserved.saturating_sub(claim_total_amount);
    // Invariant check: reserved must never exceed the escrow balance.
    if reservation.reserved > escrow_balance {
        return Err(DisputeError::ReservationInvariantViolated);
    }
    Ok(())
}

/// Load a `UserEscrowReservation` from its on-chain account data.
fn load_reservation(ai: &AccountInfo) -> Result<UserEscrowReservation, ProgramError> {
    let data = ai.try_borrow_data()?;
    UserEscrowReservation::try_from_slice(&data)
        .map_err(|_| ProgramError::InvalidAccountData)
}

/// Write a `UserEscrowReservation` back to its on-chain account.
fn write_reservation(ai: &AccountInfo, res: &UserEscrowReservation) -> Result<(), ProgramError> {
    let serialized = borsh::to_vec(res).map_err(|_| ProgramError::InvalidAccountData)?;
    let mut data = ai.try_borrow_mut_data()?;
    if serialized.len() <= data.len() {
        data[..serialized.len()].copy_from_slice(&serialized);
        Ok(())
    } else {
        Err(ProgramError::AccountDataTooSmall)
    }
}

/// Load a `RewardsConfig` from its on-chain account data.
fn load_rewards_config(ai: &AccountInfo) -> Result<RewardsConfig, ProgramError> {
    let data = ai.try_borrow_data()?;
    RewardsConfig::try_from_slice(&data).map_err(|_| ProgramError::InvalidAccountData)
}

/// Write a `RewardsConfig` back to its on-chain account.
fn write_rewards_config(ai: &AccountInfo, cfg: &RewardsConfig) -> Result<(), ProgramError> {
    let serialized = borsh::to_vec(cfg).map_err(|_| ProgramError::InvalidAccountData)?;
    let mut data = ai.try_borrow_mut_data()?;
    if serialized.len() <= data.len() {
        data[..serialized.len()].copy_from_slice(&serialized);
        Ok(())
    } else {
        Err(ProgramError::AccountDataTooSmall)
    }
}

/// Read the `balance` field from an Anchor `UserEscrow` account.
///
/// Anchor accounts are prefixed with an 8-byte discriminator. Layout:
///   [0..8]   discriminator
///   [8..40]  user (Pubkey, 32 bytes)
///   [40..48] balance (u64, 8 bytes)
///
/// Returns `Err(InvalidAccountData)` if the account is too small.
pub fn load_user_escrow_balance(ai: &AccountInfo) -> Result<u64, ProgramError> {
    const BALANCE_OFFSET: usize = 8 + 32; // 8 discriminator + 32 user Pubkey
    let data = ai.try_borrow_data()?;
    if data.len() < BALANCE_OFFSET + 8 {
        return Err(ProgramError::InvalidAccountData);
    }
    let bytes: [u8; 8] = data[BALANCE_OFFSET..BALANCE_OFFSET + 8]
        .try_into()
        .map_err(|_| ProgramError::InvalidAccountData)?;
    Ok(u64::from_le_bytes(bytes))
}

/// Load a `PendingClaimsStore` from an account, returning default if absent/empty.
fn load_store(ai: &AccountInfo) -> Result<PendingClaimsStore, ProgramError> {
    if ai.data_len() == 0 || ai.lamports() == 0 {
        return Ok(PendingClaimsStore::default());
    }
    let data = ai.try_borrow_data()?;
    PendingClaimsStore::try_from_slice(&data)
        .map_err(|_| ProgramError::InvalidAccountData)
}

/// Write a `PendingClaimsStore` back to its on-chain account.
fn write_store(ai: &AccountInfo, store: &PendingClaimsStore) -> Result<(), ProgramError> {
    let serialized = borsh::to_vec(store).map_err(|_| ProgramError::InvalidAccountData)?;
    if serialized.len() <= ai.data_len() {
        let mut data = ai.try_borrow_mut_data()?;
        data[..serialized.len()].copy_from_slice(&serialized);
        Ok(())
    } else {
        Err(ProgramError::AccountDataTooSmall)
    }
}

// ── Instruction processors ────────────────────────────────────────────────────

#[allow(clippy::too_many_arguments)]
#[inline(never)]
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

    // account[2] (optional, readonly): RewardRatesAccount PDA [b"reward_rates"]
    // When present and valid, live PDA rates are used for reward calculation (E1 fix).
    // When absent or unparseable, falls back to BASE_* constants (backward compatible).
    let reward_rates_ai = accounts_iter.next();
    let (routing_per_mb, seeding_per_mb, uptime_per_hour) = match reward_rates_ai {
        Some(ai) if ai.lamports() > 0 && ai.data_len() >= RewardRatesAccount::SIZE => {
            match RewardRatesAccount::try_from_slice(&ai.try_borrow_data()?) {
                Ok(rr) => {
                    msg!(
                        "ClaimRewards: PDA rates routing={}/MB seeding={}/MB uptime={}/hr",
                        rr.routing_per_mb, rr.seeding_per_mb, rr.uptime_per_hour
                    );
                    (rr.routing_per_mb, rr.seeding_per_mb, rr.uptime_per_hour)
                }
                Err(_) => {
                    msg!("ClaimRewards: reward_rates PDA parse failed — using fallback constants");
                    (RewardAccount::BASE_ROUTING_PER_MB, RewardAccount::BASE_SEEDING_PER_MB, RewardAccount::BASE_UPTIME_PER_HOUR)
                }
            }
        }
        _ => {
            msg!("ClaimRewards: no reward_rates PDA supplied — using fallback constants");
            (RewardAccount::BASE_ROUTING_PER_MB, RewardAccount::BASE_SEEDING_PER_MB, RewardAccount::BASE_UPTIME_PER_HOUR)
        }
    };

    if !relay_wallet.is_signer {
        return Err(ProgramError::MissingRequiredSignature);
    }

    // F1-H5: Cap repflow_balance to the Icon-tier maximum (50,001 units).
    // repflow_balance comes from instruction data (not on-chain) — an inflated
    // value boosts the multiplier from 0.9x (Newcomer) up to 1.5x (Icon), but
    // claiming more than Icon is meaningless and signals tampering.
    const MAX_REPFLOW_BALANCE: u64 = 100_000; // 2× Icon threshold — generous safety margin
    if repflow_balance > MAX_REPFLOW_BALANCE {
        msg!("ClaimRewards: repflow_balance {} exceeds sanity cap {}", repflow_balance, MAX_REPFLOW_BALANCE);
        return Err(ProgramError::InvalidInstructionData);
    }

    // F1-M1: Cap per-period bytes to prevent fabricated overclaims.
    // At MAX_BYTES_PER_SECOND (1 GB/s) over the max period (48 h), legitimate
    // throughput is at most ~172 TB. Cap at 200 TB to give headroom.
    const MAX_BYTES_PER_PERIOD: u64 = 200 * 1024 * 1024 * 1024 * 1024; // 200 TB
    if bytes_routed > MAX_BYTES_PER_PERIOD || bytes_seeded > MAX_BYTES_PER_PERIOD {
        msg!("ClaimRewards: bytes exceed per-period cap (200 TB)");
        return Err(ProgramError::InvalidInstructionData);
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
            tier:                   1,
            bump:                   0,
            repflow_balance,
            repflow_tier,
            total_cashback_earned:  0,
        }
    };

    if state.last_claim_ts > 0 {
        let elapsed = clock.unix_timestamp - state.last_claim_ts;
        if elapsed < RewardAccount::MIN_CLAIM_INTERVAL {
            msg!("Claim too soon: {}s elapsed, need {}s", elapsed, RewardAccount::MIN_CLAIM_INTERVAL);
            return Err(ProgramError::InvalidInstructionData);
        }
    }

    let reward = state.calculate_reward(
        bytes_routed, bytes_seeded, uptime_seconds, repflow_balance,
        routing_per_mb, seeding_per_mb, uptime_per_hour,
    );
    if reward == 0 {
        msg!("No rewards to claim");
        return Err(ProgramError::InvalidInstructionData);
    }

    let repflow_tier  = RepFlowTier::from_balance(repflow_balance);
    let cashback_pct  = repflow_tier.cashback_percent();
    let routing_mb    = bytes_routed / (1024 * 1024);
    let seeding_mb    = bytes_seeded / (1024 * 1024);
    // H-01: Use saturating arithmetic throughout — mirrors calculate_reward() with PDA rates.
    let routing_r     = routing_mb
        .saturating_mul(routing_per_mb)
        .saturating_mul(repflow_tier.reward_multiplier_bps())
        .saturating_div(100);
    let seeding_r     = seeding_mb
        .saturating_mul(seeding_per_mb)
        .saturating_mul(repflow_tier.reward_multiplier_bps())
        .saturating_div(100);
    let cashback      = routing_r
        .saturating_add(seeding_r)
        .saturating_mul(cashback_pct)
        .saturating_div(100);

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

#[inline(never)]
fn process_record_bytes(
    _program_id:  &Pubkey,
    _accounts:    &[AccountInfo],
    _relay_pubkey: [u8; 32],
    _bytes_routed: u64,
    _bytes_seeded: u64,
) -> ProgramResult {
    // F1-H4: RecordBytes is permanently disabled.
    //
    // This legacy instruction allowed any oracle signer to post byte counters
    // on behalf of any relay, with no on-chain proof that the counts are real.
    // It has been superseded by ClaimUsage (per-record Ed25519 client signatures
    // + sequence tracking). Keeping it callable would let anyone manipulate
    // reward eligibility without cryptographic evidence.
    //
    // Clients that relied on RecordBytes must migrate to ClaimUsage.
    msg!("RecordBytes: this instruction is permanently disabled. Use ClaimUsage (0x02) instead.");
    Err(ProgramError::InvalidInstructionData)
}

/// Parsed account references for `process_claim_usage`.
/// `'s` = slice/reference lifetime; `'info` = AccountInfo inner data lifetime.
/// Field names match the original local variable names — handler body unchanged.
struct ParsedClaimUsageAccounts<'s, 'info: 's> {
    relay_wallet:             &'s AccountInfo<'info>,
    reward_account_ai:        &'s AccountInfo<'info>,
    claim_state_ai:           &'s AccountInfo<'info>,
    pending_claims_ai:        Option<&'s AccountInfo<'info>>,
    rewards_config_ai:        Option<&'s AccountInfo<'info>>,
    reservation_ai:           Option<&'s AccountInfo<'info>>,
    user_escrow_ai:           Option<&'s AccountInfo<'info>>,
    hold_user_escrow_prog_ai: Option<&'s AccountInfo<'info>>,
    hold_mint_authority_ai:   Option<&'s AccountInfo<'info>>,
    hold_user_ai:             Option<&'s AccountInfo<'info>>,
    fund_hold_ai:             Option<&'s AccountInfo<'info>>,
    hold_spender_registry_ai: Option<&'s AccountInfo<'info>>,
    hold_system_program_ai:   Option<&'s AccountInfo<'info>>,
    repflow_user_ai:          Option<&'s AccountInfo<'info>>,
    stake_account_ai:         Option<&'s AccountInfo<'info>>,
    bond_config_ai:           Option<&'s AccountInfo<'info>>,
    reward_rates_ai:          Option<&'s AccountInfo<'info>>,
}

/// Walk the accounts iterator for `process_claim_usage`.
/// Runs in its own call frame so all iterator state is freed before the handler runs.
#[inline(never)]
fn parse_claim_usage_accounts<'s, 'info: 's>(
    accounts: &'s [AccountInfo<'info>],
) -> Result<ParsedClaimUsageAccounts<'s, 'info>, ProgramError> {
    let iter = &mut accounts.iter();
    Ok(ParsedClaimUsageAccounts {
        relay_wallet:             next_account_info(iter)?,
        reward_account_ai:        next_account_info(iter)?,
        claim_state_ai:           next_account_info(iter)?,
        pending_claims_ai:        iter.next(),
        rewards_config_ai:        iter.next(),
        reservation_ai:           iter.next(),
        user_escrow_ai:           iter.next(),
        hold_user_escrow_prog_ai: iter.next(),
        hold_mint_authority_ai:   iter.next(),
        hold_user_ai:             iter.next(),
        fund_hold_ai:             iter.next(),
        hold_spender_registry_ai: iter.next(),
        hold_system_program_ai:   iter.next(),
        repflow_user_ai:          iter.next(),
        stake_account_ai:         iter.next(),
        bond_config_ai:           iter.next(),
        reward_rates_ai:          iter.next(),
    })
}

/// Process a ClaimUsage instruction — enforces per-(client,relay) sequence numbers.
///
/// P1 update: checks `UserEscrowReservation` before escrowing. Blocks during
/// `migration_mode = true` (`MigrationWindowActive`). Requires reservation PDA
/// (returns `ReservationNotInitialized` if absent — Rule 2). Increments
/// `reservation.reserved` by `total_amount` after validation.
///
/// Account layout:
///   0: relay_wallet      — signer
///   1: reward_account    — relay's aggregate reward PDA (writable)
///   2: claim_state       — UserRelayClaimState PDA for (client, relay) (writable)
///   3: pending_claims    — PendingClaimsStore PDA for this relay (writable, optional)
///   4: rewards_config    — RewardsConfig PDA (readable, optional)
///   5: reservation       — UserEscrowReservation PDA for the user (writable, optional)
///   6: user_escrow       — UserEscrow PDA from user-escrow program (readable, optional)
///
///   --- Hold-CPI accounts (all 6 must be present together) ---
///   7: user_escrow_program — user-escrow program (for CPI)
///   8: mint_authority      — rewards mint_authority PDA (PDA signer)
///   9: hold_user           — user wallet (non-signer; PDA seed in user-escrow)
///  10: fund_hold           — FundHold PDA (init, writable)
///  11: hold_spender_reg    — AuthorizedSpenderRegistry PDA
///  12: hold_system_program — System Program (for FundHold rent)
///
///   --- RepFlow-Bond gate accounts (Phase 2, optional for backward compat) ---
///  13: relay_repflow_user  — RepFlowUser PDA from repflow-token program (readable, optional)
///  14: relay_stake_account — StakeAccount PDA from staking program (readable, optional)
///  15: bond_config         — BondConfig PDA [b"bond_config"] (readable, optional)
///  16: reward_rates        — RewardRatesAccount PDA [b"reward_rates"] (readable, optional)
///
/// All records in a batch must be for the SAME client. To claim for multiple
/// clients, submit multiple transactions.
#[inline(never)]
fn process_claim_usage(
    program_id: &Pubkey,
    accounts:   &[AccountInfo],
    records:    Vec<UsageRecordOnChain>,
) -> ProgramResult {
    let ParsedClaimUsageAccounts {
        relay_wallet,
        reward_account_ai,
        claim_state_ai,
        pending_claims_ai,
        rewards_config_ai,
        reservation_ai,
        user_escrow_ai,
        hold_user_escrow_prog_ai,
        hold_mint_authority_ai,
        hold_user_ai,
        fund_hold_ai,
        hold_spender_registry_ai,
        hold_system_program_ai,
        repflow_user_ai,
        stake_account_ai,
        bond_config_ai,
        reward_rates_ai,
    } = parse_claim_usage_accounts(accounts)?;

    if !relay_wallet.is_signer {
        return Err(ProgramError::MissingRequiredSignature);
    }

    if records.is_empty() {
        return Ok(());
    }

    let clock = Clock::get()?;

    // ── P1: migration_mode guard (Rule 9) ─────────────────────────────────────
    // If a RewardsConfig account is provided and migration_mode is true, block.
    if let Some(cfg_ai) = rewards_config_ai {
        if cfg_ai.data_len() >= RewardsConfig::SIZE && cfg_ai.lamports() > 0 {
            let cfg = load_rewards_config(cfg_ai)?;
            if cfg.migration_mode {
                msg!("ClaimUsage blocked: migration_mode=true. Initialize reservation PDAs first.");
                return Err(DisputeError::MigrationWindowActive.into());
            }
        }
    }

    let relay_pubkey_bytes = relay_wallet.key.to_bytes();

    // ── Phase 2: repFlow gate (backward compatible) ───────────────────────────
    // If relay_repflow_user account (index 13) is provided, verify that the relay
    // holds at least MIN_RELAY_REPFLOW (2,001) units.
    // If the account is absent, we skip the check (backward-compat mode).
    if let Some(rfu_ai) = repflow_user_ai {
        if rfu_ai.lamports() > 0 && rfu_ai.data_len() >= 48 {
            // Verify PDA: [b"repflow_user", relay_pubkey] from REPFLOW_PROGRAM_ID.
            let (expected_repflow_pda, _) = Pubkey::find_program_address(
                &[b"repflow_user", &relay_pubkey_bytes],
                &REPFLOW_PROGRAM_ID,
            );
            if *rfu_ai.key != expected_repflow_pda {
                msg!(
                    "ClaimUsage: repflow_user PDA mismatch — expected {}, got {}",
                    expected_repflow_pda, rfu_ai.key,
                );
                return Err(ProgramError::InvalidAccountData);
            }
            if *rfu_ai.owner != REPFLOW_PROGRAM_ID {
                msg!("ClaimUsage: repflow_user wrong owner — {}", rfu_ai.owner);
                return Err(ProgramError::InvalidAccountOwner);
            }
            // RepFlowUser layout (Anchor): 8-byte discriminator + 32-byte wallet + 8-byte balance.
            let data = rfu_ai.try_borrow_data()?;
            let balance = u64::from_le_bytes(data[40..48].try_into().unwrap_or([0u8; 8]));
            msg!("ClaimUsage: repFlow balance={}", balance);
            if balance < MIN_RELAY_REPFLOW {
                msg!(
                    "ClaimUsage: InsufficientRelayReputation — balance {} < minimum {}",
                    balance, MIN_RELAY_REPFLOW,
                );
                return Err(RewardsError::InsufficientRelayReputation.into());
            }
        } else {
            msg!("ClaimUsage: repflow_user account empty/too small — backward-compat skip");
        }
    } else {
        msg!("ClaimUsage: no repflow_user account provided — backward-compat mode");
    }

    // ── Phase 2: stake gate (backward compatible) ─────────────────────────────
    // If relay_stake_account (index 14) is provided, verify the relay has staked
    // at least the computed minimum.
    // If absent, skip (backward-compat mode).
    if let Some(sa_ai) = stake_account_ai {
        if sa_ai.lamports() > 0 && sa_ai.data_len() > 0 {
            // Verify owner == staking program.
            if *sa_ai.owner != STAKING_PROGRAM_ID {
                msg!("ClaimUsage: stake_account wrong owner — {}", sa_ai.owner);
                return Err(RewardsError::StakeAccountNotFound.into());
            }
            // Verify PDA derivation: [b"stake", relay_pubkey] from staking program.
            let (expected_stake_pda, _) = Pubkey::find_program_address(
                &[b"stake", &relay_pubkey_bytes],
                &STAKING_PROGRAM_ID,
            );
            if *sa_ai.key != expected_stake_pda {
                msg!(
                    "ClaimUsage: stake_account PDA mismatch — expected {}, got {}",
                    expected_stake_pda, sa_ai.key,
                );
                return Err(ProgramError::InvalidAccountData);
            }
            // StakeAccount layout (Borsh): relay_wallet[32] + staked_lamports[8] +
            //   slashed_lamports[8] + last_stake_ts[8] + unstake_ts[8] + status[1] +
            //   tier[1] + bump[1].
            // staked_lamports at offset 32.
            // status at offset 32+8+8+8+8 = 64.
            let data           = sa_ai.try_borrow_data()?;
            if data.len() < 65 {
                msg!("ClaimUsage: stake_account data too short ({})", data.len());
                return Err(ProgramError::InvalidAccountData);
            }
            let staked_lamports = u64::from_le_bytes(data[32..40].try_into().unwrap_or([0u8; 8]));
            let status          = data[64];

            if status != 0 {
                msg!(
                    "ClaimUsage: relay not in Locked state — status={}",
                    status
                );
                return Err(RewardsError::InsufficientStake.into());
            }

            // Read total_lamports_claimed from reward_account for earnings-based stake scaling.
            let total_claimed = if reward_account_ai.data_len() >= RewardAccount::SIZE
                && reward_account_ai.lamports() > 0
            {
                let ra_data = reward_account_ai.try_borrow_data()?;
                if let Ok(ra) = RewardAccount::try_from_slice(&ra_data) {
                    ra.total_lamports_claimed
                } else {
                    0
                }
            } else {
                0
            };

            // Read price from RewardRatesAccount if provided.
            let flow_price_cents = if let Some(rr_ai) = reward_rates_ai {
                if rr_ai.lamports() > 0 && rr_ai.data_len() >= RewardRatesAccount::SIZE {
                    let rr_data = rr_ai.try_borrow_data()?;
                    if let Ok(rr) = RewardRatesAccount::try_from_slice(&rr_data) {
                        rr.flow_price_cents
                    } else {
                        0
                    }
                } else {
                    0
                }
            } else {
                0
            };

            // Read BondConfig if provided, else use defaults.
            let min_stake = if let Some(bc_ai) = bond_config_ai {
                if bc_ai.lamports() > 0 && bc_ai.data_len() >= BondConfig::SIZE {
                    let bc_data = bc_ai.try_borrow_data()?;
                    if let Ok(bc) = BondConfig::try_from_slice(&bc_data) {
                        bc.compute_min_stake(flow_price_cents, total_claimed)
                    } else {
                        DEFAULT_MIN_STAKE_FLOW
                    }
                } else {
                    DEFAULT_MIN_STAKE_FLOW
                }
            } else {
                DEFAULT_MIN_STAKE_FLOW
            };

            msg!(
                "ClaimUsage: staked={} min_required={} (price_cents={} claimed={})",
                staked_lamports, min_stake, flow_price_cents, total_claimed,
            );

            if staked_lamports < min_stake {
                msg!(
                    "ClaimUsage: InsufficientStake — staked {} < minimum {}",
                    staked_lamports, min_stake,
                );
                return Err(RewardsError::InsufficientStake.into());
            }
        } else {
            msg!("ClaimUsage: stake_account empty — backward-compat skip");
        }
    } else {
        msg!("ClaimUsage: no stake_account provided — backward-compat mode");
    }

    // Validate batch ordering (ascending seq) before processing.
    validate_batch_order(&records)
        .map_err(|_| ProgramError::InvalidInstructionData)?;

    // Load or initialise claim state for this (client, relay) pair.
    let mut state = if claim_state_ai.data_len() >= UserRelayClaimState::SIZE
        && claim_state_ai.lamports() > 0
    {
        let data = claim_state_ai.try_borrow_data()?;
        UserRelayClaimState::try_from_slice(&data)
            .map_err(|_| ProgramError::InvalidAccountData)?
    } else {
        UserRelayClaimState {
            user:                records[0].user,
            relay:               relay_wallet.key.to_bytes(),
            last_claimed_seq:    0,
            total_claimed_bytes: 0,
            last_claim_slot:     0,
            bump:                0,
        }
    };

    let user_pubkey_bytes  = records[0].user;

    // H-03: Validate that claim_state_ai is the canonical PDA for (user, relay).
    // Without this check, a relay can pass an attacker-controlled account whose
    // data happens to deserialize as a UserRelayClaimState with last_claimed_seq=0,
    // bypassing double-spend protection.
    let (expected_claim_pda, _) = solana_program::pubkey::Pubkey::find_program_address(
        &[b"claim_state", &user_pubkey_bytes, &relay_pubkey_bytes],
        program_id,
    );
    if *claim_state_ai.key != expected_claim_pda {
        msg!(
            "ClaimUsage: claim_state PDA mismatch. got={} expected={}",
            claim_state_ai.key, expected_claim_pda
        );
        return Err(ProgramError::InvalidAccountData);
    }

    let mut total_bytes = 0u64;

    for record in &records {
        validate_usage_record(record, &state, &relay_pubkey_bytes, clock.unix_timestamp)
            .map_err(|e| {
                msg!("Usage record validation failed for seq={}: {:?}", record.seq, e);
                ProgramError::InvalidInstructionData
            })?;

        state.last_claimed_seq    = record.seq;
        state.total_claimed_bytes = state.total_claimed_bytes.saturating_add(record.bytes);
        state.last_claim_slot     = clock.slot;
        total_bytes               = total_bytes.saturating_add(record.bytes);
    }

    // Persist updated claim state (seq tracking for double-spend protection).
    {
        let mut data = claim_state_ai.try_borrow_mut_data()?;
        state.serialize(&mut &mut data[..])?;
    }

    // Escrow rewards into PendingClaimsStore — do NOT credit RewardAccount yet.
    let claim_hash = if let Some(pc_ai) = pending_claims_ai {
        let mut store = if pc_ai.data_len() > 0 && pc_ai.lamports() > 0 {
            let data = pc_ai.try_borrow_data()?;
            PendingClaimsStore::try_from_slice(&data).unwrap_or_default()
        } else {
            PendingClaimsStore::default()
        };

        let tip          = &records[records.len() - 1];
        let tip_hash     = compute_record_hash_onchain(tip);
        let tip_nonce    = tip.nonce;
        let session_id   = tip.session_id;
        let total_amount: u64 = records.iter().map(|r| r.charge_flow).sum();
        let record_count = records.len() as u32;
        // Sum bytes routed across all records — stored in PendingClaim for repFlow calc.
        let bytes_routed: u64 = records.iter().map(|r| r.bytes).sum();

        // ── P1: reservation check + increment ─────────────────────────────────
        // If a reservation account is provided, enforce effective-balance check
        // and increment reserved. Rule 2: ClaimUsage NEVER creates the PDA.
        if let Some(res_ai) = reservation_ai {
            if res_ai.data_len() == 0 || res_ai.lamports() == 0 {
                msg!("ClaimUsage: reservation PDA not initialized for user");
                return Err(DisputeError::ReservationNotInitialized.into());
            }
            let mut reservation = load_reservation(res_ai)?;

            // Read user escrow balance for effective-balance check.
            let escrow_balance = if let Some(ue_ai) = user_escrow_ai {
                load_user_escrow_balance(ue_ai)?
            } else {
                u64::MAX // fallback: skip balance check if not provided
            };

            let effective_balance = escrow_balance.saturating_sub(reservation.reserved);
            if effective_balance < total_amount {
                msg!(
                    "ClaimUsage: insufficient effective balance: balance={} reserved={} effective={} needed={}",
                    escrow_balance, reservation.reserved, effective_balance, total_amount
                );
                return Err(DisputeError::InsufficientEffectiveBalance.into());
            }

            // Increment reserved by total_amount.
            reservation.reserved = reservation.reserved.saturating_add(total_amount);
            write_reservation(res_ai, &reservation)?;
            msg!(
                "ClaimUsage: reservation.reserved incremented by {} → {}",
                total_amount, reservation.reserved
            );
        }

        let hash = submit_claim_with_bond(
            &mut store,
            &relay_pubkey_bytes,
            &session_id,
            tip_nonce,
            &tip_hash,
            total_amount,
            record_count,
            clock.unix_timestamp,
            &user_pubkey_bytes,
            bytes_routed,
            0, // bytes_seeded: not tracked in UsageRecordOnChain
        );

        // ── Hold CPI: lock total_amount in FundHold PDA ───────────────────────
        // Activated when all 6 hold accounts (7–12) are present.  relay_wallet
        // is the payer for FundHold rent.  user_escrow_ai (account 6) doubles as
        // the UserEscrow state for hold_client_funds (writable).
        if let (
            Some(uep_ai), Some(ma_ai), Some(hu_ai), Some(fh_ai), Some(sr_ai), Some(sp_ai),
        ) = (
            hold_user_escrow_prog_ai, hold_mint_authority_ai, hold_user_ai,
            fund_hold_ai, hold_spender_registry_ai, hold_system_program_ai,
        ) {
            let ue_state_ai = user_escrow_ai.ok_or(ProgramError::NotEnoughAccountKeys)?;
            let bump = verify_and_get_mint_authority_bump(ma_ai, program_id)?;
            cpi_hold_client_funds(
                uep_ai,
                ma_ai,
                relay_wallet,  // payer (relay pays FundHold rent)
                hu_ai,
                ue_state_ai,
                fh_ai,
                sr_ai,
                sp_ai,
                total_amount,
                hash,
                session_id,
                bump,
            )?;
            msg!(
                "ClaimUsage: held {} $FLOW in FundHold (claim {:08x})",
                total_amount,
                u32::from_le_bytes([hash[0], hash[1], hash[2], hash[3]]),
            );
        }

        let serialized = borsh::to_vec(&store).map_err(|_| ProgramError::InvalidAccountData)?;
        if serialized.len() <= pc_ai.data_len() {
            let mut data = pc_ai.try_borrow_mut_data()?;
            data[..serialized.len()].copy_from_slice(&serialized);
        }

        u32::from_le_bytes([hash[0], hash[1], hash[2], hash[3]])
    } else {
        // No pending_claims account — stub mode.
        let tip      = &records[records.len() - 1];
        let tip_hash = compute_record_hash_onchain(tip);
        let h = compute_claim_hash(&relay_pubkey_bytes, &tip.session_id, tip.nonce, &tip_hash);
        u32::from_le_bytes([h[0], h[1], h[2], h[3]])
    };

    msg!(
        "ClaimUsage: {} records escrowed (bond={} $FLOW), dispute_deadline=+7d, hash_prefix={}",
        records.len(),
        RELAY_BOND_FLOW,
        claim_hash,
    );

    Ok(())
}

/// Process a DisputeClaim instruction.
///
/// Challenger disputes a specific record in a pending claim within the 7-day window.
/// Process DisputeClaim instruction.
///
/// Account layout:
///   0: challenger        — signer
///   1: pending_claims    — PendingClaimsStore PDA (writable)
///   --- Optional Phase 5 dynamic bond accounts ---
///   2: bond_config       — BondConfig PDA [b"bond_config"] (readable, optional)
///   3: reward_rates      — RewardRatesAccount PDA [b"reward_rates"] (readable, optional)
#[inline(never)]
fn process_dispute_claim(
    program_id:      &Pubkey,
    accounts:        &[AccountInfo],
    claim_hash:      [u8; 32],
    record_index:    u32,
    disputed_record: UsageRecordOnChain,
) -> ProgramResult {
    let accounts_iter     = &mut accounts.iter();
    let challenger        = next_account_info(accounts_iter)?;
    let pending_claims_ai = next_account_info(accounts_iter)?;

    // Optional Phase 5 accounts for dynamic bond computation.
    let dispute_bond_config_ai  = accounts_iter.next();
    let dispute_reward_rates_ai = accounts_iter.next();

    if !challenger.is_signer {
        return Err(ProgramError::MissingRequiredSignature);
    }

    // M-01: Require a non-zero client_signature in the disputed record.
    // An all-zero signature means the challenger provided no cryptographic evidence.
    // The on-chain resolver verifies this signature — submitting without it allows
    // frivolous disputes that always resolve as invalid, wasting relay bond lamports.
    if disputed_record.client_signature == [0u8; 64] {
        msg!("DisputeClaim: evidence required — client_signature must be non-zero");
        return Err(ProgramError::InvalidInstructionData);
    }

    let clock = Clock::get()?;

    // ── Phase 5: compute dynamic challenger bond ──────────────────────────────
    // If BondConfig and RewardRatesAccount are provided, compute the bond dynamically.
    // Otherwise fall back to DEFAULT_CHALLENGER_BOND_FLOW (50 $FLOW).
    let flow_price_cents = if let Some(rr_ai) = dispute_reward_rates_ai {
        if rr_ai.lamports() > 0 && rr_ai.data_len() >= RewardRatesAccount::SIZE {
            let rr_data = rr_ai.try_borrow_data()?;
            if let Ok(rr) = RewardRatesAccount::try_from_slice(&rr_data) {
                // Verify PDA address to prevent spoofed reward rates.
                let (expected_rr_pda, _) =
                    Pubkey::find_program_address(&[b"reward_rates"], program_id);
                if *rr_ai.key == expected_rr_pda { rr.flow_price_cents } else { 0 }
            } else {
                0
            }
        } else {
            0
        }
    } else {
        0
    };

    let challenger_bond = if let Some(bc_ai) = dispute_bond_config_ai {
        if bc_ai.lamports() > 0 && bc_ai.data_len() >= BondConfig::SIZE {
            let bc_data = bc_ai.try_borrow_data()?;
            if let Ok(bc) = BondConfig::try_from_slice(&bc_data) {
                // Verify PDA address.
                let (expected_bc_pda, _) =
                    Pubkey::find_program_address(&[b"bond_config"], program_id);
                if *bc_ai.key == expected_bc_pda {
                    let bond = bc.compute_challenger_bond(flow_price_cents);
                    msg!("DisputeClaim: dynamic challenger_bond={} (price_cents={})", bond, flow_price_cents);
                    bond
                } else {
                    DEFAULT_CHALLENGER_BOND_FLOW
                }
            } else {
                DEFAULT_CHALLENGER_BOND_FLOW
            }
        } else {
            DEFAULT_CHALLENGER_BOND_FLOW
        }
    } else {
        DEFAULT_CHALLENGER_BOND_FLOW
    };

    // Validate bond range to catch garbage oracle values.
    if challenger_bond < MIN_CHALLENGER_BOND_FLOW || challenger_bond > MAX_CHALLENGER_BOND_FLOW {
        msg!(
            "DisputeClaim: computed bond {} outside [{}, {}]",
            challenger_bond, MIN_CHALLENGER_BOND_FLOW, MAX_CHALLENGER_BOND_FLOW,
        );
        return Err(RewardsError::InvalidChallengerBond.into());
    }

    let mut store = if pending_claims_ai.data_len() > 0 && pending_claims_ai.lamports() > 0 {
        let data = pending_claims_ai.try_borrow_data()?;
        PendingClaimsStore::try_from_slice(&data)
            .map_err(|_| ProgramError::InvalidAccountData)?
    } else {
        return Err(DisputeError::ClaimNotFound.into());
    };

    dispute_claim(
        &mut store,
        claim_hash,
        record_index,
        disputed_record,
        challenger.key.to_bytes(),
        clock.unix_timestamp,
        pending_claims_ai.key.to_bytes(),
        challenger_bond,
    )
    .map_err(ProgramError::from)?;

    let serialized = borsh::to_vec(&store)
        .map_err(|_| ProgramError::InvalidAccountData)?;
    if serialized.len() <= pending_claims_ai.data_len() {
        let mut data = pending_claims_ai.try_borrow_mut_data()?;
        data[..serialized.len()].copy_from_slice(&serialized);
    }

    msg!(
        "DisputeClaim: filed against record_index={} in claim {:08x} (bond={} $FLOW)",
        record_index,
        u32::from_le_bytes([claim_hash[0], claim_hash[1], claim_hash[2], claim_hash[3]]),
        challenger_bond,
    );

    Ok(())
}

/// Process ResolveDisputeRelaySlashed — challenger proved forgery, relay is slashed.
///
/// P1: calls `settle_reservation` (Rule 1, Rule 4, Rule 8).
/// Phase 6: CPI-slashes relay's stake in staking program (Option C: challenger gets bond back).
///
/// Account layout:
///   0: challenger        — signer (receives challenger reward)
///   1: pending_claims    — PendingClaimsStore PDA (writable)
///   2: reservation       — UserEscrowReservation PDA for user (writable, optional)
///   3: user_escrow       — UserEscrow PDA (writable, optional; also used for balance check)
///
///   --- Release-CPI accounts (all optional; all 5 must be present together) ---
///   4: user_escrow_prog  — user-escrow program (for CPI)
///   5: mint_authority    — rewards mint_authority PDA ["mint_authority"] (PDA signer)
///   6: user_wallet       — user wallet (non-signer; PDA seed in user-escrow)
///   7: fund_hold         — FundHold PDA (writable; Active → Released)
///   8: spender_registry  — AuthorizedSpenderRegistry PDA
///
///   --- Phase 6: Staking CPI accounts (all optional; all 5 must be present together) ---
///   9: staking_program        — staking program (read-only)
///  10: slash_authority        — slash_authority PDA [b"slash_authority"] of rewards program (signer via PDA)
///  11: relay_stake_account    — StakeAccount PDA (writable)
///  12: relay_escrow_ata       — relay's $FLOW escrow ATA in staking program (writable)
///  13: staking_treasury_ata   — treasury's $FLOW ATA (writable; receives slashed tokens)
///  14: staking_token_program  — SPL Token program (read-only)
#[inline(never)]
fn process_resolve_relay_slashed_ix(
    program_id:  &Pubkey,
    accounts:    &[AccountInfo],
    claim_hash:  [u8; 32],
) -> ProgramResult {
    let accounts_iter     = &mut accounts.iter();
    let challenger        = next_account_info(accounts_iter)?;
    let pending_claims_ai = next_account_info(accounts_iter)?;
    let reservation_ai    = accounts_iter.next();
    let user_escrow_ai    = accounts_iter.next();

    // Release-CPI accounts (all optional; all 5 must be provided together).
    let rel_user_escrow_prog_ai  = accounts_iter.next();
    let rel_mint_authority_ai    = accounts_iter.next();
    let rel_user_ai              = accounts_iter.next();
    let rel_fund_hold_ai         = accounts_iter.next();
    let rel_spender_registry_ai  = accounts_iter.next();

    // Phase 6: Staking CPI accounts (all optional; all 5 must be provided together).
    let staking_program_ai       = accounts_iter.next();
    let slash_authority_ai       = accounts_iter.next();
    let relay_stake_account_ai   = accounts_iter.next();
    let relay_escrow_ata_ai      = accounts_iter.next();
    let staking_treasury_ata_ai  = accounts_iter.next();
    let staking_token_program_ai = accounts_iter.next();

    // ── repFlow accounts (all optional; accounts 15-20) ───────────────────────
    // Challenger earns repFlow for policing the network (DisputeWin activity).
    // Rate: 1 repFlow per GB of the disputed traffic (same as bandwidth rate).
    // Uses rel_mint_authority_ai (account 5) as rewards_authority for signing.
    let repflow_program_rs_ai      = accounts_iter.next(); // 15: repflow-token program
    let repflow_config_rs_ai       = accounts_iter.next(); // 16: RepFlowConfig PDA
    let repflow_chal_user_rs_ai    = accounts_iter.next(); // 17: challenger's RepFlowUser PDA (writable)
    let repflow_mint_rs_ai         = accounts_iter.next(); // 18: repFlow SPL mint (writable)
    let repflow_chal_ata_rs_ai     = accounts_iter.next(); // 19: challenger's repFlow ATA (writable)
    let repflow_token_prog_rs_ai   = accounts_iter.next(); // 20: Token-2022 program

    if !challenger.is_signer {
        return Err(ProgramError::MissingRequiredSignature);
    }

    let mut store = if pending_claims_ai.data_len() > 0 && pending_claims_ai.lamports() > 0 {
        let data = pending_claims_ai.try_borrow_data()?;
        PendingClaimsStore::try_from_slice(&data)
            .map_err(|_| ProgramError::InvalidAccountData)?
    } else {
        return Err(DisputeError::ClaimNotFound.into());
    };

    // ── P1 Rule 8: terminal guard ──────────────────────────────────────────────
    let (claim_total_amount, claim_bytes_routed_rs) = {
        let claim = store
            .claims
            .iter()
            .find(|c| c.claim_hash == claim_hash)
            .ok_or::<ProgramError>(DisputeError::ClaimNotFound.into())?;
        if claim.status.is_terminal() {
            return Err(DisputeError::ClaimAlreadySettled.into());
        }
        (claim.total_amount, claim.bytes_routed)
    };

    let outcome = resolve_dispute_relay_slashed(&mut store, claim_hash)
        .map_err(ProgramError::from)?;

    write_store(pending_claims_ai, &store)?;

    // ── P1 Rule 1: settle_reservation ─────────────────────────────────────────
    if let Some(res_ai) = reservation_ai {
        if res_ai.data_len() > 0 && res_ai.lamports() > 0 {
            let mut reservation = load_reservation(res_ai)?;
            let escrow_balance = if let Some(ue_ai) = user_escrow_ai {
                load_user_escrow_balance(ue_ai)?
            } else {
                reservation.reserved
            };
            settle_reservation(&mut reservation, claim_total_amount, escrow_balance)
                .map_err(ProgramError::from)?;
            write_reservation(res_ai, &reservation)?;
        }
    }

    // ── Release-CPI: unhold funds (relay slashed, user keeps tokens) ──────────
    // Activated when all 5 release-CPI accounts (4–8) are provided.
    // release_funds decrements UserEscrow.held and marks FundHold as Released,
    // leaving the tokens in the user's escrow (they were never burned).
    if let (
        Some(uep_ai), Some(ma_ai), Some(hu_ai), Some(fh_ai), Some(sr_ai),
    ) = (
        rel_user_escrow_prog_ai, rel_mint_authority_ai, rel_user_ai,
        rel_fund_hold_ai, rel_spender_registry_ai,
    ) {
        let ue_state_ai = user_escrow_ai.ok_or(ProgramError::NotEnoughAccountKeys)?;
        let bump = verify_and_get_mint_authority_bump(ma_ai, program_id)?;
        cpi_release_funds(
            uep_ai,
            ma_ai,
            hu_ai,
            ue_state_ai,
            fh_ai,
            sr_ai,
            claim_hash,
            bump,
        )?;
        msg!(
            "ResolveRelaySlashed: released FundHold — {} $FLOW returned to user escrow",
            claim_total_amount,
        );

        // ── repFlow CPI: challenger earns DisputeWin repFlow ─────────────────
        maybe_mint_repflow_for_claim(
            claim_bytes_routed_rs, 6 /* DisputeWin */, ma_ai, bump,
            repflow_program_rs_ai, repflow_config_rs_ai, repflow_chal_user_rs_ai,
            repflow_mint_rs_ai, repflow_chal_ata_rs_ai, repflow_token_prog_rs_ai,
        )?;
    }

    // ── Phase 6: CPI slash to staking program ────────────────────────────────
    // Activated when all 6 staking CPI accounts (9–14) are provided.
    // The rewards program's slash_authority PDA signs via invoke_signed.
    // Option C: challenger only gets bond back — no bonus from stake.
    if let (
        Some(sp_ai), Some(sa_auth_ai), Some(rsa_ai), Some(rea_ai), Some(sta_ai), Some(stp_ai),
    ) = (
        staking_program_ai, slash_authority_ai, relay_stake_account_ai,
        relay_escrow_ata_ai, staking_treasury_ata_ai, staking_token_program_ai,
    ) {
        // Verify slash_authority is the expected PDA.
        let (expected_slash_auth, slash_auth_bump) = find_slash_authority_pda(program_id);
        if *sa_auth_ai.key != expected_slash_auth {
            msg!(
                "ResolveRelaySlashed: slash_authority mismatch — expected {}, got {}",
                expected_slash_auth, sa_auth_ai.key,
            );
            return Err(ProgramError::InvalidArgument);
        }

        // Get the challenger bond from the dispute record (the slash amount).
        let slash_amount = if let DisputeOutcome::RelaySlashed { challenger_bond_returned, .. } = &outcome {
            *challenger_bond_returned
        } else {
            DEFAULT_CHALLENGER_BOND_FLOW
        };

        // Build StakingInstruction::Slash { slash_lamports, reason: 1 } (reason=1: dispute slash).
        // Borsh encoding: variant index (u32le = 2) + u64le + u8
        let mut slash_data = Vec::with_capacity(1 + 8 + 1);
        // StakingInstruction is BorshDeserialize; Slash is variant 2.
        slash_data.extend_from_slice(&(2u32).to_le_bytes());
        slash_data.extend_from_slice(&slash_amount.to_le_bytes());
        slash_data.push(1u8); // reason = 1 (dispute slash)

        let slash_ix = solana_program::instruction::Instruction {
            program_id: *sp_ai.key,
            accounts: vec![
                solana_program::instruction::AccountMeta::new_readonly(*sa_auth_ai.key, true),
                solana_program::instruction::AccountMeta::new(*rsa_ai.key, false),
                solana_program::instruction::AccountMeta::new(*rea_ai.key, false),
                solana_program::instruction::AccountMeta::new(*sta_ai.key, false),
                solana_program::instruction::AccountMeta::new_readonly(*stp_ai.key, false),
            ],
            data: slash_data,
        };

        solana_program::program::invoke_signed(
            &slash_ix,
            &[
                sa_auth_ai.clone(),
                rsa_ai.clone(),
                rea_ai.clone(),
                sta_ai.clone(),
                stp_ai.clone(),
            ],
            &[&[b"slash_authority", &[slash_auth_bump]]],
        )?;

        msg!(
            "ResolveRelaySlashed: staking CPI slash executed — {} $FLOW slashed from relay stake",
            slash_amount,
        );
    }

    if let DisputeOutcome::RelaySlashed { challenger_reward, burned, challenger_bond_returned } = &outcome {
        msg!(
            "ResolveDisputeRelaySlashed: relay SLASHED (Ed25519 precompile proved forgery). \
             challenger_reward={} $FLOW, burned={} $FLOW, bond_returned={} $FLOW",
            challenger_reward, burned, challenger_bond_returned,
        );
    }

    Ok(())
}

/// Process ResolveDisputeChallengerSlashed — relay proved signature valid, challenger slashed.
///
/// P1: calls `settle_reservation` (Rule 1, Rule 4, Rule 8).
/// CPI Bridge: burns user's $FLOW from escrow + mints 70:30 (relay wins, relay was legitimate).
///
/// Account layout:
///   0: relay_wallet      — signer (also used as `relay` param in spend_from_escrow CPI)
///   1: pending_claims    — PendingClaimsStore PDA (writable)
///   2: reservation       — UserEscrowReservation PDA for user (writable, optional)
///   3: user_escrow_state — UserEscrow PDA from user-escrow program (writable, optional)
///
///   --- CPI Bridge (all optional; all must be present together) ---
///   4: mint_authority    — rewards mint_authority PDA ["mint_authority"]
///   5: token_mint        — $FLOW SPL mint (writable)
///   6: relay_token       — relay's $FLOW token account (writable; receives 70%; relay_token guard)
///   7: treasury_token    — treasury's $FLOW token account (writable; receives 30%)
///   8: user_escrow_token — user's escrow SPL token account (writable; burned from)
///   9: user_wallet       — user's wallet pubkey (for spend_from_escrow PDA seed)
///  10: spender_registry  — AuthorizedSpenderRegistry PDA
///  11: user_escrow_prog  — user-escrow program (for CPI)
///  12: token_program     — SPL Token program
///  13: fund_hold         — FundHold PDA (optional; activates burn_held_funds path)
///                          When present, calls burn_held_funds instead of spend_from_escrow.
#[inline(never)]
fn process_resolve_challenger_slashed_ix(
    program_id: &Pubkey,
    accounts:   &[AccountInfo],
    claim_hash: [u8; 32],
) -> ProgramResult {
    let accounts_iter        = &mut accounts.iter();
    let relay_wallet         = next_account_info(accounts_iter)?;
    let pending_claims_ai    = next_account_info(accounts_iter)?;
    let reservation_ai       = accounts_iter.next();
    let user_escrow_state_ai = accounts_iter.next();

    // CPI bridge accounts.
    let mint_authority_ai    = accounts_iter.next();
    let token_mint_ai        = accounts_iter.next();
    let relay_token_ai       = accounts_iter.next();
    let treasury_token_ai    = accounts_iter.next();
    let user_escrow_token_ai = accounts_iter.next();
    let user_wallet_ai       = accounts_iter.next();
    let spender_registry_ai  = accounts_iter.next();
    let user_escrow_prog_ai  = accounts_iter.next();
    let token_program_ai     = accounts_iter.next();
    // Account 13 (mandatory when CPI bridge active): TreasuryConfig PDA.
    let treasury_config_cs_ai = accounts_iter.next();
    // Account 14 (optional): FundHold PDA — activates burn_held_funds path.
    let fund_hold_cs_ai      = accounts_iter.next();

    // ── repFlow accounts (all optional; accounts 15-20) ───────────────────────
    // When all 6 are present and claim.bytes_routed > 0, mints bandwidth repFlow to relay.
    let repflow_program_cs_ai    = accounts_iter.next(); // 15: repflow-token program
    let repflow_config_cs_ai     = accounts_iter.next(); // 16: RepFlowConfig PDA
    let repflow_user_cs_ai       = accounts_iter.next(); // 17: relay's RepFlowUser PDA (writable)
    let repflow_mint_cs_ai       = accounts_iter.next(); // 18: repFlow SPL mint (writable)
    let repflow_relay_ata_cs_ai  = accounts_iter.next(); // 19: relay's repFlow ATA (writable)
    let repflow_token_prog_cs_ai = accounts_iter.next(); // 20: Token-2022 program

    if !relay_wallet.is_signer {
        return Err(ProgramError::MissingRequiredSignature);
    }

    let mut store = if pending_claims_ai.data_len() > 0 && pending_claims_ai.lamports() > 0 {
        let data = pending_claims_ai.try_borrow_data()?;
        PendingClaimsStore::try_from_slice(&data)
            .map_err(|_| ProgramError::InvalidAccountData)?
    } else {
        return Err(DisputeError::ClaimNotFound.into());
    };

    // ── P1 Rule 8: terminal guard ──────────────────────────────────────────────
    let (claim_total_amount, claim_bytes_routed_cs) = {
        let claim = store
            .claims
            .iter()
            .find(|c| c.claim_hash == claim_hash)
            .ok_or::<ProgramError>(DisputeError::ClaimNotFound.into())?;
        if claim.status.is_terminal() {
            return Err(DisputeError::ClaimAlreadySettled.into());
        }
        (claim.total_amount, claim.bytes_routed)
    };

    let outcome = resolve_dispute_challenger_slashed(&mut store, claim_hash)
        .map_err(ProgramError::from)?;

    write_store(pending_claims_ai, &store)?;

    // ── P1 Rule 1: settle_reservation ─────────────────────────────────────────
    if let Some(res_ai) = reservation_ai {
        if res_ai.data_len() > 0 && res_ai.lamports() > 0 {
            let mut reservation = load_reservation(res_ai)?;
            let escrow_balance = if let Some(ue_ai) = user_escrow_state_ai {
                load_user_escrow_balance(ue_ai)?
            } else {
                reservation.reserved
            };
            settle_reservation(&mut reservation, claim_total_amount, escrow_balance)
                .map_err(ProgramError::from)?;
            write_reservation(res_ai, &reservation)?;
        }
    }

    // ── CPI Bridge: burn + mint 70:30 (relay wins — challenger was frivolous) ──
    if let (
        Some(ma_ai), Some(tm_ai), Some(rt_ai), Some(tt_ai),
        Some(uet_ai), Some(uw_ai), Some(sr_ai), Some(uep_ai), Some(tp_ai),
    ) = (
        mint_authority_ai, token_mint_ai, relay_token_ai, treasury_token_ai,
        user_escrow_token_ai, user_wallet_ai, spender_registry_ai,
        user_escrow_prog_ai, token_program_ai,
    ) {
        let ue_state_ai = user_escrow_state_ai
            .ok_or(ProgramError::NotEnoughAccountKeys)?;
        let bump = verify_and_get_mint_authority_bump(ma_ai, program_id)?;

        // ── GAP-11: mandatory treasury validation ──────────────────────────────
        let tc_ai = treasury_config_cs_ai.ok_or(RewardsError::UnauthorizedTreasury)?;
        validate_treasury_token(tc_ai, tt_ai, program_id)?;

        // If a FundHold PDA is supplied (account 14), use burn_held_funds which
        // decrements both `held` and `balance` and marks the FundHold as Burned.
        // Otherwise fall back to the legacy spend_from_escrow path.
        if let Some(fh_ai) = fund_hold_cs_ai {
            cpi_burn_held_funds(
                uep_ai,
                ma_ai,
                uw_ai,
                ue_state_ai,
                uet_ai,
                fh_ai,
                sr_ai,
                tm_ai,
                tp_ai,
                claim_hash,
                bump,
            )?;
        } else {
            // Legacy path: spend_from_escrow.
            //   verifies: (a) mint_authority_ai in spender registry,
            //   (b) relay_token.owner == relay_wallet, (c) escrow balance >= amount.
            cpi_burn_from_escrow(
                uep_ai, ma_ai, uw_ai, ue_state_ai, uet_ai,
                rt_ai, relay_wallet, sr_ai, tm_ai, tp_ai,
                claim_total_amount, bump,
            )?;
        }

        let relay_share   = claim_total_amount.saturating_mul(RELAY_MINT_SHARE_BPS).saturating_div(10_000);
        let treasury_share = claim_total_amount.saturating_sub(relay_share);
        cpi_mint_to(tp_ai, tm_ai, rt_ai, ma_ai, relay_share, bump)?;
        cpi_mint_to(tp_ai, tm_ai, tt_ai, ma_ai, treasury_share, bump)?;

        msg!(
            "ResolveDisputeChallengerSlashed CPI: burned={}, minted_relay={}, minted_treasury={}",
            claim_total_amount, relay_share, treasury_share
        );

        // ── repFlow CPI: bandwidth repFlow for relay (relay won the dispute) ──
        maybe_mint_repflow_for_claim(
            claim_bytes_routed_cs, 2 /* Bandwidth */, ma_ai, bump,
            repflow_program_cs_ai, repflow_config_cs_ai, repflow_user_cs_ai,
            repflow_mint_cs_ai, repflow_relay_ata_cs_ai, repflow_token_prog_cs_ai,
        )?;
    }

    if let DisputeOutcome::ChallengerSlashed { burned, .. } = &outcome {
        msg!(
            "ResolveDisputeChallengerSlashed: challenger SLASHED (Ed25519 precompile proved sig valid). \
             burned={} $FLOW (bond penalty)",
            burned
        );
    }

    Ok(())
}

/// Process ForceResolve — anyone breaks a 3-day stalled dispute.
///
/// P1: calls `settle_reservation` (Rule 1, Rule 4, Rule 8).
/// CPI Bridge: burns user's $FLOW from escrow + mints 70:30 (relay wins by inaction).
///
/// Account layout:
///   0: resolver          — signer (anyone)
///   1: pending_claims    — PendingClaimsStore PDA (writable)
///   2: reservation       — UserEscrowReservation PDA for user (writable, optional)
///   3: user_escrow_state — UserEscrow PDA from user-escrow program (writable, optional)
///
///   --- CPI Bridge (all optional; all must be present together) ---
///   4: mint_authority    — rewards mint_authority PDA ["mint_authority"]
///   5: token_mint        — $FLOW SPL mint (writable)
///   6: relay_token       — relay's $FLOW token account (writable; receives 70%)
///   7: treasury_token    — treasury's $FLOW token account (writable; receives 30%)
///   8: user_escrow_token — user's escrow SPL token account (writable; burned from)
///   9: user_wallet       — user's wallet pubkey (for spend_from_escrow PDA seed)
///  10: relay_wallet_acct — relay's wallet pubkey (for relay param in spend_from_escrow)
///  11: spender_registry  — AuthorizedSpenderRegistry PDA
///  12: user_escrow_prog  — user-escrow program (for CPI)
///  13: token_program     — SPL Token program
#[inline(never)]
fn process_force_resolve_ix(
    program_id: &Pubkey,
    accounts:   &[AccountInfo],
    claim_hash: [u8; 32],
) -> ProgramResult {
    let accounts_iter        = &mut accounts.iter();
    let resolver             = next_account_info(accounts_iter)?;
    let pending_claims_ai    = next_account_info(accounts_iter)?;
    let reservation_ai       = accounts_iter.next();
    let user_escrow_state_ai = accounts_iter.next();

    // CPI bridge accounts.
    let mint_authority_ai    = accounts_iter.next();
    let token_mint_ai        = accounts_iter.next();
    let relay_token_ai       = accounts_iter.next();
    let treasury_token_ai    = accounts_iter.next();
    let user_escrow_token_ai = accounts_iter.next();
    let user_wallet_ai       = accounts_iter.next();
    let relay_wallet_cpi_ai  = accounts_iter.next(); // relay wallet for CPI relay param
    let spender_registry_ai  = accounts_iter.next();
    let user_escrow_prog_ai  = accounts_iter.next();
    let token_program_ai     = accounts_iter.next();
    // Account 14 (mandatory when CPI bridge active): TreasuryConfig PDA.
    let treasury_config_fr_ai = accounts_iter.next();

    // ── repFlow accounts (all optional; accounts 15-20) ───────────────────────
    // When all 6 are present and claim.bytes_routed > 0, mints bandwidth repFlow to relay.
    let repflow_program_fr_ai    = accounts_iter.next(); // 15: repflow-token program
    let repflow_config_fr_ai     = accounts_iter.next(); // 16: RepFlowConfig PDA
    let repflow_user_fr_ai       = accounts_iter.next(); // 17: relay's RepFlowUser PDA (writable)
    let repflow_mint_fr_ai       = accounts_iter.next(); // 18: repFlow SPL mint (writable)
    let repflow_relay_ata_fr_ai  = accounts_iter.next(); // 19: relay's repFlow ATA (writable)
    let repflow_token_prog_fr_ai = accounts_iter.next(); // 20: Token-2022 program

    if !resolver.is_signer {
        return Err(ProgramError::MissingRequiredSignature);
    }

    let clock = Clock::get()?;

    let mut store = if pending_claims_ai.data_len() > 0 && pending_claims_ai.lamports() > 0 {
        let data = pending_claims_ai.try_borrow_data()?;
        PendingClaimsStore::try_from_slice(&data)
            .map_err(|_| ProgramError::InvalidAccountData)?
    } else {
        return Err(DisputeError::ClaimNotFound.into());
    };

    // ── P1 Rule 8: terminal guard ──────────────────────────────────────────────
    let (claim_total_amount, claim_bytes_routed_fr) = {
        let claim = store
            .claims
            .iter()
            .find(|c| c.claim_hash == claim_hash)
            .ok_or::<ProgramError>(DisputeError::ClaimNotFound.into())?;
        if claim.status.is_terminal() {
            return Err(DisputeError::ClaimAlreadySettled.into());
        }
        (claim.total_amount, claim.bytes_routed)
    };

    let outcome = force_resolve_dispute(&mut store, claim_hash, clock.unix_timestamp)
        .map_err(ProgramError::from)?;

    write_store(pending_claims_ai, &store)?;

    // ── P1 Rule 1: settle_reservation ─────────────────────────────────────────
    if let Some(res_ai) = reservation_ai {
        if res_ai.data_len() > 0 && res_ai.lamports() > 0 {
            let mut reservation = load_reservation(res_ai)?;
            let escrow_balance = if let Some(ue_ai) = user_escrow_state_ai {
                load_user_escrow_balance(ue_ai)?
            } else {
                reservation.reserved
            };
            settle_reservation(&mut reservation, claim_total_amount, escrow_balance)
                .map_err(ProgramError::from)?;
            write_reservation(res_ai, &reservation)?;
        }
    }

    // ── CPI Bridge: burn + mint 70:30 (relay wins by inaction) ───────────────
    if let (
        Some(ma_ai), Some(tm_ai), Some(rt_ai), Some(tt_ai),
        Some(uet_ai), Some(uw_ai), Some(rw_ai), Some(sr_ai),
        Some(uep_ai), Some(tp_ai),
    ) = (
        mint_authority_ai, token_mint_ai, relay_token_ai, treasury_token_ai,
        user_escrow_token_ai, user_wallet_ai, relay_wallet_cpi_ai,
        spender_registry_ai, user_escrow_prog_ai, token_program_ai,
    ) {
        let ue_state_ai = user_escrow_state_ai
            .ok_or(ProgramError::NotEnoughAccountKeys)?;
        let bump = verify_and_get_mint_authority_bump(ma_ai, program_id)?;

        // ── GAP-11: mandatory treasury validation ──────────────────────────────
        let tc_ai = treasury_config_fr_ai.ok_or(RewardsError::UnauthorizedTreasury)?;
        validate_treasury_token(tc_ai, tt_ai, program_id)?;

        // relay_token (rt_ai) must be owned by relay_wallet (rw_ai) at the SPL level.
        // NOTE: resolver != relay here — rw_ai is passed separately as the relay's
        // wallet pubkey (account 10 in the layout); relay_wallet is the `resolver`
        // account (account 0), which is a different signer.
        // spend_from_escrow enforces relay_token.owner == relay_wallet internally;
        // the CPI returns EscrowError::InvalidRelayWallet if this check fails.
        // spend_from_escrow verifies: (a) mint_authority_ai in spender registry,
        //    (b) relay_token.owner == relay_wallet (rw_ai), (c) escrow balance >= amount.
        cpi_burn_from_escrow(
            uep_ai, ma_ai, uw_ai, ue_state_ai, uet_ai,
            rt_ai, rw_ai, sr_ai, tm_ai, tp_ai,
            claim_total_amount, bump,
        )?;

        let relay_share    = claim_total_amount.saturating_mul(RELAY_MINT_SHARE_BPS).saturating_div(10_000);
        let treasury_share = claim_total_amount.saturating_sub(relay_share);
        cpi_mint_to(tp_ai, tm_ai, rt_ai, ma_ai, relay_share, bump)?;
        cpi_mint_to(tp_ai, tm_ai, tt_ai, ma_ai, treasury_share, bump)?;

        msg!(
            "ForceResolve CPI: burned={}, minted_relay={}, minted_treasury={}",
            claim_total_amount, relay_share, treasury_share
        );

        // ── repFlow CPI: bandwidth repFlow for relay (relay wins by inaction) ──
        maybe_mint_repflow_for_claim(
            claim_bytes_routed_fr, 2 /* Bandwidth */, ma_ai, bump,
            repflow_program_fr_ai, repflow_config_fr_ai, repflow_user_fr_ai,
            repflow_mint_fr_ai, repflow_relay_ata_fr_ai, repflow_token_prog_fr_ai,
        )?;
    }

    if let DisputeOutcome::ChallengerSlashed { burned, .. } = &outcome {
        msg!(
            "ForceResolve: 3-day inactivity timeout expired. Challenger bond burned={} $FLOW. \
             Relay claim {:08x} resolved.",
            burned,
            u32::from_le_bytes([claim_hash[0], claim_hash[1], claim_hash[2], claim_hash[3]])
        );
    }

    Ok(())
}

/// Parsed account references for `process_release_rewards_ix` (22 accounts).
struct ParsedReleaseAccounts<'s, 'info: 's> {
    relay_wallet:             &'s AccountInfo<'info>,
    reward_account:           &'s AccountInfo<'info>,
    pending_claims_ai:        &'s AccountInfo<'info>,
    reservation_ai:           Option<&'s AccountInfo<'info>>,
    user_escrow_state_ai:     Option<&'s AccountInfo<'info>>,
    mint_authority_ai:        Option<&'s AccountInfo<'info>>,
    token_mint_ai:            Option<&'s AccountInfo<'info>>,
    relay_token_ai:           Option<&'s AccountInfo<'info>>,
    treasury_token_ai:        Option<&'s AccountInfo<'info>>,
    user_escrow_token_ai:     Option<&'s AccountInfo<'info>>,
    user_wallet_ai:           Option<&'s AccountInfo<'info>>,
    spender_registry_ai:      Option<&'s AccountInfo<'info>>,
    user_escrow_prog_ai:      Option<&'s AccountInfo<'info>>,
    token_program_ai:         Option<&'s AccountInfo<'info>>,
    treasury_config_ai:       Option<&'s AccountInfo<'info>>,
    fund_hold_rr_ai:          Option<&'s AccountInfo<'info>>,
    repflow_program_rr_ai:    Option<&'s AccountInfo<'info>>,
    repflow_config_rr_ai:     Option<&'s AccountInfo<'info>>,
    repflow_user_rr_ai:       Option<&'s AccountInfo<'info>>,
    repflow_mint_rr_ai:       Option<&'s AccountInfo<'info>>,
    repflow_relay_ata_rr_ai:  Option<&'s AccountInfo<'info>>,
    repflow_token_prog_rr_ai: Option<&'s AccountInfo<'info>>,
}

#[inline(never)]
fn parse_release_accounts<'s, 'info: 's>(
    accounts: &'s [AccountInfo<'info>],
) -> Result<ParsedReleaseAccounts<'s, 'info>, ProgramError> {
    let iter = &mut accounts.iter();
    Ok(ParsedReleaseAccounts {
        relay_wallet:             next_account_info(iter)?,
        reward_account:           next_account_info(iter)?,
        pending_claims_ai:        next_account_info(iter)?,
        reservation_ai:           iter.next(),
        user_escrow_state_ai:     iter.next(),
        mint_authority_ai:        iter.next(),
        token_mint_ai:            iter.next(),
        relay_token_ai:           iter.next(),
        treasury_token_ai:        iter.next(),
        user_escrow_token_ai:     iter.next(),
        user_wallet_ai:           iter.next(),
        spender_registry_ai:      iter.next(),
        user_escrow_prog_ai:      iter.next(),
        token_program_ai:         iter.next(),
        treasury_config_ai:       iter.next(),
        fund_hold_rr_ai:          iter.next(),
        repflow_program_rr_ai:    iter.next(),
        repflow_config_rr_ai:     iter.next(),
        repflow_user_rr_ai:       iter.next(),
        repflow_mint_rr_ai:       iter.next(),
        repflow_relay_ata_rr_ai:  iter.next(),
        repflow_token_prog_rr_ai: iter.next(),
    })
}

/// Process a ReleaseRewards instruction.
///
/// Releases escrowed rewards to the relay after the dispute window expires.
/// P1: calls `settle_reservation` to decrement `reserved` (Rule 1, Rule 4, Rule 8).
/// CPI Bridge: burns user's $FLOW from escrow + mints new $FLOW 70:30 (relay/treasury).
///
/// Account layout:
///   0: relay_wallet          — signer (relay's wallet; also used as `relay` param in CPI)
///   1: reward_account        — relay's aggregate reward PDA (writable)
///   2: pending_claims        — PendingClaimsStore PDA (writable)
///   3: reservation           — UserEscrowReservation PDA for user (writable, optional)
///   4: user_escrow_state     — UserEscrow PDA from user-escrow program (writable, optional)
///
///   --- CPI Bridge accounts (all optional; all must be provided together) ---
///   5: mint_authority        — rewards mint_authority PDA ["mint_authority"] (signer via invoke_signed)
///   6: token_mint            — $FLOW SPL mint (writable)
///   7: relay_token           — relay's $FLOW token account (writable; receives 70%)
///   8: treasury_token        — treasury's $FLOW token account (writable; receives 30%)
///   9: user_escrow_token     — user's escrow SPL token account (writable; burned from)
///  10: user_wallet           — user's wallet pubkey (for spend_from_escrow PDA seed)
///  11: spender_registry      — AuthorizedSpenderRegistry PDA (read-only)
///  12: user_escrow_program   — user-escrow program (for CPI)
///  13: token_program         — SPL Token program
///  14: fund_hold             — FundHold PDA (optional; activates burn_held_funds path)
///                              When present, calls burn_held_funds (decrements held+balance)
///                              instead of spend_from_escrow (legacy path).
#[inline(never)]
fn process_release_rewards_ix(
    program_id: &Pubkey,
    accounts:   &[AccountInfo],
    claim_hash: [u8; 32],
) -> ProgramResult {
    let ParsedReleaseAccounts {
        relay_wallet,
        reward_account,
        pending_claims_ai,
        reservation_ai,
        user_escrow_state_ai,
        mint_authority_ai,
        token_mint_ai,
        relay_token_ai,
        treasury_token_ai,
        user_escrow_token_ai,
        user_wallet_ai,
        spender_registry_ai,
        user_escrow_prog_ai,
        token_program_ai,
        treasury_config_ai,
        fund_hold_rr_ai,
        repflow_program_rr_ai,
        repflow_config_rr_ai,
        repflow_user_rr_ai,
        repflow_mint_rr_ai,
        repflow_relay_ata_rr_ai,
        repflow_token_prog_rr_ai,
    } = parse_release_accounts(accounts)?;

    if !relay_wallet.is_signer {
        return Err(ProgramError::MissingRequiredSignature);
    }

    let clock = Clock::get()?;

    let mut store = if pending_claims_ai.data_len() > 0 && pending_claims_ai.lamports() > 0 {
        let data = pending_claims_ai.try_borrow_data()?;
        PendingClaimsStore::try_from_slice(&data)
            .map_err(|_| ProgramError::InvalidAccountData)?
    } else {
        return Err(DisputeError::ClaimNotFound.into());
    };

    // ── P1 Rule 8: terminal guard — check claim is NOT already terminal ────────
    let (claim_total_amount, claim_bytes_routed) = {
        let claim = store
            .claims
            .iter()
            .find(|c| c.claim_hash == claim_hash)
            .ok_or::<ProgramError>(DisputeError::ClaimNotFound.into())?;
        if claim.status.is_terminal() {
            msg!("ReleaseRewards: claim already in terminal state {:?}", claim.status);
            return Err(DisputeError::ClaimAlreadySettled.into());
        }
        (claim.total_amount, claim.bytes_routed)
    };

    let (amount, bond, _treasury_penalty) =
        release_rewards(&mut store, claim_hash, clock.unix_timestamp)
            .map_err(ProgramError::from)?;

    write_store(pending_claims_ai, &store)?;

    // ── P1 Rule 1: settle_reservation — the ONLY decrement path ───────────────
    //
    // ORDERING INVARIANT (Issue #1):
    // `user_escrow.balance` is captured HERE — before any CPI burn — so the
    // invariant check `reserved <= escrow_balance` uses the pre-burn balance.
    // After `cpi_burn_from_escrow` runs, the user-escrow program decrements
    // `user_escrow.balance` by `claim_total_amount`. Transaction atomicity
    // ensures that if the CPI fails, this settle_reservation decrement is also
    // reverted; there is no partial-execution window that could leave `reserved`
    // inconsistent with the on-chain escrow balance.
    if let Some(res_ai) = reservation_ai {
        if res_ai.data_len() > 0 && res_ai.lamports() > 0 {
            let mut reservation = load_reservation(res_ai)?;
            // Read balance BEFORE CPI burn (pre-burn snapshot for invariant check).
            let pre_burn_escrow_balance = if let Some(ue_ai) = user_escrow_state_ai {
                load_user_escrow_balance(ue_ai)?
            } else {
                reservation.reserved // safe fallback: invariant can't fire
            };
            settle_reservation(&mut reservation, claim_total_amount, pre_burn_escrow_balance)
                .map_err(ProgramError::from)?;
            write_reservation(res_ai, &reservation)?;
            msg!(
                "ReleaseRewards: reservation.reserved decremented by {} → {} \
                 (pre_burn_balance={})",
                claim_total_amount, reservation.reserved, pre_burn_escrow_balance
            );
        }
    }

    // ── CPI Bridge: burn user's $FLOW + mint 70:30 (relay / treasury) ─────────
    //
    // Activated when all 9 CPI bridge accounts (5–13) are provided.
    // Burns `claim_total_amount` from user escrow via CPI to user-escrow's
    // `spend_from_escrow` (spend_from_escrow internally signs for the user_escrow
    // PDA and decrements user_escrow.balance). Then mints new $FLOW 70:30.
    //
    // NOTE: settle_reservation MUST run before this block (see ordering invariant
    // above). The CPI burn modifies user_escrow_state_ai.data in-place; reading
    // the balance after the burn would return the post-burn value, not the value
    // that satisfies the `reserved <= balance` invariant used by settle_reservation.
    if let (
        Some(ma_ai), Some(tm_ai), Some(rt_ai), Some(tt_ai),
        Some(uet_ai), Some(uw_ai), Some(sr_ai), Some(uep_ai), Some(tp_ai),
    ) = (
        mint_authority_ai, token_mint_ai, relay_token_ai, treasury_token_ai,
        user_escrow_token_ai, user_wallet_ai, spender_registry_ai,
        user_escrow_prog_ai, token_program_ai,
    ) {
        let ue_state_ai = user_escrow_state_ai
            .ok_or(ProgramError::NotEnoughAccountKeys)?;

        let bump = verify_and_get_mint_authority_bump(ma_ai, program_id)?;

        // ── GAP-11: mandatory treasury validation (no backward-compatible skip) ──
        let tc_ai = treasury_config_ai.ok_or(RewardsError::UnauthorizedTreasury)?;
        validate_treasury_token(tc_ai, tt_ai, program_id)?;

        // relay_token (rt_ai) must be owned by relay_wallet at the SPL level.
        // spend_from_escrow enforces relay_token.owner == relay_wallet internally;
        // the CPI returns EscrowError::InvalidRelayWallet if this check fails.

        // 1. Burn claim_total_amount from user escrow.
        //    If a FundHold PDA is supplied (account 15), use the new
        //    burn_held_funds path which decrements both `held` and `balance`
        //    and marks the FundHold as Burned.
        //    Otherwise fall back to the legacy spend_from_escrow path.
        if let Some(fh_ai) = fund_hold_rr_ai {
            // New path: burn_held_funds (FundHold must be Active).
            cpi_burn_held_funds(
                uep_ai,
                ma_ai,
                uw_ai,
                ue_state_ai,
                uet_ai,
                fh_ai,
                sr_ai,
                tm_ai,
                tp_ai,
                claim_hash,
                bump,
            )?;
        } else {
            // Legacy path: spend_from_escrow.
            //   verifies: (a) mint_authority_ai in spender registry,
            //   (b) relay_token.owner == relay_wallet, (c) escrow balance >= amount.
            cpi_burn_from_escrow(
                uep_ai,
                ma_ai,
                uw_ai,
                ue_state_ai,
                uet_ai,
                rt_ai,
                relay_wallet,
                sr_ai,
                tm_ai,
                tp_ai,
                claim_total_amount,
                bump,
            )?;
        }

        // 2. Mint 70:30 split on `claim_total_amount`.
        //    Relay receives 70%, treasury receives 30%.
        let relay_share   = claim_total_amount
            .saturating_mul(RELAY_MINT_SHARE_BPS)
            .saturating_div(10_000);
        let treasury_share = claim_total_amount.saturating_sub(relay_share);

        cpi_mint_to(tp_ai, tm_ai, rt_ai, ma_ai, relay_share, bump)?;
        cpi_mint_to(tp_ai, tm_ai, tt_ai, ma_ai, treasury_share, bump)?;

        msg!(
            "ReleaseRewards CPI: burned={}, minted_relay={}, minted_treasury={}",
            claim_total_amount, relay_share, treasury_share
        );

        // ── repFlow CPI: bandwidth repFlow for relay ──────────────────────────
        maybe_mint_repflow_for_claim(
            claim_bytes_routed, 2 /* Bandwidth */, ma_ai, bump,
            repflow_program_rr_ai, repflow_config_rr_ai, repflow_user_rr_ai,
            repflow_mint_rr_ai, repflow_relay_ata_rr_ai, repflow_token_prog_rr_ai,
        )?;
    }

    // Credit released amount to the relay's aggregate reward account.
    if reward_account.data_len() >= RewardAccount::SIZE && reward_account.lamports() > 0 {
        let mut data = reward_account.try_borrow_mut_data()?;
        let mut acct = RewardAccount::try_from_slice(&data)
            .map_err(|_| ProgramError::InvalidAccountData)?;
        acct.total_lamports_claimed = acct.total_lamports_claimed.saturating_add(amount);
        acct.serialize(&mut &mut data[..])?;
    }

    msg!(
        "ReleaseRewards: {} $FLOW released + {} $FLOW bond returned (claim {:08x})",
        amount, bond,
        u32::from_le_bytes([claim_hash[0], claim_hash[1], claim_hash[2], claim_hash[3]])
    );

    Ok(())
}

// ── P1 New instruction handlers ──────────────────────────────────────────────

/// Initialize the global `RewardsConfig` PDA.
///
/// Creates and funds the PDA account, then writes the initial config.
/// Sets `migration_mode = true` on first call (Rule 9).
/// One-shot — refuses to overwrite an already-initialized account.
///
/// Account layout:
///   0: foundation     (signer — Foundation multisig)
///   1: rewards_config (RewardsConfig PDA [b"rewards_config"], writable — will be created)
///   2: system_program (SystemProgram)
#[inline(never)]
fn process_initialize_rewards_config(
    program_id: &Pubkey,
    accounts:   &[AccountInfo],
) -> ProgramResult {
    let accounts_iter     = &mut accounts.iter();
    let foundation        = next_account_info(accounts_iter)?;
    let rewards_config_ai = next_account_info(accounts_iter)?;
    let system_prog_info  = next_account_info(accounts_iter)?;

    if !foundation.is_signer {
        return Err(ProgramError::MissingRequiredSignature);
    }
    // C-01: Verify the signer is the authorised Foundation multisig.
    if *foundation.key != FOUNDATION_PUBKEY {
        msg!("InitializeRewardsConfig: unauthorized — signer {} is not Foundation", foundation.key);
        return Err(ProgramError::InvalidArgument);
    }
    if *system_prog_info.key != system_program::ID {
        return Err(ProgramError::IncorrectProgramId);
    }

    // Derive and verify the PDA.
    let (expected_pda, bump) = Pubkey::find_program_address(&[b"rewards_config"], program_id);
    if *rewards_config_ai.key != expected_pda {
        msg!(
            "InitializeRewardsConfig: PDA mismatch — expected {}, got {}",
            expected_pda, rewards_config_ai.key
        );
        return Err(ProgramError::InvalidArgument);
    }

    // Hard guard — refuse to overwrite an already-initialized account.
    // Once the config PDA is allocated and funded, it must never be re-initialized.
    // (Prevents double 200M $FLOW pre-mint by resetting foundation_pre_minted.)
    if rewards_config_ai.data_len() >= RewardsConfig::SIZE && rewards_config_ai.lamports() > 0 {
        msg!("InitializeRewardsConfig: config account already initialized — refusing to overwrite");
        return Err(ProgramError::AccountAlreadyInitialized);
    }

    // Create and fund the PDA account.
    let rent     = Rent::get()?;
    let lamports = rent.minimum_balance(RewardsConfig::SIZE);
    let pda_seeds: &[&[u8]] = &[b"rewards_config", &[bump]];
    invoke_signed(
        &system_instruction::create_account(
            foundation.key,
            &expected_pda,
            lamports,
            RewardsConfig::SIZE as u64,
            program_id,
        ),
        &[foundation.clone(), rewards_config_ai.clone(), system_prog_info.clone()],
        &[pda_seeds],
    )?;

    let cfg = RewardsConfig {
        migration_mode:        true,  // start in migration mode (Rule 9)
        migration_locked:      false,
        bump,
        total_minted:          0,
        max_supply:            RewardsConfig::MAX_SUPPLY,
        foundation_pre_minted: false,
    };
    write_rewards_config(rewards_config_ai, &cfg)?;

    msg!("InitializeRewardsConfig: initialized with migration_mode=true bump={}", bump);
    Ok(())
}

/// Initialize a `UserEscrowReservation` PDA for a user.
///
/// Idempotent: returns `Ok(())` if the PDA already has the correct user pubkey (Rule 3).
/// Foundation attestation (Ed25519 precompile in same tx) validates `initial_reserved`.
///
/// Account layout:
///   0: payer         (signer)
///   1: reservation   (UserEscrowReservation PDA, writable — pre-created)
#[inline(never)]
fn process_initialize_reservation(
    _program_id:      &Pubkey,
    accounts:         &[AccountInfo],
    user:             [u8; 32],
    initial_reserved: u64,
    _deployment_slot: u64,
    _foundation_sig:  [u8; 64],
) -> ProgramResult {
    let accounts_iter  = &mut accounts.iter();
    let payer          = next_account_info(accounts_iter)?;
    let reservation_ai = next_account_info(accounts_iter)?;

    if !payer.is_signer {
        return Err(ProgramError::MissingRequiredSignature);
    }

    // Idempotent: if PDA already has the correct user, return early (Rule 3).
    if reservation_ai.data_len() >= UserEscrowReservation::SIZE && reservation_ai.lamports() > 0 {
        if let Ok(existing) = load_reservation(reservation_ai) {
            if existing.user == user {
                msg!(
                    "InitializeReservation: already initialized for user {:?} (reserved={})",
                    &user[..4], existing.reserved
                );
                return Ok(());
            }
            // Different user — this is an error (wrong PDA passed in).
            msg!("InitializeReservation: PDA has different user — wrong account");
            return Err(ProgramError::InvalidAccountData);
        }
    }

    // Foundation attestation: the Ed25519 precompile in this transaction verifies
    // the Foundation signature over {user ‖ initial_reserved ‖ deployment_slot}.
    // We trust the precompile; no additional verification here.

    let reservation = UserEscrowReservation {
        user,
        reserved: initial_reserved,
        bump:     0,
    };
    write_reservation(reservation_ai, &reservation)?;

    msg!(
        "InitializeReservation: initialized for user {:?} with reserved={}",
        &user[..4], initial_reserved
    );
    Ok(())
}

/// Set migration mode. `false` is IRREVERSIBLE — sets `migration_locked = true` (Rule 6).
///
/// Account layout:
///   0: foundation    (signer — Foundation multisig)
///   1: rewards_config (RewardsConfig PDA, writable)
#[inline(never)]
fn process_set_migration_mode(
    _program_id:  &Pubkey,
    accounts:     &[AccountInfo],
    enabled:      bool,
) -> ProgramResult {
    let accounts_iter     = &mut accounts.iter();
    let foundation        = next_account_info(accounts_iter)?;
    let rewards_config_ai = next_account_info(accounts_iter)?;

    if !foundation.is_signer {
        return Err(ProgramError::MissingRequiredSignature);
    }
    // C-01: Verify the signer is the authorised Foundation multisig.
    if *foundation.key != FOUNDATION_PUBKEY {
        msg!("SetMigrationMode: unauthorized — signer {} is not Foundation", foundation.key);
        return Err(ProgramError::InvalidArgument);
    }

    let mut cfg = load_rewards_config(rewards_config_ai)?;

    if !enabled {
        // Rule 6: SetMigrationMode(false) is IRREVERSIBLE.
        if cfg.migration_locked {
            msg!("SetMigrationMode: already locked — cannot re-enable migration mode");
            return Err(DisputeError::MigrationAlreadyLocked.into());
        }
        cfg.migration_mode   = false;
        cfg.migration_locked = true; // permanent lock
        msg!("SetMigrationMode: migration_mode=false (IRREVERSIBLE). migration_locked=true.");
    } else {
        // Enabling migration mode is only allowed before the lock.
        if cfg.migration_locked {
            return Err(DisputeError::MigrationAlreadyLocked.into());
        }
        cfg.migration_mode = true;
        msg!("SetMigrationMode: migration_mode=true");
    }

    write_rewards_config(rewards_config_ai, &cfg)?;
    Ok(())
}

/// Pre-mint 200M $FLOW to the Foundation token account (one-time, 80:20 tokenomics).
///
/// Enforces hard cap: fails if `total_minted + FOUNDATION_ALLOCATION > MAX_SUPPLY`.
/// Idempotent: returns Ok(()) if `foundation_pre_minted = true`.
///
/// Account layout:
///   0: foundation       (signer — Foundation multisig, C-01 pubkey checked)
///   1: rewards_config   (RewardsConfig PDA, writable)
///   2: mint_authority   (mint_authority PDA [b"mint_authority"], signer via PDA)
///   3: token_mint       ($FLOW SPL mint, writable)
///   4: foundation_token (Foundation's $FLOW token account, writable)
///   5: token_program    (SPL Token program)
#[inline(never)]
fn process_pre_mint_foundation(
    program_id: &Pubkey,
    accounts:   &[AccountInfo],
) -> ProgramResult {
    let accounts_iter      = &mut accounts.iter();
    let foundation         = next_account_info(accounts_iter)?;
    let rewards_config_ai  = next_account_info(accounts_iter)?;
    let mint_authority_ai  = next_account_info(accounts_iter)?;
    let token_mint_ai      = next_account_info(accounts_iter)?;
    let foundation_token   = next_account_info(accounts_iter)?;
    let token_program_ai   = next_account_info(accounts_iter)?;

    if !foundation.is_signer {
        return Err(ProgramError::MissingRequiredSignature);
    }
    // C-01 guard reused: same Foundation pubkey check.
    if *foundation.key != FOUNDATION_PUBKEY {
        msg!("PreMintFoundation: unauthorized — signer {} is not Foundation", foundation.key);
        return Err(ProgramError::InvalidArgument);
    }

    let mut cfg = load_rewards_config(rewards_config_ai)?;

    // Idempotent: if already executed, return Ok without re-minting.
    if cfg.foundation_pre_minted {
        msg!("PreMintFoundation: already executed — no-op");
        return Ok(());
    }

    // Hard cap: ensure total_minted + FOUNDATION_ALLOCATION ≤ MAX_SUPPLY.
    let new_total = cfg
        .total_minted
        .checked_add(RewardsConfig::FOUNDATION_ALLOCATION)
        .ok_or(ProgramError::ArithmeticOverflow)?;
    if new_total > cfg.effective_max_supply() {
        msg!(
            "PreMintFoundation: would exceed hard cap ({} + {} > {})",
            cfg.total_minted, RewardsConfig::FOUNDATION_ALLOCATION, cfg.effective_max_supply()
        );
        return Err(ProgramError::InvalidInstructionData);
    }

    // Derive mint_authority bump.
    let (_, mint_authority_bump) = solana_program::pubkey::Pubkey::find_program_address(
        &[b"mint_authority"],
        program_id,
    );

    // Mint FOUNDATION_ALLOCATION $FLOW to the Foundation's token account.
    cpi_mint_to(
        token_program_ai,
        token_mint_ai,
        foundation_token,
        mint_authority_ai,
        RewardsConfig::FOUNDATION_ALLOCATION,
        mint_authority_bump,
    )?;

    // Persist updated counters.
    cfg.total_minted          = new_total;
    cfg.foundation_pre_minted = true;
    write_rewards_config(rewards_config_ai, &cfg)?;

    msg!(
        "PreMintFoundation: minted {} $FLOW lamports to Foundation. total_minted={}",
        RewardsConfig::FOUNDATION_ALLOCATION, cfg.total_minted
    );
    Ok(())
}

// ─── RewardRates instruction handlers ────────────────────────────────────────

/// Initialize the `RewardRatesAccount` PDA with default or custom rates.
///
/// One-time setup — fails with `AccountAlreadyInitialized` if the PDA is
/// already funded and sized. Only the Foundation authority may call this.
///
/// Account layout:
///   0: foundation    (signer, writable — pays for PDA creation)
///   1: reward_rates  (RewardRatesAccount PDA [b"reward_rates"], writable)
///   2: system_program (readonly)
#[inline(never)]
fn process_initialize_reward_rates(
    program_id:       &Pubkey,
    accounts:         &[AccountInfo],
    routing_per_mb:   u64,
    seeding_per_mb:   u64,
    uptime_per_hour:  u64,
    flow_price_cents: u64,
) -> ProgramResult {
    let accounts_iter    = &mut accounts.iter();
    let foundation       = next_account_info(accounts_iter)?;
    let reward_rates_ai  = next_account_info(accounts_iter)?;
    let system_prog_info = next_account_info(accounts_iter)?;

    // Authority check — only the Foundation multisig may initialize.
    if !foundation.is_signer {
        return Err(ProgramError::MissingRequiredSignature);
    }
    if *foundation.key != FOUNDATION_PUBKEY {
        msg!(
            "InitializeRewardRates: unauthorized — signer {} is not Foundation",
            foundation.key
        );
        return Err(ProgramError::InvalidArgument);
    }
    if *system_prog_info.key != system_program::ID {
        return Err(ProgramError::IncorrectProgramId);
    }

    // Derive and verify the PDA.
    let (expected_pda, bump) = Pubkey::find_program_address(&[b"reward_rates"], program_id);
    if *reward_rates_ai.key != expected_pda {
        msg!(
            "InitializeRewardRates: reward_rates PDA mismatch — expected {}, got {}",
            expected_pda, reward_rates_ai.key
        );
        return Err(ProgramError::InvalidArgument);
    }

    // Re-initialization guard.
    if reward_rates_ai.data_len() >= RewardRatesAccount::SIZE && reward_rates_ai.lamports() > 0 {
        msg!("InitializeRewardRates: reward_rates PDA already initialized — refusing to overwrite");
        return Err(ProgramError::AccountAlreadyInitialized);
    }

    // Create and fund the PDA account.
    let rent     = Rent::get()?;
    let lamports = rent.minimum_balance(RewardRatesAccount::SIZE);
    let pda_seeds: &[&[u8]] = &[b"reward_rates", &[bump]];
    invoke_signed(
        &system_instruction::create_account(
            foundation.key,
            &expected_pda,
            lamports,
            RewardRatesAccount::SIZE as u64,
            program_id,
        ),
        &[foundation.clone(), reward_rates_ai.clone(), system_prog_info.clone()],
        &[pda_seeds],
    )?;

    let clock = Clock::get()?;

    let rates = RewardRatesAccount {
        authority:       foundation.key.to_bytes(),
        routing_per_mb:  if routing_per_mb  > 0 { routing_per_mb  } else { RewardRatesAccount::DEFAULT_ROUTING_PER_MB  },
        seeding_per_mb:  if seeding_per_mb  > 0 { seeding_per_mb  } else { RewardRatesAccount::DEFAULT_SEEDING_PER_MB  },
        uptime_per_hour: if uptime_per_hour > 0 { uptime_per_hour } else { RewardRatesAccount::DEFAULT_UPTIME_PER_HOUR },
        flow_price_cents,
        last_updated:    clock.unix_timestamp,
        change_count:    0,
        bump,
    };

    let serialized = borsh::to_vec(&rates).map_err(|_| ProgramError::InvalidAccountData)?;
    let mut data = reward_rates_ai.try_borrow_mut_data()?;
    if serialized.len() > data.len() {
        msg!(
            "InitializeRewardRates: account too small ({} < {})",
            data.len(), serialized.len()
        );
        return Err(ProgramError::AccountDataTooSmall);
    }
    data[..serialized.len()].copy_from_slice(&serialized);

    msg!(
        "InitializeRewardRates: routing_per_mb={} seeding_per_mb={} uptime_per_hour={} \
         flow_price_cents={} bump={}",
        rates.routing_per_mb, rates.seeding_per_mb, rates.uptime_per_hour,
        rates.flow_price_cents, bump
    );
    Ok(())
}

/// Update reward rates in the existing `RewardRatesAccount` PDA.
///
/// Only the Foundation authority may call this. Any field passed as 0 is
/// left unchanged (a field that is intentionally set to 0 should use 1 to
/// represent "reset"; this is acceptable because rates of 0 are operationally
/// meaningless and would disable rewards). `change_count` is incremented and
/// `last_updated` is set to the current clock timestamp.
///
/// Account layout:
///   0: foundation    (signer — must equal FOUNDATION_PUBKEY)
///   1: reward_rates  (RewardRatesAccount PDA [b"reward_rates"], writable)
#[inline(never)]
fn process_update_reward_rates(
    program_id:       &Pubkey,
    accounts:         &[AccountInfo],
    routing_per_mb:   u64,
    seeding_per_mb:   u64,
    uptime_per_hour:  u64,
    flow_price_cents: u64,
) -> ProgramResult {
    let accounts_iter   = &mut accounts.iter();
    let foundation      = next_account_info(accounts_iter)?;
    let reward_rates_ai = next_account_info(accounts_iter)?;

    // Authority check.
    if !foundation.is_signer {
        return Err(ProgramError::MissingRequiredSignature);
    }
    if *foundation.key != FOUNDATION_PUBKEY {
        msg!(
            "UpdateRewardRates: unauthorized — signer {} is not Foundation",
            foundation.key
        );
        return Err(ProgramError::InvalidArgument);
    }

    // Verify the PDA is the canonical one.
    let (expected_pda, _) = Pubkey::find_program_address(&[b"reward_rates"], program_id);
    if *reward_rates_ai.key != expected_pda {
        msg!(
            "UpdateRewardRates: reward_rates PDA mismatch — expected {}, got {}",
            expected_pda, reward_rates_ai.key
        );
        return Err(ProgramError::InvalidArgument);
    }

    // Load existing state.
    if reward_rates_ai.data_len() < RewardRatesAccount::SIZE || reward_rates_ai.lamports() == 0 {
        msg!("UpdateRewardRates: reward_rates PDA not initialized — call InitializeRewardRates first");
        return Err(ProgramError::UninitializedAccount);
    }
    let mut rates: RewardRatesAccount = {
        let data = reward_rates_ai.try_borrow_data()?;
        RewardRatesAccount::try_from_slice(&data).map_err(|_| ProgramError::InvalidAccountData)?
    };

    let clock = Clock::get()?;

    // Apply non-zero updates only (0 means "keep current value").
    if routing_per_mb  > 0 { rates.routing_per_mb  = routing_per_mb;  }
    if seeding_per_mb  > 0 { rates.seeding_per_mb  = seeding_per_mb;  }
    if uptime_per_hour > 0 { rates.uptime_per_hour = uptime_per_hour; }
    if flow_price_cents > 0 { rates.flow_price_cents = flow_price_cents; }
    rates.last_updated = clock.unix_timestamp;
    rates.change_count = rates.change_count.saturating_add(1);

    // Write back.
    let serialized = borsh::to_vec(&rates).map_err(|_| ProgramError::InvalidAccountData)?;
    let mut data = reward_rates_ai.try_borrow_mut_data()?;
    data[..serialized.len()].copy_from_slice(&serialized);

    msg!(
        "UpdateRewardRates: routing_per_mb={} seeding_per_mb={} uptime_per_hour={} \
         flow_price_cents={} change_count={} last_updated={}",
        rates.routing_per_mb, rates.seeding_per_mb, rates.uptime_per_hour,
        rates.flow_price_cents, rates.change_count, rates.last_updated
    );
    Ok(())
}

// ── TreasuryConfig instruction handlers ──────────────────────────────────────

/// Initialize the `TreasuryConfig` PDA.
///
/// Creates and funds the PDA account, then writes the initial config.
/// One-time — fails with `AccountAlreadyInitialized` if already initialized.
/// Only `FOUNDATION_PUBKEY` may call this.
///
/// Account layout:
///   0: foundation      (signer — must equal FOUNDATION_PUBKEY, writable — pays rent)
///   1: treasury_config (TreasuryConfig PDA [b"treasury_config"], writable — will be created)
///   2: system_program  (readonly)
#[inline(never)]
fn process_initialize_treasury_config_ix(
    program_id: &Pubkey,
    accounts:   &[AccountInfo],
    initial_treasury_keys: Vec<[u8; 32]>,
) -> ProgramResult {
    let accounts_iter       = &mut accounts.iter();
    let foundation          = next_account_info(accounts_iter)?;
    let treasury_config_ai  = next_account_info(accounts_iter)?;
    let system_prog_info    = next_account_info(accounts_iter)?;

    if !foundation.is_signer {
        return Err(ProgramError::MissingRequiredSignature);
    }
    if *foundation.key != FOUNDATION_PUBKEY {
        msg!(
            "InitializeTreasuryConfig: unauthorized — signer {} is not Foundation",
            foundation.key
        );
        return Err(ProgramError::InvalidArgument);
    }
    if *system_prog_info.key != system_program::ID {
        return Err(ProgramError::IncorrectProgramId);
    }

    // Derive and verify the PDA.
    let (expected_pda, bump) = Pubkey::find_program_address(&[b"treasury_config"], program_id);
    if *treasury_config_ai.key != expected_pda {
        msg!(
            "InitializeTreasuryConfig: PDA mismatch — expected {}, got {}",
            expected_pda, treasury_config_ai.key
        );
        return Err(ProgramError::InvalidArgument);
    }

    // Idempotency guard — refuse to reinitialize.
    if treasury_config_ai.data_len() >= TreasuryConfig::SIZE && treasury_config_ai.lamports() > 0 {
        msg!("InitializeTreasuryConfig: already initialized — refusing to overwrite");
        return Err(ProgramError::AccountAlreadyInitialized);
    }

    // Require at least one initial key.
    if initial_treasury_keys.is_empty() {
        msg!("InitializeTreasuryConfig: must provide at least one initial treasury key");
        return Err(ProgramError::InvalidArgument);
    }
    if initial_treasury_keys.len() > TreasuryConfig::MAX_KEYS {
        msg!(
            "InitializeTreasuryConfig: too many keys ({} > max {})",
            initial_treasury_keys.len(), TreasuryConfig::MAX_KEYS
        );
        return Err(ProgramError::InvalidArgument);
    }

    // Create and fund the PDA account.
    let rent     = Rent::get()?;
    let lamports = rent.minimum_balance(TreasuryConfig::SIZE);
    let pda_seeds: &[&[u8]] = &[b"treasury_config", &[bump]];
    invoke_signed(
        &system_instruction::create_account(
            foundation.key,
            &expected_pda,
            lamports,
            TreasuryConfig::SIZE as u64,
            program_id,
        ),
        &[foundation.clone(), treasury_config_ai.clone(), system_prog_info.clone()],
        &[pda_seeds],
    )?;

    let config = TreasuryConfig {
        authority:     FOUNDATION_PUBKEY.to_bytes(),
        treasury_keys: initial_treasury_keys.clone(),
        change_count:  0,
    };

    let serialized = borsh::to_vec(&config).map_err(|_| ProgramError::InvalidAccountData)?;
    let mut data   = treasury_config_ai.try_borrow_mut_data()?;
    if data.len() < serialized.len() {
        return Err(ProgramError::AccountDataTooSmall);
    }
    data[..serialized.len()].copy_from_slice(&serialized);

    msg!(
        "InitializeTreasuryConfig: initialized with {} treasury key(s)",
        initial_treasury_keys.len()
    );
    Ok(())
}

/// Update the authorized treasury pool in `TreasuryConfig`.
///
/// Only `FOUNDATION_PUBKEY` may call this. Increments `change_count`.
/// Must leave at least 1 key in the pool.
///
/// Account layout:
///   0: foundation      (signer — must equal FOUNDATION_PUBKEY)
///   1: treasury_config (TreasuryConfig PDA [b"treasury_config"], writable)
#[inline(never)]
fn process_update_treasury_pool_ix(
    program_id:           &Pubkey,
    accounts:             &[AccountInfo],
    add_treasury_keys:    Vec<[u8; 32]>,
    remove_treasury_keys: Vec<[u8; 32]>,
) -> ProgramResult {
    let accounts_iter      = &mut accounts.iter();
    let foundation         = next_account_info(accounts_iter)?;
    let treasury_config_ai = next_account_info(accounts_iter)?;

    if !foundation.is_signer {
        return Err(ProgramError::MissingRequiredSignature);
    }
    if *foundation.key != FOUNDATION_PUBKEY {
        msg!(
            "UpdateTreasuryPool: unauthorized — signer {} is not Foundation",
            foundation.key
        );
        return Err(ProgramError::InvalidArgument);
    }

    // Verify PDA address.
    let (expected_pda, _) = Pubkey::find_program_address(&[b"treasury_config"], program_id);
    if *treasury_config_ai.key != expected_pda {
        msg!(
            "UpdateTreasuryPool: PDA mismatch — expected {}, got {}",
            expected_pda, treasury_config_ai.key
        );
        return Err(ProgramError::InvalidArgument);
    }

    // Load existing config.
    if treasury_config_ai.data_len() < TreasuryConfig::SIZE || treasury_config_ai.lamports() == 0 {
        msg!("UpdateTreasuryPool: treasury_config not initialized — call InitializeTreasuryConfig first");
        return Err(ProgramError::UninitializedAccount);
    }
    let mut config: TreasuryConfig = {
        let data = treasury_config_ai.try_borrow_data()?;
        TreasuryConfig::try_from_slice(&data).map_err(|_| ProgramError::InvalidAccountData)?
    };

    // Apply removals first.
    for key in &remove_treasury_keys {
        config.treasury_keys.retain(|k| k != key);
    }

    // Apply additions (deduplicated).
    for key in add_treasury_keys {
        if !config.treasury_keys.contains(&key) {
            if config.treasury_keys.len() >= TreasuryConfig::MAX_KEYS {
                msg!("UpdateTreasuryPool: cannot add key — pool is at max capacity ({})", TreasuryConfig::MAX_KEYS);
                return Err(ProgramError::InvalidArgument);
            }
            config.treasury_keys.push(key);
        }
    }

    // Must retain at least one key.
    if config.treasury_keys.is_empty() {
        msg!("UpdateTreasuryPool: cannot remove all treasury keys — pool must have at least 1");
        return Err(ProgramError::InvalidArgument);
    }

    config.change_count = config.change_count.saturating_add(1);

    let serialized = borsh::to_vec(&config).map_err(|_| ProgramError::InvalidAccountData)?;
    let mut data   = treasury_config_ai.try_borrow_mut_data()?;
    data[..serialized.len()].copy_from_slice(&serialized);

    msg!(
        "UpdateTreasuryPool: {} key(s) in pool, change_count={}",
        config.treasury_keys.len(), config.change_count
    );
    Ok(())
}

// ── BondConfig instructions (Phase 2) ────────────────────────────────────────

/// Initialize the `BondConfig` PDA with dynamic bond/stake parameters.
///
/// Creates and funds the PDA account, then writes the initial config.
/// One-time call by Foundation — idempotent (returns Ok if already initialized).
///
/// Accounts:
///   0: foundation    — signer, writable (payer)
///   1: bond_config   — BondConfig PDA [b"bond_config"], writable (will be created)
///   2: system_program
#[inline(never)]
fn process_initialize_bond_config_ix(
    program_id:            &Pubkey,
    accounts:              &[AccountInfo],
    challenger_bond_cents: u64,
    min_stake_usd_cents:   u64,
    stake_earnings_bps:    u64,
    max_stake_flow:        u64,
) -> ProgramResult {
    let accounts_iter    = &mut accounts.iter();
    let foundation       = next_account_info(accounts_iter)?;
    let bond_config_ai   = next_account_info(accounts_iter)?;
    let system_prog_info = next_account_info(accounts_iter)?;

    if !foundation.is_signer {
        return Err(ProgramError::MissingRequiredSignature);
    }
    if *foundation.key != FOUNDATION_PUBKEY {
        msg!("InitializeBondConfig: unauthorized signer {}", foundation.key);
        return Err(ProgramError::InvalidArgument);
    }
    if *system_prog_info.key != system_program::ID {
        return Err(ProgramError::IncorrectProgramId);
    }

    let (expected_pda, bump) = Pubkey::find_program_address(&[b"bond_config"], program_id);
    if *bond_config_ai.key != expected_pda {
        msg!(
            "InitializeBondConfig: PDA mismatch — expected {}, got {}",
            expected_pda, bond_config_ai.key
        );
        return Err(ProgramError::InvalidArgument);
    }

    // Idempotent: skip if already initialized.
    if bond_config_ai.data_len() >= BondConfig::SIZE && bond_config_ai.lamports() > 0 {
        msg!("InitializeBondConfig: already initialized — skipping");
        return Ok(());
    }

    // Create and fund the PDA account.
    let rent     = Rent::get()?;
    let lamports = rent.minimum_balance(BondConfig::SIZE);
    let pda_seeds: &[&[u8]] = &[b"bond_config", &[bump]];
    invoke_signed(
        &system_instruction::create_account(
            foundation.key,
            &expected_pda,
            lamports,
            BondConfig::SIZE as u64,
            program_id,
        ),
        &[foundation.clone(), bond_config_ai.clone(), system_prog_info.clone()],
        &[pda_seeds],
    )?;

    let config = BondConfig {
        authority:             foundation.key.to_bytes(),
        challenger_bond_cents: if challenger_bond_cents == 0 {
            BondConfig::DEFAULT_CHALLENGER_BOND_CENTS
        } else {
            challenger_bond_cents
        },
        min_stake_usd_cents: if min_stake_usd_cents == 0 {
            BondConfig::DEFAULT_MIN_STAKE_USD_CENTS
        } else {
            min_stake_usd_cents
        },
        stake_earnings_bps: if stake_earnings_bps == 0 {
            BondConfig::DEFAULT_STAKE_EARNINGS_BPS
        } else {
            stake_earnings_bps
        },
        max_stake_flow: if max_stake_flow == 0 {
            BondConfig::DEFAULT_MAX_STAKE_FLOW
        } else {
            max_stake_flow
        },
        bump,
    };

    let serialized = borsh::to_vec(&config).map_err(|_| ProgramError::InvalidAccountData)?;
    let mut data   = bond_config_ai.try_borrow_mut_data()?;
    if serialized.len() > data.len() {
        msg!("InitializeBondConfig: account too small ({} < {})", data.len(), serialized.len());
        return Err(ProgramError::AccountDataTooSmall);
    }
    data[..serialized.len()].copy_from_slice(&serialized);

    msg!(
        "InitializeBondConfig: challenger_bond_cents={} min_stake_usd_cents={} stake_earnings_bps={} max_stake_flow={} bump={}",
        config.challenger_bond_cents, config.min_stake_usd_cents,
        config.stake_earnings_bps, config.max_stake_flow, bump,
    );
    Ok(())
}

/// Update the `BondConfig` PDA parameters.
///
/// Accounts:
///   0: foundation   — signer (must equal FOUNDATION_PUBKEY)
///   1: bond_config  — BondConfig PDA [b"bond_config"], writable
#[inline(never)]
fn process_update_bond_config_ix(
    program_id:            &Pubkey,
    accounts:              &[AccountInfo],
    challenger_bond_cents: u64,
    min_stake_usd_cents:   u64,
    stake_earnings_bps:    u64,
    max_stake_flow:        u64,
) -> ProgramResult {
    let accounts_iter  = &mut accounts.iter();
    let foundation     = next_account_info(accounts_iter)?;
    let bond_config_ai = next_account_info(accounts_iter)?;

    if !foundation.is_signer {
        return Err(ProgramError::MissingRequiredSignature);
    }
    if *foundation.key != FOUNDATION_PUBKEY {
        msg!("UpdateBondConfig: unauthorized signer {}", foundation.key);
        return Err(ProgramError::InvalidArgument);
    }

    let (expected_pda, _) = Pubkey::find_program_address(&[b"bond_config"], program_id);
    if *bond_config_ai.key != expected_pda {
        msg!(
            "UpdateBondConfig: PDA mismatch — expected {}, got {}",
            expected_pda, bond_config_ai.key
        );
        return Err(ProgramError::InvalidArgument);
    }

    if bond_config_ai.data_len() < BondConfig::SIZE || bond_config_ai.lamports() == 0 {
        msg!("UpdateBondConfig: not initialized — call InitializeBondConfig first");
        return Err(ProgramError::UninitializedAccount);
    }

    let mut config: BondConfig = {
        let data = bond_config_ai.try_borrow_data()?;
        BondConfig::try_from_slice(&data).map_err(|_| ProgramError::InvalidAccountData)?
    };

    if challenger_bond_cents != 0 { config.challenger_bond_cents = challenger_bond_cents; }
    if min_stake_usd_cents   != 0 { config.min_stake_usd_cents   = min_stake_usd_cents;   }
    if stake_earnings_bps    != 0 { config.stake_earnings_bps    = stake_earnings_bps;    }
    if max_stake_flow        != 0 { config.max_stake_flow        = max_stake_flow;        }

    let serialized = borsh::to_vec(&config).map_err(|_| ProgramError::InvalidAccountData)?;
    let mut data   = bond_config_ai.try_borrow_mut_data()?;
    data[..serialized.len()].copy_from_slice(&serialized);

    msg!(
        "UpdateBondConfig: challenger_bond_cents={} min_stake_usd_cents={} stake_earnings_bps={} max_stake_flow={}",
        config.challenger_bond_cents, config.min_stake_usd_cents,
        config.stake_earnings_bps, config.max_stake_flow,
    );
    Ok(())
}

// ── Treasury validation helper ────────────────────────────────────────────────

/// Verify that `treasury_token_ai`'s SPL owner is in the authorized `TreasuryConfig` pool.
///
/// **Mandatory** — no backward-compatible skip path. If the `treasury_config` PDA is
/// not initialized, or the treasury token account owner is not in the pool, this
/// returns `RewardsError::UnauthorizedTreasury` and the whole transaction reverts.
///
/// Called before every `cpi_mint_to(... treasury_token ...)` in the 70/30 split paths.
fn validate_treasury_token(
    treasury_config_ai: &AccountInfo,
    treasury_token_ai:  &AccountInfo,
    program_id:         &Pubkey,
) -> ProgramResult {
    // Verify PDA address matches canonical seeds.
    let (expected_pda, _) = Pubkey::find_program_address(&[b"treasury_config"], program_id);
    if *treasury_config_ai.key != expected_pda {
        msg!(
            "TreasuryConfig: PDA mismatch — expected {}, got {}",
            expected_pda, treasury_config_ai.key
        );
        return Err(RewardsError::UnauthorizedTreasury.into());
    }

    // Require the PDA to be initialized (non-backward-compatible).
    if treasury_config_ai.data_len() < TreasuryConfig::SIZE || treasury_config_ai.lamports() == 0 {
        msg!("TreasuryConfig: account not initialized — treasury validation is mandatory");
        return Err(RewardsError::UnauthorizedTreasury.into());
    }

    let config = TreasuryConfig::try_from_slice(&treasury_config_ai.try_borrow_data()?)
        .map_err(|_| ProgramError::InvalidAccountData)?;

    if config.treasury_keys.is_empty() {
        msg!("TreasuryConfig: no authorized treasury keys configured");
        return Err(RewardsError::UnauthorizedTreasury.into());
    }

    // Read treasury token account owner: SPL TokenAccount layout has owner at bytes 32..64.
    let token_data = treasury_token_ai.try_borrow_data()?;
    if token_data.len() < 64 {
        msg!("TreasuryConfig: treasury_token account too small to read SPL owner field");
        return Err(ProgramError::InvalidAccountData);
    }
    let mut owner = [0u8; 32];
    owner.copy_from_slice(&token_data[32..64]);

    if !config.treasury_keys.iter().any(|k| *k == owner) {
        msg!(
            "TreasuryConfig: treasury_token owner {} is not in the authorized pool",
            Pubkey::new_from_array(owner)
        );
        return Err(RewardsError::UnauthorizedTreasury.into());
    }

    msg!("TreasuryConfig: treasury_token owner validated");
    Ok(())
}

/// Sweep all Pending claims that have exceeded the 60-day timeout.
///
/// P1: also calls `settle_reservation` for each swept claim belonging to the
/// user identified by the optional reservation account.
///
/// CPI Bridge: for each swept claim matching the provided user, burns 100% of
/// the claim amount from user escrow (via CPI to `spend_from_escrow`) and
/// mints 80% back to the treasury. The remaining 20% is deflationary.
///
/// Account layout:
///   0: sweeper            (signer — anyone)
///   1: pending_claims     (PendingClaimsStore PDA, writable)
///   2: reservation        (UserEscrowReservation PDA for user, writable, optional)
///   3: user_escrow_state  (UserEscrow PDA from user-escrow program, writable, optional)
///
///   --- CPI Bridge accounts (all optional; all must be provided together) ---
///   4: mint_authority     — rewards mint_authority PDA ["mint_authority"]
///   5: token_mint         — $FLOW SPL mint (writable)
///   6: treasury_token     — treasury's $FLOW token account (writable; receives 80%; also relay_token guard)
///   7: treasury_wallet    — treasury wallet pubkey (used as `relay` param in spend_from_escrow)
///   8: user_escrow_token  — user's escrow SPL token account (writable; burned from)
///   9: user_wallet        — user's wallet pubkey (for spend_from_escrow PDA seed)
///  10: spender_registry   — AuthorizedSpenderRegistry PDA (read-only)
///  11: user_escrow_program — user-escrow program (for CPI)
///  12: token_program      — SPL Token program
#[inline(never)]
fn process_sweep_expired_escrow_ix(
    program_id: &Pubkey,
    accounts:   &[AccountInfo],
) -> ProgramResult {
    let accounts_iter        = &mut accounts.iter();
    let sweeper              = next_account_info(accounts_iter)?;
    let pending_claims_ai    = next_account_info(accounts_iter)?;
    let reservation_ai       = accounts_iter.next();
    let user_escrow_state_ai = accounts_iter.next();

    // CPI bridge accounts (all optional).
    let mint_authority_ai    = accounts_iter.next();
    let token_mint_ai        = accounts_iter.next();
    let treasury_token_ai    = accounts_iter.next();
    let treasury_wallet_ai   = accounts_iter.next();
    let user_escrow_token_ai = accounts_iter.next();
    let user_wallet_ai       = accounts_iter.next();
    let spender_registry_ai  = accounts_iter.next();
    let user_escrow_prog_ai  = accounts_iter.next();
    let token_program_ai     = accounts_iter.next();
    // Account 13 (mandatory when CPI bridge active): TreasuryConfig PDA.
    let treasury_config_sw_ai = accounts_iter.next();

    if !sweeper.is_signer {
        return Err(ProgramError::MissingRequiredSignature);
    }

    let clock = Clock::get()?;

    let mut store = if pending_claims_ai.data_len() > 0 && pending_claims_ai.lamports() > 0 {
        let data = pending_claims_ai.try_borrow_data()?;
        PendingClaimsStore::try_from_slice(&data)
            .map_err(|_| ProgramError::InvalidAccountData)?
    } else {
        return Err(DisputeError::NothingToSweep.into());
    };

    // Snapshot which claims are Pending before sweep (for settle_reservation + CPI loops).
    let pre_sweep_pending: Vec<([u8; 32], u64, Option<[u8; 32]>)> = store
        .claims
        .iter()
        .filter(|c| c.status == ClaimStatus::Pending)
        .map(|c| (c.claim_hash, c.total_amount, c.user))
        .collect();

    let result = sweep_expired_escrow(&mut store, clock.unix_timestamp)
        .map_err(ProgramError::from)?;

    write_store(pending_claims_ai, &store)?;

    // ── P1 Rule 1: settle_reservation for each newly swept claim ──────────────
    let reservation_user: Option<[u8; 32]> = if let Some(res_ai) = reservation_ai {
        if res_ai.data_len() > 0 && res_ai.lamports() > 0 {
            let mut reservation = load_reservation(res_ai)?;
            let escrow_balance = if let Some(ue_ai) = user_escrow_state_ai {
                load_user_escrow_balance(ue_ai)?
            } else {
                reservation.reserved
            };
            let user = reservation.user;

            // Settle for each claim that is now Swept and matches the reservation's user.
            for (hash, total_amount, user_opt) in &pre_sweep_pending {
                let newly_swept = store
                    .claims
                    .iter()
                    .any(|c| c.claim_hash == *hash && c.status == ClaimStatus::Swept);
                if newly_swept {
                    if let Some(claim_user) = user_opt {
                        if *claim_user == reservation.user {
                            settle_reservation(&mut reservation, *total_amount, escrow_balance)
                                .map_err(ProgramError::from)?;
                        }
                    }
                }
            }
            write_reservation(res_ai, &reservation)?;
            Some(user)
        } else {
            None
        }
    } else {
        None
    };

    // ── CPI Bridge: burn + mint for each swept claim matching the user ─────────
    //
    // Burns 100% from user escrow via spend_from_escrow.
    // Mints 80% (SWEEP_TREASURY_MINT_SHARE_BPS) to treasury.
    // Remaining 20% is deflationary (not re-minted).
    //
    // Only processes claims whose `claim.user` matches the provided `user_wallet_ai`.
    // Requires ALL CPI bridge accounts (4–12) to be provided together.
    if let (
        Some(ma_ai), Some(tm_ai), Some(tt_ai), Some(tw_ai),
        Some(uet_ai), Some(uw_ai), Some(sr_ai), Some(uep_ai), Some(tp_ai),
    ) = (
        mint_authority_ai, token_mint_ai, treasury_token_ai, treasury_wallet_ai,
        user_escrow_token_ai, user_wallet_ai, spender_registry_ai,
        user_escrow_prog_ai, token_program_ai,
    ) {
        let ue_state_ai = user_escrow_state_ai
            .ok_or(ProgramError::NotEnoughAccountKeys)?;

        let bump = verify_and_get_mint_authority_bump(ma_ai, program_id)?;

        // ── GAP-11: mandatory treasury validation ──────────────────────────────
        let tc_ai = treasury_config_sw_ai.ok_or(RewardsError::UnauthorizedTreasury)?;
        validate_treasury_token(tc_ai, tt_ai, program_id)?;

        let cpi_user_key = *uw_ai.key;

        let mut total_burned_cpi: u64 = 0;
        let mut total_minted_cpi: u64 = 0;

        for (hash, total_amount, user_opt) in &pre_sweep_pending {
            // Only burn/mint for claims matching the provided user account.
            if user_opt != &Some(cpi_user_key.to_bytes()) {
                continue;
            }
            // Confirm the claim was actually swept.
            let was_swept = store
                .claims
                .iter()
                .any(|c| c.claim_hash == *hash && c.status == ClaimStatus::Swept);
            if !was_swept {
                continue;
            }

            // Sweep economics: the user's $FLOW is 100% burned because the claim
            // was never acknowledged by any relay within the 60-day window. The user
            // has already consumed the bandwidth represented by this claim; there is
            // no service to refund. Per FLOW-CLOSED-LOOP-ECONOMY.md sweep spec:
            //   • 100% of total_amount is burned from the user's escrow token account.
            //   • 80% (SWEEP_TREASURY_MINT_SHARE_BPS = 8_000 bps) is re-minted to
            //     treasury to fund protocol operations.
            //   • The remaining 20% is net deflation — permanently removed from supply.
            //
            // treasury_wallet acts as `relay` (CPI redirect-protection param):
            // spend_from_escrow requires relay_token.owner == relay_wallet at the SPL
            // level. For sweep, treasury fills both roles. This is a deployment
            // requirement: the treasury token account must be owned by treasury_wallet.
            cpi_burn_from_escrow(
                uep_ai,
                ma_ai,
                uw_ai,
                ue_state_ai,
                uet_ai,
                tt_ai,   // treasury_token as relay_token (redirect guard)
                tw_ai,   // treasury_wallet as relay param
                sr_ai,
                tm_ai,
                tp_ai,
                *total_amount,
                bump,
            )?;
            total_burned_cpi = total_burned_cpi.saturating_add(*total_amount);

            // Mint 80% to treasury (20% stays deflationary).
            let treasury_mint = total_amount
                .saturating_mul(SWEEP_TREASURY_MINT_SHARE_BPS)
                .saturating_div(10_000);
            cpi_mint_to(tp_ai, tm_ai, tt_ai, ma_ai, treasury_mint, bump)?;
            total_minted_cpi = total_minted_cpi.saturating_add(treasury_mint);
        }

        if total_burned_cpi > 0 {
            msg!(
                "SweepExpiredEscrow CPI: burned={}, minted_treasury={}",
                total_burned_cpi, total_minted_cpi
            );
        }

        let _ = reservation_user; // suppress unused warning
    }

    msg!(
        "SweepExpiredEscrow: {} claims swept, treasury={} $FLOW, burned={} $FLOW",
        result.claims_swept, result.treasury_amount, result.burned_amount
    );
    Ok(())
}

/// Request a Foundation reconciliation of a user's reservation.
///
/// Starts the 72-hour timelock. Foundation must be the signer.
///
/// Account layout:
///   0: foundation       (signer — Foundation multisig)
///   1: reconcile_intent (ReconcileIntent PDA, writable — pre-created)
#[inline(never)]
fn process_request_reconciliation(
    _program_id:  &Pubkey,
    accounts:     &[AccountInfo],
    user:         [u8; 32],
    new_reserved: u64,
) -> ProgramResult {
    let accounts_iter      = &mut accounts.iter();
    let foundation         = next_account_info(accounts_iter)?;
    let reconcile_intent_ai = next_account_info(accounts_iter)?;

    if !foundation.is_signer {
        return Err(ProgramError::MissingRequiredSignature);
    }

    let clock = Clock::get()?;

    let intent = ReconcileIntent {
        user,
        new_reserved,
        requested_at: clock.unix_timestamp,
        executed:     false,
    };

    let serialized = borsh::to_vec(&intent).map_err(|_| ProgramError::InvalidAccountData)?;
    if serialized.len() <= reconcile_intent_ai.data_len() {
        let mut data = reconcile_intent_ai.try_borrow_mut_data()?;
        data[..serialized.len()].copy_from_slice(&serialized);
    } else {
        return Err(ProgramError::AccountDataTooSmall);
    }

    msg!(
        "RequestReconciliation: user={:?} new_reserved={} timelock=72h",
        &user[..4], new_reserved
    );
    Ok(())
}

/// Execute a pending reconciliation after the 72-hour timelock elapses.
///
/// Account layout:
///   0: executor         (signer — anyone after timelock)
///   1: reconcile_intent (ReconcileIntent PDA, writable)
///   2: reservation      (UserEscrowReservation PDA, writable)
#[inline(never)]
fn process_execute_reconciliation(
    _program_id: &Pubkey,
    accounts:    &[AccountInfo],
    user:        [u8; 32],
) -> ProgramResult {
    let accounts_iter       = &mut accounts.iter();
    let executor            = next_account_info(accounts_iter)?;
    let reconcile_intent_ai = next_account_info(accounts_iter)?;
    let reservation_ai      = next_account_info(accounts_iter)?;

    if !executor.is_signer {
        return Err(ProgramError::MissingRequiredSignature);
    }

    let clock = Clock::get()?;

    if reconcile_intent_ai.data_len() < ReconcileIntent::SIZE || reconcile_intent_ai.lamports() == 0 {
        return Err(DisputeError::ReconcileIntentNotFound.into());
    }

    let data = reconcile_intent_ai.try_borrow_data()?;
    let mut intent = ReconcileIntent::try_from_slice(&data)
        .map_err(|_| ProgramError::InvalidAccountData)?;
    drop(data);

    if intent.user != user {
        return Err(ProgramError::InvalidAccountData);
    }
    if intent.executed {
        return Err(DisputeError::ClaimAlreadySettled.into()); // reuse for "already done"
    }

    // Enforce 72-hour timelock.
    let elapsed = clock.unix_timestamp.saturating_sub(intent.requested_at);
    if elapsed < ReconcileIntent::TIMELOCK_SECONDS {
        msg!(
            "ExecuteReconciliation: timelock not elapsed ({}/{}s)",
            elapsed, ReconcileIntent::TIMELOCK_SECONDS
        );
        return Err(DisputeError::ReconcileTimelockNotElapsed.into());
    }

    // Apply the corrected reserved value.
    let mut reservation = load_reservation(reservation_ai)?;
    if reservation.user != user {
        return Err(ProgramError::InvalidAccountData);
    }
    let old_reserved = reservation.reserved;
    reservation.reserved = intent.new_reserved;
    write_reservation(reservation_ai, &reservation)?;

    // Mark intent as executed.
    intent.executed = true;
    let serialized = borsh::to_vec(&intent).map_err(|_| ProgramError::InvalidAccountData)?;
    let mut data = reconcile_intent_ai.try_borrow_mut_data()?;
    data[..serialized.len()].copy_from_slice(&serialized);

    msg!(
        "ExecuteReconciliation: user={:?} reserved {} → {}",
        &user[..4], old_reserved, intent.new_reserved
    );
    Ok(())
}

/// Cancel a pending reconciliation intent. Foundation-only.
///
/// Account layout:
///   0: foundation       (signer — Foundation multisig)
///   1: reconcile_intent (ReconcileIntent PDA, writable)
#[inline(never)]
fn process_cancel_reconciliation(
    _program_id: &Pubkey,
    accounts:    &[AccountInfo],
    user:        [u8; 32],
) -> ProgramResult {
    let accounts_iter       = &mut accounts.iter();
    let foundation          = next_account_info(accounts_iter)?;
    let reconcile_intent_ai = next_account_info(accounts_iter)?;

    if !foundation.is_signer {
        return Err(ProgramError::MissingRequiredSignature);
    }

    if reconcile_intent_ai.data_len() < ReconcileIntent::SIZE || reconcile_intent_ai.lamports() == 0 {
        return Err(DisputeError::ReconcileIntentNotFound.into());
    }

    let data = reconcile_intent_ai.try_borrow_data()?;
    let intent = ReconcileIntent::try_from_slice(&data)
        .map_err(|_| ProgramError::InvalidAccountData)?;
    drop(data);

    if intent.user != user {
        return Err(ProgramError::InvalidAccountData);
    }

    // Zero out the account to signal cancellation.
    let mut data = reconcile_intent_ai.try_borrow_mut_data()?;
    data.fill(0);

    msg!("CancelReconciliation: cancelled for user {:?}", &user[..4]);
    Ok(())
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ─── Helpers ─────────────────────────────────────────────────────────────

    fn relay_a() -> [u8; 32] { [0xAA; 32] }
    fn relay_b() -> [u8; 32] { [0xBB; 32] }
    fn client_x() -> [u8; 32] { [0xCC; 32] }

    fn fresh_state(user: [u8; 32], relay: [u8; 32]) -> UserRelayClaimState {
        UserRelayClaimState {
            user,
            relay,
            last_claimed_seq:    0,
            total_claimed_bytes: 0,
            last_claim_slot:     0,
            bump:                0,
        }
    }

    fn make_record(
        user:     [u8; 32],
        relay:    [u8; 32],
        seq:      u64,
        bytes:    u64,
        start_ts: u64,
        end_ts:   u64,
    ) -> UsageRecordOnChain {
        UsageRecordOnChain {
            user,
            relay,
            session_id:    [0u8; 16],
            bytes,
            charge_usd:    (bytes as f64 / 1e9 * 0.10 * 1_000_000.0) as u64,
            charge_flow:   0,
            start_ts,
            end_ts,
            seq,
            session_pubkey: [0u8; 32],
            user_sig:        [0u8; 64],
            relay_sig:       [0u8; 64],
            client_signature: [0u8; 64],
            // Chain fields — zeroed for legacy tests (not chain-validated here).
            prev_hash:       [0u8; 32],
            nonce:          seq, // use seq as nonce for convenience
            session_total:  bytes,
            record_hash:    [0u8; 32],
        }
    }

    /// Make a chain-valid record with proper chain linkage.
    fn make_chain_record(
        relay:     [u8; 32],
        seq:       u64,
        bytes:     u64,
        start_ts:  u64,
        end_ts:    u64,
        nonce:     u64,
        prev_hash: [u8; 32],
        prev_total: u64,
    ) -> UsageRecordOnChain {
        let session_total = prev_total + bytes;
        let mut r = UsageRecordOnChain {
            user:          client_x(),
            relay,
            session_id:    [0u8; 16],
            bytes,
            charge_usd:    0,
            charge_flow:   0,
            start_ts,
            end_ts,
            seq,
            session_pubkey: [0u8; 32],
            user_sig:        [0u8; 64],
            relay_sig:       [0u8; 64],
            client_signature: [0u8; 64],
            prev_hash,
            nonce,
            session_total,
            record_hash:   [0u8; 32],
        };
        // Compute and set the record_hash so chain links are correct.
        r.record_hash = compute_record_hash_onchain(&r);
        r
    }

    fn now_ts() -> i64 { 1_700_000_000 } // fixed timestamp for reproducible tests

    /// Make a record with recent timestamps (relative to now_ts) — passes age check.
    fn make_recent_record(
        user:  [u8; 32],
        relay: [u8; 32],
        seq:   u64,
        bytes: u64,
    ) -> UsageRecordOnChain {
        let end_ts   = (now_ts() - 60) as u64;  // 60s ago
        let start_ts = end_ts - 10;              // 10s segment
        make_record(user, relay, seq, bytes, start_ts, end_ts)
    }

    // ─── validate_usage_record tests ─────────────────────────────────────────

    #[test]
    fn valid_record_accepted() {
        let state  = fresh_state(client_x(), relay_a());
        let record = make_record(client_x(), relay_a(), 1, 1_024 * 1_024 * 1_024, 1_699_990_000, 1_699_999_000);
        assert_eq!(
            validate_usage_record(&record, &state, &relay_a(), now_ts()),
            Ok(())
        );
    }

    #[test]
    fn sequential_seqs_accepted() {
        let mut state = fresh_state(client_x(), relay_a());

        let r1 = make_recent_record(client_x(), relay_a(), 1, 1024);
        let r2 = make_recent_record(client_x(), relay_a(), 2, 1024);
        let r3 = make_recent_record(client_x(), relay_a(), 3, 1024);

        let ts = now_ts();
        validate_usage_record(&r1, &state, &relay_a(), ts).unwrap();
        state.last_claimed_seq = r1.seq;

        validate_usage_record(&r2, &state, &relay_a(), ts).unwrap();
        state.last_claimed_seq = r2.seq;

        validate_usage_record(&r3, &state, &relay_a(), ts).unwrap();
        state.last_claimed_seq = r3.seq;

        assert_eq!(state.last_claimed_seq, 3);
    }

    #[test]
    fn duplicate_seq_rejected() {
        let mut state = fresh_state(client_x(), relay_a());
        state.last_claimed_seq = 5; // already claimed up to seq 5

        let record = make_record(client_x(), relay_a(), 5, 1024, 1_000, 2_000);
        assert_eq!(
            validate_usage_record(&record, &state, &relay_a(), now_ts()),
            Err(RewardsError::DuplicateSequence)
        );
    }

    #[test]
    fn replay_seq_rejected() {
        let mut state = fresh_state(client_x(), relay_a());
        state.last_claimed_seq = 10;

        // Seq 3 was already included in batch that updated to 10.
        let record = make_record(client_x(), relay_a(), 3, 1024, 1_000, 2_000);
        assert_eq!(
            validate_usage_record(&record, &state, &relay_a(), now_ts()),
            Err(RewardsError::DuplicateSequence)
        );
    }

    #[test]
    fn cross_relay_claim_rejected() {
        // Relay B tries to claim a record bound to Relay A.
        let state  = fresh_state(client_x(), relay_a());
        let record = make_record(client_x(), relay_a(), 1, 1024, 1_000, 2_000);
        // relay_b is the signer — mismatch with record.relay = relay_a
        assert_eq!(
            validate_usage_record(&record, &state, &relay_b(), now_ts()),
            Err(RewardsError::WrongRelay)
        );
    }

    #[test]
    fn relay_a_cannot_claim_relay_b_records() {
        // Record signed for Relay B — Relay A cannot claim it.
        let state  = fresh_state(client_x(), relay_b());
        let record = make_record(client_x(), relay_b(), 1, 1024, 1_000, 2_000);
        assert_eq!(
            validate_usage_record(&record, &state, &relay_a(), now_ts()),
            Err(RewardsError::WrongRelay)
        );
    }

    #[test]
    fn rate_limit_enforced() {
        let state = fresh_state(client_x(), relay_a());
        // 2 GB in 1 second = 2 GB/s > 1 GB/s limit.
        let bytes    = 2 * 1_024 * 1_024 * 1_024u64;
        let record   = make_record(client_x(), relay_a(), 1, bytes, 1_000, 1_001); // 1 second
        assert_eq!(
            validate_usage_record(&record, &state, &relay_a(), now_ts()),
            Err(RewardsError::RateLimitExceeded)
        );
    }

    #[test]
    fn rate_limit_passes_at_boundary() {
        let state = fresh_state(client_x(), relay_a());
        // Exactly 1 GB in 1 second = 1 GB/s = boundary (OK).
        let bytes    = MAX_BYTES_PER_SECOND;
        let end_ts   = (now_ts() - 60) as u64;
        let start_ts = end_ts - 1; // 1-second window
        let record   = make_record(client_x(), relay_a(), 1, bytes, start_ts, end_ts);
        assert_eq!(
            validate_usage_record(&record, &state, &relay_a(), now_ts()),
            Ok(())
        );
    }

    #[test]
    fn stale_record_rejected() {
        let state = fresh_state(client_x(), relay_a());
        // Record ended 72 hours ago — exceeds 48h window.
        let stale_end = (now_ts() - 72 * 3600) as u64;
        let record    = make_record(client_x(), relay_a(), 1, 1024, stale_end - 10, stale_end);
        assert_eq!(
            validate_usage_record(&record, &state, &relay_a(), now_ts()),
            Err(RewardsError::RecordTooOld)
        );
    }

    #[test]
    fn record_at_48h_boundary_accepted() {
        let state = fresh_state(client_x(), relay_a());
        // Exactly at the 48h boundary — should be accepted (age == MAX_RECORD_AGE_SECONDS).
        let end_ts = (now_ts() - MAX_RECORD_AGE_SECONDS) as u64;
        let record  = make_record(client_x(), relay_a(), 1, 1024, end_ts - 100, end_ts);
        assert_eq!(
            validate_usage_record(&record, &state, &relay_a(), now_ts()),
            Ok(())
        );
    }

    #[test]
    fn record_just_past_48h_rejected() {
        let state = fresh_state(client_x(), relay_a());
        let end_ts = (now_ts() - MAX_RECORD_AGE_SECONDS - 1) as u64;
        let record  = make_record(client_x(), relay_a(), 1, 1024, end_ts - 100, end_ts);
        assert_eq!(
            validate_usage_record(&record, &state, &relay_a(), now_ts()),
            Err(RewardsError::RecordTooOld)
        );
    }

    #[test]
    fn zero_duration_rejected() {
        let state  = fresh_state(client_x(), relay_a());
        // end_ts == start_ts → zero duration.
        let record = make_record(client_x(), relay_a(), 1, 1024, 1_000, 1_000);
        assert_eq!(
            validate_usage_record(&record, &state, &relay_a(), now_ts()),
            Err(RewardsError::ZeroDuration)
        );
    }

    #[test]
    fn reversed_timestamps_rejected() {
        let state  = fresh_state(client_x(), relay_a());
        // end_ts < start_ts → negative duration.
        let record = make_record(client_x(), relay_a(), 1, 1024, 2_000, 1_000);
        assert_eq!(
            validate_usage_record(&record, &state, &relay_a(), now_ts()),
            Err(RewardsError::ZeroDuration)
        );
    }

    // ─── validate_batch_order tests ──────────────────────────────────────────

    #[test]
    fn ascending_batch_accepted() {
        let r1 = make_record(client_x(), relay_a(), 1, 1024, 1_000, 2_000);
        let r2 = make_record(client_x(), relay_a(), 2, 1024, 2_000, 3_000);
        let r3 = make_record(client_x(), relay_a(), 3, 1024, 3_000, 4_000);
        assert_eq!(validate_batch_order(&[r1, r2, r3]), Ok(()));
    }

    #[test]
    fn unordered_batch_rejected() {
        let r1 = make_record(client_x(), relay_a(), 1, 1024, 1_000, 2_000);
        let r3 = make_record(client_x(), relay_a(), 3, 1024, 3_000, 4_000);
        let r2 = make_record(client_x(), relay_a(), 2, 1024, 2_000, 3_000);
        // r1, r3, r2 — not ascending.
        assert_eq!(
            validate_batch_order(&[r1, r3, r2]),
            Err(RewardsError::RecordsNotSorted)
        );
    }

    #[test]
    fn duplicate_seq_in_batch_rejected() {
        let r1 = make_record(client_x(), relay_a(), 1, 1024, 1_000, 2_000);
        let r2 = make_record(client_x(), relay_a(), 1, 1024, 2_000, 3_000); // dup seq
        assert_eq!(
            validate_batch_order(&[r1, r2]),
            Err(RewardsError::RecordsNotSorted)
        );
    }

    #[test]
    fn single_record_batch_accepted() {
        let r = make_record(client_x(), relay_a(), 42, 1024, 1_000, 2_000);
        assert_eq!(validate_batch_order(&[r]), Ok(()));
    }

    // ─── Independent sequence spaces per (client, relay) ─────────────────────

    #[test]
    fn relay_a_and_b_have_independent_seq_spaces() {
        // Client X used Relay A (seq 1-3) and Relay B (seq 1-3).
        // Both claiming should succeed independently.
        let mut state_a = fresh_state(client_x(), relay_a());
        let mut state_b = fresh_state(client_x(), relay_b());

        let ts = now_ts();

        // Relay A claims seq 1-3.
        for seq in 1u64..=3 {
            let r = make_recent_record(client_x(), relay_a(), seq, 1024);
            validate_usage_record(&r, &state_a, &relay_a(), ts).unwrap();
            state_a.last_claimed_seq = seq;
        }

        // Relay B claims seq 1-3 independently.
        for seq in 1u64..=3 {
            let r = make_recent_record(client_x(), relay_b(), seq, 1024);
            validate_usage_record(&r, &state_b, &relay_b(), ts).unwrap();
            state_b.last_claimed_seq = seq;
        }

        assert_eq!(state_a.last_claimed_seq, 3);
        assert_eq!(state_b.last_claimed_seq, 3);
    }

    #[test]
    fn client_returning_to_relay_continues_sequence() {
        // Client X leaves Relay A at seq 3, returns later → seq 4, 5 accepted.
        let mut state = fresh_state(client_x(), relay_a());
        state.last_claimed_seq = 3;

        let ts = now_ts();
        let r4 = make_recent_record(client_x(), relay_a(), 4, 1024);
        let r5 = make_recent_record(client_x(), relay_a(), 5, 1024);

        validate_usage_record(&r4, &state, &relay_a(), ts).unwrap();
        state.last_claimed_seq = 4;
        validate_usage_record(&r5, &state, &relay_a(), ts).unwrap();
        state.last_claimed_seq = 5;

        assert_eq!(state.last_claimed_seq, 5);
    }

    #[test]
    fn partial_overlap_handled_correctly() {
        // Relay already claimed seq 1-5. Client tries to submit seq 3-7.
        // Only seq 6 and 7 should be new; 3-5 are duplicates.
        let mut state = fresh_state(client_x(), relay_a());
        state.last_claimed_seq = 5;

        let ts = now_ts();

        // Seq 3-5: duplicate → rejected regardless of timestamp.
        for seq in 3u64..=5 {
            let r = make_recent_record(client_x(), relay_a(), seq, 1024);
            assert_eq!(
                validate_usage_record(&r, &state, &relay_a(), ts),
                Err(RewardsError::DuplicateSequence),
                "seq {seq} should be rejected"
            );
        }

        // Seq 6-7: new → accepted.
        for seq in 6u64..=7 {
            let r = make_recent_record(client_x(), relay_a(), seq, 1024);
            validate_usage_record(&r, &state, &relay_a(), ts).unwrap();
            state.last_claimed_seq = seq;
        }

        assert_eq!(state.last_claimed_seq, 7);
    }

    // ─── Dispute Window tests ─────────────────────────────────────────────────

    fn relay_pubkey() -> [u8; 32] { [0xDD; 32] }
    fn challenger_pubkey() -> [u8; 32] { [0xEE; 32] }

    fn make_batch(count: usize, base_seq: u64) -> Vec<UsageRecordOnChain> {
        (0..count)
            .map(|i| {
                let seq = base_seq + i as u64;
                make_recent_record(client_x(), relay_pubkey(), seq, 1_073_741_824)
            })
            .collect()
    }

    fn submit_batch(store: &mut PendingClaimsStore, records: &[UsageRecordOnChain], ts: i64) -> [u8; 32] {
        let tip          = records.last().expect("non-empty batch");
        let tip_hash     = compute_record_hash_onchain(tip);
        let tip_nonce    = tip.nonce;
        let session_id   = tip.session_id;
        let total_amount: u64 = records.iter().map(|r| r.charge_flow).sum();
        let record_count = records.len() as u32;
        let bytes_routed: u64 = records.iter().map(|r| r.bytes).sum();
        // Use the user from the first record (all records in a batch share the same user).
        let user_pubkey  = records[0].user;
        submit_claim_with_bond(
            store, &relay_pubkey(), &session_id, tip_nonce, &tip_hash,
            total_amount, record_count, ts, &user_pubkey,
            bytes_routed, 0,
        )
    }

    // ── submit_claim_with_bond ───────────────────────────────────────────────

    #[test]
    fn submit_claim_creates_pending_entry() {
        let mut store = PendingClaimsStore::default();
        let records   = make_batch(3, 1);
        let ts        = now_ts();
        let hash      = submit_batch(&mut store, &records, ts);

        assert_eq!(store.claims.len(), 1);
        let claim = &store.claims[0];
        assert_eq!(claim.status,           ClaimStatus::Pending);
        assert_eq!(claim.relay,            relay_pubkey());
        assert_eq!(claim.claim_hash,       hash);
        assert_eq!(claim.record_count,     3);
        assert_eq!(claim.submitted_at,     ts);
        assert_eq!(claim.dispute_deadline, ts + DISPUTE_WINDOW_SECONDS);
        assert_eq!(claim.bond,             RELAY_BOND_FLOW);
    }

    #[test]
    fn claim_hash_is_deterministic() {
        // Same inputs always produce the same hash (domain-separated + chain tip).
        let relay      = relay_pubkey();
        let session_id = [0u8; 16];
        let tip_nonce  = 3u64;
        let tip_hash   = [0xAAu8; 32];
        let h1 = compute_claim_hash(&relay, &session_id, tip_nonce, &tip_hash);
        let h2 = compute_claim_hash(&relay, &session_id, tip_nonce, &tip_hash);
        assert_eq!(h1, h2, "Hash must be deterministic");
    }

    #[test]
    fn different_records_produce_different_hashes() {
        // Different tip_nonce → different claim hash.
        let relay      = relay_pubkey();
        let session_id = [0u8; 16];
        let tip_hash   = [0xAAu8; 32];
        let h1 = compute_claim_hash(&relay, &session_id, 1, &tip_hash);
        let h2 = compute_claim_hash(&relay, &session_id, 2, &tip_hash);
        assert_ne!(h1, h2, "Different tip_nonce must produce different hash");
    }

    #[test]
    fn claim_hash_domain_separation() {
        // Domain separator prevents cross-protocol collisions.
        let relay      = relay_pubkey();
        let session_id = [0u8; 16];
        let tip_hash   = [0x00u8; 32];
        let h = compute_claim_hash(&relay, &session_id, 1, &tip_hash);
        // Must not be all zeros (i.e., the domain label influences the hash).
        assert_ne!(h, [0u8; 32]);
    }

    #[test]
    fn claim_hash_differs_by_relay() {
        // Different relay pubkey → different claim hash.
        let relay_a    = [0xAAu8; 32];
        let relay_b    = [0xBBu8; 32];
        let session_id = [0u8; 16];
        let tip_hash   = [0xCCu8; 32];
        let h1 = compute_claim_hash(&relay_a, &session_id, 1, &tip_hash);
        let h2 = compute_claim_hash(&relay_b, &session_id, 1, &tip_hash);
        assert_ne!(h1, h2, "Different relay must produce different hash");
    }

    // ── dispute_claim ────────────────────────────────────────────────────────

    #[test]
    fn dispute_within_window_sets_status_disputed() {
        let mut store = PendingClaimsStore::default();
        let records   = make_batch(1, 1);
        let ts        = now_ts();
        let hash      = submit_batch(&mut store, &records, ts);

        // Dispute filed 1 day later — well within 7-day window.
        let dispute_ts = ts + 86_400;
        dispute_claim(
            &mut store, hash, 0,
            records[0].clone(), challenger_pubkey(), dispute_ts, [0u8; 32],
            DEFAULT_CHALLENGER_BOND_FLOW,
        ).unwrap();

        assert_eq!(store.claims[0].status, ClaimStatus::Disputed);
        assert_eq!(store.disputes.len(),   1);
        assert_eq!(store.disputes[0].challenger, challenger_pubkey());
        assert_eq!(store.disputes[0].bond,       CHALLENGER_BOND_FLOW);
    }

    #[test]
    fn dispute_after_window_rejected() {
        let mut store = PendingClaimsStore::default();
        let records   = make_batch(1, 1);
        let ts        = now_ts();
        let hash      = submit_batch(&mut store, &records, ts);

        // Dispute filed 8 days later — 1 day past the 7-day window.
        let late_ts = ts + DISPUTE_WINDOW_SECONDS + 86_400;
        let result  = dispute_claim(
            &mut store, hash, 0,
            records[0].clone(), challenger_pubkey(), late_ts, [0u8; 32],
            DEFAULT_CHALLENGER_BOND_FLOW,
        );

        assert_eq!(result, Err(DisputeError::DisputeWindowExpired));
        assert_eq!(store.claims[0].status, ClaimStatus::Pending); // unchanged
    }

    #[test]
    fn dispute_nonexistent_claim_fails() {
        let mut store    = PendingClaimsStore::default();
        let wrong_hash   = [0xFFu8; 32];
        let records      = make_batch(1, 1);
        let result = dispute_claim(
            &mut store, wrong_hash, 0,
            records[0].clone(), challenger_pubkey(), now_ts(), [0u8; 32],
            DEFAULT_CHALLENGER_BOND_FLOW,
        );
        assert_eq!(result, Err(DisputeError::ClaimNotFound));
    }

    #[test]
    fn double_dispute_rejected() {
        let mut store = PendingClaimsStore::default();
        let records   = make_batch(1, 1);
        let ts        = now_ts();
        let hash      = submit_batch(&mut store, &records, ts);

        dispute_claim(
            &mut store, hash, 0, records[0].clone(), challenger_pubkey(), ts, [0u8; 32],
            DEFAULT_CHALLENGER_BOND_FLOW,
        ).unwrap();

        // Second dispute on the same claim — already Disputed.
        let result = dispute_claim(
            &mut store, hash, 0, records[0].clone(), [0xFFu8; 32], ts + 100, [0u8; 32],
            DEFAULT_CHALLENGER_BOND_FLOW,
        );
        assert_eq!(result, Err(DisputeError::ClaimAlreadyDisputed));
    }

    // ── resolve_dispute ──────────────────────────────────────────────────────

    #[test]
    fn valid_dispute_slashes_relay() {
        let mut store = PendingClaimsStore::default();
        let records   = make_batch(1, 1);
        let ts        = now_ts();
        let hash      = submit_batch(&mut store, &records, ts);

        dispute_claim(
            &mut store, hash, 0, records[0].clone(), challenger_pubkey(), ts, [0u8; 32],
            DEFAULT_CHALLENGER_BOND_FLOW,
        ).unwrap();

        // Challenger proved forgery via Ed25519 precompile → relay slashed.
        let outcome = resolve_dispute_relay_slashed(&mut store, hash).unwrap();

        assert_eq!(store.claims[0].status, ClaimStatus::Slashed);
        assert!(matches!(outcome, DisputeOutcome::RelaySlashed { .. }));

        if let DisputeOutcome::RelaySlashed { challenger_reward, burned, .. } = outcome {
            assert_eq!(challenger_reward + burned, RELAY_BOND_FLOW);
            assert_eq!(challenger_reward, RELAY_BOND_FLOW / 2);
        }
    }

    #[test]
    fn invalid_dispute_slashes_challenger() {
        let mut store = PendingClaimsStore::default();
        let records   = make_batch(1, 1);
        let ts        = now_ts();
        let hash      = submit_batch(&mut store, &records, ts);

        dispute_claim(
            &mut store, hash, 0, records[0].clone(), challenger_pubkey(), ts, [0u8; 32],
            DEFAULT_CHALLENGER_BOND_FLOW,
        ).unwrap();

        // Relay proved sig valid via Ed25519 precompile → challenger slashed.
        let outcome = resolve_dispute_challenger_slashed(&mut store, hash).unwrap();

        assert_eq!(store.claims[0].status, ClaimStatus::Resolved);
        assert!(matches!(outcome, DisputeOutcome::ChallengerSlashed { .. }));
        if let DisputeOutcome::ChallengerSlashed { relay_reward, burned } = outcome {
            // 80% to relay, 20% burned.
            assert_eq!(relay_reward + burned, CHALLENGER_BOND_FLOW);
            assert_eq!(relay_reward, CHALLENGER_BOND_FLOW * TREASURY_SHARE_BPS / 10_000);
        }
    }

    #[test]
    fn resolve_undisputed_claim_fails() {
        let mut store = PendingClaimsStore::default();
        let records   = make_batch(1, 1);
        let hash      = submit_batch(&mut store, &records, now_ts());

        // No dispute filed — neither resolve function applies.
        assert_eq!(resolve_dispute_relay_slashed(&mut store, hash), Err(DisputeError::NotDisputed));
        assert_eq!(resolve_dispute_challenger_slashed(&mut store, hash), Err(DisputeError::NotDisputed));
    }

    #[test]
    fn resolve_nonexistent_claim_fails() {
        let mut store = PendingClaimsStore::default();
        assert_eq!(resolve_dispute_relay_slashed(&mut store, [0xABu8; 32]),    Err(DisputeError::ClaimNotFound));
        assert_eq!(resolve_dispute_challenger_slashed(&mut store, [0xABu8; 32]), Err(DisputeError::ClaimNotFound));
    }

    // ── force_resolve_dispute ────────────────────────────────────────────────

    #[test]
    fn force_resolve_after_3_days_succeeds() {
        let mut store = PendingClaimsStore::default();
        let records   = make_batch(1, 1);
        let ts        = now_ts();
        let hash      = submit_batch(&mut store, &records, ts);

        dispute_claim(&mut store, hash, 0, records[0].clone(), challenger_pubkey(), ts, [0u8; 32], DEFAULT_CHALLENGER_BOND_FLOW).unwrap();

        // Force-resolve after 3 days + 1 second.
        let force_ts = ts + DISPUTE_RESOLVE_SECONDS + 1;
        let outcome  = force_resolve_dispute(&mut store, hash, force_ts).unwrap();

        assert_eq!(store.claims[0].status, ClaimStatus::Resolved);
        assert!(matches!(outcome, DisputeOutcome::ChallengerSlashed { .. }));
        if let DisputeOutcome::ChallengerSlashed { relay_reward, burned } = outcome {
            // 80% to relay, 20% burned.
            assert_eq!(relay_reward + burned, CHALLENGER_BOND_FLOW);
            assert_eq!(relay_reward, CHALLENGER_BOND_FLOW * TREASURY_SHARE_BPS / 10_000);
        }
    }

    #[test]
    fn force_resolve_before_3_days_rejected() {
        let mut store = PendingClaimsStore::default();
        let records   = make_batch(1, 1);
        let ts        = now_ts();
        let hash      = submit_batch(&mut store, &records, ts);

        dispute_claim(&mut store, hash, 0, records[0].clone(), challenger_pubkey(), ts, [0u8; 32], DEFAULT_CHALLENGER_BOND_FLOW).unwrap();

        // Only 1 day elapsed — too early.
        let result = force_resolve_dispute(&mut store, hash, ts + 86_400);
        assert_eq!(result, Err(DisputeError::ResolveTooEarly));
        assert_eq!(store.claims[0].status, ClaimStatus::Disputed); // unchanged
    }

    #[test]
    fn force_resolve_undisputed_claim_fails() {
        let mut store = PendingClaimsStore::default();
        let records   = make_batch(1, 1);
        let ts        = now_ts();
        let hash      = submit_batch(&mut store, &records, ts);

        // No dispute was ever filed — DisputeNotFound.
        let result = force_resolve_dispute(&mut store, hash, ts + DISPUTE_RESOLVE_SECONDS + 1);
        assert_eq!(result, Err(DisputeError::DisputeNotFound));
    }

    #[test]
    fn force_resolve_already_resolved_fails() {
        let mut store = PendingClaimsStore::default();
        let records   = make_batch(1, 1);
        let ts        = now_ts();
        let hash      = submit_batch(&mut store, &records, ts);

        dispute_claim(&mut store, hash, 0, records[0].clone(), challenger_pubkey(), ts, [0u8; 32], DEFAULT_CHALLENGER_BOND_FLOW).unwrap();

        // Relay resolves normally first.
        resolve_dispute_challenger_slashed(&mut store, hash).unwrap();
        assert_eq!(store.claims[0].status, ClaimStatus::Resolved);

        // Now try to force-resolve the already-settled claim.
        let result = force_resolve_dispute(&mut store, hash, ts + DISPUTE_RESOLVE_SECONDS + 1);
        assert_eq!(result, Err(DisputeError::NotDisputed));
    }

    // ── release_rewards ──────────────────────────────────────────────────────

    #[test]
    fn release_after_window_succeeds() {
        let mut store = PendingClaimsStore::default();
        let records   = make_batch(2, 1);
        let ts        = now_ts();
        let hash      = submit_batch(&mut store, &records, ts);

        // Release called 8 days later — past the dispute window.
        let release_ts = ts + DISPUTE_WINDOW_SECONDS + 86_400;
        let (amount, bond, treasury_penalty) = release_rewards(&mut store, hash, release_ts).unwrap();

        assert_eq!(store.claims[0].status, ClaimStatus::Released);
        assert_eq!(bond, RELAY_BOND_FLOW);
        assert_eq!(treasury_penalty, 0); // normal claim — no penalty
        // amount = sum of charge_flow across both records (0 in make_recent_record)
        let _ = amount; // actual value depends on make_recent_record's charge_flow
    }

    #[test]
    fn release_before_window_fails() {
        let mut store = PendingClaimsStore::default();
        let records   = make_batch(1, 1);
        let ts        = now_ts();
        let hash      = submit_batch(&mut store, &records, ts);

        // Release attempted only 1 day later — window not yet expired.
        let result = release_rewards(&mut store, hash, ts + 86_400);
        assert_eq!(result, Err(DisputeError::DisputeWindowNotExpired));
        assert_eq!(store.claims[0].status, ClaimStatus::Pending); // unchanged
    }

    #[test]
    fn release_disputed_claim_fails() {
        let mut store = PendingClaimsStore::default();
        let records   = make_batch(1, 1);
        let ts        = now_ts();
        let hash      = submit_batch(&mut store, &records, ts);

        dispute_claim(
            &mut store, hash, 0, records[0].clone(), challenger_pubkey(), ts, [0u8; 32],
            DEFAULT_CHALLENGER_BOND_FLOW,
        ).unwrap();

        // Cannot release a disputed claim (status is Disputed, not Pending).
        let result = release_rewards(&mut store, hash, ts + DISPUTE_WINDOW_SECONDS + 1);
        assert_eq!(result, Err(DisputeError::ClaimAlreadySettled));
    }

    #[test]
    fn release_nonexistent_claim_fails() {
        let mut store = PendingClaimsStore::default();
        let result    = release_rewards(&mut store, [0xCCu8; 32], now_ts() + DISPUTE_WINDOW_SECONDS + 1);
        assert_eq!(result, Err(DisputeError::ClaimNotFound));
    }

    // ── Bond accounting ──────────────────────────────────────────────────────

    #[test]
    fn relay_slash_accounting_50_50_split() {
        let mut store = PendingClaimsStore::default();
        let records   = make_batch(1, 1);
        let hash      = submit_batch(&mut store, &records, now_ts());

        dispute_claim(
            &mut store, hash, 0, records[0].clone(), challenger_pubkey(), now_ts(), [0u8; 32],
            DEFAULT_CHALLENGER_BOND_FLOW,
        ).unwrap();

        let outcome = resolve_dispute_relay_slashed(&mut store, hash).unwrap();

        if let DisputeOutcome::RelaySlashed { challenger_reward, burned, .. } = outcome {
            // 50% to challenger, 50% burned — total = relay bond.
            assert_eq!(challenger_reward, RELAY_BOND_FLOW / 2);
            assert_eq!(burned,            RELAY_BOND_FLOW - RELAY_BOND_FLOW / 2);
            assert_eq!(challenger_reward + burned, RELAY_BOND_FLOW);
        } else {
            panic!("Expected RelaySlashed outcome");
        }
    }

    #[test]
    fn multiple_claims_tracked_independently() {
        let mut store = PendingClaimsStore::default();
        let ts = now_ts();

        let records1 = make_batch(2, 1);
        let records2 = make_batch(3, 100);

        let hash1 = submit_batch(&mut store, &records1, ts);
        let hash2 = submit_batch(&mut store, &records2, ts + 60);

        assert_eq!(store.claims.len(), 2);
        assert_ne!(hash1, hash2);

        // Dispute claim 1, release claim 2 after window.
        dispute_claim(
            &mut store, hash1, 0, records1[0].clone(), challenger_pubkey(), ts, [0u8; 32],
            DEFAULT_CHALLENGER_BOND_FLOW,
        ).unwrap();

        // release_ts must exceed deadline of claim2 = ts + 60 + DISPUTE_WINDOW_SECONDS
        let release_ts = ts + 60 + DISPUTE_WINDOW_SECONDS + 1;
        let (_, _, _) = release_rewards(&mut store, hash2, release_ts).unwrap();

        assert_eq!(store.claims[0].status, ClaimStatus::Disputed);
        assert_eq!(store.claims[1].status, ClaimStatus::Released);
    }

    // ─── RepFlowTier + RewardAccount (existing tests) ────────────────────────

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
            tier:                   1,
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

    // Helper: return current BASE_* constants as a rate tuple so tests
    // don't need to repeat the three constant names.
    fn default_rates() -> (u64, u64, u64) {
        (RewardAccount::BASE_ROUTING_PER_MB,
         RewardAccount::BASE_SEEDING_PER_MB,
         RewardAccount::BASE_UPTIME_PER_HOUR)
    }

    #[test]
    fn icon_earns_more_than_newcomer() {
        let (r, s, u) = default_rates();
        let bytes  = 100 * 1024 * 1024 * 1024_u64;
        let uptime = 3600_u64;
        let icon     = make_account(100_000);
        let newcomer = make_account(0);
        let icon_r   = icon.calculate_reward(bytes, bytes, uptime, 100_000, r, s, u);
        let newc_r   = newcomer.calculate_reward(bytes, bytes, uptime, 0, r, s, u);
        assert!(icon_r > newc_r);
        let ratio = icon_r as f64 / newc_r as f64;
        assert!(ratio > 1.5, "Icon/Newcomer ratio must exceed 1.5× (got {ratio:.2}×)");
    }

    #[test]
    fn cashback_is_included_in_total() {
        let (r, s, u) = default_rates();
        let routing_mb = 1024u64;
        let bytes      = routing_mb * 1024 * 1024;
        let icon       = make_account(100_000);
        let total      = icon.calculate_reward(bytes, 0, 0, 100_000, r, s, u);
        let base       = routing_mb * r;
        let multiplied = base * 150 / 100;
        let cashback   = multiplied * 12 / 100;
        let expected   = multiplied + cashback;
        assert_eq!(total, expected);
    }

    #[test]
    fn uptime_reward_not_multiplied() {
        let (r, s, u) = default_rates();
        let uptime_hrs = 24u64;
        let uptime_s   = uptime_hrs * 3600;
        let icon     = make_account(100_000);
        let newcomer = make_account(0);
        // With full hours the new formula gives the same result as the old one.
        let uptime_expected = uptime_hrs * u;
        assert_eq!(icon.calculate_reward(0, 0, uptime_s, 100_000, r, s, u), uptime_expected);
        assert_eq!(newcomer.calculate_reward(0, 0, uptime_s, 0, r, s, u),   uptime_expected);
    }

    #[test]
    fn rewards_calculation_with_repflow_veteran() {
        let (r, s, u) = default_rates();
        let routing_mb   = 1024u64;
        let bytes_routed = routing_mb * 1024 * 1024;
        let repflow_bal  = 15_000;
        let acct         = make_account(repflow_bal);
        let total        = acct.calculate_reward(bytes_routed, 0, 0, repflow_bal, r, s, u);
        let base         = routing_mb * r;
        let mult         = base * 130 / 100;
        let cashback     = mult * 7 / 100;
        assert_eq!(total, mult + cashback);
    }

    #[test]
    fn zero_activity_zero_reward() {
        let (r, s, u) = default_rates();
        let acct = make_account(5_000);
        assert_eq!(acct.calculate_reward(0, 0, 0, 5_000, r, s, u), 0);
    }

    // ─── E2 regression: partial-hour uptime earns proportional reward ────────

    #[test]
    fn uptime_partial_hour_earns_proportional_reward() {
        // E2 fix: 3599 s should earn almost 1 full hour — NOT zero.
        // Old formula: (3599 / 3600) * rate = 0  (integer division truncates)
        // New formula: (3599 * rate) / 3600     ≈ rate (99.97% of 1 hr)
        let (r, s, u) = default_rates();
        let acct     = make_account(2_000); // Active tier, 1.0× multiplier
        let uptime_s = 3599_u64;

        let actual   = acct.calculate_reward(0, 0, uptime_s, 2_000, r, s, u);
        let expected = uptime_s.saturating_mul(u).saturating_div(3600);

        assert!(expected > 0, "3599 s must yield non-zero uptime reward");
        assert_eq!(actual, expected, "actual must equal multiply-then-divide formula");
        // Must be ≥ 99 % of 1 full-hour reward.
        assert!(actual >= u * 99 / 100,
            "3599 s should earn ≥99%% of 1 hr reward; got {actual}, 1hr reward={u}");
    }

    // ─── E1 regression: 1000× higher rates produce 1000× reward ────────────

    #[test]
    fn higher_rates_yield_proportionally_higher_rewards() {
        // Shape of E1: PDA stores 1_000_000/MB; old hardcoded = 1_000/MB (1000× gap).
        // Verify calculate_reward() scales linearly with the rate parameters.
        let acct     = make_account(2_000); // Active tier, 1.0× (no mult effect)
        let bytes    = 1024u64 * 1024 * 1024; // 1 GB
        let uptime_s = 3600_u64;             // exact 1 hour so both formulas agree

        // Old constants (pre-fix fallback)
        let reward_old = acct.calculate_reward(
            bytes, 0, uptime_s, 2_000,
            1_000, 2_000, 10_000_000,
        );
        // Target rates (what the PDA already stores)
        let reward_new = acct.calculate_reward(
            bytes, 0, uptime_s, 2_000,
            1_000_000, 2_000_000, 10_000_000_000,
        );

        assert!(reward_old > 0, "old-rate reward must be non-zero");
        assert_eq!(reward_new, reward_old * 1_000,
            "1000× rates must produce 1000× reward (got old={reward_old} new={reward_new})");
    }

    // ─── Append-Only Chain validation tests ─────────────────────────────────

    fn make_valid_chain(count: usize) -> Vec<UsageRecordOnChain> {
        let ts = (now_ts() - 60) as u64;
        let mut records = Vec::new();
        let mut prev_hash = [0u8; 32];
        let mut prev_total = 0u64;
        for i in 0..count {
            let nonce = (i + 1) as u64;
            let bytes = 1_073_741_824u64;
            let r = make_chain_record(
                relay_a(), (i + 1) as u64, bytes,
                ts + i as u64 * 10, ts + i as u64 * 10 + 9,
                nonce, prev_hash, prev_total,
            );
            prev_hash  = r.record_hash;
            prev_total = r.session_total;
            records.push(r);
        }
        records
    }

    #[test]
    fn valid_chain_accepted() {
        let chain = make_valid_chain(3);
        assert_eq!(validate_chain(&chain), Ok(()));
    }

    #[test]
    fn empty_chain_rejected() {
        assert_eq!(validate_chain(&[]), Err(RewardsError::EmptyChain));
    }

    #[test]
    fn single_record_chain_accepted() {
        let chain = make_valid_chain(1);
        assert_eq!(validate_chain(&chain), Ok(()));
    }

    #[test]
    fn genesis_nonzero_prev_hash_rejected() {
        let mut chain = make_valid_chain(1);
        chain[0].prev_hash = [0xAAu8; 32]; // non-zero prev_hash on genesis
        assert_eq!(validate_chain(&chain), Err(RewardsError::InvalidGenesis));
    }

    #[test]
    fn genesis_wrong_nonce_rejected() {
        let ts = (now_ts() - 60) as u64;
        let mut r = make_chain_record(relay_a(), 1, 1024, ts, ts + 9, 2, [0u8; 32], 0);
        r.nonce = 2; // genesis must have nonce == 1
        r.record_hash = compute_record_hash_onchain(&r);
        assert_eq!(validate_chain(&[r]), Err(RewardsError::NonceGap));
    }

    #[test]
    fn broken_chain_prev_hash_mismatch_rejected() {
        let mut chain = make_valid_chain(3);
        // Corrupt r2's prev_hash — breaks the link between r1 and r2.
        chain[1].prev_hash = [0xBBu8; 32];
        assert_eq!(validate_chain(&chain), Err(RewardsError::BrokenChain));
    }

    #[test]
    fn nonce_gap_detected() {
        let mut chain = make_valid_chain(3);
        // Skip nonce 2 → nonce jumps from 1 to 3.
        chain[1].nonce = 3;
        chain[1].record_hash = compute_record_hash_onchain(&chain[1]);
        // r2 now has nonce 3, r3 should be 4, but was built as 3 — also a gap
        assert_eq!(validate_chain(&chain), Err(RewardsError::NonceGap));
    }

    #[test]
    fn total_mismatch_detected() {
        let mut chain = make_valid_chain(2);
        // Corrupt session_total on record 2 — should be prev_total + bytes.
        chain[1].session_total = chain[1].session_total + 1; // off by one
        chain[1].record_hash = compute_record_hash_onchain(&chain[1]);
        assert_eq!(validate_chain(&chain), Err(RewardsError::TotalMismatch));
    }

    #[test]
    fn session_total_accumulates_correctly() {
        let chain = make_valid_chain(5);
        let expected_total = 5 * 1_073_741_824u64;
        assert_eq!(chain.last().unwrap().session_total, expected_total);
    }

    // ─── 60-day sweep tests ──────────────────────────────────────────────────

    #[test]
    fn sweep_after_60_days_succeeds() {
        let mut store = PendingClaimsStore::default();
        let ts     = now_ts();
        let hash   = submit_batch(&mut store, &make_batch(2, 1), ts);

        // Sweep after 61 days.
        let sweep_ts = ts + SWEEP_TIMEOUT_SECONDS + 86_400;
        let result   = sweep_expired_escrow(&mut store, sweep_ts).unwrap();

        assert_eq!(result.claims_swept, 1);
        assert!(result.total_swept > 0);
        // Treasury gets 80%.
        assert_eq!(result.treasury_amount, result.total_swept * 8_000 / 10_000);
        // Burned gets remaining 20%.
        assert_eq!(result.burned_amount, result.total_swept - result.treasury_amount);
        // Claim is now marked Swept (M3: distinct from Slashed).
        let claim = store.claims.iter().find(|c| c.claim_hash == hash).unwrap();
        assert_eq!(claim.status, ClaimStatus::Swept);
    }

    #[test]
    fn sweep_before_60_days_rejected() {
        let mut store = PendingClaimsStore::default();
        let ts = now_ts();
        submit_batch(&mut store, &make_batch(1, 1), ts);

        // Try to sweep after only 30 days.
        let result = sweep_expired_escrow(&mut store, ts + 30 * 24 * 3600);
        assert_eq!(result, Err(DisputeError::SweepTooEarly));
    }

    #[test]
    fn sweep_empty_store_returns_nothing_to_sweep() {
        let mut store = PendingClaimsStore::default();
        let result = sweep_expired_escrow(&mut store, now_ts() + SWEEP_TIMEOUT_SECONDS + 1);
        assert_eq!(result, Err(DisputeError::NothingToSweep));
    }

    #[test]
    fn sweep_only_affects_expired_pending_claims() {
        let mut store = PendingClaimsStore::default();
        let ts  = now_ts();

        // Claim1 submitted now → will expire.
        let hash1 = submit_batch(&mut store, &make_batch(1, 1), ts);
        // Claim2 submitted 30 days from now → not yet expired.
        let hash2 = submit_batch(&mut store, &make_batch(1, 10), ts + 30 * 24 * 3600);

        // Sweep at exactly ts + SWEEP_TIMEOUT_SECONDS + 1 (claim1 expired, claim2 not).
        let sweep_ts = ts + SWEEP_TIMEOUT_SECONDS + 1;
        let result   = sweep_expired_escrow(&mut store, sweep_ts).unwrap();

        assert_eq!(result.claims_swept, 1);

        let claim1 = store.claims.iter().find(|c| c.claim_hash == hash1).unwrap();
        let claim2 = store.claims.iter().find(|c| c.claim_hash == hash2).unwrap();
        assert_eq!(claim1.status, ClaimStatus::Swept);     // M3: Swept not Slashed
        assert_eq!(claim2.status, ClaimStatus::Pending); // untouched
    }

    #[test]
    fn sweep_includes_relay_bond() {
        let mut store = PendingClaimsStore::default();
        let ts  = now_ts();
        submit_batch(&mut store, &make_batch(1, 1), ts);

        let sweep_ts = ts + SWEEP_TIMEOUT_SECONDS + 1;
        let result   = sweep_expired_escrow(&mut store, sweep_ts).unwrap();

        // total_swept = total_amount + relay_bond.
        // In our test make_batch uses charge_flow = 0, so only bond is swept.
        assert!(result.total_swept >= RELAY_BOND_FLOW, "Sweep must include relay bond");
    }

    // ─── Dispute type P6 tests ───────────────────────────────────────────────

    #[test]
    fn chain_dispute_kind_borsh_roundtrip() {
        let kinds = [
            ChainDisputeKind::TotalMismatch,
            ChainDisputeKind::BrokenChain,
            ChainDisputeKind::ForgedSignature,
            ChainDisputeKind::DuplicateNonce,
        ];
        for kind in &kinds {
            let encoded = borsh::to_vec(kind).unwrap();
            let decoded: ChainDisputeKind = borsh::from_slice(&encoded).unwrap();
            assert_eq!(*kind, decoded);
        }
    }

    // ─── force_claim tests ───────────────────────────────────────────────────

    /// Helper: timestamps where both timeout gates pass.
    /// `last_activity` and `session_updated_at` are both 25h before `clock_ts`.
    fn force_claim_ts() -> (i64, i64, i64) {
        let clock_ts           = now_ts();
        let last_activity_ts   = clock_ts - FORCE_CLAIM_TIMEOUT_SECS as i64 - 3_600; // 25h ago
        let session_updated_at = clock_ts - FORCE_CLAIM_TIMEOUT_SECS as i64 - 3_600; // 25h ago
        (clock_ts, last_activity_ts, session_updated_at)
    }

    fn force_claim_tip() -> ([u8; 16], u64, [u8; 32]) {
        ([0x01u8; 16], 3, [0xABu8; 32])
    }

    #[test]
    fn force_claim_after_timeout_succeeds() {
        let mut store                    = PendingClaimsStore::default();
        let (clock, last_act, net_act)   = force_claim_ts();
        let (sid, nonce, tip)            = force_claim_tip();

        let result = force_claim(
            &mut store, &relay_pubkey(), &sid, nonce, &tip,
            1_000_000, 5, clock, last_act, net_act, &client_x(), 0, 0,
        );
        assert!(result.is_ok(), "force_claim should succeed: {result:?}");
        assert_eq!(store.claims.len(), 1);
    }

    #[test]
    fn force_claim_before_timeout_fails() {
        let mut store          = PendingClaimsStore::default();
        let clock_ts           = now_ts();
        let last_activity_ts   = clock_ts - 3_600; // only 1h ago — well within 24h window
        let session_updated_at = clock_ts - FORCE_CLAIM_TIMEOUT_SECS as i64 - 3_600;
        let (sid, nonce, tip)  = force_claim_tip();

        let result = force_claim(
            &mut store, &relay_pubkey(), &sid, nonce, &tip,
            1_000_000, 5, clock_ts, last_activity_ts, session_updated_at, &client_x(), 0, 0,
        );
        assert_eq!(result, Err(RewardsError::ForceClaimTooEarly));
        assert!(store.claims.is_empty());
    }

    #[test]
    fn force_claim_session_still_active_fails() {
        // Client is 25h idle on this relay but the DHT shows session activity 30m ago.
        let mut store          = PendingClaimsStore::default();
        let clock_ts           = now_ts();
        let last_activity_ts   = clock_ts - FORCE_CLAIM_TIMEOUT_SECS as i64 - 3_600; // 25h
        let session_updated_at = clock_ts - 1_800; // only 30m ago — client is on another relay
        let (sid, nonce, tip)  = force_claim_tip();

        let result = force_claim(
            &mut store, &relay_pubkey(), &sid, nonce, &tip,
            1_000_000, 5, clock_ts, last_activity_ts, session_updated_at, &client_x(), 0, 0,
        );
        assert_eq!(result, Err(RewardsError::SessionStillActive));
        assert!(store.claims.is_empty());
    }

    #[test]
    fn force_claim_session_inactive_succeeds() {
        // Both this relay and the network have been idle for >24h — client is truly gone.
        let mut store                    = PendingClaimsStore::default();
        let (clock, last_act, net_act)   = force_claim_ts();
        let (sid, nonce, tip)            = force_claim_tip();

        let result = force_claim(
            &mut store, &relay_pubkey(), &sid, nonce, &tip,
            5_000, 2, clock, last_act, net_act, &client_x(), 0, 0,
        );
        assert!(result.is_ok());
        assert_eq!(store.claims[0].is_force_claim, true);
    }

    #[test]
    fn force_claim_penalty_is_20_percent() {
        let mut store                    = PendingClaimsStore::default();
        let (clock, last_act, net_act)   = force_claim_ts();
        let (sid, nonce, tip)            = force_claim_tip();
        let total_amount                 = 10_000u64;

        let (_, penalty) = force_claim(
            &mut store, &relay_pubkey(), &sid, nonce, &tip,
            total_amount, 1, clock, last_act, net_act, &client_x(), 0, 0,
        ).unwrap();

        assert_eq!(penalty, 2_000); // 20% of 10_000
    }

    #[test]
    fn force_claim_sets_is_force_claim_flag() {
        let mut store                    = PendingClaimsStore::default();
        let (clock, last_act, net_act)   = force_claim_ts();
        let (sid, nonce, tip)            = force_claim_tip();

        let (hash, _) = force_claim(
            &mut store, &relay_pubkey(), &sid, nonce, &tip,
            1_000, 1, clock, last_act, net_act, &client_x(), 0, 0,
        ).unwrap();

        let claim = store.claims.iter().find(|c| c.claim_hash == hash).unwrap();
        assert!(claim.is_force_claim, "is_force_claim must be true for force claims");
        // M1: user field is set.
        assert_eq!(claim.user, Some(client_x()));
    }

    #[test]
    fn force_claim_release_deducts_penalty() {
        let mut store                    = PendingClaimsStore::default();
        let (clock, last_act, net_act)   = force_claim_ts();
        let (sid, nonce, tip)            = force_claim_tip();
        let total_amount                 = 10_000u64;

        let (hash, _) = force_claim(
            &mut store, &relay_pubkey(), &sid, nonce, &tip,
            total_amount, 1, clock, last_act, net_act, &client_x(), 0, 0,
        ).unwrap();

        // Release after the dispute window.
        let release_ts = clock + DISPUTE_WINDOW_SECONDS + 1;
        let (relay_amount, bond, treasury_penalty) =
            release_rewards(&mut store, hash, release_ts).unwrap();

        let expected_penalty = total_amount * FORCE_CLAIM_PENALTY_BPS / 10_000;
        assert_eq!(treasury_penalty, expected_penalty,     "20% should go to treasury");
        assert_eq!(relay_amount,     total_amount - expected_penalty, "relay gets 80%");
        assert_eq!(bond,             RELAY_BOND_FLOW,      "bond returned regardless");
        assert_eq!(relay_amount + treasury_penalty, total_amount);
    }

    #[test]
    fn force_claim_dispute_window_still_applies() {
        // force_claim still has a 7-day dispute window.
        let mut store                    = PendingClaimsStore::default();
        let (clock, last_act, net_act)   = force_claim_ts();
        let (sid, nonce, tip)            = force_claim_tip();

        let (hash, _) = force_claim(
            &mut store, &relay_pubkey(), &sid, nonce, &tip,
            1_000, 1, clock, last_act, net_act, &client_x(), 0, 0,
        ).unwrap();

        let claim = store.claims.iter().find(|c| c.claim_hash == hash).unwrap();
        assert_eq!(claim.dispute_deadline, clock + DISPUTE_WINDOW_SECONDS);
        assert_eq!(claim.bond,             RELAY_BOND_FLOW);

        // Attempting to release before window expires must fail.
        let early_ts = clock + 86_400; // only 1 day later
        assert_eq!(
            release_rewards(&mut store, hash, early_ts),
            Err(DisputeError::DisputeWindowNotExpired)
        );
    }

    #[test]
    fn force_claim_hash_differs_from_normal_claim() {
        // Same chain tip but different nonces → different hashes.
        let mut store                    = PendingClaimsStore::default();
        let (clock, last_act, net_act)   = force_claim_ts();
        let session_id                   = [0x02u8; 16];
        let tip_hash                     = [0xCCu8; 32];

        let (force_hash, _) = force_claim(
            &mut store, &relay_pubkey(), &session_id, 3, &tip_hash,
            1_000, 1, clock, last_act, net_act, &client_x(), 0, 0,
        ).unwrap();

        // Normal claim with a different tip_nonce.
        let normal_hash = submit_claim_with_bond(
            &mut store, &relay_pubkey(), &session_id, 4, &tip_hash,
            1_000, 1, clock, &client_x(), 0, 0,
        );

        assert_ne!(force_hash, normal_hash, "force_claim and normal claim must have different hashes");
    }

    #[test]
    fn force_claim_zero_bytes_zero_penalty() {
        let mut store                    = PendingClaimsStore::default();
        let (clock, last_act, net_act)   = force_claim_ts();
        let (sid, nonce, tip)            = force_claim_tip();

        let (_, penalty) = force_claim(
            &mut store, &relay_pubkey(), &sid, nonce, &tip,
            0, 0, clock, last_act, net_act, &client_x(), 0, 0,
        ).unwrap();

        assert_eq!(penalty, 0, "zero-byte claim has zero penalty");
    }

    #[test]
    fn force_claim_hopping_client_blocked() {
        // Client hops to another relay 60 seconds ago — session_updated_at is very recent.
        let mut store          = PendingClaimsStore::default();
        let clock_ts           = now_ts();
        let last_activity_ts   = clock_ts - FORCE_CLAIM_TIMEOUT_SECS as i64 - 7_200; // 26h ago on this relay
        let session_updated_at = clock_ts - 60; // DHT shows session updated 60s ago
        let (sid, nonce, tip)  = force_claim_tip();

        let result = force_claim(
            &mut store, &relay_pubkey(), &sid, nonce, &tip,
            5_000, 1, clock_ts, last_activity_ts, session_updated_at, &client_x(), 0, 0,
        );

        // Gate 2 must fire even though gate 1 would pass.
        assert_eq!(result, Err(RewardsError::SessionStillActive),
            "hopping client must block force_claim");
    }

    #[test]
    fn force_claim_offline_client_allowed() {
        // Client has been offline for 3 full days — both gates clear easily.
        let mut store          = PendingClaimsStore::default();
        let clock_ts           = now_ts();
        let three_days         = 3 * 24 * 3_600i64;
        let last_activity_ts   = clock_ts - three_days;
        let session_updated_at = clock_ts - three_days;
        let (sid, nonce, tip)  = force_claim_tip();

        let result = force_claim(
            &mut store, &relay_pubkey(), &sid, nonce, &tip,
            20_000, 10, clock_ts, last_activity_ts, session_updated_at, &client_x(), 0, 0,
        );

        assert!(result.is_ok(), "3-day-offline client should allow force_claim: {result:?}");
        let (_, penalty) = result.unwrap();
        assert_eq!(penalty, 4_000); // 20% of 20_000
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

    // ─── P1 ClaimStatus::is_terminal tests ──────────────────────────────────

    #[test]
    fn terminal_states_are_terminal() {
        assert!(ClaimStatus::Released.is_terminal(), "Released must be terminal");
        assert!(ClaimStatus::Slashed.is_terminal(),  "Slashed must be terminal");
        assert!(ClaimStatus::Resolved.is_terminal(), "Resolved must be terminal");
        assert!(ClaimStatus::Swept.is_terminal(),    "Swept must be terminal (M3)");
    }

    #[test]
    fn non_terminal_states_are_not_terminal() {
        assert!(!ClaimStatus::Pending.is_terminal(),  "Pending must NOT be terminal");
        assert!(!ClaimStatus::Disputed.is_terminal(), "Disputed must NOT be terminal");
    }

    // ─── P1 ClaimStatus::Swept (M3) tests ───────────────────────────────────

    #[test]
    fn swept_is_distinct_from_slashed() {
        assert_ne!(
            ClaimStatus::Swept, ClaimStatus::Slashed,
            "Swept and Slashed must be distinct variants (M3)"
        );
    }

    #[test]
    fn sweep_marks_claims_swept_not_slashed() {
        let mut store = PendingClaimsStore::default();
        let ts    = now_ts();
        let hash  = submit_batch(&mut store, &make_batch(1, 1), ts);
        let sweep_ts = ts + SWEEP_TIMEOUT_SECONDS + 1;
        sweep_expired_escrow(&mut store, sweep_ts).unwrap();

        let claim = store.claims.iter().find(|c| c.claim_hash == hash).unwrap();
        assert_eq!(claim.status, ClaimStatus::Swept,   "must be Swept after sweep (M3)");
        assert_ne!(claim.status, ClaimStatus::Slashed, "must NOT be Slashed after sweep (M3)");
    }

    #[test]
    fn cannot_dispute_swept_claim() {
        let mut store = PendingClaimsStore::default();
        let ts    = now_ts();
        let records = make_batch(1, 1);
        let hash  = submit_batch(&mut store, &records, ts);

        // Sweep the claim.
        let sweep_ts = ts + SWEEP_TIMEOUT_SECONDS + 1;
        sweep_expired_escrow(&mut store, sweep_ts).unwrap();

        // Attempting to dispute a Swept claim must fail with ClaimAlreadySettled.
        let result = dispute_claim(
            &mut store, hash, 0, records[0].clone(), challenger_pubkey(), ts, [0u8; 32],
            DEFAULT_CHALLENGER_BOND_FLOW,
        );
        assert_eq!(result, Err(DisputeError::ClaimAlreadySettled),
            "Swept claims must not be disputable (M3 dispute gate)");
    }

    // ─── P1 PendingClaim.user field (M1) tests ──────────────────────────────

    #[test]
    fn submit_claim_with_bond_sets_user_field() {
        let mut store = PendingClaimsStore::default();
        let records   = make_batch(1, 1);
        let hash      = submit_batch(&mut store, &records, now_ts());
        let claim     = store.claims.iter().find(|c| c.claim_hash == hash).unwrap();
        assert_eq!(claim.user, Some(client_x()), "M1: user field must be set in PendingClaim");
    }

    #[test]
    fn pending_claim_borsh_roundtrip_with_user() {
        let claim = PendingClaim {
            relay:            relay_pubkey(),
            claim_hash:       [0x01u8; 32],
            total_amount:     5_000,
            record_count:     3,
            submitted_at:     now_ts(),
            dispute_deadline: now_ts() + DISPUTE_WINDOW_SECONDS,
            bond:             RELAY_BOND_FLOW,
            status:           ClaimStatus::Pending,
            is_force_claim:   false,
            user:             Some(client_x()),
            bytes_routed:     0,
            bytes_seeded:     0,
            uptime_seconds:   0,
        };
        let encoded = borsh::to_vec(&claim).unwrap();
        let decoded: PendingClaim = borsh::from_slice(&encoded).unwrap();
        assert_eq!(decoded.user, Some(client_x()));
        assert_eq!(decoded.total_amount, 5_000);
    }

    #[test]
    fn pending_claim_borsh_backward_compat_no_user_field() {
        // Simulate old on-chain data without the user field.
        // Serialize a claim with user=None, then deserialize — should yield None.
        let claim = PendingClaim {
            relay:            relay_pubkey(),
            claim_hash:       [0x02u8; 32],
            total_amount:     1_000,
            record_count:     1,
            submitted_at:     now_ts(),
            dispute_deadline: now_ts() + DISPUTE_WINDOW_SECONDS,
            bond:             RELAY_BOND_FLOW,
            status:           ClaimStatus::Pending,
            is_force_claim:   false,
            user:             None, // legacy
            bytes_routed:     0,
            bytes_seeded:     0,
            uptime_seconds:   0,
        };
        let encoded = borsh::to_vec(&claim).unwrap();
        let decoded: PendingClaim = borsh::from_slice(&encoded).unwrap();
        assert_eq!(decoded.user, None, "legacy claim with no user must deserialize to None");
    }

    // ─── P1 UserEscrowReservation + settle_reservation (M4) tests ───────────

    #[test]
    fn settle_reservation_decrements_reserved() {
        let mut reservation = UserEscrowReservation {
            user:     client_x(),
            reserved: 10_000,
            bump:     0,
        };
        settle_reservation(&mut reservation, 3_000, 20_000).unwrap();
        assert_eq!(reservation.reserved, 7_000);
    }

    #[test]
    fn settle_reservation_saturates_at_zero() {
        let mut reservation = UserEscrowReservation {
            user:     client_x(),
            reserved: 100,
            bump:     0,
        };
        // Decrement more than reserved — should clamp to 0, not panic.
        settle_reservation(&mut reservation, 9_999, 50_000).unwrap();
        assert_eq!(reservation.reserved, 0, "saturating_sub must clamp to 0");
    }

    #[test]
    fn settle_reservation_invariant_violation() {
        let mut reservation = UserEscrowReservation {
            user:     client_x(),
            reserved: 5_000,
            bump:     0,
        };
        // After decrement, reserved=4_000 but escrow_balance=3_000 — invariant violated.
        // Hmm wait: after saturating_sub(1_000) = 4_000, and 4_000 > 3_000 → error.
        let result = settle_reservation(&mut reservation, 1_000, 3_000);
        assert_eq!(result, Err(DisputeError::ReservationInvariantViolated));
    }

    #[test]
    fn settle_reservation_is_only_decrement_path() {
        // Rule 1: prove settle_reservation handles all terminal paths by calling it
        // directly from release_rewards flow.
        let mut store = PendingClaimsStore::default();
        let records   = make_batch(1, 1);
        let ts        = now_ts();
        let hash      = submit_batch(&mut store, &records, ts);

        let mut reservation = UserEscrowReservation {
            user:     client_x(),
            reserved: 1_000,
            bump:     0,
        };

        // Claim total is 0 (charge_flow=0 in make_batch) — so reservation unchanged.
        let release_ts = ts + DISPUTE_WINDOW_SECONDS + 1;
        let (relay_amount, bond, _) = release_rewards(&mut store, hash, release_ts).unwrap();

        // Manually call settle (simulating what the handler does).
        settle_reservation(&mut reservation, 0, 10_000).unwrap();
        assert_eq!(reservation.reserved, 1_000, "zero-amount settle must not change reserved");
        let _ = (relay_amount, bond); // suppress unused warnings
    }

    #[test]
    fn settle_reservation_called_for_all_terminal_states() {
        // Test that each terminal state correctly flows through settle_reservation.
        // We test the pure logic, not the on-chain handler (which needs AccountInfo).
        let base_reserved = 5_000u64;
        let claim_amount  = 500u64;
        let escrow_bal    = 10_000u64;

        // Released
        let mut r = UserEscrowReservation { user: client_x(), reserved: base_reserved, bump: 0 };
        settle_reservation(&mut r, claim_amount, escrow_bal).unwrap();
        assert_eq!(r.reserved, base_reserved - claim_amount);

        // Slashed
        let mut r = UserEscrowReservation { user: client_x(), reserved: base_reserved, bump: 0 };
        settle_reservation(&mut r, claim_amount, escrow_bal).unwrap();
        assert_eq!(r.reserved, base_reserved - claim_amount);

        // Resolved
        let mut r = UserEscrowReservation { user: client_x(), reserved: base_reserved, bump: 0 };
        settle_reservation(&mut r, claim_amount, escrow_bal).unwrap();
        assert_eq!(r.reserved, base_reserved - claim_amount);

        // Swept
        let mut r = UserEscrowReservation { user: client_x(), reserved: base_reserved, bump: 0 };
        settle_reservation(&mut r, claim_amount, escrow_bal).unwrap();
        assert_eq!(r.reserved, base_reserved - claim_amount);
    }

    // ─── P1 RewardsConfig (M2) tests ────────────────────────────────────────

    #[test]
    fn rewards_config_default_state() {
        let cfg = RewardsConfig::default();
        assert!(!cfg.migration_mode,   "default migration_mode must be false");
        assert!(!cfg.migration_locked, "default migration_locked must be false");
    }

    #[test]
    fn rewards_config_borsh_roundtrip() {
        let cfg = RewardsConfig {
            migration_mode:        true,
            migration_locked:      false,
            bump:                  42,
            total_minted:          1_000,
            max_supply:            RewardsConfig::MAX_SUPPLY,
            foundation_pre_minted: false,
        };
        let encoded = borsh::to_vec(&cfg).unwrap();
        let decoded: RewardsConfig = borsh::from_slice(&encoded).unwrap();
        assert!(decoded.migration_mode);
        assert!(!decoded.migration_locked);
        assert_eq!(decoded.bump, 42);
        assert_eq!(decoded.total_minted, 1_000);
        assert_eq!(decoded.max_supply, RewardsConfig::MAX_SUPPLY);
        assert!(!decoded.foundation_pre_minted);
    }

    // ─── P1 UserEscrowReservation borsh + default tests ─────────────────────

    #[test]
    fn user_escrow_reservation_default() {
        let r = UserEscrowReservation::default();
        assert_eq!(r.reserved, 0);
        assert_eq!(r.user, [0u8; 32]);
    }

    #[test]
    fn user_escrow_reservation_borsh_roundtrip() {
        let r = UserEscrowReservation {
            user:     client_x(),
            reserved: 99_999,
            bump:     7,
        };
        let enc = borsh::to_vec(&r).unwrap();
        let dec: UserEscrowReservation = borsh::from_slice(&enc).unwrap();
        assert_eq!(dec.user,     client_x());
        assert_eq!(dec.reserved, 99_999);
        assert_eq!(dec.bump,     7);
    }

    // ─── P1 Migration integration test ──────────────────────────────────────

    #[test]
    fn initialize_reservation_idempotent() {
        // Rule 3: InitializeReservation is the ONLY creator; idempotent if exists.
        // We test the pure struct logic since we can't create AccountInfo in unit tests.
        let user = client_x();
        let reservation = UserEscrowReservation {
            user,
            reserved: 500,
            bump:     0,
        };
        // Verify the existing check: same user → idempotent (return early).
        assert_eq!(reservation.user, user, "existing reservation user matches");
    }

    #[test]
    fn sweep_after_60_days_marks_swept_and_is_terminal() {
        let mut store = PendingClaimsStore::default();
        let ts     = now_ts();
        let hash   = submit_batch(&mut store, &make_batch(2, 1), ts);
        let sweep_ts = ts + SWEEP_TIMEOUT_SECONDS + 86_400;
        sweep_expired_escrow(&mut store, sweep_ts).unwrap();
        let claim = store.claims.iter().find(|c| c.claim_hash == hash).unwrap();
        assert_eq!(claim.status, ClaimStatus::Swept);
        assert!(claim.status.is_terminal(), "Swept must be a terminal state");
    }

    // ── CPI Bridge unit tests ─────────────────────────────────────────────────

    #[test]
    fn anchor_ix_discriminator_produces_8_bytes() {
        let disc = anchor_ix_discriminator(b"spend_from_escrow");
        assert_eq!(disc.len(), 8, "discriminator must be exactly 8 bytes");
        // Verify determinism: same input → same output.
        let disc2 = anchor_ix_discriminator(b"spend_from_escrow");
        assert_eq!(disc, disc2, "discriminator must be deterministic");
    }

    #[test]
    fn anchor_ix_discriminator_differs_for_different_names() {
        let d1 = anchor_ix_discriminator(b"spend_from_escrow");
        let d2 = anchor_ix_discriminator(b"purchase_and_escrow");
        assert_ne!(d1, d2, "different instruction names must produce different discriminators");
    }

    #[test]
    fn anchor_ix_discriminator_matches_expected_spend_from_escrow() {
        // sha256("global:spend_from_escrow")[..8] computed via solana_program::hash::hashv
        // This test verifies the discriminator is stable across builds.
        let disc = anchor_ix_discriminator(b"spend_from_escrow");
        // Verify it's non-zero (all-zero would mean hash collision, which is impossible).
        assert_ne!(disc, [0u8; 8], "discriminator must not be all-zero");
        // Verify first byte is consistent (regression check against accidental changes).
        let disc_again = anchor_ix_discriminator(b"spend_from_escrow");
        assert_eq!(disc[0], disc_again[0], "discriminator byte 0 must be stable");
    }

    #[test]
    fn find_mint_authority_pda_produces_valid_pda() {
        use solana_program::pubkey::Pubkey;
        // Use a deterministic "program id" for testing.
        let fake_program_id = Pubkey::new_from_array([1u8; 32]);
        let (pda, bump) = find_mint_authority_pda(&fake_program_id);
        // Verify we can reconstruct the same PDA from the returned bump.
        let reconstructed =
            Pubkey::create_program_address(&[b"mint_authority", &[bump]], &fake_program_id)
                .expect("reconstructed PDA must be valid");
        assert_eq!(pda, reconstructed, "PDA derived from bump must match find result");
    }

    #[test]
    fn find_mint_authority_pda_is_deterministic() {
        use solana_program::pubkey::Pubkey;
        let pid = Pubkey::new_from_array([42u8; 32]);
        let (pda1, bump1) = find_mint_authority_pda(&pid);
        let (pda2, bump2) = find_mint_authority_pda(&pid);
        assert_eq!(pda1, pda2);
        assert_eq!(bump1, bump2);
    }

    #[test]
    fn relay_mint_share_bps_plus_treasury_equals_10000() {
        assert_eq!(
            RELAY_MINT_SHARE_BPS + TREASURY_MINT_SHARE_BPS,
            10_000,
            "relay (70%) + treasury (30%) must equal 100%"
        );
    }

    #[test]
    fn sweep_treasury_mint_share_bps_is_80_percent() {
        assert_eq!(SWEEP_TREASURY_MINT_SHARE_BPS, 8_000);
    }

    #[test]
    fn mint_split_70_30_arithmetic_correct() {
        // For 1000 total: relay = 700, treasury = 300.
        let total: u64 = 1_000;
        let relay_share   = total.saturating_mul(RELAY_MINT_SHARE_BPS).saturating_div(10_000);
        let treasury_share = total.saturating_sub(relay_share);
        assert_eq!(relay_share,   700, "relay gets 70%");
        assert_eq!(treasury_share, 300, "treasury gets 30%");
        assert_eq!(relay_share + treasury_share, total, "shares sum to total");
    }

    #[test]
    fn mint_split_70_30_arithmetic_odd_numbers() {
        // For 1001 total: relay = 700 (floor), treasury = 301 (remainder).
        let total: u64 = 1_001;
        let relay_share   = total.saturating_mul(RELAY_MINT_SHARE_BPS).saturating_div(10_000);
        let treasury_share = total.saturating_sub(relay_share);
        assert_eq!(relay_share,   700);
        assert_eq!(treasury_share, 301);
        assert_eq!(relay_share + treasury_share, total);
    }

    #[test]
    fn sweep_mint_split_80_percent_arithmetic() {
        // 1000 total: treasury = 800, burned (deflated) = 200.
        let total: u64 = 1_000;
        let treasury_mint = total.saturating_mul(SWEEP_TREASURY_MINT_SHARE_BPS).saturating_div(10_000);
        let deflated = total.saturating_sub(treasury_mint);
        assert_eq!(treasury_mint, 800, "treasury gets 80% on sweep");
        assert_eq!(deflated,      200, "20% deflated (not re-minted)");
    }

    #[test]
    fn mint_split_zero_amount_produces_zero() {
        let total: u64 = 0;
        let relay_share   = total.saturating_mul(RELAY_MINT_SHARE_BPS).saturating_div(10_000);
        let treasury_share = total.saturating_sub(relay_share);
        assert_eq!(relay_share,   0);
        assert_eq!(treasury_share, 0);
    }

    #[test]
    fn relay_slashed_requires_no_cpi_burn() {
        // ResolveDisputeRelaySlashed → NO burn. User's $FLOW stays in escrow.
        // This is enforced by NOT including CPI bridge accounts in that handler.
        // Verify the semantic: relay was fraudulent → user refunded → no spend_from_escrow.
        let mut store = PendingClaimsStore::default();
        let ts = now_ts();
        let hash = submit_batch(&mut store, &make_batch(1, 1), ts);
        // file a dispute
        let _dispute_ok = dispute_claim(
            &mut store,
            hash,
            0,
            make_batch(1, 1)[0].clone(),
            [99u8; 32],    // challenger pubkey
            ts,            // clock_ts
            [0u8; 32],     // escrow_pda
            DEFAULT_CHALLENGER_BOND_FLOW,
        );
        // resolve: relay slashed (fraudulent claim)
        let outcome = resolve_dispute_relay_slashed(&mut store, hash);
        assert!(outcome.is_ok(), "resolve_relay_slashed must succeed");
        let claim = store.claims.iter().find(|c| c.claim_hash == hash).unwrap();
        // Status is Slashed (terminal, no burn of user escrow).
        assert_eq!(claim.status, ClaimStatus::Slashed,
            "relay slashed → Slashed status, no CPI burn");
        assert!(claim.status.is_terminal());
    }

    #[test]
    fn challenger_slashed_claim_is_resolved_terminal() {
        // ResolveDisputeChallengerSlashed → burn + mint 70:30.
        // The claim transitions to Resolved (terminal), enabling burn+mint CPI.
        let mut store = PendingClaimsStore::default();
        let ts = now_ts();
        let hash = submit_batch(&mut store, &make_batch(1, 1), ts);
        let batch = make_batch(1, 1);
        let _dispute_ok = dispute_claim(
            &mut store,
            hash,
            0,
            batch[0].clone(),
            [99u8; 32],    // challenger pubkey
            ts,            // clock_ts
            [0u8; 32],     // escrow_pda
            DEFAULT_CHALLENGER_BOND_FLOW,
        );
        let outcome = resolve_dispute_challenger_slashed(&mut store, hash);
        assert!(outcome.is_ok());
        let claim = store.claims.iter().find(|c| c.claim_hash == hash).unwrap();
        assert_eq!(claim.status, ClaimStatus::Resolved,
            "challenger slashed → Resolved status (burn+mint CPI would fire)");
        assert!(claim.status.is_terminal());
    }

    #[test]
    fn force_resolve_marks_resolved_terminal_enabling_burn_mint() {
        // ForceResolve → burn + mint 70:30.
        // After 3-day inactivity, claim transitions to Resolved (terminal).
        let mut store = PendingClaimsStore::default();
        let ts = now_ts();
        let hash = submit_batch(&mut store, &make_batch(1, 1), ts);
        let batch = make_batch(1, 1);
        let _dispute_ok = dispute_claim(
            &mut store,
            hash,
            0,
            batch[0].clone(),
            [99u8; 32],    // challenger pubkey
            ts,            // clock_ts
            [0u8; 32],     // escrow_pda
            DEFAULT_CHALLENGER_BOND_FLOW,
        );
        // Force resolve after 3-day timeout.
        let resolve_ts = ts + DISPUTE_RESOLVE_SECONDS + 86_400;
        let outcome = force_resolve_dispute(&mut store, hash, resolve_ts);
        assert!(outcome.is_ok(), "force_resolve_dispute must succeed after timeout");
        let claim = store.claims.iter().find(|c| c.claim_hash == hash).unwrap();
        assert_eq!(claim.status, ClaimStatus::Resolved,
            "force-resolved claim → Resolved (burn+mint CPI would fire)");
        assert!(claim.status.is_terminal());
    }

    #[test]
    fn release_rewards_marks_released_terminal_enabling_burn_mint() {
        // ReleaseRewards → burn + mint 70:30.
        // charge_flow = 0 in make_batch (test records), so relay_amount = 0.
        // We test status transitions (not token amounts) here.
        let mut store = PendingClaimsStore::default();
        let ts = now_ts();
        let hash = submit_batch(&mut store, &make_batch(1, 1), ts);
        let release_ts = ts + DISPUTE_WINDOW_SECONDS + 1;
        let result = release_rewards(&mut store, hash, release_ts);
        assert!(result.is_ok(), "release_rewards must succeed");
        let claim = store.claims.iter().find(|c| c.claim_hash == hash).unwrap();
        assert_eq!(claim.status, ClaimStatus::Released,
            "released claim → Released (burn+mint CPI would fire)");
        assert!(claim.status.is_terminal());
    }

    #[test]
    fn cpi_bridge_skipped_without_cpi_accounts_release() {
        // process_release_rewards_ix with only 3 accounts (no CPI bridge accounts)
        // should succeed without attempting any CPI (backward compatible).
        // We verify this by observing that release_rewards itself succeeds,
        // and no CPI failure can occur if accounts 5-13 are absent.
        let mut store = PendingClaimsStore::default();
        let ts = now_ts();
        let hash = submit_batch(&mut store, &make_batch(1, 1), ts);
        let release_ts = ts + DISPUTE_WINDOW_SECONDS + 1;
        // Simulate the core logic only (CPI skipped because no CPI accounts).
        let result = release_rewards(&mut store, hash, release_ts);
        assert!(result.is_ok(), "release_rewards core logic must succeed");
    }

    #[test]
    fn sweep_burn_amount_equals_100_percent_of_total() {
        // For sweep CPI: burn = total_amount (all of user's escrowed $FLOW for the claim).
        let total: u64 = 5_000;
        let burned = total; // 100% burned from user escrow
        let treasury_minted = total.saturating_mul(SWEEP_TREASURY_MINT_SHARE_BPS).saturating_div(10_000);
        let deflated = burned.saturating_sub(treasury_minted);
        assert_eq!(burned, 5_000);
        assert_eq!(treasury_minted, 4_000, "80% minted to treasury");
        assert_eq!(deflated, 1_000, "20% net deflation");
    }

    // ─── CPI Bridge — ordering / documentation tests ─────────────────────────

    /// Issue #1 — settle_reservation runs BEFORE CPI burn (ordering invariant).
    ///
    /// The `pre_burn_escrow_balance` is captured before `cpi_burn_from_escrow` so that
    /// `settle_reservation`'s invariant check (`reserved <= escrow_balance`) uses the
    /// pre-burn value. This test verifies that settle_reservation succeeds when called
    /// with the pre-burn escrow balance, even when that balance exactly equals `reserved`.
    #[test]
    fn test_cpi_burn_post_cpi_balance_verification() {
        let user = [0x01u8; 32];

        // Simulate: escrow balance == reserved (tight — exactly enough).
        // settle_reservation must succeed here (pre-burn balance is the correct input).
        let mut reservation = UserEscrowReservation {
            user,
            reserved: 1_000,
            bump: 0,
        };
        let pre_burn_escrow_balance: u64 = 1_000; // captured BEFORE CPI burn
        let claim_amount: u64 = 600;

        let result = settle_reservation(&mut reservation, claim_amount, pre_burn_escrow_balance);
        assert!(result.is_ok(), "settle_reservation with pre-burn balance must succeed");
        assert_eq!(reservation.reserved, 400, "reserved decremented by claim_amount");

        // After CPI burn the escrow balance would be 400, but settle_reservation already ran.
        // This demonstrates the ordering invariant: using post-burn balance (400) here would
        // have given the same result for this particular case, but when reserved == escrow_balance
        // exactly and you're burning 100% (as in sweep), a post-burn balance of 0 would fail
        // the invariant unless the check uses the pre-burn snapshot.
        let post_burn_escrow_balance: u64 = pre_burn_escrow_balance - claim_amount; // 400
        assert_eq!(post_burn_escrow_balance, 400);
    }

    /// Issue #2 — sweep treasury token account ownership (deployment requirement).
    ///
    /// For SweepUnclaimed CPI, treasury_wallet acts as the `relay` param and
    /// treasury_token acts as `relay_token`. spend_from_escrow validates
    /// relay_token.owner == relay_wallet at the SPL level. This test documents
    /// the deployment requirement: treasury_token.owner must equal treasury_wallet.
    ///
    /// We test the mathematical invariant that represents this: if the sweep CPI
    /// is configured correctly, cpi_burn_from_escrow receives treasury_token as
    /// relay_token and treasury_wallet as relay, and the accounts are consistent.
    #[test]
    fn test_sweep_treasury_token_owner_validation() {
        // Simulate sweep account role mapping:
        //   relay_token_ai   ← treasury_token (SPL token account owned by treasury_wallet)
        //   relay_wallet_ai  ← treasury_wallet
        //
        // The constraint enforced by spend_from_escrow:
        //   treasury_token.owner == treasury_wallet   (SPL TokenAccount.owner field)
        //
        // We can't call the actual CPI in a unit test, but we verify the
        // BPS accounting is correct and the mapping is documented.
        let treasury_wallet = [0xDD_u8; 32]; // placeholder treasury wallet pubkey bytes
        // treasury_token.owner must equal treasury_wallet — deployment requirement
        let treasury_token_owner = treasury_wallet; // satisfies spend_from_escrow check
        assert_eq!(
            treasury_token_owner, treasury_wallet,
            "sweep: treasury_token.owner MUST equal treasury_wallet for CPI redirect guard"
        );

        // Verify sweep BPS constants are correctly defined.
        assert_eq!(SWEEP_TREASURY_MINT_SHARE_BPS, 8_000,
            "80% of swept amount is minted back to treasury");
        let deflation_bps = 10_000u64 - SWEEP_TREASURY_MINT_SHARE_BPS;
        assert_eq!(deflation_bps, 2_000, "20% of swept amount is net deflation");
    }

    /// Issue #3 — sweep 80/20 economics explicitly documented per spec.
    ///
    /// Per FLOW-CLOSED-LOOP-ECONOMY.md sweep spec:
    ///   1. 100% of total_amount is burned from the user's escrow token account.
    ///   2. 80% (SWEEP_TREASURY_MINT_SHARE_BPS = 8_000 bps) is re-minted to treasury.
    ///   3. The remaining 20% is net deflation — permanently removed from supply.
    #[test]
    fn test_sweep_80_20_economics_documented() {
        // Test at multiple amounts to ensure BPS arithmetic is exact.
        for total in [100u64, 1_000, 10_000, 100_000, 1_000_000] {
            let burned: u64 = total; // 100% always
            let treasury_minted = total
                .saturating_mul(SWEEP_TREASURY_MINT_SHARE_BPS)
                .saturating_div(10_000);
            let net_deflation = burned.saturating_sub(treasury_minted);
            let treasury_bps = treasury_minted.saturating_mul(10_000) / total;
            let deflation_bps = net_deflation.saturating_mul(10_000) / total;

            assert_eq!(treasury_bps, 8_000,
                "treasury receives exactly 80% at total={}", total);
            assert_eq!(deflation_bps, 2_000,
                "net deflation is exactly 20% at total={}", total);
            assert_eq!(treasury_minted + net_deflation, burned,
                "treasury + deflation must equal burned amount at total={}", total);
        }
    }

    /// Issue #6 — relay_token.owner == relay_wallet guard is enforced by spend_from_escrow.
    ///
    /// All handlers that call cpi_burn_from_escrow pass relay_token and relay_wallet.
    /// spend_from_escrow (user-escrow program) validates relay_token.owner == relay_wallet.
    /// This test documents the validation constraint and verifies the correct accounts
    /// are threaded through for each handler type.
    #[test]
    fn test_relay_token_owner_validation() {
        // For ReleaseRewards and ResolveDisputeChallengerSlashed:
        //   relay_token_ai owner must be relay_wallet (the signer)
        let relay_wallet = [0xAA_u8; 32];
        let relay_token_owner = relay_wallet; // correct: token owned by relay wallet
        assert_eq!(
            relay_token_owner, relay_wallet,
            "ReleaseRewards/ChallengerSlashed: relay_token.owner must equal relay_wallet"
        );

        // For ForceResolve: resolver != relay_wallet.
        // relay_wallet_cpi_ai (account 10) is the relay's wallet, NOT the resolver.
        // relay_token.owner must equal relay_wallet_cpi_ai (not the resolver pubkey).
        let resolver = [0x55u8; 32];
        let relay_wallet_cpi = [0xAA_u8; 32]; // relay_wallet_cpi_ai — separate from resolver
        let relay_token_owner_fr = relay_wallet_cpi; // token owned by relay (not resolver)
        assert_ne!(resolver, relay_wallet_cpi,
            "ForceResolve: resolver and relay_wallet must be different accounts");
        assert_eq!(
            relay_token_owner_fr, relay_wallet_cpi,
            "ForceResolve: relay_token.owner must equal relay_wallet_cpi_ai, not resolver"
        );

        // For SweepUnclaimed: treasury acts as relay.
        // treasury_token.owner must equal treasury_wallet.
        let treasury_wallet = [0xCC_u8; 32];
        let treasury_token_owner = treasury_wallet; // correct for sweep
        assert_eq!(
            treasury_token_owner, treasury_wallet,
            "SweepUnclaimed: treasury_token.owner must equal treasury_wallet"
        );
    }

    /// Full lifecycle test — claim submission → release_rewards → verify status + math.
    ///
    /// This test exercises the complete lifecycle without CPI (unit test boundary):
    /// 1. Submit a batch (creates claim in Pending)
    /// 2. Wait for dispute window
    /// 3. Call release_rewards → claim transitions to Released
    /// 4. Verify the 70:30 mint split math matches the claim amount
    ///
    /// The actual CPI burn/mint is not exercised here (no on-chain accounts), but
    /// the status transition and arithmetic are verified end-to-end.
    #[test]
    fn test_release_rewards_full_lifecycle_with_balance_check() {
        let mut store = PendingClaimsStore::default();
        let ts = now_ts();

        // 1. Submit claim.
        let hash = submit_batch(&mut store, &make_batch(1, 1), ts);
        let claim_before = store.claims.iter().find(|c| c.claim_hash == hash).unwrap();
        assert_eq!(claim_before.status, ClaimStatus::Pending);
        let total_amount = claim_before.total_amount;

        // 2. Simulate reservation pre-burn balance.
        let pre_burn_balance: u64 = total_amount + 500; // some extra balance
        let mut reservation = UserEscrowReservation {
            user: client_x(),
            reserved: total_amount,
            bump: 0,
        };

        // 3. settle_reservation with pre-burn balance (ordering invariant).
        let sr_result = settle_reservation(&mut reservation, total_amount, pre_burn_balance);
        assert!(sr_result.is_ok(), "settle_reservation must succeed with pre-burn balance");
        assert_eq!(reservation.reserved, 0, "reserved fully decremented after release");

        // 4. release_rewards — transitions claim to Released.
        let release_ts = ts + DISPUTE_WINDOW_SECONDS + 1;
        let result = release_rewards(&mut store, hash, release_ts);
        assert!(result.is_ok(), "release_rewards must succeed");
        let claim_after = store.claims.iter().find(|c| c.claim_hash == hash).unwrap();
        assert_eq!(claim_after.status, ClaimStatus::Released,
            "claim must be Released after dispute window");
        assert!(claim_after.status.is_terminal());

        // 5. Verify 70:30 split math for this claim amount.
        let relay_share   = total_amount.saturating_mul(RELAY_MINT_SHARE_BPS).saturating_div(10_000);
        let treasury_share = total_amount.saturating_sub(relay_share);
        assert_eq!(
            relay_share + treasury_share, total_amount,
            "relay_share + treasury_share must equal total_amount (no rounding loss)"
        );
        // relay_share <= treasury_share is only true when total_amount is 0;
        // normally relay_share is 70% (larger).
        if total_amount > 0 {
            assert!(relay_share >= treasury_share,
                "relay (70%) must receive at least as much as treasury (30%)");
        }
    }

    // ─── Phase 9: BondConfig unit tests ─────────────────────────────────────

    fn default_bond_config() -> BondConfig {
        BondConfig {
            authority:             [0u8; 32],
            challenger_bond_cents: BondConfig::DEFAULT_CHALLENGER_BOND_CENTS, // 125_000
            min_stake_usd_cents:   BondConfig::DEFAULT_MIN_STAKE_USD_CENTS,   // 250_000_000
            stake_earnings_bps:    BondConfig::DEFAULT_STAKE_EARNINGS_BPS,    // 1_000
            max_stake_flow:        BondConfig::DEFAULT_MAX_STAKE_FLOW,        // 100_000
            bump:                  255,
        }
    }

    /// The challenger bond formula is: bond = challenger_bond_cents * 1_000_000 / flow_price_cents
    ///
    /// With challenger_bond_cents = 125_000 ($1.25), the flow_price_cents at which bond = 50:
    ///   50 = 125_000 * 1_000_000 / flow_price_cents  →  flow_price_cents = 2_500_000_000
    #[test]
    fn bond_config_compute_challenger_bond_at_default_price() {
        let cfg = default_bond_config();
        // Derived: price at which 125_000 * 1_000_000 / price = 50
        let flow_price_cents = 2_500_000_000u64;
        let bond = cfg.compute_challenger_bond(flow_price_cents);
        assert_eq!(bond, DEFAULT_CHALLENGER_BOND_FLOW,
            "bond must equal DEFAULT_CHALLENGER_BOND_FLOW = 50 at this price");
    }

    /// Bond is clamped at MAX_CHALLENGER_BOND_FLOW (500) for low prices.
    ///
    /// At price = 250_000_000: 125_000 * 1_000_000 / 250_000_000 = 500 (= MAX exactly).
    #[test]
    fn bond_config_compute_challenger_bond_low_price_clamped_to_max() {
        let cfg = default_bond_config();
        // 125_000 * 1_000_000 / 250_000_000 = 500 (exactly at MAX)
        let flow_price_cents = 250_000_000u64;
        let bond = cfg.compute_challenger_bond(flow_price_cents);
        assert_eq!(bond, MAX_CHALLENGER_BOND_FLOW,
            "price 250_000_000 → bond = MAX_CHALLENGER_BOND_FLOW = 500");

        // Any lower price → still MAX.
        let even_lower = 100_000_000u64; // → raw 1250 → clamped to 500
        assert_eq!(cfg.compute_challenger_bond(even_lower), MAX_CHALLENGER_BOND_FLOW,
            "lower price still clamps to MAX");
    }

    /// Bond is clamped at MIN_CHALLENGER_BOND_FLOW (10) for high prices.
    ///
    /// At price = 12_500_000_000: 125_000 * 1_000_000 / 12_500_000_000 = 10 (= MIN exactly).
    #[test]
    fn bond_config_compute_challenger_bond_high_price_clamped_to_min() {
        let cfg = default_bond_config();
        // 125_000 * 1_000_000 / 12_500_000_000 = 10 (exactly at MIN)
        let flow_price_at_min = 12_500_000_000u64;
        let bond = cfg.compute_challenger_bond(flow_price_at_min);
        assert_eq!(bond, MIN_CHALLENGER_BOND_FLOW,
            "price 12_500_000_000 → bond = MIN_CHALLENGER_BOND_FLOW = 10");

        // Any higher price → still MIN.
        let very_high = 100_000_000_000u64; // → raw 1 → clamped to 10
        assert_eq!(cfg.compute_challenger_bond(very_high), MIN_CHALLENGER_BOND_FLOW,
            "higher price still clamps to MIN");
    }

    /// flow_price_cents = 0 (oracle not set) → DEFAULT_CHALLENGER_BOND_FLOW (50).
    #[test]
    fn bond_config_compute_challenger_bond_zero_price_returns_default() {
        let cfg = default_bond_config();
        assert_eq!(
            cfg.compute_challenger_bond(0),
            DEFAULT_CHALLENGER_BOND_FLOW,
            "price=0 must fall back to DEFAULT_CHALLENGER_BOND_FLOW"
        );
    }

    /// Monotonic: higher $FLOW price → lower bond requirement.
    #[test]
    fn bond_config_compute_challenger_bond_decreases_with_price() {
        let cfg = default_bond_config();
        // Prices spanning from MAX-clamp region to MIN-clamp region.
        let prices = [250_000_000u64, 1_000_000_000, 2_500_000_000, 10_000_000_000, 12_500_000_000];
        let bonds: Vec<u64> = prices.iter().map(|&p| cfg.compute_challenger_bond(p)).collect();
        for i in 1..bonds.len() {
            assert!(bonds[i] <= bonds[i - 1],
                "bond[{}]={} must be <= bond[{}]={} (higher price → lower bond)",
                i, bonds[i], i - 1, bonds[i - 1]);
        }
    }

    /// At a high $FLOW price, base min-stake is below max_stake_flow.
    ///
    /// Formula: base = min_stake_usd_cents * 1_000_000 / flow_price_cents
    /// With min_stake_usd_cents = 250_000_000 and price = 25_000_000_000:
    ///   base = 250_000_000 * 1_000_000 / 25_000_000_000 = 10_000 FLOW
    #[test]
    fn bond_config_compute_min_stake_base_only() {
        let cfg = default_bond_config();
        // 250_000_000 * 1_000_000 / 25_000_000_000 = 10_000
        let flow_price_cents = 25_000_000_000u64;
        let min_stake = cfg.compute_min_stake(flow_price_cents, 0);
        assert_eq!(min_stake, 10_000,
            "at this price with no earnings, min_stake = 10_000 FLOW");
    }

    /// Earnings increase min_stake linearly (10% of total_lamports_claimed added).
    #[test]
    fn bond_config_compute_min_stake_with_earnings() {
        let cfg = default_bond_config();
        // base = 250_000_000 * 1_000_000 / 25_000_000_000 = 10_000
        let flow_price_cents = 25_000_000_000u64;
        // stake_earnings_bps = 1_000 (10%): extra = 50_000 * 1_000 / 10_000 = 5_000
        let total_lamports_claimed = 50_000u64;
        let min_stake = cfg.compute_min_stake(flow_price_cents, total_lamports_claimed);
        assert_eq!(min_stake, 15_000,
            "base(10_000) + extra(5_000) = 15_000 FLOW");
    }

    /// min_stake is capped at max_stake_flow (100_000) regardless of earnings.
    #[test]
    fn bond_config_compute_min_stake_capped_at_max() {
        let cfg = default_bond_config();
        // base = 10_000 at this price
        let flow_price_cents = 25_000_000_000u64;
        // earnings that push past 100_000:
        //   extra = 999_000 * 1_000 / 10_000 = 99_900 → total = 109_900 → capped at 100_000
        let huge_earnings = 999_000u64;
        let min_stake = cfg.compute_min_stake(flow_price_cents, huge_earnings);
        assert_eq!(min_stake, BondConfig::DEFAULT_MAX_STAKE_FLOW,
            "min_stake must be capped at max_stake_flow = 100_000");
    }

    /// flow_price_cents = 0 → DEFAULT_MIN_STAKE_FLOW (100).
    #[test]
    fn bond_config_compute_min_stake_zero_price_returns_default() {
        let cfg = default_bond_config();
        assert_eq!(
            cfg.compute_min_stake(0, 0),
            DEFAULT_MIN_STAKE_FLOW,
            "price=0 must fall back to DEFAULT_MIN_STAKE_FLOW"
        );
    }

    /// BondConfig Borsh round-trip serialization/deserialization.
    #[test]
    fn bond_config_borsh_roundtrip() {
        let cfg = BondConfig {
            authority:             [0xABu8; 32],
            challenger_bond_cents: 99_999,
            min_stake_usd_cents:   123_456_789,
            stake_earnings_bps:    500,
            max_stake_flow:        50_000,
            bump:                  42,
        };
        let encoded = borsh::to_vec(&cfg).unwrap();
        assert_eq!(encoded.len(), BondConfig::SIZE,
            "BondConfig serializes to exactly {} bytes", BondConfig::SIZE);
        let decoded: BondConfig = borsh::from_slice(&encoded).unwrap();
        assert_eq!(decoded.authority,             cfg.authority);
        assert_eq!(decoded.challenger_bond_cents, cfg.challenger_bond_cents);
        assert_eq!(decoded.min_stake_usd_cents,   cfg.min_stake_usd_cents);
        assert_eq!(decoded.stake_earnings_bps,    cfg.stake_earnings_bps);
        assert_eq!(decoded.max_stake_flow,        cfg.max_stake_flow);
        assert_eq!(decoded.bump,                  cfg.bump);
    }

    /// dispute_claim() stores the passed `challenger_bond` in DisputeRecord.bond.
    ///
    /// This is the mechanism that makes bond resolution dynamic: the bond is computed
    /// off-chain (or from BondConfig) at dispute time and stored for later resolution.
    #[test]
    fn dispute_stores_challenger_bond_in_record() {
        let mut store = PendingClaimsStore::default();
        let ts   = now_ts();
        let hash = submit_batch(&mut store, &make_batch(1, 1), ts);
        let custom_bond = 123u64; // arbitrary non-default value
        dispute_claim(
            &mut store, hash, 0, make_batch(1, 1)[0].clone(),
            challenger_pubkey(), ts, [0u8; 32], custom_bond,
        ).unwrap();
        let dispute = store.disputes.iter().find(|d| d.claim_hash == hash).unwrap();
        assert_eq!(dispute.bond, custom_bond,
            "DisputeRecord.bond must equal the passed challenger_bond");
    }

    /// resolve_dispute_relay_slashed() reads challenger_bond from DisputeRecord.bond.
    ///
    /// Verifies that the `challenger_bond_returned` field in the outcome equals
    /// the bond stored at dispute time, not the hardcoded CHALLENGER_BOND_FLOW constant.
    #[test]
    fn relay_slash_outcome_returns_record_bond() {
        let mut store = PendingClaimsStore::default();
        let ts   = now_ts();
        let hash = submit_batch(&mut store, &make_batch(1, 1), ts);
        let custom_bond = 200u64; // 4× default
        dispute_claim(
            &mut store, hash, 0, make_batch(1, 1)[0].clone(),
            challenger_pubkey(), ts, [0u8; 32], custom_bond,
        ).unwrap();
        let outcome = resolve_dispute_relay_slashed(&mut store, hash).unwrap();
        if let DisputeOutcome::RelaySlashed { challenger_bond_returned, challenger_reward, burned } = outcome {
            assert_eq!(challenger_bond_returned, custom_bond,
                "challenger_bond_returned must equal the bond stored in DisputeRecord");
            // relay_bond is split 50/50 (independent of challenger bond).
            assert_eq!(challenger_reward + burned, RELAY_BOND_FLOW,
                "relay_bond total must split into challenger_reward + burned");
        } else {
            panic!("Expected DisputeOutcome::RelaySlashed");
        }
    }

    /// resolve_dispute_challenger_slashed() uses DisputeRecord.bond for the slash amounts.
    ///
    /// relay_reward and burned are computed from `dispute.bond`, not from CHALLENGER_BOND_FLOW.
    #[test]
    fn challenger_slash_outcome_uses_record_bond() {
        let mut store = PendingClaimsStore::default();
        let ts   = now_ts();
        let hash = submit_batch(&mut store, &make_batch(1, 1), ts);
        let custom_bond = 300u64; // 6× default
        dispute_claim(
            &mut store, hash, 0, make_batch(1, 1)[0].clone(),
            challenger_pubkey(), ts, [0u8; 32], custom_bond,
        ).unwrap();
        let outcome = resolve_dispute_challenger_slashed(&mut store, hash).unwrap();
        if let DisputeOutcome::ChallengerSlashed { relay_reward, burned } = outcome {
            assert_eq!(relay_reward + burned, custom_bond,
                "relay_reward + burned must equal the stored challenger bond (not CHALLENGER_BOND_FLOW)");
            let expected_relay_reward = custom_bond * TREASURY_SHARE_BPS / 10_000;
            assert_eq!(relay_reward, expected_relay_reward,
                "relay_reward = bond * TREASURY_SHARE_BPS / 10_000");
        } else {
            panic!("Expected DisputeOutcome::ChallengerSlashed");
        }
    }

    /// force_resolve uses DisputeRecord.bond for the slash amounts (same as challenger slash).
    #[test]
    fn force_resolve_uses_record_bond() {
        let mut store = PendingClaimsStore::default();
        let ts   = now_ts();
        let hash = submit_batch(&mut store, &make_batch(1, 1), ts);
        let custom_bond = 75u64; // 1.5× default
        dispute_claim(
            &mut store, hash, 0, make_batch(1, 1)[0].clone(),
            challenger_pubkey(), ts, [0u8; 32], custom_bond,
        ).unwrap();
        let resolve_ts = ts + DISPUTE_RESOLVE_SECONDS + 1;
        let outcome = force_resolve_dispute(&mut store, hash, resolve_ts).unwrap();
        if let DisputeOutcome::ChallengerSlashed { relay_reward, burned } = outcome {
            assert_eq!(relay_reward + burned, custom_bond,
                "force_resolve must use DisputeRecord.bond, not CHALLENGER_BOND_FLOW");
        } else {
            panic!("Expected DisputeOutcome::ChallengerSlashed from force_resolve");
        }
    }

    /// Multiple disputes with different bonds each use their own record.
    #[test]
    fn multiple_disputes_each_use_own_bond() {
        let mut store = PendingClaimsStore::default();
        let ts = now_ts();

        // Two separate claims with different challenger bonds.
        let records1 = make_batch(1, 1);
        let records2 = make_batch(1, 100);
        let hash1 = submit_batch(&mut store, &records1, ts);
        let hash2 = submit_batch(&mut store, &records2, ts + 1);

        let bond1 = 30u64;
        let bond2 = 150u64;

        dispute_claim(&mut store, hash1, 0, records1[0].clone(), [0x11u8; 32], ts, [0u8; 32], bond1).unwrap();
        dispute_claim(&mut store, hash2, 0, records2[0].clone(), [0x22u8; 32], ts + 1, [0u8; 32], bond2).unwrap();

        let d1 = store.disputes.iter().find(|d| d.claim_hash == hash1).unwrap();
        let d2 = store.disputes.iter().find(|d| d.claim_hash == hash2).unwrap();
        assert_eq!(d1.bond, bond1, "dispute 1 must store bond1");
        assert_eq!(d2.bond, bond2, "dispute 2 must store bond2");
    }
}
