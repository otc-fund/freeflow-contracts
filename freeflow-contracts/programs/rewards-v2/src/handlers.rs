//! Instruction handlers for rewards-v2.
//!
//! All handlers follow the same pattern:
//!   1. Validate accounts and signers
//!   2. Load / create PDAs via account data deserialization
//!   3. Business logic
//!   4. Serialize updated state back to account data
//!   5. msg! for off-chain observability
//!
//! **Ed25519 presignature note (v1):**
//! On-chain Ed25519 precompile verification is NOT enabled in v1.
//! Signatures are stored on-chain and checked for non-null only.
//! The 7-day dispute window + tiered repFlow slashing provide the economic deterrent.
//! Precompile verification will be added in a future version.

use borsh::{BorshDeserialize, BorshSerialize};
use solana_program::{
    account_info::{next_account_info, AccountInfo},
    clock::Clock,
    entrypoint::ProgramResult,
    hash::hashv,
    msg,
    program::{invoke, invoke_signed},
    program_error::ProgramError,
    pubkey::Pubkey,
    rent::Rent,
    system_instruction,
    sysvar::Sysvar,
};

use crate::{
    constants::*,
    cpi::*,
    errors::RewardsError,
    merkle::{
        compute_merkle_leaf_hash, compute_merkle_leaf_hash_from_entry,
        compute_merkle_leaf_hash_from_release, verify_merkle_proof,
    },
    types::*,
};

// ── PDA helpers ──────────────────────────────────────────────────────────────

fn create_pda_account<'a>(
    payer:        &AccountInfo<'a>,
    new_account:  &AccountInfo<'a>,
    system_prog:  &AccountInfo<'a>,
    program_id:   &Pubkey,
    seeds:        &[&[u8]],
    space:        usize,
) -> ProgramResult {
    let rent   = Rent::get()?;
    let lamports = rent.minimum_balance(space);
    let ix = system_instruction::create_account(
        payer.key,
        new_account.key,
        lamports,
        space as u64,
        program_id,
    );
    invoke_signed(
        &ix,
        &[payer.clone(), new_account.clone(), system_prog.clone()],
        &[seeds],
    )
}


/// Is a PDA initialised *by this program*?
///
/// Ownership + data length — never lamports. A PDA address is derivable by
/// anyone from public inputs, so anyone can `transfer` rent to it; that leaves
/// the account **system-owned with zero data length** while `lamports() != 0`.
/// A lamports-based test reads that as "initialised", then deserialisation
/// fails on the empty buffer and the instruction is permanently unusable for
/// that PDA. Only the system program can allocate or assign, and only with the
/// PDA's own signature, so ownership is the one signal an attacker cannot forge.
fn is_pda_initialized(owner: &Pubkey, data_len: usize, program_id: &Pubkey) -> bool {
    owner == program_id && data_len > 0
}

/// Initialise a PDA that may already hold lamports.
///
/// `create_pda_account` cannot be used where the address is attacker-reachable:
/// `system_instruction::create_account` fails with `AccountAlreadyInUse` once
/// the target has any balance, so a rent-sized transfer to a derivable PDA
/// would permanently block its creation. `allocate` + `assign` is the standard
/// pattern that works whether or not the account was pre-funded.
///
/// Tops the account up to rent-exemption first (from `payer`), so an account
/// pre-funded with less than rent — or not funded at all — still ends up
/// rent-exempt rather than collectable.
fn init_pda_allow_prefunded<'a>(
    payer:       &AccountInfo<'a>,
    new_account: &AccountInfo<'a>,
    system_prog: &AccountInfo<'a>,
    program_id:  &Pubkey,
    seeds:       &[&[u8]],
    space:       usize,
) -> ProgramResult {
    let required  = Rent::get()?.minimum_balance(space);
    let shortfall = required.saturating_sub(new_account.lamports());
    if shortfall > 0 {
        invoke(
            &system_instruction::transfer(payer.key, new_account.key, shortfall),
            &[payer.clone(), new_account.clone(), system_prog.clone()],
        )?;
    }

    invoke_signed(
        &system_instruction::allocate(new_account.key, space as u64),
        &[new_account.clone(), system_prog.clone()],
        &[seeds],
    )?;
    invoke_signed(
        &system_instruction::assign(new_account.key, program_id),
        &[new_account.clone(), system_prog.clone()],
        &[seeds],
    )?;
    Ok(())
}

fn save_account<T: BorshSerialize>(account_ai: &AccountInfo, data: &T) -> ProgramResult {
    let bytes = borsh::to_vec(data).map_err(|_| ProgramError::InvalidAccountData)?;
    let mut acct_data = account_ai.data.borrow_mut();
    if acct_data.len() < bytes.len() {
        return Err(ProgramError::AccountDataTooSmall);
    }
    acct_data[..bytes.len()].copy_from_slice(&bytes);
    Ok(())
}

/// Derive a $FLOW amount from bytes and a pinned per-MB rate.
///
/// Saturating throughout: `bytes` is relay-supplied and unbounded within u64,
/// and a bare `as u64` on the u128 quotient silently wraps (verified reachable:
/// 2e19 wrapped to 1_553_255_926_290_448_384).
pub fn derive_reward_amount(bytes: u64, routing_per_mb: u64) -> u64 {
    (bytes as u128)
        .saturating_mul(routing_per_mb as u128)
        .checked_div(MB_DIVISOR as u128)
        .unwrap_or(0)
        .min(u64::MAX as u128) as u64
}

/// Read the repFlow balance from a repflow-token RepFlowUser Anchor account.
/// Anchor accounts have an 8-byte discriminator prefix — skip it.
fn read_repflow_balance(repflow_user_ai: &AccountInfo) -> Result<u64, ProgramError> {
    let data = repflow_user_ai.data.borrow();
    if data.len() < 8 + 8 {
        return Err(ProgramError::InvalidAccountData);
    }
    // Skip 8-byte Anchor discriminator, then read wallet(32) + balance(8)
    let offset = 8 + 32; // discriminator + wallet pubkey
    if data.len() < offset + 8 {
        return Err(ProgramError::InvalidAccountData);
    }
    let balance = u64::from_le_bytes(
        data[offset..offset + 8].try_into().map_err(|_| ProgramError::InvalidAccountData)?
    );
    Ok(balance)
}

/// Validate that `repflow_user_ai` is a genuine repflow-token `RepFlowUser` PDA,
/// then read its balance. This is the ONLY balance reader the handlers should use.
///
/// The bare `read_repflow_balance` trusts raw bytes at a fixed offset — it checks
/// neither the account owner nor its address, so any 48-byte account (a fabricated
/// one the caller owns, or an unrelated relay's *public* PDA) can satisfy the
/// repFlow gate or absorb a slash. Binding the account to the authentic
/// `REPFLOW_PROGRAM_ID` closes both:
///   1. owner must be repflow-token — a system-owned or attacker-owned account fails;
///   2. the address must be the canonical `[b"repflow_user", wallet]` PDA.
///
/// `expected_wallet`:
///   - `Some(w)` — the address must be the PDA for `w`. Use at the repFlow gate
///     (`w = relay_wallet`, so a relay presents *its own* balance, never a
///     borrowed one) and in `ClientDispute` (`w = commitment.relay_pubkey`, so the
///     slash burns the committing relay, never an unrelated account).
///   - `None` — bind to the account's *own* stored wallet (bytes `[8..40]`). Use
///     where a trusted signer names the target (`SlashTrialFraud`); this still
///     rejects any account that is not a genuine repflow_user PDA.
///
/// `REPFLOW_PROGRAM_ID` is a compile-time constant, never a caller-supplied
/// account, so the derivation cannot be pointed at an attacker program.
fn read_checked_repflow_balance(
    repflow_user_ai: &AccountInfo,
    expected_wallet: Option<&[u8; 32]>,
) -> Result<u64, ProgramError> {
    if repflow_user_ai.owner != &REPFLOW_PROGRAM_ID {
        return Err(RewardsError::RepFlowUserInvalid.into());
    }
    let stored_wallet: [u8; 32] = {
        let data = repflow_user_ai.data.borrow();
        if data.len() < 8 + 32 {
            return Err(ProgramError::InvalidAccountData);
        }
        data[8..40].try_into().map_err(|_| ProgramError::InvalidAccountData)?
    };
    let wallet = expected_wallet.unwrap_or(&stored_wallet);
    let (expected_pda, _) = Pubkey::find_program_address(
        &[b"repflow_user", wallet.as_ref()],
        &REPFLOW_PROGRAM_ID,
    );
    if repflow_user_ai.key != &expected_pda {
        return Err(RewardsError::RepFlowUserInvalid.into());
    }
    read_repflow_balance(repflow_user_ai)
}

// ── 0: CommitClaim ───────────────────────────────────────────────────────────

/// Clamp reported uptime to what is provably claimable.
///
/// Both bounds are required. `elapsed` alone bounds time *passed*, not time
/// *served*: a relay offline 30 days would claim 720h it never served, minted
/// immediately with no dispute window. The per-epoch cap alone would let a
/// relay commit epochs back to back and claim the maximum on each.
///
/// `last_committed_at == None` means the relay has no prior epoch: it earns
/// zero uptime. A bootstrap allowance was rejected as sybil-multipliable —
/// every fresh wallet would draw a free grant.
pub fn clamp_uptime_hours(
    reported:          u64,
    now:               i64,
    last_committed_at: Option<i64>,
    enabled:           bool,
) -> u64 {
    if !enabled {
        return 0;
    }
    let Some(last) = last_committed_at else { return 0 };
    let elapsed_hours = now.saturating_sub(last).max(0) as u64 / 3600;
    reported.min(elapsed_hours).min(MAX_UPTIME_HOURS_PER_EPOCH)
}

/// CommitClaim: relay publishes Merkle root committing to all client batches.
///
/// Accounts:
///   0: relay_wallet      (signer, writable, payer)
///   1: claim_commitment  (writable, PDA [b"claim_commitment", relay, epoch_le] — created)
///   2: system_program
///   3: reward_rates      (readonly, MANDATORY, PDA [b"reward_rates"]) — the pinned rate
///   4: relay_meta        (writable, PDA [b"relay_meta", relay] — created on first commit)
///   5: foundation_config (readonly, PDA [b"foundation_config"]) — uptime kill switch
///
/// The relay supplies quantities only (`total_bytes`, `uptime_hours`); the
/// program derives every amount from the foundation-governed rate and pins that
/// rate into the commitment.
///
/// No repFlow gate. Any relay can commit.
pub fn process_commit_claim_ix(
    program_id:   &Pubkey,
    accounts:     &[AccountInfo],
    merkle_root:  [u8; 32],
    client_count: u32,
    total_bytes:  u64,
    uptime_hours: u64,
    claim_epoch:  u64,
) -> ProgramResult {
    let iter            = &mut accounts.iter();
    let relay_wallet    = next_account_info(iter)?;
    let commitment_ai   = next_account_info(iter)?;
    let system_prog     = next_account_info(iter)?;

    if !relay_wallet.is_signer {
        return Err(ProgramError::MissingRequiredSignature);
    }

    // ── Mandatory reward rates (spec §5.2) ────────────────────────────────────
    // reward_rates is REQUIRED (REWARD_RATES_REQUIRED=true) and key-validated.
    // It was optional during rollout, which meant a relay could send a 3-account
    // CommitClaim and skip rate enforcement entirely.
    let reward_rates_ai = next_account_info(iter)?;
    let (rr_pda, _) = Pubkey::find_program_address(&[b"reward_rates"], program_id);
    if reward_rates_ai.key != &rr_pda || reward_rates_ai.lamports() == 0 {
        return Err(RewardsError::RewardRatesNotInitialized.into());
    }
    let rr = RewardRatesAccount::try_from_slice(&reward_rates_ai.data.borrow())
        .map_err(|_| ProgramError::InvalidAccountData)?;

    // ── Relay meta (monotonic clamp basis) ────────────────────────────────────
    let relay_meta_ai = next_account_info(iter)?;
    let (rm_pda, rm_bump) = Pubkey::find_program_address(
        &[b"relay_meta", relay_wallet.key.as_ref()], program_id,
    );
    if relay_meta_ai.key != &rm_pda {
        return Err(RewardsError::RelayMetaInvalid.into());
    }
    // Computed ONCE, before the read, and reused verbatim at the write site
    // below — if the read and the write could disagree about whether the PDA
    // exists, one of the two branches is always wrong.
    //
    // Lamports are deliberately not the signal: `[b"relay_meta", relay]` is
    // derivable from a public relay pubkey, so anyone can transfer rent to it
    // and leave it system-owned with zero data. Under a `lamports() == 0` test
    // that account read as "initialised", `try_from_slice` failed on the empty
    // buffer, and the relay could never CommitClaim again — a permanent halt of
    // all bandwidth, trial, and uptime revenue for the price of the transfer.
    let relay_meta_initialized =
        is_pda_initialized(relay_meta_ai.owner, relay_meta_ai.data_len(), program_id);

    let last_committed_at: Option<i64> = if relay_meta_initialized {
        Some(RelayClaimMeta::try_from_slice(&relay_meta_ai.data.borrow())
            .map_err(|_| ProgramError::InvalidAccountData)?
            .last_committed_at)
    } else {
        None
    };

    // ── Kill switch ───────────────────────────────────────────────────────────
    let foundation_config_ai = next_account_info(iter)?;
    let (fc_pda, _) = Pubkey::find_program_address(&[b"foundation_config"], program_id);
    if foundation_config_ai.key != &fc_pda {
        return Err(ProgramError::InvalidArgument);
    }
    let uptime_enabled = if foundation_config_ai.lamports() == 0 {
        true // config not yet created — default enabled
    } else {
        // Legacy-tolerant: the live PDA may still be the pre-upgrade 34-byte
        // layout (no `uptime_enabled` field). See read_foundation_config_compat.
        read_foundation_config_compat(&foundation_config_ai.data.borrow())?.uptime_enabled
    };

    let clock = Clock::get()?;
    let now = clock.unix_timestamp;

    // Verify claim_epoch matches current epoch.
    let current_epoch = now as u64 / EPOCH_SECS;
    if claim_epoch != current_epoch {
        msg!(
            "CommitClaim: epoch mismatch — provided {} current {}",
            claim_epoch, current_epoch
        );
        return Err(ProgramError::InvalidArgument);
    }

    // Derive PDA and verify.
    let (expected_pda, bump) = Pubkey::find_program_address(
        &[b"claim_commitment", relay_wallet.key.as_ref(), &claim_epoch.to_le_bytes()],
        program_id,
    );
    if commitment_ai.key != &expected_pda {
        return Err(ProgramError::InvalidArgument);
    }

    // Create PDA — fails atomically if already exists (EpochAlreadyCommitted).
    if commitment_ai.lamports() > 0 {
        return Err(RewardsError::EpochAlreadyCommitted.into());
    }

    // ── Derive value; the relay supplied none ─────────────────────────────────
    let clamped_hours = clamp_uptime_hours(uptime_hours, now, last_committed_at, uptime_enabled);
    // `total_bytes` is relay-supplied and unbounded within u64, and `routing_per_mb`
    // is governance-set, so the u128 product can exceed u64::MAX. Saturate rather
    // than wrap — bandwidth_amount is the only budget releases are checked against,
    // so a wrapped value would corrupt the cap.
    let bandwidth_amount = derive_reward_amount(total_bytes, rr.routing_per_mb);
    let uptime_amount = clamped_hours.saturating_mul(rr.uptime_per_hour);

    msg!(
        "CommitClaim: bandwidth={} uptime={} (hours {}->{}) routing_per_mb={} uptime_per_hour={}",
        bandwidth_amount, uptime_amount, uptime_hours, clamped_hours,
        rr.routing_per_mb, rr.uptime_per_hour,
    );

    create_pda_account(
        relay_wallet,
        commitment_ai,
        system_prog,
        program_id,
        &[b"claim_commitment", relay_wallet.key.as_ref(), &claim_epoch.to_le_bytes(), &[bump]],
        CLAIM_COMMITMENT_SIZE,
    )?;

    let commitment = ClaimCommitment {
        relay_pubkey:    relay_wallet.key.to_bytes(),
        claim_epoch,
        merkle_root,
        client_count,
        bandwidth_amount,
        uptime_amount,
        total_bytes,
        uptime_hours:    clamped_hours,
        routing_per_mb:  rr.routing_per_mb,
        uptime_per_hour: rr.uptime_per_hour,
        committed_at:    now,
        uptime_paid:     false,
        reserved_count:  0,
        released_count:  0,
        released_amount: 0,
        released_bytes:  0,
        status:          ClaimCommitmentStatus::Active,
        dispute_deadline: now + DISPUTE_WINDOW_SECS,
        bump,
    };

    save_account(commitment_ai, &commitment)?;

    // ── Advance the monotonic clamp basis ─────────────────────────────────────
    if !relay_meta_initialized {
        // allocate + assign rather than create_account: the account may already
        // hold attacker-supplied lamports, which create_account rejects.
        init_pda_allow_prefunded(
            relay_wallet, relay_meta_ai, system_prog, program_id,
            &[b"relay_meta", relay_wallet.key.as_ref(), &[rm_bump]],
            RELAY_CLAIM_META_SIZE,
        )?;
    }
    save_account(relay_meta_ai, &RelayClaimMeta {
        relay: relay_wallet.key.to_bytes(),
        last_committed_at: now,
        bump: rm_bump,
    })?;

    msg!(
        "CommitClaim: epoch={} root={:?} clients={} bytes={}",
        claim_epoch,
        &merkle_root[..4],
        client_count,
        total_bytes,
    );
    Ok(())
}

// ── 1: ReserveBatch ──────────────────────────────────────────────────────────

/// ReserveBatch: lock client funds via CPI to user_escrow (up to 10 clients per tx).
///
/// Accounts:
///   0:  relay_wallet         (signer, payer)
///   1:  claim_commitment     (writable)
///   2:  user_escrow_program
///   3:  service_authority    (mint_authority PDA)
///   4:  spender_registry     (AuthorizedSpenderRegistry PDA)
///   5:  system_program
///   6+: per client × 6 accounts: [user_wallet, claim_state, user_escrow, fund_hold, user_escrow_token, reservation]
///
/// No repFlow gate.
pub fn process_reserve_batch_ix(
    program_id:  &Pubkey,
    accounts:    &[AccountInfo],
    claim_epoch: u64,
    entries:     Vec<ReserveBatchEntry>,
) -> ProgramResult {
    let iter              = &mut accounts.iter();
    let relay_wallet      = next_account_info(iter)?;
    let commitment_ai     = next_account_info(iter)?;
    let escrow_program    = next_account_info(iter)?;
    let service_authority = next_account_info(iter)?;
    let spender_registry  = next_account_info(iter)?;
    let system_prog       = next_account_info(iter)?;

    if !relay_wallet.is_signer {
        return Err(ProgramError::MissingRequiredSignature);
    }

    // Load and validate commitment.
    let mut commitment: ClaimCommitment =
        ClaimCommitment::try_from_slice(&commitment_ai.data.borrow())
            .map_err(|_| RewardsError::ClaimCommitmentNotFound)?;

    // Bind the commitment to the SIGNER before touching it. Without this any
    // keypair could pass another relay's commitment and release its epoch —
    // see `require_own_commitment`.
    require_own_commitment(commitment_ai, relay_wallet, claim_epoch, program_id)?;

    if commitment.claim_epoch != claim_epoch {
        return Err(ProgramError::InvalidArgument);
    }
    if commitment.status != ClaimCommitmentStatus::Active {
        return Err(RewardsError::EpochComplete.into());
    }

    // Verify service_authority is our mint_authority PDA.
    let (expected_authority, authority_bump) =
        Pubkey::find_program_address(&[b"mint_authority"], program_id);
    if service_authority.key != &expected_authority {
        return Err(ProgramError::InvalidArgument);
    }

    let mut total_entry_amount: u64 = 0;
    let mut total_entry_bytes:  u64 = 0;

    for entry in &entries {
        // Per-client accounts (6 per client).
        let user_ai             = next_account_info(iter)?; // client wallet (read-only, PDA seed)
        let claim_state_ai      = next_account_info(iter)?;
        let user_escrow_ai      = next_account_info(iter)?;
        let fund_hold_ai        = next_account_info(iter)?;
        let _user_escrow_token_ai = next_account_info(iter)?;
        let reservation_ai      = next_account_info(iter)?;

        // Load or create UserRelayClaimState.
        let (claim_state_pda, cs_bump) = Pubkey::find_program_address(
            &[b"claim_state", &entry.client_pubkey, relay_wallet.key.as_ref()],
            program_id,
        );
        if claim_state_ai.key != &claim_state_pda {
            return Err(ProgramError::InvalidArgument);
        }

        let mut claim_state: UserRelayClaimState = if claim_state_ai.lamports() == 0 {
            create_pda_account(
                relay_wallet, claim_state_ai, system_prog, program_id,
                &[b"claim_state", &entry.client_pubkey, relay_wallet.key.as_ref(), &[cs_bump]],
                USER_RELAY_CLAIM_STATE_SIZE,
            )?;
            UserRelayClaimState {
                user:                entry.client_pubkey,
                relay:               relay_wallet.key.to_bytes(),
                last_claimed_seq:    0,
                total_claimed_bytes: 0,
                last_claim_slot:     0,
                last_release_epoch:  0,
                bump:                cs_bump,
            }
        } else {
            UserRelayClaimState::try_from_slice(&claim_state_ai.data.borrow())
                .map_err(|_| ProgramError::InvalidAccountData)?
        };

        // Seq must advance.
        if entry.highest_seq <= claim_state.last_claimed_seq {
            return Err(RewardsError::SeqAlreadyAdvanced.into());
        }

        let clock = Clock::get()?;
        claim_state.last_claimed_seq    = entry.highest_seq;
        claim_state.total_claimed_bytes += entry.bytes;
        claim_state.last_claim_slot     = clock.slot;
        save_account(claim_state_ai, &claim_state)?;

        // Compute leaf hash and claim hash.
        let leaf_hash  = compute_merkle_leaf_hash_from_entry(entry);
        let claim_hash = compute_claim_hash(&entry.client_pubkey, &entry.session_id, entry.highest_seq, &leaf_hash);

        // Note: fund_hold PDA is derived by user_escrow program, not rewards-v2.
        // We pass the account as provided; user_escrow validates the seeds internally.

        // Value is derived, never accepted. The relay reports bytes only.
        // `entry.bytes` is relay-supplied and unbounded within u64, and `routing_per_mb`
        // is governance-set, so the u128 product can exceed u64::MAX. Saturate rather
        // than wrap, matching process_commit_claim_ix exactly so the two derivations
        // cannot drift — bandwidth_amount is the only budget reserves are checked
        // against, so a wrapped value would corrupt the cap.
        let derived_amount = derive_reward_amount(entry.bytes, commitment.routing_per_mb);

        // CPI: hold_client_funds.
        cpi_hold_client_funds(
            escrow_program,
            service_authority,
            relay_wallet,
            user_ai,
            user_escrow_ai,
            fund_hold_ai,
            spender_registry,
            system_prog,
            derived_amount,
            claim_hash,
            entry.session_id,
            authority_bump,
        ).map_err(|_| RewardsError::ReserveBatchFailed)?;

        // Load or create Reservation PDA.
        let (reservation_pda, res_bump) = Pubkey::find_program_address(
            &[b"reservation", &entry.client_pubkey],
            program_id,
        );
        if reservation_ai.key != &reservation_pda {
            return Err(ProgramError::InvalidArgument);
        }
        let mut reservation: Reservation = if reservation_ai.lamports() == 0 {
            create_pda_account(
                relay_wallet, reservation_ai, system_prog, program_id,
                &[b"reservation", &entry.client_pubkey, &[res_bump]],
                RESERVATION_SIZE,
            )?;
            Reservation { user: entry.client_pubkey, reserved: 0, bump: res_bump }
        } else {
            Reservation::try_from_slice(&reservation_ai.data.borrow())
                .map_err(|_| ProgramError::InvalidAccountData)?
        };

        reservation.reserved = reservation.reserved
            .checked_add(derived_amount)
            .ok_or(RewardsError::ArithmeticOverflow)?;
        save_account(reservation_ai, &reservation)?;

        total_entry_amount = total_entry_amount
            .checked_add(derived_amount)
            .ok_or(RewardsError::ArithmeticOverflow)?;
        total_entry_bytes = total_entry_bytes
            .checked_add(entry.bytes)
            .ok_or(RewardsError::ArithmeticOverflow)?;

        commitment.reserved_count += 1;
    }

    // Aggregate totals cap check.
    if total_entry_amount > commitment.bandwidth_amount {
        return Err(RewardsError::ReserveExceedsCommitment.into());
    }
    if total_entry_bytes > commitment.total_bytes {
        return Err(RewardsError::ReserveExceedsCommitment.into());
    }

    save_account(commitment_ai, &commitment)?;

    msg!(
        "ReserveBatch: epoch={} reserved {} clients total={}",
        claim_epoch, entries.len(), total_entry_amount,
    );
    Ok(())
}

#[cfg(test)]
mod complete_latch_tests {
    use super::*;

    fn commitment(client_count: u32, reserved: u32, released: u32) -> ClaimCommitment {
        ClaimCommitment {
            relay_pubkey: [0u8; 32], claim_epoch: 1, merkle_root: [0u8; 32],
            client_count, bandwidth_amount: 0, uptime_amount: 0, total_bytes: 0,
            uptime_hours: 0, routing_per_mb: 0, uptime_per_hour: 0, committed_at: 0,
            uptime_paid: false, reserved_count: reserved, released_count: released,
            released_amount: 0, released_bytes: 0,
            status: ClaimCommitmentStatus::Releasing, dispute_deadline: 0, bump: 0,
        }
    }

    /// THE regression. The relay fits exactly one paid release per transaction,
    /// so an epoch with two reserved clients closes over two txs. Latching
    /// Complete after the first sent the second to `_ => EpochComplete` and
    /// stranded its FundHold permanently — nothing in the program can
    /// un-Complete a commitment.
    #[test]
    fn first_of_two_releases_must_not_complete_the_epoch() {
        assert!(
            !epoch_is_fully_released(&commitment(2, 2, 1)),
            "1 of 2 reserved clients released — the epoch must stay Releasing, \
             or the second tx reverts EpochComplete and its FundHold is lost"
        );
        assert!(
            epoch_is_fully_released(&commitment(2, 2, 2)),
            "the LAST release closes the epoch"
        );
    }

    /// The denominator must be reserved_count, not client_count. client_count
    /// is the relay's batches.len() — paid AND trial — while ReleaseClaim
    /// releases only the paid subset, so comparing against it would hang every
    /// mixed epoch in Releasing forever: the same bug wearing the other mask.
    #[test]
    fn mixed_paid_and_trial_epoch_completes_on_the_paid_subset() {
        // 3 clients committed, only 1 of them paid and therefore reserved.
        let c = commitment(3, 1, 1);
        assert!(
            epoch_is_fully_released(&c),
            "the single reserved (paid) client has been released — the epoch is \
             done, even though client_count is 3 and the other two were trial"
        );
    }

    /// The gap the first version of this guard had, and the reason the audit
    /// called the fix incomplete.
    ///
    /// `released_count` was incremented by BOTH release paths while
    /// `reserved_count` counts paid clients only. An epoch with 2 paid and 1
    /// trial client therefore reached `released_count == 2 == reserved_count`
    /// after the trial release plus the FIRST paid release — latching
    /// `Complete` one release early and stranding the second paid client's
    /// FundHold permanently, which is precisely the bug the guard exists to
    /// prevent.
    ///
    /// Fixed by making the trial path leave `released_count` alone. This test
    /// models the state the program can now actually produce: after a trial
    /// release, `released_count` is still 0.
    ///
    /// **This test is documentation, NOT the guard.** Mutation-checked: restore
    /// the increment in `process_release_trial_claim_ix` and this still passes,
    /// because it hand-builds the commitment rather than driving the handler —
    /// the same weakness the audit flagged in the rest of this module. The
    /// regression is actually caught by
    /// `release_trial_claim_integration_tests::release_trial_claim_success_mints_70_30_and_records_usage`,
    /// which asserts `released_count == 0` against a real transaction. Keep
    /// that assertion; it is load-bearing.
    #[test]
    fn a_trial_release_does_not_advance_the_paid_latch() {
        // 2 paid (reserved) + 1 trial. The trial release has already happened
        // and contributed NOTHING to released_count.
        let after_trial_release = commitment(3, 2, 0);
        assert!(
            !epoch_is_fully_released(&after_trial_release),
            "a trial release must not move the paid latch at all"
        );

        // First paid release.
        let after_first_paid = commitment(3, 2, 1);
        assert!(
            !epoch_is_fully_released(&after_first_paid),
            "1 of 2 paid clients released — the epoch must stay Releasing. If \
             the trial release had counted, released_count would read 2 here and \
             the second paid client would be stranded"
        );

        // Second paid release closes it.
        assert!(epoch_is_fully_released(&commitment(3, 2, 2)));
    }

    /// A partially-succeeded ReserveBatch leaves reserved_count short. Still
    /// correct: a client with no FundHold cannot be released at all, so the
    /// epoch closes over exactly what was reservable.
    #[test]
    fn partial_reserve_still_closes_on_what_was_reserved() {
        assert!(epoch_is_fully_released(&commitment(5, 2, 2)));
        assert!(!epoch_is_fully_released(&commitment(5, 2, 1)));
    }

    /// Degenerate: nothing reserved (an all-trial epoch reaching ReleaseClaim).
    /// `>=` rather than `==` keeps this closing instead of hanging.
    #[test]
    fn nothing_reserved_is_vacuously_complete() {
        assert!(epoch_is_fully_released(&commitment(2, 0, 0)));
    }
}

#[cfg(test)]
mod derive_amount_tests {
    use super::*;

    fn derive(bytes: u64, routing_per_mb: u64) -> u64 {
        derive_reward_amount(bytes, routing_per_mb)
    }

    #[test]
    fn one_gb_at_default_rate_is_one_flow() {
        assert_eq!(derive(1_000_000_000, 1_000_000), 1_000_000_000);
    }

    #[test]
    fn per_client_sum_never_exceeds_aggregate() {
        // floor(a/d) + floor(b/d) <= floor((a+b)/d) — the per-entry cap can
        // never overrun the aggregate bandwidth_amount.
        let (a, b, rate) = (1_500_001u64, 2_500_001u64, 1_000_000u64);
        assert!(derive(a, rate) + derive(b, rate) <= derive(a + b, rate));
    }

    #[test]
    fn truncates_to_zero_below_one_base_unit() {
        // 999 * 1_000 = 999_000 < MB_DIVISOR (1_000_000), so this floors to 0.
        assert_eq!(derive(999, 1_000), 0);
    }

    #[test]
    fn prorates_continuously_below_one_mb() {
        // routing_per_mb = 1_000_000 means one base unit per byte, so a
        // sub-MB byte count is NOT rounded away.
        assert_eq!(derive(999, 1_000_000), 999);
    }
}

#[cfg(test)]
mod pda_init_predicate_tests {
    use super::*;
    use solana_program::system_program;

    /// The attack this predicate exists to defeat.
    ///
    /// `[b"relay_meta", relay]` is derivable by anyone from a public relay
    /// pubkey. A bare lamport transfer to it produces exactly this state:
    /// system-owned, zero data length, non-zero lamports. The old
    /// `lamports() == 0` test classified it as INITIALISED, then
    /// `RelayClaimMeta::try_from_slice` failed on the 0-byte buffer and every
    /// subsequent CommitClaim for that relay returned InvalidAccountData —
    /// permanent revenue DoS, no in-program recovery.
    #[test]
    fn lamport_funded_but_unallocated_account_is_uninitialized() {
        let program_id = Pubkey::new_unique();
        assert!(
            !is_pda_initialized(&system_program::ID, 0, &program_id),
            "a system-owned zero-length account must read as UNINITIALISED \
             however many lamports it holds",
        );
    }

    #[test]
    fn program_owned_with_data_is_initialized() {
        let program_id = Pubkey::new_unique();
        assert!(is_pda_initialized(&program_id, RELAY_CLAIM_META_SIZE, &program_id));
    }

    /// An account at the same address owned by some *other* program must never
    /// be deserialised as ours.
    #[test]
    fn foreign_owned_account_is_uninitialized() {
        let program_id = Pubkey::new_unique();
        assert!(!is_pda_initialized(
            &Pubkey::new_unique(), RELAY_CLAIM_META_SIZE, &program_id,
        ));
    }

    /// Both halves of the predicate are load-bearing: ownership alone would
    /// accept a zero-length account and fail the same way lamports did.
    #[test]
    fn program_owned_zero_length_is_uninitialized() {
        let program_id = Pubkey::new_unique();
        assert!(!is_pda_initialized(&program_id, 0, &program_id));
    }
}

// ── Helper: is this commitment the signer's own? ──────────────────────────────

/// Reject a `claim_commitment` that does not belong to the signing relay.
///
/// Every instruction that mutates a commitment must call this. Without it, the
/// commitment is just an account the caller hands over, and nothing ties it to
/// the signer:
///
/// * `ReleaseClaim` verified only `claim_epoch` and `status`, and did not pin
///   `claim_state` either (unlike `process_reserve_batch_ix`, which re-derives
///   it). So `AlreadyReleased` was no defence — an attacker supplies any
///   `claim_state` whose `last_release_epoch` differs.
/// * Every input needed to pass the Merkle check is public: the victim's own
///   `ReserveBatch` instruction data carries `client_pubkey`, `session_id`,
///   `highest_seq`, `bytes` and `record_count`, which is the whole leaf. For a
///   single-client epoch the proof is empty and `root == leaf`.
/// * `client_signature` is only checked non-zero, so any 64 bytes pass.
///
/// The result was direct theft: relay B calls `ReleaseClaim` on relay A's
/// matured commitment with B's own `reward_relay`, the client's escrow burns,
/// and B mints A's 70%. Below the repFlow gate B accrues A's reward into B's
/// own `ClaimableBalance` instead — the same theft, deferred. Even without
/// monetising, calling it advances the victim's `released_count` and flips the
/// commitment out of `Active`, stranding its remaining clients.
///
/// Re-deriving the PDA from the SIGNER is strictly stronger than comparing
/// `commitment.relay_pubkey`: it also proves the account is a real commitment
/// for this program and epoch, not an attacker-owned look-alike. The same idiom
/// already guards `ClaimRelayUptime` and, for the sibling PDA,
/// `process_claim_pending_ix`.
fn require_own_commitment(
    commitment_ai: &AccountInfo,
    relay_wallet:  &AccountInfo,
    claim_epoch:   u64,
    program_id:    &Pubkey,
) -> ProgramResult {
    let (expected, _) = Pubkey::find_program_address(
        &[b"claim_commitment", relay_wallet.key.as_ref(), &claim_epoch.to_le_bytes()],
        program_id,
    );
    if commitment_ai.key != &expected {
        msg!(
            "claim_commitment {} does not belong to signer {} for epoch {}",
            commitment_ai.key, relay_wallet.key, claim_epoch,
        );
        return Err(ProgramError::InvalidArgument);
    }
    Ok(())
}

// ── Helper: has every reserved client been released? ──────────────────────────

/// True once every client this epoch actually reserved has been released.
///
/// Guards the `Complete` latch in both branches of `process_release_claim_ix`.
/// Before this existed the status was set unconditionally at the end of the
/// FIRST transaction, and the relay fits exactly one paid release per
/// transaction — so any epoch with 2+ paid clients stranded every client after
/// the first: the next tx falls to the `_ => EpochComplete` arm, and nothing in
/// the program can un-Complete a commitment (`ClientDispute` requires `Active`).
///
/// **The denominator is `reserved_count`, not `client_count`.** `client_count`
/// is the relay's `batches.len()` — paid AND trial — while `ReleaseClaim`
/// releases only the paid subset, so comparing against it would leave every
/// mixed paid+trial epoch stuck in `Releasing` forever: the same bug wearing
/// the opposite mask. `reserved_count` increments once per `ReserveBatch` entry
/// (`process_reserve_batch_ix`) and only paid clients are ever reserved, which
/// makes it exactly the set `ReleaseClaim` can close.
///
/// It stays exact in three edge cases worth naming:
/// * A paid batch capped to 0 bytes is dropped from the reserve AND from the
///   release by identical relay-side filters, so it is in neither count.
/// * If `ReserveBatch` partially failed, `reserved_count` is short — still
///   correct, because a client with no `FundHold` cannot be released at all.
/// * **Trial releases do not increment `released_count`.** They used to, which
///   made the comparison asymmetric — `reserved_count` counts paid clients
///   only, so an epoch with 2 paid and 1 trial client latched `Complete` after
///   the trial release plus the FIRST paid release, stranding the second paid
///   client exactly as the unguarded version did. Both counters are now
///   paid-only. See the note at the trial handler's `released_amount` update.
fn epoch_is_fully_released(commitment: &ClaimCommitment) -> bool {
    commitment.released_count >= commitment.reserved_count
}

// ── Helper: pin the treasury sink ─────────────────────────────────────────────

/// The 30% treasury share may ONLY be minted to the foundation's canonical
/// $FLOW ATA.
///
/// Without this a relay passes a second account it controls as
/// `reward_treasury` and keeps 100% of the reward instead of 70% —
/// `cpi_mint_flow` validates nothing about its destination and signs with the
/// program's own `mint_authority` PDA, so the mint simply succeeds.
///
/// `reward_relay` is deliberately NOT constrained: the relay legitimately owns
/// its 70%, and forcing an ATA there would break relays paid into non-ATA
/// accounts. Same reasoning as `process_claim_relay_uptime_ix`.
///
/// $FLOW is a classic SPL mint, so the ATA is derived with
/// `SPL_TOKEN_PROGRAM_ID`; using the Token-2022 id would produce an address
/// that does not exist.
fn require_foundation_treasury(
    reward_treasury: &AccountInfo,
    flow_mint:       &AccountInfo,
) -> ProgramResult {
    let (expected, _) = Pubkey::find_program_address(
        &[
            FOUNDATION_PUBKEY.as_ref(),
            SPL_TOKEN_PROGRAM_ID.as_ref(),
            flow_mint.key.as_ref(),
        ],
        &ASSOCIATED_TOKEN_PROGRAM_ID,
    );
    if reward_treasury.key != &expected {
        msg!(
            "reward_treasury {} is not the foundation ATA {}",
            reward_treasury.key, expected,
        );
        return Err(RewardsError::InvalidTreasuryAccount.into());
    }
    Ok(())
}

// ── Helper: compute claim_hash ────────────────────────────────────────────────

fn compute_claim_hash(
    client_pubkey: &[u8; 32],
    session_id:    &[u8; 16],
    batch_nonce:   u64,
    leaf_hash:     &[u8; 32],
) -> [u8; 32] {
    hashv(&[
        client_pubkey.as_slice(),
        session_id.as_slice(),
        &batch_nonce.to_le_bytes(),
        leaf_hash.as_slice(),
    ]).to_bytes()
}

// ── 2: ReleaseClaim ──────────────────────────────────────────────────────────

/// ReleaseClaim: burn client $FLOW and mint 70/30 to relay/foundation.
///
/// repFlow gate (2001) checked at mint time only.
/// Must be after 7-day dispute window (commitment.dispute_deadline).
///
/// Accounts:
///   0:  relay_wallet         (signer, payer)
///   1:  claim_commitment     (writable)
///   2:  user_escrow_program
///   3:  service_authority    (mint_authority PDA)
///   4:  spender_registry
///   5:  token_program
///   6:  flow_mint            (writable)
///   7:  repflow_program
///   8:  repflow_config       (readonly) — PDA-only, no shared-counter write
///   9:  relay_repflow_user   (writable) — for balance check + repFlow credit
///   10: slash_authority_pda
///   11: reward_account_relay     (writable)
///   12: reward_account_treasury  (writable)
///   13: system_program
///   14+: per release × 5: [user_wallet, claim_state, user_escrow, fund_hold, user_escrow_token]
pub fn process_release_claim_ix(
    program_id:  &Pubkey,
    accounts:    &[AccountInfo],
    claim_epoch: u64,
    releases:    Vec<ClientReleaseOnChain>,
) -> ProgramResult {
    let iter                  = &mut accounts.iter();
    let relay_wallet          = next_account_info(iter)?;
    let commitment_ai         = next_account_info(iter)?;
    let escrow_program        = next_account_info(iter)?;
    let service_authority     = next_account_info(iter)?;
    let spender_registry      = next_account_info(iter)?;
    let token_program         = next_account_info(iter)?;
    let flow_mint             = next_account_info(iter)?;
    let repflow_program       = next_account_info(iter)?;
    let repflow_config        = next_account_info(iter)?;
    let relay_repflow_user    = next_account_info(iter)?;
    let _slash_authority      = next_account_info(iter)?;
    let reward_relay          = next_account_info(iter)?;
    let reward_treasury       = next_account_info(iter)?;
    let system_prog           = next_account_info(iter)?;

    if !relay_wallet.is_signer {
        return Err(ProgramError::MissingRequiredSignature);
    }

    let mut commitment: ClaimCommitment =
        ClaimCommitment::try_from_slice(&commitment_ai.data.borrow())
            .map_err(|_| RewardsError::ClaimCommitmentNotFound)?;

    // Bind the commitment to the SIGNER before touching it. Without this any
    // keypair could pass another relay's commitment and release its epoch —
    // see `require_own_commitment`.
    require_own_commitment(commitment_ai, relay_wallet, claim_epoch, program_id)?;

    if commitment.claim_epoch != claim_epoch {
        return Err(ProgramError::InvalidArgument);
    }

    let clock = Clock::get()?;

    // Transition from Active → Releasing after dispute deadline.
    match commitment.status {
        ClaimCommitmentStatus::Active => {
            if clock.unix_timestamp < commitment.dispute_deadline {
                return Err(RewardsError::DisputeWindowActive.into());
            }
            commitment.status = ClaimCommitmentStatus::Releasing;
        }
        ClaimCommitmentStatus::Releasing => {}
        _ => return Err(RewardsError::EpochComplete.into()),
    }

    let (_, authority_bump) = Pubkey::find_program_address(&[b"mint_authority"], program_id);

    let mut total_released_amount: u64 = 0;
    let mut total_released_bytes:  u64 = 0;

    for release in &releases {
        let user_wallet_ai       = next_account_info(iter)?;
        let claim_state_ai       = next_account_info(iter)?;
        let user_escrow_ai       = next_account_info(iter)?;
        let fund_hold_ai         = next_account_info(iter)?;
        let user_escrow_token_ai = next_account_info(iter)?;

        // 1. Compute leaf hash and verify Merkle proof.
        let leaf_hash = compute_merkle_leaf_hash_from_release(release);
        if !verify_merkle_proof(leaf_hash, &release.merkle_proof, commitment.merkle_root) {
            return Err(RewardsError::MerkleProofInvalid.into());
        }

        // 2. Signature non-null check (v1 — no Ed25519 precompile).
        if release.client_signature == [0u8; 64] {
            return Err(RewardsError::ClientSignatureInvalid.into());
        }

        // 3. Pin claim_state to (this client, THIS relay), then check
        //    AlreadyReleased.
        //
        //    `process_reserve_batch_ix` already re-derives this PDA; the
        //    release path did not, so the account was whatever the caller
        //    passed. That made the `AlreadyReleased` guard below worthless as a
        //    replay defence — supply any `UserRelayClaimState` whose
        //    `last_release_epoch` differs and it passes. Both halves matter:
        //    the seed binds the CLIENT (so one client's state cannot stand in
        //    for another's) and the RELAY (so a foreign relay cannot release
        //    against its own untouched state).
        let (expected_claim_state, _) = Pubkey::find_program_address(
            &[b"claim_state", &release.client_pubkey, relay_wallet.key.as_ref()],
            program_id,
        );
        if claim_state_ai.key != &expected_claim_state {
            msg!(
                "claim_state {} is not the PDA for this client and relay",
                claim_state_ai.key,
            );
            return Err(ProgramError::InvalidArgument);
        }
        let mut claim_state: UserRelayClaimState =
            UserRelayClaimState::try_from_slice(&claim_state_ai.data.borrow())
                .map_err(|_| ProgramError::InvalidAccountData)?;
        if claim_state.last_release_epoch == claim_epoch {
            return Err(RewardsError::AlreadyReleased.into());
        }

        // 4. Derive value from bytes and the pinned rate; the relay supplies none.
        let derived_amount = derive_reward_amount(release.total_bytes, commitment.routing_per_mb);

        // 5. Cumulative cap check. Capped by bandwidth_amount — the budget
        // releases may draw on — not the uptime allowance.
        let new_amount = commitment.released_amount
            .checked_add(derived_amount)
            .ok_or(RewardsError::ArithmeticOverflow)?;
        let new_bytes = commitment.released_bytes
            .checked_add(release.total_bytes)
            .ok_or(RewardsError::ArithmeticOverflow)?;
        if new_amount > commitment.bandwidth_amount {
            return Err(RewardsError::ReleaseExceedsCommitment.into());
        }
        if new_bytes > commitment.total_bytes {
            return Err(RewardsError::ReleaseExceedsCommitment.into());
        }

        // 6. Compute claim_hash and CPI burn_held_funds.
        let claim_hash = compute_claim_hash(
            &release.client_pubkey, &release.session_id, release.batch_nonce, &leaf_hash,
        );

        // User AccountInfo: derive from client_pubkey (read-only seed account).
        // In practice the caller must include the user wallet AccountInfo.
        // For CPI the escrow program validates via PDA seeds.
        cpi_burn_held_funds(
            escrow_program,
            // The relay funded this FundHold in hold_client_funds; closing it
            // refunds the rent to the same account. It is already account 0 of
            // this instruction, so nothing new enters the transaction.
            relay_wallet,
            service_authority,
            user_wallet_ai,
            user_escrow_ai,
            user_escrow_token_ai,
            fund_hold_ai,
            spender_registry,
            flow_mint,
            token_program,
            claim_hash,
            authority_bump,
        ).map_err(|_| RewardsError::CpiFailed)?;

        commitment.released_count  += 1;
        commitment.released_amount  = new_amount;
        commitment.released_bytes   = new_bytes;

        claim_state.last_release_epoch = claim_epoch;
        save_account(claim_state_ai, &claim_state)?;

        total_released_amount = total_released_amount
            .checked_add(derived_amount)
            .ok_or(RewardsError::ArithmeticOverflow)?;
        total_released_bytes = total_released_bytes
            .checked_add(release.total_bytes)
            .ok_or(RewardsError::ArithmeticOverflow)?;
    }

    // repFlow gate check.
    let repflow_balance =
        read_checked_repflow_balance(relay_repflow_user, Some(&relay_wallet.key.to_bytes()))?;

    if repflow_balance >= MIN_RELAY_REPFLOW {
        // Mint $FLOW 70/30.
        // H-1: the 30% may only go to the foundation ATA. Unpinned, a relay
        // passes its own account here and keeps 100%.
        require_foundation_treasury(reward_treasury, flow_mint)?;

        // M-1: derive treasury as remainder to avoid truncation loss.
        let relay_amount    = total_released_amount * RELAY_SPLIT_PCT / 100;
        let treasury_amount = total_released_amount - relay_amount;
        cpi_mint_flow(token_program, flow_mint, reward_relay, service_authority, relay_amount, authority_bump)?;
        cpi_mint_flow(token_program, flow_mint, reward_treasury, service_authority, treasury_amount, authority_bump)?;

        // Mint bandwidth repFlow.
        let repflow_amount = total_released_bytes / BYTES_PER_FLOW;
        if repflow_amount > 0 {
            cpi_mint_repflow_bandwidth(
                repflow_program, repflow_config, relay_repflow_user,
                service_authority, repflow_amount, authority_bump,
            )?;
        }

        // Only the LAST release of the epoch may close it. See
        // `epoch_is_fully_released` for why the denominator is reserved_count.
        if epoch_is_fully_released(&commitment) {
            commitment.status = ClaimCommitmentStatus::Complete;
        }
        msg!(
            "ReleaseClaim: minted {} $FLOW (70/30) + {} repFlow",
            total_released_amount, repflow_amount,
        );
    } else {
        // Probationary relay: defer mint.
        let (cb_pda, cb_bump) = Pubkey::find_program_address(
            &[b"claimable_balance", relay_wallet.key.as_ref(), &claim_epoch.to_le_bytes()],
            program_id,
        );

        // Try to find or create ClaimableBalance account.
        let cb_ai = next_account_info(iter)?;
        if cb_ai.key != &cb_pda {
            return Err(ProgramError::InvalidArgument);
        }

        let mut cb: ClaimableBalance = if cb_ai.lamports() == 0 {
            create_pda_account(
                relay_wallet, cb_ai, system_prog, program_id,
                &[b"claimable_balance", relay_wallet.key.as_ref(), &claim_epoch.to_le_bytes(), &[cb_bump]],
                CLAIMABLE_BALANCE_SIZE,
            )?;
            ClaimableBalance {
                relay:              relay_wallet.key.to_bytes(),
                claim_epoch,
                pending_relay_flow: 0,
                pending_treasury:   0,
                pending_repflow:    0,
                status:             ClaimableBalanceStatus::Pending,
                bump:               cb_bump,
            }
        } else {
            ClaimableBalance::try_from_slice(&cb_ai.data.borrow())
                .map_err(|_| ProgramError::InvalidAccountData)?
        };

        // M-1: derive treasury as remainder to avoid truncation loss.
        let relay_amount    = total_released_amount * RELAY_SPLIT_PCT / 100;
        let treasury_amount = total_released_amount - relay_amount;
        let repflow_amount  = total_released_bytes / BYTES_PER_FLOW;

        cb.pending_relay_flow = cb.pending_relay_flow
            .checked_add(relay_amount).ok_or(RewardsError::ArithmeticOverflow)?;
        cb.pending_treasury   = cb.pending_treasury
            .checked_add(treasury_amount).ok_or(RewardsError::ArithmeticOverflow)?;
        cb.pending_repflow    = cb.pending_repflow
            .checked_add(repflow_amount).ok_or(RewardsError::ArithmeticOverflow)?;

        // H-2: persist commitment to Complete BEFORE crediting ClaimableBalance.
        // If the second save fails the commitment guard blocks a double-credit.
        // Same release-count guard as the mint branch — a probationary relay
        // splits its releases across transactions exactly like a funded one.
        if epoch_is_fully_released(&commitment) {
            commitment.status = ClaimCommitmentStatus::Complete;
        }
        save_account(commitment_ai, &commitment)?;
        save_account(cb_ai, &cb)?;
        msg!(
            "ReleaseClaim: relay probationary (<2001 repFlow). {} $FLOW deferred",
            total_released_amount,
        );
    }

    save_account(commitment_ai, &commitment)?;
    msg!(
        "ReleaseClaim: epoch={} released {}/{}",
        claim_epoch, commitment.released_count, commitment.client_count,
    );
    Ok(())
}

// ── 3: ClientDispute ─────────────────────────────────────────────────────────

/// ClientDispute: client disputes forged batches.
///
/// If the Merkle proof fails (leaf NOT in tree) → tiered repFlow slash + release funds.
/// If the Merkle proof passes (leaf IS in tree) → relay committed honestly, no action.
///
/// Accounts:
///   0:  client               (signer)
///   1:  claim_commitment     (writable)
///   2:  relay_reputation     (writable, PDA)
///   3:  user_escrow_program
///   4:  service_authority    (mint_authority PDA)
///   5:  spender_registry
///   6:  repflow_program
///   7:  repflow_config       (readonly) — PDA-only slash, no SPL burn
///   8:  relay_repflow_user   (writable)
///   9:  slash_authority_pda
///   10: system_program
///   11: fund_hold            (writable, FundHold PDA in user_escrow keyed by claim_hash)
///   12: user_escrow          (writable, UserEscrow PDA for the client)
///   13: rent_recipient       (writable, MUST be FOUNDATION_PUBKEY — receives the
///                             closed FundHold's rent; see the pin before the CPI)
#[allow(clippy::too_many_arguments)]
pub fn process_client_dispute_ix(
    program_id:          &Pubkey,
    accounts:            &[AccountInfo],
    claim_epoch:         u64,
    client_pubkey:       [u8; 32],
    session_id:          [u8; 16],
    batch_nonce:         u64,
    original_batch_hash: [u8; 32],
    total_bytes:         u64,
    record_count:        u32,
    client_signature:    [u8; 64],
    merkle_proof:        Vec<[u8; 32]>,
) -> ProgramResult {
    let iter             = &mut accounts.iter();
    let client           = next_account_info(iter)?;
    let commitment_ai    = next_account_info(iter)?;
    let reputation_ai    = next_account_info(iter)?;
    let escrow_program   = next_account_info(iter)?;
    let service_authority = next_account_info(iter)?;
    let spender_registry = next_account_info(iter)?;
    let repflow_program  = next_account_info(iter)?;
    let repflow_config   = next_account_info(iter)?;
    let relay_repflow_user = next_account_info(iter)?;
    let slash_authority  = next_account_info(iter)?;
    let system_prog      = next_account_info(iter)?;
    let fund_hold_ai     = next_account_info(iter)?;
    let user_escrow_ai   = next_account_info(iter)?;
    let rent_recipient_ai = next_account_info(iter)?;

    if !client.is_signer {
        return Err(ProgramError::MissingRequiredSignature);
    }

    let commitment: ClaimCommitment =
        ClaimCommitment::try_from_slice(&commitment_ai.data.borrow())
            .map_err(|_| RewardsError::ClaimCommitmentNotFound)?;

    if commitment.claim_epoch != claim_epoch {
        return Err(ProgramError::InvalidArgument);
    }
    if commitment.status != ClaimCommitmentStatus::Active {
        return Err(RewardsError::EpochComplete.into());
    }

    let clock = Clock::get()?;
    if clock.unix_timestamp >= commitment.dispute_deadline {
        return Err(RewardsError::DisputeWindowExpired.into());
    }

    // Verify client_pubkey matches signer.
    if client.key.to_bytes() != client_pubkey {
        return Err(ProgramError::InvalidArgument);
    }

    // Verify batch_hash consistency.
    let computed_batch_hash = hashv(&[
        &client_pubkey,
        &session_id,
        &batch_nonce.to_le_bytes(),
    ]).to_bytes();
    if computed_batch_hash != original_batch_hash {
        return Err(RewardsError::BatchSignatureInvalid.into());
    }

    // Signature non-null check (v1 — no Ed25519 precompile).
    if client_signature == [0u8; 64] {
        return Err(RewardsError::BatchSignatureInvalid.into());
    }

    // Compute expected Merkle leaf and claim hash (needed for both the
    // fund_hold guard below and the eventual cpi_release_funds call).
    let expected_leaf = compute_merkle_leaf_hash(
        &client_pubkey, &session_id, batch_nonce, &original_batch_hash,
        total_bytes, record_count,
    );
    let claim_hash = compute_claim_hash(&client_pubkey, &session_id, batch_nonce, &expected_leaf);

    // H-1: reject fabricated disputes.  A FundHold PDA is created by
    // ReserveBatch only when real client funds were locked for this exact
    // batch (keyed by claim_hash).  lamports == 0 means the batch was never
    // reserved — no legitimate dispute is possible.
    if fund_hold_ai.lamports() == 0 {
        return Err(RewardsError::NoClaimHistory.into());
    }

    // Check Merkle inclusion.
    let in_tree = if commitment.client_count == 1 {
        expected_leaf == commitment.merkle_root
    } else {
        verify_merkle_proof(expected_leaf, &merkle_proof, commitment.merkle_root)
    };

    if in_tree {
        // Relay committed honestly — no slash.
        msg!(
            "ClientDispute: epoch={} client={:?} -- batch verified in tree, no slash",
            claim_epoch, &client_pubkey[..4],
        );
        return Ok(());
    }

    // Leaf NOT in tree — forgery confirmed. Slash relay's repFlow.
    let (rep_pda, rep_bump) = Pubkey::find_program_address(
        &[b"relay_reputation", &commitment.relay_pubkey],
        program_id,
    );
    if reputation_ai.key != &rep_pda {
        return Err(ProgramError::InvalidArgument);
    }

    let mut rep: RelayReputation = if reputation_ai.lamports() == 0 {
        create_pda_account(
            client, reputation_ai, system_prog, program_id,
            &[b"relay_reputation", &commitment.relay_pubkey, &[rep_bump]],
            RELAY_REPUTATION_SIZE,
        )?;
        RelayReputation {
            relay: commitment.relay_pubkey,
            slash_count: 0,
            lifetime_slashed: 0,
            bump: rep_bump,
        }
    } else {
        RelayReputation::try_from_slice(&reputation_ai.data.borrow())
            .map_err(|_| ProgramError::InvalidAccountData)?
    };

    rep.slash_count += 1;

    // Tiered slash amount. F-1: bind the slash target to the committing relay's
    // repFlow PDA (commitment.relay_pubkey) — a dispute must never burn an
    // unrelated or fabricated account. A mismatch reverts before any slash.
    let relay_repflow_balance =
        read_checked_repflow_balance(relay_repflow_user, Some(&commitment.relay_pubkey))?;
    let slash_amount = match rep.slash_count {
        1 => SLASH_FIRST_OFFENSE,
        2 => SLASH_SECOND_OFFENSE,
        _ => relay_repflow_balance, // 100% of balance
    };
    let slash_amount = slash_amount.min(relay_repflow_balance);

    let (_, slash_bump) = Pubkey::find_program_address(&[b"slash_authority"], program_id);

    // CPI slash — PDA-only (no SPL burn).
    cpi_slash_repflow(
        repflow_program,
        repflow_config,
        relay_repflow_user,
        slash_authority,
        slash_amount,
        slash_bump,
    ).map_err(|_| RewardsError::SlashFailed)?;

    rep.lifetime_slashed = rep.lifetime_slashed
        .checked_add(slash_amount).ok_or(RewardsError::ArithmeticOverflow)?;
    save_account(reputation_ai, &rep)?;

    msg!(
        "ClientDispute: relay={:?} slashed {} repFlow (offense #{})",
        &commitment.relay_pubkey[..4], slash_amount, rep.slash_count,
    );

    // Release client's funds.
    let (_, authority_bump) = Pubkey::find_program_address(&[b"mint_authority"], program_id);

    // Releasing closes the FundHold, and its ~1.6M lamports of rent have to land
    // somewhere. Pin that somewhere to the foundation: the client signs this
    // instruction, so an unvalidated recipient would let them name their own
    // wallet and pocket the relay's rent as a bonus for disputing. Paying the
    // relay instead would reward it for the batch a dispute just proved forged.
    // Neither party profits — the foundation absorbs it.
    //
    // FOUNDATION_PUBKEY is the system-owned wallet, NOT the foundation's $FLOW
    // ATA. This is SOL: lamports parked on an SPL token account cannot be
    // withdrawn below its own rent-exemption and there is no sweep instruction,
    // so routing rent to the ATA would strand it exactly as before.
    if rent_recipient_ai.key != &FOUNDATION_PUBKEY {
        return Err(RewardsError::InvalidTreasuryAccount.into());
    }

    cpi_release_funds(
        escrow_program,
        rent_recipient_ai,
        service_authority,
        client,  // user_ai
        user_escrow_ai,
        fund_hold_ai,
        spender_registry,
        claim_hash,
        authority_bump,
    ).map_err(|_| RewardsError::CpiFailed)?;

    // L-4: do NOT set commitment to Disputed — that would freeze all other
    // clients' funds in this epoch.  Repeat disputes on the same batch are
    // caught by H-1: release closes the FundHold, so on a second attempt
    // fund_hold_ai.lamports() == 0 and the dispute is rejected as fabricated.
    // (Before the close landed, the actual guard was user-escrow's
    // `status == Active` constraint, which surfaced as a CpiFailed instead.)
    // The commitment stays Active so honest clients can still proceed to
    // ReleaseClaim.
    msg!(
        "ClientDispute: epoch={} client={:?} FORGED/OMITTED -- relay slashed (offense #{})",
        claim_epoch, &client_pubkey[..4], rep.slash_count,
    );
    Ok(())
}

// ── 4: ClaimPendingRewards ───────────────────────────────────────────────────

/// ClaimPendingRewards: probationary relay mints deferred $FLOW + repFlow.
///
/// Accounts:
///   0: relay_wallet         (signer)
///   1: claimable_balance    (writable)
///   2: token_program
///   3: flow_mint            (writable)
///   4: service_authority    (mint_authority PDA)
///   5: repflow_program
///   6: repflow_config       (readonly) — PDA-only credit, no SPL mint
///   7: relay_repflow_user   (writable)
///   8: reward_account_relay     (writable)
///   9: reward_account_treasury  (writable)
pub fn process_claim_pending_ix(
    program_id:  &Pubkey,
    accounts:    &[AccountInfo],
    claim_epoch: u64,
) -> ProgramResult {
    let iter               = &mut accounts.iter();
    let relay_wallet       = next_account_info(iter)?;
    let cb_ai              = next_account_info(iter)?;
    let token_program      = next_account_info(iter)?;
    let flow_mint          = next_account_info(iter)?;
    let service_authority  = next_account_info(iter)?;
    let repflow_program    = next_account_info(iter)?;
    let repflow_config     = next_account_info(iter)?;
    let relay_repflow_user = next_account_info(iter)?;
    let reward_relay       = next_account_info(iter)?;
    let reward_treasury    = next_account_info(iter)?;

    if !relay_wallet.is_signer {
        return Err(ProgramError::MissingRequiredSignature);
    }

    let mut cb: ClaimableBalance =
        ClaimableBalance::try_from_slice(&cb_ai.data.borrow())
            .map_err(|_| RewardsError::ClaimableBalanceNotFound)?;

    if cb.claim_epoch != claim_epoch {
        return Err(ProgramError::InvalidArgument);
    }
    if cb.relay != relay_wallet.key.to_bytes() {
        return Err(ProgramError::InvalidArgument);
    }
    if cb.status != ClaimableBalanceStatus::Pending {
        return Err(RewardsError::EpochComplete.into());
    }

    // Check repFlow gate.
    let repflow_balance =
        read_checked_repflow_balance(relay_repflow_user, Some(&relay_wallet.key.to_bytes()))?;
    if repflow_balance < MIN_RELAY_REPFLOW {
        return Err(RewardsError::RepFlowGateNotMet.into());
    }

    let (_, authority_bump) = Pubkey::find_program_address(&[b"mint_authority"], program_id);

    // H-1: same pin as the inline release. This is where the deferred branch's
    // treasury share is finally paid, so it is the sink that must carry the
    // check for every probationary release.
    require_foundation_treasury(reward_treasury, flow_mint)?;

    // Mint $FLOW.
    cpi_mint_flow(token_program, flow_mint, reward_relay, service_authority, cb.pending_relay_flow, authority_bump)?;
    cpi_mint_flow(token_program, flow_mint, reward_treasury, service_authority, cb.pending_treasury, authority_bump)?;

    // Mint bandwidth repFlow.
    if cb.pending_repflow > 0 {
        cpi_mint_repflow_bandwidth(
            repflow_program, repflow_config, relay_repflow_user,
            service_authority, cb.pending_repflow, authority_bump,
        )?;
    }

    let total_minted = cb.pending_relay_flow + cb.pending_treasury;
    cb.status = ClaimableBalanceStatus::Claimed;
    save_account(cb_ai, &cb)?;

    msg!(
        "ClaimPendingRewards: relay={:?} minted {} $FLOW (pending) + {} repFlow",
        &relay_wallet.key.to_bytes()[..4], total_minted, cb.pending_repflow,
    );
    Ok(())
}

// ── 5: ReleaseTrialClaim ─────────────────────────────────────────────────────

/// ReleaseTrialClaim: direct mint for free trial users (no $FLOW to burn).
///
/// repFlow gate (2001) checked. Uses TrialUsage PDA for per-user cap enforcement.
/// TrialMintCap PDA enforces per-relay-per-epoch cap.
///
/// Accounts:
///   0:  relay_wallet          (signer, payer)
///   1:  claim_commitment      (writable)
///   2:  foundation_config     (PDA [b"foundation_config"])
///   3:  token_program
///   4:  flow_mint             (writable)
///   5:  service_authority     (mint_authority PDA)
///   6:  repflow_program
///   7:  repflow_config        (readonly) — PDA-only credit, no SPL mint
///   8:  relay_repflow_user    (writable)
///   9:  reward_account_relay  (writable)
///   10: reward_account_treasury (writable)
///   11: trial_mint_cap        (writable, PDA)
///   12: system_program
///   13+: per release × 2: [claim_state (writable), trial_usage_pda (writable)]
pub fn process_release_trial_claim_ix(
    program_id:  &Pubkey,
    accounts:    &[AccountInfo],
    claim_epoch: u64,
    releases:    Vec<ClientReleaseOnChain>,
) -> ProgramResult {
    let iter                = &mut accounts.iter();
    let relay_wallet        = next_account_info(iter)?;
    let commitment_ai       = next_account_info(iter)?;
    let foundation_config_ai = next_account_info(iter)?;
    let token_program       = next_account_info(iter)?;
    let flow_mint           = next_account_info(iter)?;
    let service_authority   = next_account_info(iter)?;
    let repflow_program     = next_account_info(iter)?;
    let repflow_config      = next_account_info(iter)?;
    let relay_repflow_user  = next_account_info(iter)?;
    let reward_relay        = next_account_info(iter)?;
    let reward_treasury     = next_account_info(iter)?;
    let trial_mint_cap_ai   = next_account_info(iter)?;
    let system_prog         = next_account_info(iter)?;

    if !relay_wallet.is_signer {
        return Err(ProgramError::MissingRequiredSignature);
    }

    // Load and validate commitment.
    let mut commitment: ClaimCommitment =
        ClaimCommitment::try_from_slice(&commitment_ai.data.borrow())
            .map_err(|_| RewardsError::ClaimCommitmentNotFound)?;

    // Bind the commitment to the SIGNER before touching it. Without this any
    // keypair could pass another relay's commitment and release its epoch —
    // see `require_own_commitment`.
    require_own_commitment(commitment_ai, relay_wallet, claim_epoch, program_id)?;
    if commitment.claim_epoch != claim_epoch {
        return Err(ProgramError::InvalidArgument);
    }
    // C-1 / M-3: Guard against calling on an already-Complete commitment.
    // (ReleaseClaim does this via Active→Releasing state machine; trial path must
    // guard explicitly since it bypasses that machine.)
    if commitment.status == ClaimCommitmentStatus::Complete {
        return Err(RewardsError::EpochComplete.into());
    }

    // M-3: this handler read `foundation_config` without ever checking it is
    // the canonical PDA — unlike ClaimRelayUptime and SetTrialEnabled. A relay
    // could hand over a forged account and flip the kill switch back on for
    // itself. Check it before trusting a single field.
    let (fc_pda, _) = Pubkey::find_program_address(&[b"foundation_config"], program_id);
    if foundation_config_ai.key != &fc_pda {
        msg!(
            "ReleaseTrialClaim: foundation_config {} is not the canonical PDA {}",
            foundation_config_ai.key, fc_pda,
        );
        return Err(ProgramError::InvalidArgument);
    }

    // Check foundation kill switch. Legacy-tolerant — see read_foundation_config_compat.
    let foundation_config = read_foundation_config_compat(&foundation_config_ai.data.borrow())?;
    if !foundation_config.trial_enabled {
        return Err(RewardsError::TrialDisabled.into());
    }

    // Divergence tripwire for the two sources of truth about the foundation
    // wallet. `require_foundation_treasury` pins the treasury against the
    // hardcoded FOUNDATION_PUBKEY (no wire change at the sinks that lack this
    // account), while `process_claim_relay_uptime_ix` derives it from
    // `foundation_config.wallet` so a rotation needs no upgrade. This handler
    // is the ONLY one holding both, so it is the only place the two can be
    // compared.
    //
    // Rotate the foundation wallet without updating the constant and, without
    // this, uptime would quietly pay the new treasury while every release paid
    // the old one. Here it fails loudly on the next trial release instead.
    // Now verified above to be the real config PDA, so this cannot be spoofed.
    if foundation_config.wallet != FOUNDATION_PUBKEY.to_bytes() {
        msg!(
            "ReleaseTrialClaim: foundation_config.wallet has diverged from \
             FOUNDATION_PUBKEY — the foundation wallet was rotated without \
             updating constants.rs. Refusing to pay a treasury that half the \
             program disagrees about."
        );
        return Err(RewardsError::InvalidTreasuryAccount.into());
    }

    // repFlow gate — DEFER below it, do not reject.
    //
    // This used to `return Err(RepFlowGateNotMet)` before any mutation, so a
    // relay under MIN_RELAY_REPFLOW could not release trial claims at all: not
    // deferred, refused, with the whole transaction reverted. The paid path has
    // had an escape hatch since the beginning (`process_release_claim_ix`
    // credits a `ClaimableBalance` instead of minting), and the trial path had
    // none.
    //
    // It was self-locking, which is what made it worth fixing rather than
    // documenting: the trial path's own bandwidth-repFlow mint below is the
    // relay's way of EARNING repFlow, and it sat downstream of the gate it
    // could not pass. A relay that started under 2001 could never climb out
    // through trial traffic.
    let repflow_balance =
        read_checked_repflow_balance(relay_repflow_user, Some(&relay_wallet.key.to_bytes()))?;
    let probationary = repflow_balance < MIN_RELAY_REPFLOW;

    let clock = Clock::get()?;
    let now = clock.unix_timestamp as u64;

    let (_, authority_bump) = Pubkey::find_program_address(&[b"mint_authority"], program_id);

    let mut total_released_amount: u64 = 0; // all releases — used for 70/30 mint
    let mut total_released_bytes:  u64 = 0;
    let mut trial_cap_amount:      u64 = 0; // trial clients only — used for TrialMintCap

    for release in &releases {
        let claim_state_ai = next_account_info(iter)?;
        let trial_usage_ai = next_account_info(iter)?;

        // Verify Merkle proof.
        let leaf_hash = compute_merkle_leaf_hash_from_release(release);
        if !verify_merkle_proof(leaf_hash, &release.merkle_proof, commitment.merkle_root) {
            return Err(RewardsError::MerkleProofInvalid.into());
        }

        // Signature non-null check (v1).
        if release.client_signature == [0u8; 64] {
            return Err(RewardsError::ClientSignatureInvalid.into());
        }

        // AlreadyReleased guard via UserRelayClaimState (same guard as paid ReleaseClaim).
        let (claim_state_pda, cs_bump) = Pubkey::find_program_address(
            &[b"claim_state", &release.client_pubkey, relay_wallet.key.as_ref()],
            program_id,
        );
        if claim_state_ai.key != &claim_state_pda {
            return Err(ProgramError::InvalidArgument);
        }
        let mut claim_state: UserRelayClaimState = if claim_state_ai.lamports() == 0 {
            create_pda_account(
                relay_wallet, claim_state_ai, system_prog, program_id,
                &[b"claim_state", &release.client_pubkey, relay_wallet.key.as_ref(), &[cs_bump]],
                USER_RELAY_CLAIM_STATE_SIZE,
            )?;
            UserRelayClaimState {
                user:                release.client_pubkey,
                relay:               relay_wallet.key.to_bytes(),
                last_claimed_seq:    0,
                total_claimed_bytes: 0,
                last_claim_slot:     0,
                last_release_epoch:  0,
                bump:                cs_bump,
            }
        } else {
            UserRelayClaimState::try_from_slice(&claim_state_ai.data.borrow())
                .map_err(|_| ProgramError::InvalidAccountData)?
        };
        if claim_state.last_release_epoch == claim_epoch {
            return Err(RewardsError::AlreadyReleased.into());
        }

        // Derive value from bytes and the pinned rate; the relay supplies none.
        let derived_amount = derive_reward_amount(release.total_bytes, commitment.routing_per_mb);

        // Cumulative cap. Capped by bandwidth_amount — the budget releases may
        // draw on — not the uptime allowance.
        let new_amount = commitment.released_amount
            .checked_add(derived_amount)
            .ok_or(RewardsError::ArithmeticOverflow)?;
        let new_bytes = commitment.released_bytes
            .checked_add(release.total_bytes)
            .ok_or(RewardsError::ArithmeticOverflow)?;
        if new_amount > commitment.bandwidth_amount {
            return Err(RewardsError::ReleaseExceedsCommitment.into());
        }
        if new_bytes > commitment.total_bytes {
            return Err(RewardsError::ReleaseExceedsCommitment.into());
        }

        // ── Trial client path: enforce TrialUsage PDA (10 GB cap, 30-day expiry) ──
        let (trial_usage_pda, tu_bump) = Pubkey::find_program_address(
            &[b"trial_usage", &release.client_pubkey],
            program_id,
        );
        if trial_usage_ai.key != &trial_usage_pda {
            return Err(ProgramError::InvalidArgument);
        }

        if trial_usage_ai.lamports() == 0 {
            create_pda_account(
                relay_wallet, trial_usage_ai, system_prog, program_id,
                &[b"trial_usage", &release.client_pubkey, &[tu_bump]],
                TRIAL_USAGE_SIZE,
            )?;
            let trial_usage = TrialUsage {
                user_pubkey:   release.client_pubkey,
                used_bytes:    release.total_bytes,
                claimed_bytes: 0,
                device_uuid:   release.device_uuid,
                first_seen_ts: now,
                last_usage_ts: now,
                expires_at:    now + FREE_TRIAL_DURATION_SECS,
                cap_bytes:     FREE_TRIAL_BYTES,
                bump:          tu_bump,
            };
            save_account(trial_usage_ai, &trial_usage)?;
        } else {
            let mut trial_usage: TrialUsage =
                TrialUsage::try_from_slice(&trial_usage_ai.data.borrow())
                    .map_err(|_| ProgramError::InvalidAccountData)?;

            if trial_usage.expires_at <= now {
                return Err(RewardsError::TrialExpired.into());
            }
            let new_claimed = trial_usage.claimed_bytes
                .checked_add(release.total_bytes)
                .ok_or(RewardsError::ArithmeticOverflow)?;
            if new_claimed > trial_usage.cap_bytes {
                return Err(RewardsError::TrialCapExceeded.into());
            }
            if trial_usage.device_uuid != release.device_uuid {
                return Err(ProgramError::InvalidArgument);
            }
            trial_usage.claimed_bytes = new_claimed;
            trial_usage.used_bytes    = trial_usage.used_bytes
                .saturating_add(release.total_bytes);
            trial_usage.last_usage_ts = now;
            save_account(trial_usage_ai, &trial_usage)?;
        }

        // Only trial clients count against TrialMintCap.
        trial_cap_amount = trial_cap_amount
            .checked_add(derived_amount)
            .ok_or(RewardsError::ArithmeticOverflow)?;

        // NOT `released_count`. That counter is the denominator half of
        // `epoch_is_fully_released`, which compares it against `reserved_count`
        // — and `reserved_count` is incremented only by `process_reserve_batch_ix`,
        // i.e. it counts PAID clients only. Counting trial releases here made
        // the two asymmetric: an epoch with 2 paid clients and 1 trial client
        // reached `released_count == reserved_count == 2` after the trial
        // release plus the FIRST paid release, latching `Complete` one release
        // early and stranding the second paid client's FundHold permanently.
        //
        // `released_amount` and `released_bytes` below stay shared on purpose:
        // both kinds of release genuinely draw on `bandwidth_amount`, and the
        // ReleaseExceedsCommitment cap must see the total.
        //
        commitment.released_amount  = new_amount;
        commitment.released_bytes   = new_bytes;

        claim_state.last_release_epoch = claim_epoch;
        save_account(claim_state_ai, &claim_state)?;

        total_released_amount = total_released_amount
            .checked_add(derived_amount)
            .ok_or(RewardsError::ArithmeticOverflow)?;
        total_released_bytes = total_released_bytes
            .checked_add(release.total_bytes)
            .ok_or(RewardsError::ArithmeticOverflow)?;
    }

    // TrialMintCap check.
    // Per-relay-per-epoch cap: PDA keyed by (relay, epoch) so the cap resets each
    // epoch. Seed MUST match the off-chain clients
    // (find_trial_mint_cap_pda → [b"trial_mint_cap", relay, epoch_le]).
    let (tmc_pda, tmc_bump) = Pubkey::find_program_address(
        &[b"trial_mint_cap", relay_wallet.key.as_ref(), &claim_epoch.to_le_bytes()],
        program_id,
    );
    if trial_mint_cap_ai.key != &tmc_pda {
        return Err(ProgramError::InvalidArgument);
    }

    let mut tmc: TrialMintCap = if trial_mint_cap_ai.lamports() == 0 {
        create_pda_account(
            relay_wallet, trial_mint_cap_ai, system_prog, program_id,
            &[b"trial_mint_cap", relay_wallet.key.as_ref(), &claim_epoch.to_le_bytes(), &[tmc_bump]],
            TRIAL_MINT_CAP_SIZE,
        )?;
        TrialMintCap {
            relay: relay_wallet.key.to_bytes(),
            epoch: claim_epoch, // this PDA's epoch (part of the seed)
            minted_so_far: 0,
            bump: tmc_bump,
        }
    } else {
        TrialMintCap::try_from_slice(&trial_mint_cap_ai.data.borrow())
            .map_err(|_| ProgramError::InvalidAccountData)?
    };

    // Cap applies to all free-trial client amounts released this epoch.
    let new_minted = tmc.minted_so_far
        .checked_add(trial_cap_amount)
        .ok_or(RewardsError::ArithmeticOverflow)?;
    if new_minted > MAX_TRIAL_MINT_PER_RELAY_PER_EPOCH {
        return Err(RewardsError::TrialMintCapExceeded.into());
    }
    tmc.minted_so_far = new_minted;
    save_account(trial_mint_cap_ai, &tmc)?;

    // Mint $FLOW 70/30 directly (no burn).
    // M-1: derive treasury as remainder to avoid truncation loss.
    let relay_amount    = total_released_amount * RELAY_SPLIT_PCT / 100;
    let treasury_amount = total_released_amount - relay_amount;
    // Use this transaction's bytes only, not the commitment cumulative — that
    // would double-count on every subsequent ReleaseTrialClaim in the epoch.
    let repflow_amount  = total_released_bytes / BYTES_PER_FLOW;

    // Note the TrialMintCap above was advanced BEFORE this branch, so a
    // deferred release still consumes the epoch's trial quota. That is
    // deliberate: the quota is per relay per epoch and the reward is owed
    // either way, so charging it at defer time keeps ClaimPendingRewards — which
    // has no trial-cap check — from paying out beyond the cap later.
    if probationary {
        // Below the gate: credit a ClaimableBalance instead of minting, exactly
        // as process_release_claim_ix does. Same PDA, so a relay that earns
        // both paid and trial rewards in one epoch accumulates them in one
        // account and drains them with a single ClaimPendingRewards.
        //
        // Consumed AFTER the per-release loop, so it is the last account in the
        // instruction — matching ReleaseClaim's layout and keeping the
        // per-release stride untouched.
        let cb_ai = next_account_info(iter)?;
        let (cb_pda, cb_bump) = Pubkey::find_program_address(
            &[b"claimable_balance", relay_wallet.key.as_ref(), &claim_epoch.to_le_bytes()],
            program_id,
        );
        if cb_ai.key != &cb_pda {
            return Err(ProgramError::InvalidArgument);
        }

        let mut cb: ClaimableBalance = if cb_ai.lamports() == 0 {
            create_pda_account(
                relay_wallet, cb_ai, system_prog, program_id,
                &[b"claimable_balance", relay_wallet.key.as_ref(), &claim_epoch.to_le_bytes(), &[cb_bump]],
                CLAIMABLE_BALANCE_SIZE,
            )?;
            ClaimableBalance {
                relay:              relay_wallet.key.to_bytes(),
                claim_epoch,
                pending_relay_flow: 0,
                pending_treasury:   0,
                pending_repflow:    0,
                status:             ClaimableBalanceStatus::Pending,
                bump:               cb_bump,
            }
        } else {
            ClaimableBalance::try_from_slice(&cb_ai.data.borrow())
                .map_err(|_| ProgramError::InvalidAccountData)?
        };

        cb.pending_relay_flow = cb.pending_relay_flow
            .checked_add(relay_amount).ok_or(RewardsError::ArithmeticOverflow)?;
        cb.pending_treasury   = cb.pending_treasury
            .checked_add(treasury_amount).ok_or(RewardsError::ArithmeticOverflow)?;
        cb.pending_repflow    = cb.pending_repflow
            .checked_add(repflow_amount).ok_or(RewardsError::ArithmeticOverflow)?;

        save_account(commitment_ai, &commitment)?;
        save_account(cb_ai, &cb)?;
        msg!(
            "ReleaseTrialClaim: relay probationary (<{} repFlow). {} $FLOW deferred",
            MIN_RELAY_REPFLOW, total_released_amount,
        );
        return Ok(());
    }

    // H-1: pin the treasury sink. Only on the minting branch — the deferred
    // branch pays nothing here, and ClaimPendingRewards carries the same check
    // for when it finally does.
    require_foundation_treasury(reward_treasury, flow_mint)?;

    cpi_mint_flow(token_program, flow_mint, reward_relay, service_authority, relay_amount, authority_bump)?;
    cpi_mint_flow(token_program, flow_mint, reward_treasury, service_authority, treasury_amount, authority_bump)?;

    if repflow_amount > 0 {
        cpi_mint_repflow_bandwidth(
            repflow_program, repflow_config, relay_repflow_user,
            service_authority, repflow_amount, authority_bump,
        )?;
    }

    save_account(commitment_ai, &commitment)?;

    msg!(
        "ReleaseTrialClaim: epoch={} minted {} $FLOW (70/30) trial",
        claim_epoch, total_released_amount,
    );
    Ok(())
}

// ── 6: SetTrialEnabled ───────────────────────────────────────────────────────

/// SetTrialEnabled: foundation-only global kill switch for ReleaseTrialClaim.
///
/// Accounts:
///   0: foundation_wallet  (signer)
///   1: foundation_config  (writable, PDA [b"foundation_config"])
///   2: system_program
pub fn process_set_trial_enabled_ix(
    program_id: &Pubkey,
    accounts:   &[AccountInfo],
    enabled:    bool,
) -> ProgramResult {
    let iter                 = &mut accounts.iter();
    let foundation_wallet    = next_account_info(iter)?;
    let foundation_config_ai = next_account_info(iter)?;
    let system_prog          = next_account_info(iter)?;

    if !foundation_wallet.is_signer {
        return Err(ProgramError::MissingRequiredSignature);
    }

    let (fc_pda, fc_bump) = Pubkey::find_program_address(&[b"foundation_config"], program_id);
    if foundation_config_ai.key != &fc_pda {
        return Err(ProgramError::InvalidArgument);
    }

    let fc: FoundationConfig = if foundation_config_ai.lamports() == 0 {
        // First call — initialise config (foundation wallet becomes the authority).
        create_pda_account(
            foundation_wallet, foundation_config_ai, system_prog, program_id,
            &[b"foundation_config", &[fc_bump]],
            FOUNDATION_CONFIG_SIZE,
        )?;
        FoundationConfig {
            foundation_wallet: foundation_wallet.key.to_bytes(),
            trial_enabled: enabled,
            uptime_enabled: true, // default enabled, matches CommitClaim's pre-creation default
            bump: fc_bump,
        }
    } else {
        // Legacy-tolerant read — see read_foundation_config_compat. NOTE: the
        // write below is intentionally left strict: if this account is still
        // the pre-upgrade 34-byte layout, `save_account` will fail with
        // AccountDataTooSmall rather than silently reallocing. Unlike
        // SetUptimeEnabled (whose accounts already document foundation_wallet
        // as writable to fund a rent top-up), SetTrialEnabled's account list
        // only requires foundation_wallet to be a signer — quietly debiting it
        // here would add an undocumented writability requirement that existing
        // off-chain callers may not satisfy. Operators should call
        // SetUptimeEnabled once (it self-migrates the account in place) before
        // relying on SetTrialEnabled against an unmigrated account.
        let view = read_foundation_config_compat(&foundation_config_ai.data.borrow())?;
        // Only the registered foundation wallet can toggle.
        if view.wallet != foundation_wallet.key.to_bytes() {
            return Err(ProgramError::IllegalOwner);
        }
        FoundationConfig {
            foundation_wallet: view.wallet,
            trial_enabled: enabled,
            uptime_enabled: view.uptime_enabled,
            bump: view.bump,
        }
    };

    save_account(foundation_config_ai, &fc)?;
    msg!("SetTrialEnabled: trial_enabled = {}", enabled);
    Ok(())
}

// ── 7: SlashTrialFraud ───────────────────────────────────────────────────────

/// SlashTrialFraud: foundation slashes relay for fabricated trial claims.
///
/// Foundation audits DHT off-chain and calls this if device_uuid is fake.
/// Tiered slashing: same 500/1000/100% model as ClientDispute.
///
/// Accounts:
///   0: foundation_wallet    (signer)
///   1: foundation_config    (PDA [b"foundation_config"])
///   2: relay_reputation     (writable, PDA)
///   3: relay_repflow_user   (writable)
///   4: slash_authority_pda
///   5: repflow_program
///   6: repflow_config       (readonly) — PDA-only slash, no SPL burn
///   7: system_program
pub fn process_slash_trial_fraud_ix(
    program_id:       &Pubkey,
    accounts:         &[AccountInfo],
    claim_epoch:      u64,
    device_uuid:      [u8; 16],
    _device_signature: [u8; 64],
) -> ProgramResult {
    let iter                 = &mut accounts.iter();
    let foundation_wallet    = next_account_info(iter)?;
    let foundation_config_ai = next_account_info(iter)?;
    let reputation_ai        = next_account_info(iter)?;
    let relay_repflow_user   = next_account_info(iter)?;
    let slash_authority      = next_account_info(iter)?;
    let repflow_program      = next_account_info(iter)?;
    let repflow_config       = next_account_info(iter)?;
    let system_prog          = next_account_info(iter)?;

    if !foundation_wallet.is_signer {
        return Err(ProgramError::MissingRequiredSignature);
    }

    // Verify foundation authority. Legacy-tolerant — see read_foundation_config_compat.
    let fc = read_foundation_config_compat(&foundation_config_ai.data.borrow())?;
    if fc.wallet != foundation_wallet.key.to_bytes() {
        return Err(ProgramError::IllegalOwner);
    }

    // Load or create relay reputation.
    // Created here if the relay has never had a ClientDispute — trial fraud
    // may be the first offense so we cannot require the PDA to pre-exist.
    // Seed: relay_repflow_user.key identifies the relay wallet being slashed.
    let relay_key = relay_repflow_user.key.to_bytes();
    let (rep_pda, rep_bump) = Pubkey::find_program_address(
        &[b"relay_reputation", &relay_key],
        program_id,
    );
    if reputation_ai.key != &rep_pda {
        return Err(ProgramError::InvalidArgument);
    }

    let mut rep: RelayReputation = if reputation_ai.lamports() == 0 {
        // First offense — create the reputation PDA funded by the foundation.
        create_pda_account(
            foundation_wallet, reputation_ai, system_prog, program_id,
            &[b"relay_reputation", &relay_key, &[rep_bump]],
            RELAY_REPUTATION_SIZE,
        )?;
        RelayReputation {
            relay:            relay_key,
            slash_count:      0,
            lifetime_slashed: 0,
            bump:             rep_bump,
        }
    } else {
        RelayReputation::try_from_slice(&reputation_ai.data.borrow())
            .map_err(|_| ProgramError::InvalidAccountData)?
    };

    rep.slash_count += 1;
    // F-1: reject a fabricated target. The foundation names the relay, so bind to
    // the account's own stored wallet — still requires a genuine repflow_user PDA.
    let relay_repflow_balance = read_checked_repflow_balance(relay_repflow_user, None)?;
    let slash_amount = match rep.slash_count {
        1 => SLASH_FIRST_OFFENSE,
        2 => SLASH_SECOND_OFFENSE,
        _ => relay_repflow_balance,
    };
    let slash_amount = slash_amount.min(relay_repflow_balance);

    let (_, slash_bump) = Pubkey::find_program_address(&[b"slash_authority"], program_id);

    cpi_slash_repflow(
        repflow_program,
        repflow_config,
        relay_repflow_user,
        slash_authority,
        slash_amount,
        slash_bump,
    ).map_err(|_| RewardsError::SlashFailed)?;

    rep.lifetime_slashed = rep.lifetime_slashed
        .checked_add(slash_amount).ok_or(RewardsError::ArithmeticOverflow)?;
    save_account(reputation_ai, &rep)?;

    msg!(
        "SlashTrialFraud: relay={:?} offense #{} device_uuid={:?} epoch={}",
        &rep.relay[..4], rep.slash_count, &device_uuid[..4], claim_epoch,
    );
    Ok(())
}

// ── Reward-rate authority ──────────────────────────────────────────────────────

/// Read FoundationConfig and require `signer` to be the registered foundation wallet.
/// `foundation_config_ai` is the [b"foundation_config"] PDA (readonly).
fn require_foundation_signer(
    program_id:           &Pubkey,
    signer:               &AccountInfo,
    foundation_config_ai: &AccountInfo,
) -> ProgramResult {
    if !signer.is_signer {
        return Err(ProgramError::MissingRequiredSignature);
    }
    let (fc_pda, _) = Pubkey::find_program_address(&[b"foundation_config"], program_id);
    if foundation_config_ai.key != &fc_pda || foundation_config_ai.lamports() == 0 {
        return Err(ProgramError::InvalidArgument);
    }
    // Legacy-tolerant — see read_foundation_config_compat.
    let fc = read_foundation_config_compat(&foundation_config_ai.data.borrow())?;
    if fc.wallet != signer.key.to_bytes() {
        return Err(ProgramError::IllegalOwner);
    }
    Ok(())
}

// ── 8: InitializeRewardRates ───────────────────────────────────────────────────

/// InitializeRewardRates: foundation creates the reward_rates PDA once.
///
/// Accounts:
///   0: foundation_wallet  (signer, payer)
///   1: reward_rates       (writable, PDA [b"reward_rates"])
///   2: system_program
///   3: foundation_config  (readonly, PDA [b"foundation_config"])
pub fn process_initialize_reward_rates(
    program_id:       &Pubkey,
    accounts:         &[AccountInfo],
    routing_per_mb:   u64,
    seeding_per_mb:   u64,
    uptime_per_hour:  u64,
    flow_price_cents: u64,
) -> ProgramResult {
    let iter                 = &mut accounts.iter();
    let foundation_wallet    = next_account_info(iter)?;
    let reward_rates_ai      = next_account_info(iter)?;
    let system_prog          = next_account_info(iter)?;
    let foundation_config_ai = next_account_info(iter)?;

    require_foundation_signer(program_id, foundation_wallet, foundation_config_ai)?;

    let (pda, bump) = Pubkey::find_program_address(&[b"reward_rates"], program_id);
    if reward_rates_ai.key != &pda {
        return Err(ProgramError::InvalidArgument);
    }
    if reward_rates_ai.lamports() > 0 {
        return Err(RewardsError::RewardRatesAlreadyInitialized.into());
    }

    create_pda_account(
        foundation_wallet, reward_rates_ai, system_prog, program_id,
        &[b"reward_rates", &[bump]],
        REWARD_RATES_SIZE,
    )?;

    let clock = Clock::get()?;
    let rates = RewardRatesAccount {
        authority:        foundation_wallet.key.to_bytes(),
        routing_per_mb:   if routing_per_mb  > 0 { routing_per_mb  } else { DEFAULT_ROUTING_PER_MB  },
        seeding_per_mb:   if seeding_per_mb  > 0 { seeding_per_mb  } else { DEFAULT_SEEDING_PER_MB  },
        uptime_per_hour:  if uptime_per_hour > 0 { uptime_per_hour } else { DEFAULT_UPTIME_PER_HOUR },
        flow_price_cents,
        last_updated:     clock.unix_timestamp,
        change_count:     0,
        bump,
    };
    save_account(reward_rates_ai, &rates)?;
    msg!(
        "InitializeRewardRates: routing_per_mb={} uptime_per_hour={} flow_price_cents={}",
        rates.routing_per_mb, rates.uptime_per_hour, rates.flow_price_cents,
    );
    Ok(())
}

// ── 9: UpdateRewardRates ───────────────────────────────────────────────────────

/// UpdateRewardRates: foundation updates the reward_rates PDA.
///
/// Accounts:
///   0: foundation_wallet  (signer)
///   1: reward_rates       (writable, PDA [b"reward_rates"])
///   2: foundation_config  (readonly, PDA [b"foundation_config"])
pub fn process_update_reward_rates(
    program_id:       &Pubkey,
    accounts:         &[AccountInfo],
    routing_per_mb:   u64,
    seeding_per_mb:   u64,
    uptime_per_hour:  u64,
    flow_price_cents: u64,
) -> ProgramResult {
    let iter                 = &mut accounts.iter();
    let foundation_wallet    = next_account_info(iter)?;
    let reward_rates_ai      = next_account_info(iter)?;
    let foundation_config_ai = next_account_info(iter)?;

    require_foundation_signer(program_id, foundation_wallet, foundation_config_ai)?;

    let (pda, _) = Pubkey::find_program_address(&[b"reward_rates"], program_id);
    if reward_rates_ai.key != &pda {
        return Err(ProgramError::InvalidArgument);
    }
    if reward_rates_ai.lamports() == 0 {
        return Err(RewardsError::RewardRatesNotInitialized.into());
    }

    let mut rates = RewardRatesAccount::try_from_slice(&reward_rates_ai.data.borrow())
        .map_err(|_| ProgramError::InvalidAccountData)?;
    let clock = Clock::get()?;
    rates.routing_per_mb   = if routing_per_mb  > 0 { routing_per_mb  } else { rates.routing_per_mb };
    rates.seeding_per_mb   = if seeding_per_mb  > 0 { seeding_per_mb  } else { rates.seeding_per_mb };
    rates.uptime_per_hour  = if uptime_per_hour > 0 { uptime_per_hour } else { rates.uptime_per_hour };
    rates.flow_price_cents = flow_price_cents; // 0 is a valid "unset" price
    rates.last_updated     = clock.unix_timestamp;
    rates.change_count     = rates.change_count.saturating_add(1);
    save_account(reward_rates_ai, &rates)?;
    msg!(
        "UpdateRewardRates: routing_per_mb={} uptime_per_hour={} change_count={}",
        rates.routing_per_mb, rates.uptime_per_hour, rates.change_count,
    );
    Ok(())
}

// ── 10: ClaimRelayUptime ─────────────────────────────────────────────────────

/// 70/30 split matching `process_release_claim_ix`: relay gets the floor,
/// treasury gets the remainder. M-1: deriving treasury as the remainder
/// (rather than `amount * FOUNDATION_SPLIT_PCT / 100`) avoids truncation
/// loss — the two parts always sum back to `amount`.
fn split_relay_treasury(amount: u64) -> (u64, u64) {
    let relay_amount    = amount * RELAY_SPLIT_PCT / 100;
    let treasury_amount = amount - relay_amount;
    (relay_amount, treasury_amount)
}

/// 10: ClaimRelayUptime — mint the relay's own uptime reward for an epoch.
///
/// Replaces the synthetic self-client usage record, which had no UserEscrow,
/// failed ReserveBatch, and was paid only by riding the free-trial release
/// path. Uptime has no counterparty and therefore no dispute window.
///
/// `commitment.uptime_amount` was derived and clamped at CommitClaim time
/// (Task 7) from `uptime_hours * uptime_per_hour` pinned at commit — this
/// handler pays that pinned value verbatim. It never recomputes from the live
/// `reward_rates` PDA and never draws on `commitment.bandwidth_amount`, which
/// is a separate budget reserved for ReleaseClaim.
///
/// Accounts:
///   0: relay_wallet       (signer)
///   1: commitment         (writable, PDA [b"claim_commitment", relay, epoch_le])
///   2: foundation_config  (readonly, PDA [b"foundation_config"]) — uptime kill switch
///   3: relay_repflow_user (readonly) — repFlow gate (2001)
///   4: token_program
///   5: flow_mint          (writable)
///   6: service_authority  (mint_authority PDA)
///   7: reward_relay       (writable) — unconstrained; relay's own 70%
///   8: reward_treasury    (writable) — MUST be
///      `ATA(foundation_config.foundation_wallet, flow_mint)` under the classic
///      SPL Token program, else `InvalidTreasuryAccount`.
pub fn process_claim_relay_uptime_ix(
    program_id:  &Pubkey,
    accounts:    &[AccountInfo],
    claim_epoch: u64,
) -> ProgramResult {
    let iter                 = &mut accounts.iter();
    let relay_wallet         = next_account_info(iter)?;
    let commitment_ai        = next_account_info(iter)?;
    let foundation_config_ai = next_account_info(iter)?;
    let relay_repflow_user   = next_account_info(iter)?;
    let token_program        = next_account_info(iter)?;
    let flow_mint            = next_account_info(iter)?;
    let service_authority    = next_account_info(iter)?;
    let reward_relay         = next_account_info(iter)?;
    let reward_treasury      = next_account_info(iter)?;

    if !relay_wallet.is_signer {
        return Err(ProgramError::MissingRequiredSignature);
    }

    let (c_pda, _) = Pubkey::find_program_address(
        &[b"claim_commitment", relay_wallet.key.as_ref(), &claim_epoch.to_le_bytes()],
        program_id,
    );
    if commitment_ai.key != &c_pda {
        return Err(ProgramError::InvalidArgument);
    }
    let mut commitment: ClaimCommitment =
        ClaimCommitment::try_from_slice(&commitment_ai.data.borrow())
            .map_err(|_| RewardsError::ClaimCommitmentNotFound)?;

    if commitment.relay_pubkey != relay_wallet.key.to_bytes() {
        return Err(ProgramError::InvalidArgument);
    }
    if commitment.uptime_paid {
        return Err(RewardsError::UptimeAlreadyPaid.into());
    }

    // Re-checked here even though CommitClaim already checked it (clamps
    // uptime_hours to 0 when disabled): an emergency stop must halt epochs
    // that were already committed, rather than waiting out the rate-pinning
    // semantics that let a committed uptime_amount survive to this point.
    let (fc_pda, _) = Pubkey::find_program_address(&[b"foundation_config"], program_id);
    if foundation_config_ai.key != &fc_pda {
        return Err(ProgramError::InvalidArgument);
    }
    // `None` when the config PDA does not exist yet. Read once — the treasury
    // constraint below needs `wallet` from the same view.
    let foundation_config = if foundation_config_ai.lamports() == 0 {
        None
    } else {
        // Legacy-tolerant — see read_foundation_config_compat. A strict
        // FoundationConfig::try_from_slice fails on the live 34-byte PDA.
        Some(read_foundation_config_compat(&foundation_config_ai.data.borrow())?)
    };
    // config not yet created — default enabled, matches CommitClaim
    let uptime_enabled = foundation_config.as_ref().map_or(true, |fc| fc.uptime_enabled);
    if !uptime_enabled {
        return Err(RewardsError::UptimeRewardsDisabled.into());
    }

    let amount = commitment.uptime_amount;
    if amount == 0 {
        // Nothing to pay — still latch uptime_paid so a zero-uptime epoch
        // cannot be retried forever.
        commitment.uptime_paid = true;
        save_account(commitment_ai, &commitment)?;
        msg!("ClaimRelayUptime: nothing to pay for epoch {}", claim_epoch);
        return Ok(());
    }

    let repflow_balance =
        read_checked_repflow_balance(relay_repflow_user, Some(&relay_wallet.key.to_bytes()))?;
    if repflow_balance < MIN_RELAY_REPFLOW {
        return Err(RewardsError::RepFlowGateNotMet.into());
    }

    // Pin the 30% share to the foundation's own token account.
    //
    // `cpi_mint_flow` validates nothing about its destination, so without this
    // a relay could pass a second account it controls as `reward_treasury` and
    // keep 100% of its uptime reward instead of 70%.
    //
    // Derived from `foundation_config.foundation_wallet` rather than hardcoded
    // so the constraint survives a treasury or foundation-wallet rotation with
    // no program upgrade. $FLOW is a classic SPL mint — see SPL_TOKEN_PROGRAM_ID.
    //
    // Fail closed when the config PDA is absent: there is no wallet to derive
    // from, and paying an unconstrained treasury is exactly the hole this
    // closes. The live PDA exists, so no real claim is affected.
    let foundation_wallet = foundation_config
        .as_ref()
        .map(|fc| fc.wallet)
        .ok_or(RewardsError::InvalidTreasuryAccount)?;
    let (expected_treasury, _) = Pubkey::find_program_address(
        &[
            foundation_wallet.as_ref(),
            SPL_TOKEN_PROGRAM_ID.as_ref(),
            flow_mint.key.as_ref(),
        ],
        &ASSOCIATED_TOKEN_PROGRAM_ID,
    );
    if reward_treasury.key != &expected_treasury {
        msg!(
            "ClaimRelayUptime: reward_treasury {} is not the foundation ATA {}",
            reward_treasury.key, expected_treasury,
        );
        return Err(RewardsError::InvalidTreasuryAccount.into());
    }
    // NOTE: `reward_relay` is deliberately NOT constrained. The relay is the
    // legitimate beneficiary of its own 70%, so directing that to any account
    // it controls harms nobody, and requiring an ATA there would break relays
    // paid into a non-ATA token account.

    let (_, authority_bump) = Pubkey::find_program_address(&[b"mint_authority"], program_id);
    let (relay_amount, treasury_amount) = split_relay_treasury(amount);
    cpi_mint_flow(token_program, flow_mint, reward_relay, service_authority, relay_amount, authority_bump)?;
    cpi_mint_flow(token_program, flow_mint, reward_treasury, service_authority, treasury_amount, authority_bump)?;

    commitment.uptime_paid = true;
    save_account(commitment_ai, &commitment)?;

    msg!(
        "ClaimRelayUptime: epoch={} hours={} amount={} relay={} treasury={}",
        claim_epoch, commitment.uptime_hours, amount, relay_amount, treasury_amount,
    );
    Ok(())
}

#[cfg(test)]
mod claim_relay_uptime_tests {
    use super::split_relay_treasury;

    /// 70/30 split: relay gets the floor of 70%, treasury gets the exact
    /// remainder so the parts always sum back to the original amount — no
    /// truncation loss (M-1), matching `process_release_claim_ix`.
    #[test]
    fn split_relay_treasury_sums_to_amount_no_truncation_loss() {
        // Not evenly divisible by 100 — the case truncation would lose units on.
        let amount = 1_000_000_007u64;
        let (relay, treasury) = split_relay_treasury(amount);
        assert_eq!(relay + treasury, amount, "split must never lose base units");
        assert_eq!(relay, amount * 70 / 100, "relay gets the floor of 70%");
        assert_eq!(treasury, amount - relay, "treasury is the exact remainder");
    }

    #[test]
    fn split_relay_treasury_zero_amount() {
        assert_eq!(split_relay_treasury(0), (0, 0));
    }

    #[test]
    fn split_relay_treasury_evenly_divisible() {
        // 10 $FLOW at 9 decimals: evenly divisible by 100, so no remainder
        // rounding is exercised — sanity check the 70/30 ratio itself.
        let amount = 10_000_000_000u64;
        let (relay, treasury) = split_relay_treasury(amount);
        assert_eq!(relay, 7_000_000_000);
        assert_eq!(treasury, 3_000_000_000);
        assert_eq!(relay + treasury, amount);
    }

    #[test]
    fn split_relay_treasury_one_base_unit_all_goes_to_treasury() {
        // 1 * 70 / 100 == 0 (integer division) — the smallest possible
        // nonzero amount rounds the relay's share down to zero, and the
        // remainder formula must still hand that unit to treasury rather
        // than dropping it.
        let (relay, treasury) = split_relay_treasury(1);
        assert_eq!(relay, 0);
        assert_eq!(treasury, 1);
    }
}

/// Full-runtime tests for `process_claim_relay_uptime_ix`.
///
/// Only paths that resolve before the mint CPI are covered here — matching
/// the rest of the suite's convention (see test_trial.rs's module doc):
/// reaching `cpi_mint_flow` would require the SPL-Token program loaded.
/// The zero-amount path is a genuine full success path (`Ok(())`) since it
/// returns before ever calling `cpi_mint_flow`.
#[cfg(test)]
mod claim_relay_uptime_integration_tests {
    use super::*;
    use solana_program::{program_option::COption, program_pack::Pack};
    use solana_program_test::*;
    use solana_sdk::{
        account::Account,
        instruction::{AccountMeta, Instruction},
        signature::{Keypair, Signer},
        transaction::Transaction,
    };

    use crate::{id, process_instruction, RewardsInstruction};

    fn program_test() -> ProgramTest {
        ProgramTest::new("freeflow_rewards_v2", id(), processor!(process_instruction))
    }

    fn encode_ix(ix: &RewardsInstruction) -> Vec<u8> {
        borsh::to_vec(ix).expect("borsh encode")
    }

    fn commitment_pda(relay: &Pubkey, epoch: u64) -> (Pubkey, u8) {
        Pubkey::find_program_address(
            &[b"claim_commitment", relay.as_ref(), &epoch.to_le_bytes()],
            &id(),
        )
    }

    fn foundation_config_pda() -> (Pubkey, u8) {
        Pubkey::find_program_address(&[b"foundation_config"], &id())
    }

    /// Pre-populated `ClaimCommitment` account with controllable `uptime_amount`
    /// and `uptime_paid`, matching what CommitClaim (Task 7) would have written.
    fn commitment_account(
        relay:         &Pubkey,
        epoch:         u64,
        uptime_amount: u64,
        uptime_paid:   bool,
        bump:          u8,
    ) -> Account {
        let c = ClaimCommitment {
            relay_pubkey:    relay.to_bytes(),
            claim_epoch:     epoch,
            merkle_root:     [0u8; 32],
            client_count:    0,
            bandwidth_amount: 0,
            uptime_amount,
            total_bytes:     0,
            uptime_hours:    3,
            routing_per_mb:  DEFAULT_ROUTING_PER_MB,
            uptime_per_hour: DEFAULT_UPTIME_PER_HOUR,
            committed_at:    0,
            uptime_paid,
            reserved_count:  0,
            released_count:  0,
            released_amount: 0,
            released_bytes:  0,
            status:          ClaimCommitmentStatus::Active,
            dispute_deadline: 0,
            bump,
        };
        let data = borsh::to_vec(&c).expect("borsh commitment");
        let mut padded = vec![0u8; CLAIM_COMMITMENT_SIZE];
        padded[..data.len()].copy_from_slice(&data);
        Account { lamports: 1_000_000, data: padded, owner: id(), executable: false, rent_epoch: 0 }
    }

    fn foundation_config_account(wallet: &Pubkey, uptime_enabled: bool, bump: u8) -> Account {
        let fc = FoundationConfig {
            foundation_wallet: wallet.to_bytes(),
            trial_enabled: true,
            uptime_enabled,
            bump,
        };
        let data = borsh::to_vec(&fc).expect("borsh fc");
        let mut padded = vec![0u8; FOUNDATION_CONFIG_SIZE];
        padded[..data.len()].copy_from_slice(&data);
        Account { lamports: 1_000_000, data: padded, owner: id(), executable: false, rent_epoch: 0 }
    }

    /// repFlow user account layout matching `read_repflow_balance`: 8-byte
    /// Anchor discriminator + 32-byte wallet + 8-byte balance LE.
    fn repflow_user_account(balance: u64) -> Account {
        let mut data = vec![0u8; 48];
        data[40..48].copy_from_slice(&balance.to_le_bytes());
        // F-1: owned by the real repflow-token program so read_checked_repflow_balance
        // accepts it (paired with a genuine [b"repflow_user", relay] PDA at the call site).
        Account { lamports: 1_000_000, data, owner: REPFLOW_PROGRAM_ID, executable: false, rent_epoch: 0 }
    }

    /// Build a `ClaimRelayUptime` instruction in the exact account order Task
    /// 13's off-chain caller must use: relay_wallet, commitment,
    /// foundation_config, relay_repflow_user, token_program, flow_mint,
    /// service_authority, reward_relay, reward_treasury. Accounts past index
    /// 3 are stubs, sufficient for tests that resolve before the mint CPI.
    fn claim_relay_uptime_ix(
        relay:             &Keypair,
        commitment_pk:     Pubkey,
        foundation_cfg_pk: Pubkey,
        repflow_user_pk:   Pubkey,
        claim_epoch:       u64,
    ) -> Instruction {
        let stub = Keypair::new().pubkey();
        claim_relay_uptime_ix_full(
            relay, commitment_pk, foundation_cfg_pk, repflow_user_pk,
            stub /* token_program */, stub /* flow_mint */,
            stub /* service_authority */, stub /* reward_relay */,
            stub /* reward_treasury */, claim_epoch,
        )
    }

    /// Same instruction with every account under test control, so the mint-path
    /// tests can supply a real SPL mint, a real token program, and a chosen
    /// `reward_treasury`.
    #[allow(clippy::too_many_arguments)]
    fn claim_relay_uptime_ix_full(
        relay:             &Keypair,
        commitment_pk:     Pubkey,
        foundation_cfg_pk: Pubkey,
        repflow_user_pk:   Pubkey,
        token_program_pk:  Pubkey,
        flow_mint_pk:      Pubkey,
        service_auth_pk:   Pubkey,
        reward_relay_pk:   Pubkey,
        reward_treasury_pk: Pubkey,
        claim_epoch:       u64,
    ) -> Instruction {
        Instruction {
            program_id: id(),
            accounts: vec![
                AccountMeta::new(relay.pubkey(), true),             // [0] relay_wallet
                AccountMeta::new(commitment_pk, false),              // [1] commitment
                AccountMeta::new_readonly(foundation_cfg_pk, false), // [2] foundation_config
                AccountMeta::new_readonly(repflow_user_pk, false),   // [3] relay_repflow_user
                AccountMeta::new_readonly(token_program_pk, false),  // [4] token_program
                AccountMeta::new(flow_mint_pk, false),               // [5] flow_mint
                AccountMeta::new_readonly(service_auth_pk, false),   // [6] service_authority
                AccountMeta::new(reward_relay_pk, false),            // [7] reward_relay
                AccountMeta::new(reward_treasury_pk, false),         // [8] reward_treasury
            ],
            data: encode_ix(&RewardsInstruction::ClaimRelayUptime { claim_epoch }),
        }
    }

    /// The address the handler derives for `reward_treasury`. Written out here
    /// rather than reusing the handler's own constants so the test would catch
    /// a wrong program id baked into `constants.rs`.
    fn foundation_ata(foundation_wallet: &Pubkey, mint: &Pubkey) -> Pubkey {
        let ata_program = Pubkey::new_from_array([
            140, 151, 37, 143, 78, 36, 137, 241, 187, 61, 16, 41, 20, 142, 13, 131,
            11, 90, 19, 153, 218, 255, 16, 132, 4, 142, 123, 216, 219, 233, 248, 89,
        ]);
        Pubkey::find_program_address(
            &[foundation_wallet.as_ref(), spl_token::id().as_ref(), mint.as_ref()],
            &ata_program,
        ).0
    }

    /// A real, initialized SPL mint whose mint authority is the program's
    /// `mint_authority` PDA — what `cpi_mint_flow` signs as.
    fn flow_mint_account(mint_authority: &Pubkey) -> Account {
        let mut data = vec![0u8; spl_token::state::Mint::LEN];
        spl_token::state::Mint {
            mint_authority: COption::Some(*mint_authority),
            supply: 0,
            decimals: FLOW_DECIMALS as u8,
            is_initialized: true,
            freeze_authority: COption::None,
        }.pack_into_slice(&mut data);
        Account { lamports: 10_000_000, data, owner: spl_token::id(), executable: false, rent_epoch: 0 }
    }

    /// A real, initialized SPL token account holding zero of `mint`.
    fn spl_token_account(mint: &Pubkey, owner: &Pubkey) -> Account {
        let mut data = vec![0u8; spl_token::state::Account::LEN];
        spl_token::state::Account {
            mint: *mint,
            owner: *owner,
            amount: 0,
            delegate: COption::None,
            state: spl_token::state::AccountState::Initialized,
            is_native: COption::None,
            delegated_amount: 0,
            close_authority: COption::None,
        }.pack_into_slice(&mut data);
        Account { lamports: 10_000_000, data, owner: spl_token::id(), executable: false, rent_epoch: 0 }
    }

    async fn token_balance(banks: &mut BanksClient, pk: Pubkey) -> u64 {
        let acct = banks.get_account(pk).await.expect("rpc").expect("token account exists");
        spl_token::state::Account::unpack(&acct.data).expect("unpack token account").amount
    }

    async fn fund(banks: &mut BanksClient, payer: &Keypair, relay: &Pubkey, bh: solana_sdk::hash::Hash) {
        banks.process_transaction(Transaction::new_signed_with_payer(
            &[solana_sdk::system_instruction::transfer(&payer.pubkey(), relay, 1_000_000_000)],
            Some(&payer.pubkey()), &[payer], bh,
        )).await.expect("fund relay");
    }

    /// The `uptime_paid` one-shot guard: a commitment already marked paid
    /// must reject a second ClaimRelayUptime for the same epoch, before ever
    /// touching the foundation kill switch, the repFlow gate, or minting.
    #[tokio::test]
    async fn rejects_replay_when_already_paid() {
        let relay = Keypair::new();
        let claim_epoch = 500u64;
        let (c_pda, c_bump) = commitment_pda(&relay.pubkey(), claim_epoch);
        let (fc_pda, _) = foundation_config_pda();

        let mut pt = program_test();
        pt.add_account(c_pda, commitment_account(&relay.pubkey(), claim_epoch, 10_000_000_000, true, c_bump));
        // foundation_config intentionally left unfunded: uptime_paid is
        // checked first, so this account must never be read.
        let repflow_pk = Keypair::new().pubkey();

        let (mut banks, payer, bh) = pt.start().await;
        fund(&mut banks, &payer, &relay.pubkey(), bh).await;
        let bh = banks.get_latest_blockhash().await.unwrap();

        let ix = claim_relay_uptime_ix(&relay, c_pda, fc_pda, repflow_pk, claim_epoch);
        let result = banks.process_transaction(Transaction::new_signed_with_payer(
            &[ix], Some(&relay.pubkey()), &[&relay], bh,
        )).await;
        assert!(result.is_err(), "UptimeAlreadyPaid must reject a replayed claim");
    }

    /// The foundation kill switch (`uptime_enabled = false`) must halt a
    /// ClaimRelayUptime even for an epoch already committed — the deliberate
    /// re-check documented on `process_claim_relay_uptime_ix`: an emergency
    /// stop must halt already-committed epochs, not just future commits.
    #[tokio::test]
    async fn rejects_when_uptime_disabled() {
        let relay = Keypair::new();
        let claim_epoch = 501u64;
        let (c_pda, c_bump) = commitment_pda(&relay.pubkey(), claim_epoch);
        let (fc_pda, fc_bump) = foundation_config_pda();

        let mut pt = program_test();
        pt.add_account(c_pda, commitment_account(&relay.pubkey(), claim_epoch, 10_000_000_000, false, c_bump));
        pt.add_account(fc_pda, foundation_config_account(&relay.pubkey(), false /* disabled */, fc_bump));
        let repflow_pk = Keypair::new().pubkey();

        let (mut banks, payer, bh) = pt.start().await;
        fund(&mut banks, &payer, &relay.pubkey(), bh).await;
        let bh = banks.get_latest_blockhash().await.unwrap();

        let ix = claim_relay_uptime_ix(&relay, c_pda, fc_pda, repflow_pk, claim_epoch);
        let result = banks.process_transaction(Transaction::new_signed_with_payer(
            &[ix], Some(&relay.pubkey()), &[&relay], bh,
        )).await;
        assert!(result.is_err(), "UptimeRewardsDisabled must reject the claim");
    }

    /// repFlow gate (2001): rejected even after the zero-amount short-circuit
    /// doesn't apply — resolved before ever reaching the mint CPI.
    #[tokio::test]
    async fn rejects_when_repflow_below_gate() {
        let relay = Keypair::new();
        let claim_epoch = 504u64;
        let (c_pda, c_bump) = commitment_pda(&relay.pubkey(), claim_epoch);
        let (fc_pda, fc_bump) = foundation_config_pda();

        let mut pt = program_test();
        pt.add_account(c_pda, commitment_account(&relay.pubkey(), claim_epoch, 10_000_000_000, false, c_bump));
        pt.add_account(fc_pda, foundation_config_account(&relay.pubkey(), true, fc_bump));
        let repflow_pk = Pubkey::find_program_address(
            &[b"repflow_user", relay.pubkey().as_ref()], &REPFLOW_PROGRAM_ID).0; // F-1: genuine PDA
        pt.add_account(repflow_pk, repflow_user_account(MIN_RELAY_REPFLOW - 1));

        let (mut banks, payer, bh) = pt.start().await;
        fund(&mut banks, &payer, &relay.pubkey(), bh).await;
        let bh = banks.get_latest_blockhash().await.unwrap();

        let ix = claim_relay_uptime_ix(&relay, c_pda, fc_pda, repflow_pk, claim_epoch);
        let result = banks.process_transaction(Transaction::new_signed_with_payer(
            &[ix], Some(&relay.pubkey()), &[&relay], bh,
        )).await;
        assert!(result.is_err(), "RepFlowGateNotMet must reject the claim below the 2001 gate");
    }

    /// Zero-amount epoch: no repFlow gate, no mint CPI — just latch
    /// `uptime_paid = true` so the epoch can't be retried forever. This is a
    /// genuine full success path, unlike the other tests in this module.
    #[tokio::test]
    async fn zero_amount_marks_paid_without_minting() {
        let relay = Keypair::new();
        let claim_epoch = 502u64;
        let (c_pda, c_bump) = commitment_pda(&relay.pubkey(), claim_epoch);
        let (fc_pda, fc_bump) = foundation_config_pda();

        let mut pt = program_test();
        pt.add_account(c_pda, commitment_account(&relay.pubkey(), claim_epoch, 0 /* zero */, false, c_bump));
        pt.add_account(fc_pda, foundation_config_account(&relay.pubkey(), true, fc_bump));
        // repFlow account deliberately absent — must never be read on the zero path.
        let repflow_pk = Keypair::new().pubkey();

        let (mut banks, payer, bh) = pt.start().await;
        fund(&mut banks, &payer, &relay.pubkey(), bh).await;
        let bh = banks.get_latest_blockhash().await.unwrap();

        let ix = claim_relay_uptime_ix(&relay, c_pda, fc_pda, repflow_pk, claim_epoch);
        banks.process_transaction(Transaction::new_signed_with_payer(
            &[ix], Some(&relay.pubkey()), &[&relay], bh,
        )).await.expect("zero-amount ClaimRelayUptime must succeed without minting");

        let acct = banks.get_account(c_pda).await.expect("rpc").expect("commitment exists");
        let c = ClaimCommitment::try_from_slice(&acct.data[..CLAIM_COMMITMENT_SIZE]).expect("deser");
        assert!(c.uptime_paid, "zero-amount epoch must still latch uptime_paid");
    }

    /// A commitment account not at `[claim_commitment, relay, epoch]` must be
    /// rejected — guards against a caller passing an arbitrary account in the
    /// commitment slot.
    #[tokio::test]
    async fn rejects_commitment_account_at_wrong_pda() {
        let relay = Keypair::new();
        let claim_epoch = 503u64;
        let wrong_pk = Keypair::new().pubkey(); // NOT the derived PDA
        let (fc_pda, fc_bump) = foundation_config_pda();

        let mut pt = program_test();
        pt.add_account(wrong_pk, commitment_account(&relay.pubkey(), claim_epoch, 10_000_000_000, false, 255));
        pt.add_account(fc_pda, foundation_config_account(&relay.pubkey(), true, fc_bump));
        let repflow_pk = Keypair::new().pubkey();

        let (mut banks, payer, bh) = pt.start().await;
        fund(&mut banks, &payer, &relay.pubkey(), bh).await;
        let bh = banks.get_latest_blockhash().await.unwrap();

        let ix = claim_relay_uptime_ix(&relay, wrong_pk, fc_pda, repflow_pk, claim_epoch);
        let result = banks.process_transaction(Transaction::new_signed_with_payer(
            &[ix], Some(&relay.pubkey()), &[&relay], bh,
        )).await;
        assert!(result.is_err(), "commitment account not at the derived PDA must be rejected");
    }

    /// Shared fixture for the two treasury-constraint tests. Everything is
    /// identical between them except which account is passed as
    /// `reward_treasury`, so the only variable driving the outcome is the
    /// constraint under test.
    struct UptimeMintFixture {
        relay:        Keypair,
        foundation:   Pubkey,
        claim_epoch:  u64,
        amount:       u64,
        flow_mint:    Pubkey,
        service_auth: Pubkey,
        relay_token:  Pubkey,
        c_pda:        Pubkey,
        fc_pda:       Pubkey,
        repflow_pk:   Pubkey,
        pt:           ProgramTest,
    }

    fn uptime_mint_fixture(claim_epoch: u64) -> UptimeMintFixture {
        let relay       = Keypair::new();
        let foundation  = Keypair::new().pubkey();
        let amount      = 10_000_000_000u64; // 10 $FLOW → 7 relay / 3 treasury
        let (c_pda, c_bump)   = commitment_pda(&relay.pubkey(), claim_epoch);
        let (fc_pda, fc_bump) = foundation_config_pda();
        let (service_auth, _) = Pubkey::find_program_address(&[b"mint_authority"], &id());
        let flow_mint   = Keypair::new().pubkey();
        // Deliberately NOT an ATA: reward_relay is unconstrained by design.
        let relay_token = Keypair::new().pubkey();
        let repflow_pk  = Pubkey::find_program_address(&[b"repflow_user", relay.pubkey().as_ref()], &REPFLOW_PROGRAM_ID).0;

        let mut pt = program_test();
        pt.add_account(c_pda, commitment_account(&relay.pubkey(), claim_epoch, amount, false, c_bump));
        pt.add_account(fc_pda, foundation_config_account(&foundation, true, fc_bump));
        pt.add_account(repflow_pk, repflow_user_account(MIN_RELAY_REPFLOW));
        pt.add_account(flow_mint, flow_mint_account(&service_auth));
        pt.add_account(relay_token, spl_token_account(&flow_mint, &relay.pubkey()));

        UptimeMintFixture {
            relay, foundation, claim_epoch, amount, flow_mint, service_auth,
            relay_token, c_pda, fc_pda, repflow_pk, pt,
        }
    }

    /// Happy path: `reward_treasury` is the correctly derived foundation ATA,
    /// so the claim mints 70% to the relay and 30% to the foundation. This runs
    /// all the way through the SPL-Token mint CPI (ProgramTest ships the token
    /// program in genesis), so it proves the constraint admits the real payout
    /// rather than merely matching a constant.
    #[tokio::test]
    async fn foundation_ata_treasury_mints_seventy_thirty() {
        let f = uptime_mint_fixture(505);
        let treasury = foundation_ata(&f.foundation, &f.flow_mint);

        let mut pt = f.pt;
        pt.add_account(treasury, spl_token_account(&f.flow_mint, &f.foundation));

        let (mut banks, payer, bh) = pt.start().await;
        fund(&mut banks, &payer, &f.relay.pubkey(), bh).await;
        let bh = banks.get_latest_blockhash().await.unwrap();

        let ix = claim_relay_uptime_ix_full(
            &f.relay, f.c_pda, f.fc_pda, f.repflow_pk, spl_token::id(),
            f.flow_mint, f.service_auth, f.relay_token, treasury, f.claim_epoch,
        );
        banks.process_transaction(Transaction::new_signed_with_payer(
            &[ix], Some(&f.relay.pubkey()), &[&f.relay], bh,
        )).await.expect("claim with the derived foundation ATA must succeed");

        let (want_relay, want_treasury) = split_relay_treasury(f.amount);
        assert_eq!(token_balance(&mut banks, f.relay_token).await, want_relay, "relay gets 70%");
        assert_eq!(token_balance(&mut banks, treasury).await, want_treasury, "foundation gets 30%");

        let acct = banks.get_account(f.c_pda).await.expect("rpc").expect("commitment exists");
        let c = ClaimCommitment::try_from_slice(&acct.data[..CLAIM_COMMITMENT_SIZE]).expect("deser");
        assert!(c.uptime_paid, "successful claim must latch uptime_paid");
    }

    /// The skim this constraint exists to stop: a relay passes a second token
    /// account **it owns** as `reward_treasury` to capture the foundation's 30%
    /// on top of its own 70%. Must be rejected with `InvalidTreasuryAccount`,
    /// and nothing may be minted.
    #[tokio::test]
    async fn attacker_controlled_treasury_is_rejected() {
        let f = uptime_mint_fixture(506);
        // Owned by the relay, not the foundation — and not at the ATA address.
        let attacker_treasury = Keypair::new().pubkey();

        let mut pt = f.pt;
        pt.add_account(attacker_treasury, spl_token_account(&f.flow_mint, &f.relay.pubkey()));

        let (mut banks, payer, bh) = pt.start().await;
        fund(&mut banks, &payer, &f.relay.pubkey(), bh).await;
        let bh = banks.get_latest_blockhash().await.unwrap();

        let ix = claim_relay_uptime_ix_full(
            &f.relay, f.c_pda, f.fc_pda, f.repflow_pk, spl_token::id(),
            f.flow_mint, f.service_auth, f.relay_token, attacker_treasury, f.claim_epoch,
        );
        let err = banks.process_transaction(Transaction::new_signed_with_payer(
            &[ix], Some(&f.relay.pubkey()), &[&f.relay], bh,
        )).await.expect_err("attacker-supplied reward_treasury must be rejected");

        let want = format!("Custom({})", RewardsError::InvalidTreasuryAccount as u32);
        let got  = format!("{err:?}");
        assert!(got.contains(&want), "expected {want}, got {got}");

        // Fail-closed: the relay's own 70% must not be minted either.
        assert_eq!(token_balance(&mut banks, f.relay_token).await, 0, "no relay mint on reject");
        assert_eq!(token_balance(&mut banks, attacker_treasury).await, 0, "no treasury mint on reject");

        let acct = banks.get_account(f.c_pda).await.expect("rpc").expect("commitment exists");
        let c = ClaimCommitment::try_from_slice(&acct.data[..CLAIM_COMMITMENT_SIZE]).expect("deser");
        assert!(!c.uptime_paid, "rejected claim must not latch uptime_paid");
    }
}

// ── 11: SetUptimeEnabled ─────────────────────────────────────────────────────

/// Size of the pre-upgrade `FoundationConfig` account, before `uptime_enabled`
/// was inserted. The live PDA on devnet/mainnet is still this size.
///
///   old (34): foundation_wallet[0..32] | trial_enabled[32] | bump[33]
///   new (35): foundation_wallet[0..32] | trial_enabled[32] | uptime_enabled[33] | bump[34]
const FOUNDATION_CONFIG_SIZE_LEGACY: usize = 34;

const _: () = assert!(FOUNDATION_CONFIG_SIZE_LEGACY + 1 == FOUNDATION_CONFIG_SIZE);

/// Fields read from a raw `foundation_config` buffer by `read_foundation_config_compat`,
/// tolerating both the pre- and post-upgrade on-chain layouts. A named struct
/// instead of a tuple so call sites read clearly (`view.uptime_enabled`, not
/// positional `.2`).
struct FoundationConfigView {
    wallet:         [u8; 32],
    trial_enabled:  bool,
    uptime_enabled: bool,
    bump:           u8,
}

/// Read `foundation_wallet`, `trial_enabled`, `uptime_enabled`, and `bump` from
/// a raw foundation_config buffer, tolerating both the pre- and post-upgrade
/// layouts.
///
/// On a legacy 34-byte buffer `uptime_enabled` defaults to `true`: a legacy
/// account predates the kill switch entirely, and defaulting to enabled
/// preserves existing behaviour (uptime rewards keep flowing) rather than
/// silently stopping rewards the instant the upgraded program runs.
///
/// **This must be called BEFORE any realloc, and the fields must be read by
/// explicit offset rather than by deserialising the current struct.** The new
/// struct inserts `uptime_enabled` at byte 33 — exactly where the old layout
/// stored `bump`. Reallocing first and then parsing with `FoundationConfig`
/// would read the old `bump` as `uptime_enabled` and the fresh zero byte at
/// index 34 as `bump`, permanently destroying the PDA's bump seed on the live
/// foundation config.
fn read_foundation_config_compat(data: &[u8]) -> Result<FoundationConfigView, ProgramError> {
    if data.len() < FOUNDATION_CONFIG_SIZE_LEGACY {
        return Err(ProgramError::InvalidAccountData);
    }
    let mut wallet = [0u8; 32];
    wallet.copy_from_slice(&data[0..32]);
    let trial_enabled = data[32] != 0;
    let (uptime_enabled, bump) = if data.len() >= FOUNDATION_CONFIG_SIZE {
        (data[33] != 0, data[34]) // already migrated
    } else {
        (true, data[33]) // pre-upgrade layout predates the kill switch — default enabled
    };
    Ok(FoundationConfigView { wallet, trial_enabled, uptime_enabled, bump })
}

/// 11: SetUptimeEnabled — foundation-only kill switch for relay uptime rewards.
///
/// Separate from the rate because zero is unrepresentable: UpdateRewardRates
/// treats `uptime_per_hour == 0` as "keep existing", so an operator zeroing the
/// rate would get a success response while the old rate silently persisted.
///
/// Accounts:
///   0: foundation_wallet  (signer, writable — funds the rent top-up)
///   1: foundation_config  (writable, PDA [b"foundation_config"])
///   2: system_program
pub fn process_set_uptime_enabled_ix(
    program_id: &Pubkey,
    accounts:   &[AccountInfo],
    enabled:    bool,
) -> ProgramResult {
    let iter                 = &mut accounts.iter();
    let foundation_wallet    = next_account_info(iter)?;
    let foundation_config_ai = next_account_info(iter)?;
    let system_prog          = next_account_info(iter)?;

    if !foundation_wallet.is_signer {
        return Err(ProgramError::MissingRequiredSignature);
    }

    let (fc_pda, fc_bump) = Pubkey::find_program_address(&[b"foundation_config"], program_id);
    if foundation_config_ai.key != &fc_pda {
        return Err(ProgramError::InvalidArgument);
    }

    let fc: FoundationConfig = if foundation_config_ai.lamports() == 0 {
        // First call — initialise config (foundation wallet becomes the authority).
        create_pda_account(
            foundation_wallet, foundation_config_ai, system_prog, program_id,
            &[b"foundation_config", &[fc_bump]],
            FOUNDATION_CONFIG_SIZE,
        )?;
        FoundationConfig {
            foundation_wallet: foundation_wallet.key.to_bytes(),
            trial_enabled:  true, // default enabled, matches SetTrialEnabled's default
            uptime_enabled: enabled,
            bump: fc_bump,
        }
    } else {
        // Read the surviving fields by explicit offset BEFORE the realloc. The
        // borrow is scoped so it is dropped here: `realloc` takes
        // `data.borrow_mut()` internally and panics on an outstanding borrow.
        let view = {
            let data = foundation_config_ai.data.borrow();
            read_foundation_config_compat(&data)?
        };

        // Only the registered foundation wallet can toggle. Checked before the
        // realloc so an unauthorised caller never funds a rent top-up.
        if view.wallet != foundation_wallet.key.to_bytes() {
            return Err(ProgramError::IllegalOwner);
        }

        // The pre-upgrade account is one byte short of the new struct;
        // save_account would fail with AccountDataTooSmall.
        if foundation_config_ai.data_len() < FOUNDATION_CONFIG_SIZE {
            let needed = Rent::get()?
                .minimum_balance(FOUNDATION_CONFIG_SIZE)
                .saturating_sub(foundation_config_ai.lamports());
            if needed > 0 {
                invoke(
                    &system_instruction::transfer(
                        foundation_wallet.key, foundation_config_ai.key, needed,
                    ),
                    &[
                        foundation_wallet.clone(),
                        foundation_config_ai.clone(),
                        system_prog.clone(),
                    ],
                )?;
            }
            foundation_config_ai.realloc(FOUNDATION_CONFIG_SIZE, false)?;
        }

        FoundationConfig {
            foundation_wallet: view.wallet,
            trial_enabled: view.trial_enabled,
            uptime_enabled: enabled,
            bump: view.bump,
        }
    };

    save_account(foundation_config_ai, &fc)?;
    msg!("SetUptimeEnabled: uptime_enabled = {}", enabled);
    Ok(())
}

#[cfg(test)]
mod foundation_config_migration_tests {
    use super::*;

    const WALLET: [u8; 32] = [0xAB; 32];
    const BUMP:   u8       = 254;

    /// Pre-upgrade on-chain layout: 34 bytes, bump at index 33.
    fn legacy_buf(trial_enabled: bool, bump: u8) -> Vec<u8> {
        let mut v = Vec::with_capacity(FOUNDATION_CONFIG_SIZE_LEGACY);
        v.extend_from_slice(&WALLET);
        v.push(trial_enabled as u8);
        v.push(bump);
        assert_eq!(v.len(), FOUNDATION_CONFIG_SIZE_LEGACY);
        v
    }

    /// Post-upgrade layout: 35 bytes, uptime_enabled at 33, bump at 34.
    fn new_buf(trial_enabled: bool, uptime_enabled: bool, bump: u8) -> Vec<u8> {
        borsh::to_vec(&FoundationConfig {
            foundation_wallet: WALLET,
            trial_enabled,
            uptime_enabled,
            bump,
        })
        .expect("borsh encode")
    }

    #[test]
    fn new_layout_is_one_byte_longer_than_legacy() {
        assert_eq!(new_buf(true, true, BUMP).len(), FOUNDATION_CONFIG_SIZE);
        assert_eq!(FOUNDATION_CONFIG_SIZE, FOUNDATION_CONFIG_SIZE_LEGACY + 1);
    }

    #[test]
    fn legacy_34_byte_buffer_yields_correct_bump() {
        let view = read_foundation_config_compat(&legacy_buf(true, BUMP)).unwrap();
        assert_eq!(view.wallet, WALLET);
        assert!(view.trial_enabled);
        assert_eq!(view.bump, BUMP, "bump must be read from index 33 on the old layout");
    }

    #[test]
    fn new_35_byte_buffer_yields_correct_bump() {
        let view = read_foundation_config_compat(&new_buf(true, false, BUMP)).unwrap();
        assert_eq!(view.wallet, WALLET);
        assert!(view.trial_enabled);
        assert_eq!(view.bump, BUMP, "bump must be read from index 34 on the new layout");
    }

    #[test]
    fn legacy_trial_disabled_round_trips() {
        let view = read_foundation_config_compat(&legacy_buf(false, 251)).unwrap();
        assert!(!view.trial_enabled);
        assert_eq!(view.bump, 251);
    }

    /// A legacy 34-byte account predates the uptime kill switch entirely, so
    /// the compat reader must default `uptime_enabled` to `true` — otherwise
    /// the very first CommitClaim against an unmigrated live account would
    /// silently stop paying uptime rewards instead of just being tolerant of
    /// the missing field.
    #[test]
    fn legacy_34_byte_buffer_defaults_uptime_enabled_true() {
        let view = read_foundation_config_compat(&legacy_buf(true, BUMP)).unwrap();
        assert!(view.uptime_enabled, "legacy accounts must default to uptime rewards enabled");
    }

    /// Once migrated, the real stored `uptime_enabled` value must round-trip —
    /// both when it is explicitly `false` (kill switch engaged) and `true`,
    /// so the default-true fallback above never masks a real toggle.
    #[test]
    fn new_35_byte_buffer_round_trips_real_uptime_enabled_value() {
        let disabled = read_foundation_config_compat(&new_buf(true, false, BUMP)).unwrap();
        assert!(!disabled.uptime_enabled, "explicit false must not be overridden by the legacy default");

        let enabled = read_foundation_config_compat(&new_buf(true, true, BUMP)).unwrap();
        assert!(enabled.uptime_enabled);
    }

    /// Pins the bug that a post-realloc reparse would ship: realloc first, then
    /// deserialise with the CURRENT struct. Byte 33 (the old bump) lands in
    /// `uptime_enabled` and the fresh zero at 34 becomes `bump`.
    ///
    /// A bump of 0 or 1 is a valid Borsh bool, so the reparse SUCCEEDS and
    /// silently writes back a zero bump — the account keeps working until
    /// something needs the bump seed, then the PDA can never be signed again.
    #[test]
    fn post_realloc_reparse_silently_zeroes_a_low_bump() {
        let mut realloced = legacy_buf(true, 1);
        realloced.push(0); // realloc zero-fills the new byte

        let corrupted = FoundationConfig::try_from_slice(&realloced)
            .expect("bump=1 is a valid bool, so this parse succeeds — that is the danger");
        assert_eq!(corrupted.bump, 0, "the real bump (1) was overwritten by the fresh zero");
        assert!(corrupted.uptime_enabled, "the old bump byte was misread as uptime_enabled");

        // The offset reader, given the same pre-realloc bytes, keeps the bump.
        let view = read_foundation_config_compat(&legacy_buf(true, 1)).unwrap();
        assert_eq!(view.bump, 1);
    }

    /// With a canonical high bump the same reparse instead hard-fails: 254 is
    /// not a valid Borsh bool. Loud rather than silent, but still a broken
    /// instruction — recorded so the two failure modes are not confused.
    #[test]
    fn post_realloc_reparse_hard_fails_on_a_canonical_bump() {
        let mut realloced = legacy_buf(true, BUMP); // 254
        realloced.push(0);

        assert!(
            FoundationConfig::try_from_slice(&realloced).is_err(),
            "bump=254 is not a valid bool in the uptime_enabled slot",
        );

        // The offset reader handles it without complaint.
        let view = read_foundation_config_compat(&legacy_buf(true, BUMP)).unwrap();
        assert_eq!(view.bump, BUMP);
    }

    /// Borsh derives the discriminant from declaration order, so inserting a
    /// variant anywhere above SetUptimeEnabled would silently renumber the
    /// wire format for every off-chain caller. Pin the encoded byte.
    #[test]
    fn set_uptime_enabled_is_discriminant_11_on_the_wire() {
        let encoded = borsh::to_vec(&crate::RewardsInstruction::SetUptimeEnabled {
            enabled: false,
        })
        .expect("borsh encode");
        assert_eq!(encoded[0], 11, "SetUptimeEnabled must stay at discriminant 11");
        assert_eq!(encoded, vec![11, 0]);
    }

    /// ClaimRelayUptime replaced the `ReservedClaimRelayUptime` placeholder
    /// IN PLACE at slot 10 (Task 12). If it had instead been appended after
    /// SetUptimeEnabled, it would land on 12, orphan slot 10, and silently
    /// break every off-chain caller built against this discriminant.
    #[test]
    fn claim_relay_uptime_is_discriminant_10_on_the_wire() {
        let encoded = borsh::to_vec(&crate::RewardsInstruction::ClaimRelayUptime {
            claim_epoch: 7,
        })
        .expect("borsh encode");
        assert_eq!(encoded[0], 10, "ClaimRelayUptime must occupy discriminant 10");
        assert_eq!(encoded, vec![10, 7, 0, 0, 0, 0, 0, 0, 0]);
    }

    /// Guards the full run of early discriminants against having shifted —
    /// not just 10 and 11 in isolation.
    #[test]
    fn early_discriminants_0_through_9_unchanged() {
        use crate::RewardsInstruction as I;
        assert_eq!(borsh::to_vec(&I::CommitClaim {
            merkle_root: [0u8; 32], client_count: 0, total_bytes: 0, uptime_hours: 0, claim_epoch: 0,
        }).unwrap()[0], 0);
        assert_eq!(borsh::to_vec(&I::ReserveBatch { claim_epoch: 0, entries: vec![] }).unwrap()[0], 1);
        assert_eq!(borsh::to_vec(&I::ReleaseClaim { claim_epoch: 0, releases: vec![] }).unwrap()[0], 2);
        assert_eq!(borsh::to_vec(&I::ClientDispute {
            claim_epoch: 0, client_pubkey: [0u8; 32], session_id: [0u8; 16], batch_nonce: 0,
            original_batch_hash: [0u8; 32], total_bytes: 0, record_count: 0,
            client_signature: [0u8; 64], merkle_proof: vec![],
        }).unwrap()[0], 3);
        assert_eq!(borsh::to_vec(&I::ClaimPendingRewards { claim_epoch: 0 }).unwrap()[0], 4);
        assert_eq!(borsh::to_vec(&I::ReleaseTrialClaim { claim_epoch: 0, releases: vec![] }).unwrap()[0], 5);
        assert_eq!(borsh::to_vec(&I::SetTrialEnabled { enabled: false }).unwrap()[0], 6);
        assert_eq!(borsh::to_vec(&I::SlashTrialFraud {
            claim_epoch: 0, device_uuid: [0u8; 16], device_signature: [0u8; 64],
        }).unwrap()[0], 7);
        assert_eq!(borsh::to_vec(&I::InitializeRewardRates {
            routing_per_mb: 0, seeding_per_mb: 0, uptime_per_hour: 0, flow_price_cents: 0,
        }).unwrap()[0], 8);
        assert_eq!(borsh::to_vec(&I::UpdateRewardRates {
            routing_per_mb: 0, seeding_per_mb: 0, uptime_per_hour: 0, flow_price_cents: 0,
        }).unwrap()[0], 9);
    }

    #[test]
    fn undersized_buffer_is_rejected() {
        let short = vec![0u8; FOUNDATION_CONFIG_SIZE_LEGACY - 1];
        assert!(matches!(
            read_foundation_config_compat(&short),
            Err(ProgramError::InvalidAccountData)
        ));
    }

    /// A buffer longer than the new layout (future growth) must still find the
    /// bump at index 34, not at the tail.
    #[test]
    fn oversized_buffer_still_reads_bump_at_34() {
        let mut buf = new_buf(false, true, BUMP);
        buf.extend_from_slice(&[0xFF; 8]);
        let view = read_foundation_config_compat(&buf).unwrap();
        assert!(!view.trial_enabled);
        assert_eq!(view.bump, BUMP);
    }
}

#[cfg(test)]
mod clamp_tests {
    use super::*;
    const H: i64 = 3600;

    #[test]
    fn honest_claim_passes_through() {
        assert_eq!(clamp_uptime_hours(12, 100 * H, Some(88 * H), true), 12);
    }

    #[test]
    fn offline_relay_is_capped_at_epoch_max() {
        // 30 days elapsed. Elapsed-only clamp would allow 720h.
        let now = 1_000_000 * H;
        let last = now - 720 * H;
        assert_eq!(clamp_uptime_hours(720, now, Some(last), true), MAX_UPTIME_HOURS_PER_EPOCH);
    }

    #[test]
    fn back_to_back_commits_earn_nothing() {
        let now = 500 * H;
        assert_eq!(clamp_uptime_hours(12, now, Some(now), true), 0);
    }

    #[test]
    fn first_epoch_earns_zero() {
        assert_eq!(clamp_uptime_hours(12, 100 * H, None, true), 0);
    }

    #[test]
    fn kill_switch_zeroes_uptime() {
        assert_eq!(clamp_uptime_hours(12, 100 * H, Some(88 * H), false), 0);
    }

    #[test]
    fn clock_skew_backwards_is_not_negative() {
        assert_eq!(clamp_uptime_hours(12, 50 * H, Some(88 * H), true), 0);
    }

    #[test]
    fn elapsed_binds_when_below_epoch_max() {
        // reported=20, elapsed=5, MAX=24 -> elapsed is the binding constraint.
        let now = 100 * H;
        assert_eq!(clamp_uptime_hours(20, now, Some(now - 5 * H), true), 5);
    }
}

#[cfg(test)]
mod foundation_config_realloc_dryrun {
    //! Runtime dry-run of the 34->35 byte `foundation_config` realloc that
    //! `process_set_uptime_enabled_ix` performs the first time it runs against a
    //! legacy account. Unit tests (`foundation_config_migration_tests`) cover the
    //! offset arithmetic; these drive the REAL allocate / rent-top-up / realloc /
    //! save path through the BanksClient runtime against a planted replica of the
    //! LIVE devnet account, so the migration is proven to execute before it ever
    //! touches the irreplaceable on-chain PDA.
    //!
    //! Live snapshot reproduced here (predeploy_scan, 2026-07-21):
    //!   PDA 4iwTtcoXrgWRiHsKPwLyKrxRU3jXspD62fWYit7kh3Th, 34 bytes,
    //!   trial_enabled=1, bump=255. The wallet is substituted for a test signer
    //!   (the authority check requires signing as it), which is immaterial to the
    //!   realloc mechanics under test.
    use super::*;
    use solana_program_test::*;
    use solana_sdk::{
        account::Account,
        instruction::{AccountMeta, Instruction},
        signature::{Keypair, Signer},
        system_program,
        transaction::Transaction,
    };
    use crate::{id, process_instruction, RewardsInstruction};

    const LIVE_TRIAL_ENABLED: u8 = 1;
    const LIVE_BUMP: u8 = 255;

    fn program_test() -> ProgramTest {
        ProgramTest::new("freeflow_rewards_v2", id(), processor!(process_instruction))
    }

    fn fc_pda() -> Pubkey {
        Pubkey::find_program_address(&[b"foundation_config"], &id()).0
    }

    fn funded_wallet() -> Account {
        Account {
            lamports: 10_000_000_000,
            data: vec![],
            owner: system_program::id(),
            executable: false,
            rent_epoch: 0,
        }
    }

    /// A legacy 34-byte foundation_config exactly like the live one: program-owned,
    /// rent-exempt for 34 bytes, layout wallet[0..32] | trial_enabled=1 | bump=255.
    fn legacy_34b_account(wallet: &Pubkey) -> Account {
        let mut data = Vec::with_capacity(34);
        data.extend_from_slice(&wallet.to_bytes());
        data.push(LIVE_TRIAL_ENABLED);
        data.push(LIVE_BUMP);
        assert_eq!(data.len(), 34, "legacy layout must be 34 bytes");
        Account {
            lamports: solana_sdk::rent::Rent::default().minimum_balance(34),
            data,
            owner: id(),
            executable: false,
            rent_epoch: 0,
        }
    }

    /// An already-migrated 35-byte account: uptime_enabled at [33], bump at [34].
    fn migrated_35b_account(wallet: &Pubkey, uptime_enabled: u8) -> Account {
        let mut data = Vec::with_capacity(35);
        data.extend_from_slice(&wallet.to_bytes());
        data.push(LIVE_TRIAL_ENABLED);
        data.push(uptime_enabled);
        data.push(LIVE_BUMP);
        Account {
            lamports: solana_sdk::rent::Rent::default().minimum_balance(35),
            data,
            owner: id(),
            executable: false,
            rent_epoch: 0,
        }
    }

    fn set_uptime_ix(foundation_wallet: &Pubkey, enabled: bool) -> Instruction {
        Instruction {
            program_id: id(),
            accounts: vec![
                AccountMeta::new(*foundation_wallet, true),
                AccountMeta::new(fc_pda(), false),
                AccountMeta::new_readonly(system_program::id(), false),
            ],
            data: borsh::to_vec(&RewardsInstruction::SetUptimeEnabled { enabled })
                .expect("borsh encode"),
        }
    }

    /// THE DRY-RUN: legacy 34-byte account -> SetUptimeEnabled(false) -> assert it
    /// migrated to 35 bytes with the bump preserved and every other field intact.
    /// This is the exact path that runs once against the live PDA at deploy time.
    #[tokio::test]
    async fn migrates_legacy_34b_to_35b_preserving_bump() {
        let foundation = Keypair::new();
        let mut pt = program_test();
        pt.add_account(foundation.pubkey(), funded_wallet());
        pt.add_account(fc_pda(), legacy_34b_account(&foundation.pubkey()));

        let (mut banks, _payer, blockhash) = pt.start().await;

        let pre = banks.get_account(fc_pda()).await.unwrap().unwrap();
        assert_eq!(pre.data.len(), 34, "precondition: account starts at 34 bytes");

        let mut tx = Transaction::new_with_payer(
            &[set_uptime_ix(&foundation.pubkey(), false)],
            Some(&foundation.pubkey()),
        );
        tx.sign(&[&foundation], blockhash);
        banks.process_transaction(tx).await.expect("SetUptimeEnabled must succeed");

        let post = banks.get_account(fc_pda()).await.unwrap().unwrap();
        assert_eq!(post.data.len(), 35, "account must have realloc'd to 35 bytes");
        assert_eq!(&post.data[0..32], &foundation.pubkey().to_bytes(), "wallet unchanged");
        assert_eq!(post.data[32], LIVE_TRIAL_ENABLED, "trial_enabled must survive the migration");
        assert_eq!(post.data[33], 0, "uptime_enabled must be the value written (false=0)");
        assert_eq!(post.data[34], LIVE_BUMP, "BUMP MUST BE PRESERVED at byte 34");
        assert_eq!(post.owner, id(), "account must stay program-owned");
        assert!(
            post.lamports >= solana_sdk::rent::Rent::default().minimum_balance(35),
            "account must remain rent-exempt at 35 bytes",
        );
    }

    /// Idempotency: a second call on the already-35-byte account must NOT realloc
    /// again, and must toggle uptime_enabled while preserving the bump.
    #[tokio::test]
    async fn second_call_toggles_without_re_realloc() {
        let foundation = Keypair::new();
        let mut pt = program_test();
        pt.add_account(foundation.pubkey(), funded_wallet());
        pt.add_account(fc_pda(), migrated_35b_account(&foundation.pubkey(), 0));

        let (mut banks, _payer, blockhash) = pt.start().await;

        let mut tx = Transaction::new_with_payer(
            &[set_uptime_ix(&foundation.pubkey(), true)],
            Some(&foundation.pubkey()),
        );
        tx.sign(&[&foundation], blockhash);
        banks.process_transaction(tx).await.expect("toggle must succeed");

        let post = banks.get_account(fc_pda()).await.unwrap().unwrap();
        assert_eq!(post.data.len(), 35, "must stay 35 bytes, no re-realloc");
        assert_eq!(post.data[33], 1, "uptime_enabled must flip to true (1)");
        assert_eq!(post.data[34], LIVE_BUMP, "bump still preserved");
    }

    /// Authority + ordering: a non-foundation signer must be rejected AND the
    /// account left UNTOUCHED, proving the authority check runs BEFORE the rent
    /// top-up / realloc (an attacker must not be able to fund or grow it).
    #[tokio::test]
    async fn non_foundation_signer_rejected_and_account_untouched() {
        let real_foundation = Keypair::new();
        let attacker        = Keypair::new();
        let mut pt = program_test();
        pt.add_account(attacker.pubkey(), funded_wallet());
        pt.add_account(fc_pda(), legacy_34b_account(&real_foundation.pubkey()));

        let (mut banks, _payer, blockhash) = pt.start().await;

        let mut tx = Transaction::new_with_payer(
            &[set_uptime_ix(&attacker.pubkey(), false)],
            Some(&attacker.pubkey()),
        );
        tx.sign(&[&attacker], blockhash);
        assert!(
            banks.process_transaction(tx).await.is_err(),
            "attacker toggle must be rejected",
        );

        let post = banks.get_account(fc_pda()).await.unwrap().unwrap();
        assert_eq!(post.data.len(), 34, "rejected call must NOT have realloc'd the account");
        assert_eq!(post.data[33], LIVE_BUMP, "bump untouched");
    }
}

#[cfg(test)]
mod release_trial_claim_integration_tests {
    //! End-to-end SUCCESS path for ReleaseTrialClaim (disc 5) — the handler that
    //! mints $FLOW to free-trial clients and runs LIVE every epoch. The existing
    //! `test_trial::integration` tests only cover rejection paths (disabled /
    //! below-gate / epoch-mismatch / no-signer); none proves a successful mint.
    //! This drives the real 70/30 SPL-Token mint through the BanksClient runtime,
    //! exercising Task 9's derive-from-pinned-rate change and the removal of the
    //! `is_relay_self_uptime` branch.
    //!
    //! Kept under 1 GB of bytes so `repflow_amount = bytes / BYTES_PER_FLOW == 0`
    //! and the repflow-token CPI is skipped — no second program needs loading. The
    //! $FLOW mint CPI is real (SPL-Token is a built-in in solana-program-test).
    //!
    //! The small SPL/account helpers mirror `claim_relay_uptime_integration_tests`;
    //! duplicated here to keep the module self-contained.
    use super::*;
    use solana_program::{program_option::COption, program_pack::Pack};
    use solana_program_test::*;
    use solana_sdk::{
        account::Account,
        instruction::{AccountMeta, Instruction},
        signature::{Keypair, Signer},
        transaction::Transaction,
    };
    use crate::{id, process_instruction, RewardsInstruction};

    fn program_test() -> ProgramTest {
        ProgramTest::new("freeflow_rewards_v2", id(), processor!(process_instruction))
    }

    fn flow_mint_account(mint_authority: &Pubkey) -> Account {
        let mut data = vec![0u8; spl_token::state::Mint::LEN];
        spl_token::state::Mint {
            mint_authority: COption::Some(*mint_authority),
            supply: 0,
            decimals: FLOW_DECIMALS as u8,
            is_initialized: true,
            freeze_authority: COption::None,
        }
        .pack_into_slice(&mut data);
        Account { lamports: 10_000_000, data, owner: spl_token::id(), executable: false, rent_epoch: 0 }
    }

    fn spl_token_account(mint: &Pubkey, owner: &Pubkey) -> Account {
        let mut data = vec![0u8; spl_token::state::Account::LEN];
        spl_token::state::Account {
            mint: *mint,
            owner: *owner,
            amount: 0,
            delegate: COption::None,
            state: spl_token::state::AccountState::Initialized,
            is_native: COption::None,
            delegated_amount: 0,
            close_authority: COption::None,
        }
        .pack_into_slice(&mut data);
        Account { lamports: 10_000_000, data, owner: spl_token::id(), executable: false, rent_epoch: 0 }
    }

    /// repFlow mirror matching `read_repflow_balance`: 8-byte Anchor disc + 32-byte
    /// wallet + 8-byte balance LE.
    fn repflow_user_account(balance: u64) -> Account {
        let mut data = vec![0u8; 48];
        data[40..48].copy_from_slice(&balance.to_le_bytes());
        // F-1: owned by the real repflow-token program so read_checked_repflow_balance
        // accepts it (paired with a genuine [b"repflow_user", relay] PDA at the call site).
        Account { lamports: 1_000_000, data, owner: REPFLOW_PROGRAM_ID, executable: false, rent_epoch: 0 }
    }

    async fn token_balance(banks: &mut BanksClient, pk: Pubkey) -> u64 {
        let acct = banks.get_account(pk).await.expect("rpc").expect("token account exists");
        spl_token::state::Account::unpack(&acct.data).expect("unpack token account").amount
    }

    async fn fund(banks: &mut BanksClient, payer: &Keypair, to: &Pubkey, bh: solana_sdk::hash::Hash) {
        banks
            .process_transaction(Transaction::new_signed_with_payer(
                &[solana_sdk::system_instruction::transfer(&payer.pubkey(), to, 1_000_000_000)],
                Some(&payer.pubkey()),
                &[payer],
                bh,
            ))
            .await
            .expect("fund relay");
    }

    /// A post-CommitClaim commitment: single client, merkle_root == the client's
    /// leaf (single-leaf tree), enough bandwidth_amount/total_bytes to cover it.
    fn commitment_account(
        relay:            &Pubkey,
        epoch:            u64,
        merkle_root:      [u8; 32],
        bandwidth_amount: u64,
        total_bytes:      u64,
        bump:             u8,
    ) -> Account {
        let c = ClaimCommitment {
            relay_pubkey:     relay.to_bytes(),
            claim_epoch:      epoch,
            merkle_root,
            client_count:     1,
            bandwidth_amount,
            uptime_amount:    0,
            total_bytes,
            uptime_hours:     0,
            routing_per_mb:   DEFAULT_ROUTING_PER_MB,
            uptime_per_hour:  DEFAULT_UPTIME_PER_HOUR,
            committed_at:     0,
            uptime_paid:      false,
            reserved_count:   0,
            released_count:   0,
            released_amount:  0,
            released_bytes:   0,
            status:           ClaimCommitmentStatus::Active,
            dispute_deadline: 0,
            bump,
        };
        let data = borsh::to_vec(&c).expect("borsh commitment");
        let mut padded = vec![0u8; CLAIM_COMMITMENT_SIZE];
        padded[..data.len()].copy_from_slice(&data);
        Account { lamports: 10_000_000, data: padded, owner: id(), executable: false, rent_epoch: 0 }
    }

    fn foundation_config_account(wallet: &Pubkey, bump: u8) -> Account {
        let fc = FoundationConfig {
            foundation_wallet: wallet.to_bytes(),
            trial_enabled:  true,
            uptime_enabled: true,
            bump,
        };
        let data = borsh::to_vec(&fc).expect("borsh fc");
        let mut padded = vec![0u8; FOUNDATION_CONFIG_SIZE];
        padded[..data.len()].copy_from_slice(&data);
        Account { lamports: 1_000_000, data: padded, owner: id(), executable: false, rent_epoch: 0 }
    }

    /// A relay BELOW the 2001 repFlow gate must defer its trial rewards into a
    /// ClaimableBalance, not have the whole transaction reverted.
    ///
    /// Before this, `ReleaseTrialClaim` returned `RepFlowGateNotMet` before any
    /// mutation, so a probationary relay could not release trial claims at all.
    /// It was self-locking: the trial path's own bandwidth-repFlow mint is the
    /// relay's way of EARNING repFlow, and it sat downstream of the gate it
    /// could not pass. Measured 2026-08-13, RackNerd sits at ~1,450.
    ///
    /// Uses ≥ 1 GB so `repflow_amount > 0` and the deferred repFlow is
    /// non-trivial — the point is that it accrues instead of being lost.
    #[tokio::test]
    async fn release_trial_claim_below_gate_defers_instead_of_reverting() {
        let relay      = Keypair::new();
        let foundation = FOUNDATION_PUBKEY;
        let epoch      = 7_778u64;
        let client_pubkey = [11u8; 32];
        let bytes = 2_000_000_000u64; // ≥ 1 GB → repflow_amount > 0

        let release = ClientReleaseOnChain {
            client_pubkey,
            session_id:       [4u8; 16],
            batch_nonce:      1,
            total_bytes:      bytes,
            merkle_proof:     vec![],
            client_signature: [1u8; 64],
            device_uuid:      [8u8; 16],
            record_count:     1,
        };
        let merkle_root = compute_merkle_leaf_hash_from_release(&release);
        let derived = derive_reward_amount(bytes, DEFAULT_ROUTING_PER_MB);
        assert!(derived > 0);

        let (c_pda, c_bump) = Pubkey::find_program_address(
            &[b"claim_commitment", relay.pubkey().as_ref(), &epoch.to_le_bytes()], &id());
        let (fc_pda, fc_bump) = Pubkey::find_program_address(&[b"foundation_config"], &id());
        let (service_auth, _) = Pubkey::find_program_address(&[b"mint_authority"], &id());
        let (tmc_pda, _) = Pubkey::find_program_address(
            &[b"trial_mint_cap", relay.pubkey().as_ref(), &epoch.to_le_bytes()], &id());
        let (claim_state_pda, _) = Pubkey::find_program_address(
            &[b"claim_state", &client_pubkey, relay.pubkey().as_ref()], &id());
        let (trial_usage_pda, _) = Pubkey::find_program_address(
            &[b"trial_usage", &client_pubkey], &id());
        let (cb_pda, _) = Pubkey::find_program_address(
            &[b"claimable_balance", relay.pubkey().as_ref(), &epoch.to_le_bytes()], &id());

        let flow_mint      = Keypair::new().pubkey();
        let relay_token    = Keypair::new().pubkey();
        let treasury_token = Keypair::new().pubkey(); // never touched on this path
        let repflow_pk     = Pubkey::find_program_address(
            &[b"repflow_user", relay.pubkey().as_ref()], &REPFLOW_PROGRAM_ID).0;
        let stub           = Keypair::new().pubkey();

        let mut pt = program_test();
        pt.add_account(c_pda, commitment_account(&relay.pubkey(), epoch, merkle_root, derived, bytes, c_bump));
        pt.add_account(fc_pda, foundation_config_account(&foundation, fc_bump));
        // THE precondition: one short of the gate.
        pt.add_account(repflow_pk, repflow_user_account(MIN_RELAY_REPFLOW - 1));
        pt.add_account(flow_mint, flow_mint_account(&service_auth));
        pt.add_account(relay_token, spl_token_account(&flow_mint, &relay.pubkey()));
        pt.add_account(treasury_token, spl_token_account(&flow_mint, &foundation));

        let (mut banks, payer, bh) = pt.start().await;
        fund(&mut banks, &payer, &relay.pubkey(), bh).await;
        let bh = banks.get_latest_blockhash().await.unwrap();

        let ix = Instruction {
            program_id: id(),
            accounts: vec![
                AccountMeta::new(relay.pubkey(), true),
                AccountMeta::new(c_pda, false),
                AccountMeta::new_readonly(fc_pda, false),
                AccountMeta::new_readonly(spl_token::id(), false),
                AccountMeta::new(flow_mint, false),
                AccountMeta::new_readonly(service_auth, false),
                AccountMeta::new_readonly(stub, false),
                AccountMeta::new_readonly(stub, false),
                AccountMeta::new_readonly(repflow_pk, false),
                AccountMeta::new(relay_token, false),
                AccountMeta::new(treasury_token, false),
                AccountMeta::new(tmc_pda, false),
                AccountMeta::new_readonly(solana_sdk::system_program::id(), false),
                AccountMeta::new(claim_state_pda, false),
                AccountMeta::new(trial_usage_pda, false),
                // LAST, after the per-release accounts — same position as
                // ReleaseClaim's probationary ClaimableBalance.
                AccountMeta::new(cb_pda, false),
            ],
            data: borsh::to_vec(&RewardsInstruction::ReleaseTrialClaim {
                claim_epoch: epoch,
                releases:    vec![release],
            }).expect("encode"),
        };

        banks
            .process_transaction(Transaction::new_signed_with_payer(
                &[ix], Some(&relay.pubkey()), &[&relay], bh,
            ))
            .await
            .expect("below the gate must DEFER, not revert with RepFlowGateNotMet");

        // Nothing minted.
        assert_eq!(token_balance(&mut banks, relay_token).await, 0, "no $FLOW minted below the gate");
        assert_eq!(token_balance(&mut banks, treasury_token).await, 0, "treasury untouched below the gate");

        // Everything accrued instead.
        let cb_acct = banks.get_account(cb_pda).await.unwrap()
            .expect("ClaimableBalance must be created below the gate");
        let cb = ClaimableBalance::try_from_slice(&cb_acct.data[..CLAIMABLE_BALANCE_SIZE]).unwrap();
        let want_relay    = derived * RELAY_SPLIT_PCT / 100;
        assert_eq!(cb.pending_relay_flow, want_relay, "relay's 70% deferred");
        assert_eq!(cb.pending_treasury, derived - want_relay, "treasury's 30% deferred");
        assert_eq!(cb.pending_repflow, bytes / BYTES_PER_FLOW, "bandwidth repFlow deferred");
        assert_eq!(cb.status, ClaimableBalanceStatus::Pending);
        assert_eq!(cb.claim_epoch, epoch);

        // The epoch's trial quota is still consumed — the reward is owed either
        // way, and ClaimPendingRewards has no trial-cap check of its own.
        let tmc_acct = banks.get_account(tmc_pda).await.unwrap().unwrap();
        let tmc = TrialMintCap::try_from_slice(&tmc_acct.data[..TRIAL_MINT_CAP_SIZE]).unwrap();
        assert_eq!(tmc.minted_so_far, derived, "deferring still consumes the trial cap");
    }

    #[tokio::test]
    async fn release_trial_claim_success_mints_70_30_and_records_usage() {
        let relay      = Keypair::new();
        // Must be the constant: ReleaseTrialClaim is the one handler holding
        // both sources of truth and now refuses to pay when they disagree.
        let foundation = FOUNDATION_PUBKEY;
        let epoch      = 7_777u64;
        let client_pubkey = [9u8; 32];
        // < 1 GB so the repflow-token CPI is skipped; still a nonzero $FLOW reward.
        let bytes = 500_000_000u64;

        // The single trial-client release. Fields mirror `make_release` in test_e2e.
        let release = ClientReleaseOnChain {
            client_pubkey,
            session_id:       [3u8; 16],
            batch_nonce:      1,
            total_bytes:      bytes,
            merkle_proof:     vec![], // single-leaf tree: no proof needed
            client_signature: [1u8; 64], // non-null (the handler only rejects all-zero)
            device_uuid:      [7u8; 16],
            record_count:     1,
        };
        // Single-leaf tree: the root IS the leaf.
        let merkle_root = compute_merkle_leaf_hash_from_release(&release);
        let derived = derive_reward_amount(bytes, DEFAULT_ROUTING_PER_MB);
        assert!(derived > 0, "test bytes must yield a nonzero reward");

        let (c_pda, c_bump) = Pubkey::find_program_address(
            &[b"claim_commitment", relay.pubkey().as_ref(), &epoch.to_le_bytes()], &id());
        let (fc_pda, fc_bump) = Pubkey::find_program_address(&[b"foundation_config"], &id());
        let (service_auth, _) = Pubkey::find_program_address(&[b"mint_authority"], &id());
        let (tmc_pda, _) = Pubkey::find_program_address(
            &[b"trial_mint_cap", relay.pubkey().as_ref(), &epoch.to_le_bytes()], &id());
        let (claim_state_pda, _) = Pubkey::find_program_address(
            &[b"claim_state", &client_pubkey, relay.pubkey().as_ref()], &id());
        let (trial_usage_pda, _) = Pubkey::find_program_address(
            &[b"trial_usage", &client_pubkey], &id());

        let flow_mint      = Keypair::new().pubkey();
        let relay_token    = Keypair::new().pubkey();
        // H-1 + the divergence tripwire: `foundation` above is FOUNDATION_PUBKEY
        // (the handler now rejects a config whose wallet disagrees with the
        // constant), and reward_treasury must be that wallet's canonical ATA.
        // ATA program id from literal bytes, not constants.rs — same reasoning
        // as `foundation_ata` in the uptime tests.
        let treasury_token = Pubkey::find_program_address(
            &[
                FOUNDATION_PUBKEY.as_ref(),
                spl_token::id().as_ref(),
                flow_mint.as_ref(),
            ],
            &Pubkey::new_from_array([
                140, 151, 37, 143, 78, 36, 137, 241, 187, 61, 16, 41, 20, 142, 13, 131,
                11, 90, 19, 153, 218, 255, 16, 132, 4, 142, 123, 216, 219, 233, 248, 89,
            ]),
        ).0;
        let repflow_pk     = Pubkey::find_program_address(&[b"repflow_user", relay.pubkey().as_ref()], &REPFLOW_PROGRAM_ID).0;
        let stub           = Keypair::new().pubkey();

        let mut pt = program_test();
        pt.add_account(c_pda, commitment_account(&relay.pubkey(), epoch, merkle_root, derived, bytes, c_bump));
        pt.add_account(fc_pda, foundation_config_account(&foundation, fc_bump));
        pt.add_account(repflow_pk, repflow_user_account(MIN_RELAY_REPFLOW));
        pt.add_account(flow_mint, flow_mint_account(&service_auth));
        pt.add_account(relay_token, spl_token_account(&flow_mint, &relay.pubkey()));
        pt.add_account(treasury_token, spl_token_account(&flow_mint, &foundation));

        let (mut banks, payer, bh) = pt.start().await;
        fund(&mut banks, &payer, &relay.pubkey(), bh).await;
        let bh = banks.get_latest_blockhash().await.unwrap();

        let ix = Instruction {
            program_id: id(),
            accounts: vec![
                AccountMeta::new(relay.pubkey(), true),                              // 0  relay_wallet
                AccountMeta::new(c_pda, false),                                      // 1  commitment
                AccountMeta::new_readonly(fc_pda, false),                            // 2  foundation_config
                AccountMeta::new_readonly(spl_token::id(), false),                   // 3  token_program
                AccountMeta::new(flow_mint, false),                                  // 4  flow_mint
                AccountMeta::new_readonly(service_auth, false),                      // 5  service_authority
                AccountMeta::new_readonly(stub, false),                              // 6  repflow_program (not CPI'd: bytes < 1 GB)
                AccountMeta::new_readonly(stub, false),                              // 7  repflow_config
                AccountMeta::new_readonly(repflow_pk, false),                        // 8  relay_repflow_user
                AccountMeta::new(relay_token, false),                                // 9  reward_relay
                AccountMeta::new(treasury_token, false),                             // 10 reward_treasury
                AccountMeta::new(tmc_pda, false),                                    // 11 trial_mint_cap
                AccountMeta::new_readonly(solana_sdk::system_program::id(), false),  // 12 system_program
                AccountMeta::new(claim_state_pda, false),                           // + claim_state
                AccountMeta::new(trial_usage_pda, false),                           // + trial_usage
            ],
            data: borsh::to_vec(&RewardsInstruction::ReleaseTrialClaim {
                claim_epoch: epoch,
                releases:    vec![release],
            })
            .expect("encode ReleaseTrialClaim"),
        };
        banks
            .process_transaction(Transaction::new_signed_with_payer(
                &[ix], Some(&relay.pubkey()), &[&relay], bh,
            ))
            .await
            .expect("ReleaseTrialClaim success path must mint");

        // 70/30 split, remainder to treasury (matches the handler's M-1 arithmetic).
        let want_relay    = derived * RELAY_SPLIT_PCT / 100;
        let want_treasury = derived - want_relay;
        assert_eq!(token_balance(&mut banks, relay_token).await, want_relay, "relay gets 70%");
        assert_eq!(token_balance(&mut banks, treasury_token).await, want_treasury, "treasury gets 30%");

        // Commitment accounting advanced.
        let cacct = banks.get_account(c_pda).await.unwrap().unwrap();
        let c = ClaimCommitment::try_from_slice(&cacct.data[..CLAIM_COMMITMENT_SIZE]).unwrap();
        // A trial release must NOT advance released_count. That counter is
        // compared against reserved_count by `epoch_is_fully_released`, and
        // reserved_count is paid-only — counting trial releases here latched
        // `Complete` one release early on any epoch mixing trial and 2+ paid
        // clients, stranding the last paid client's FundHold permanently.
        assert_eq!(
            c.released_count, 0,
            "a trial release must leave the PAID release counter untouched"
        );
        // released_amount IS shared: both kinds draw on bandwidth_amount and the
        // ReleaseExceedsCommitment cap has to see the total.
        assert_eq!(c.released_amount, derived, "released_amount == contract-derived value");

        // Per-relay-per-epoch trial cap advanced by exactly the derived amount.
        let tmc_acct = banks.get_account(tmc_pda).await.unwrap().unwrap();
        let tmc = TrialMintCap::try_from_slice(&tmc_acct.data[..TRIAL_MINT_CAP_SIZE]).unwrap();
        assert_eq!(tmc.minted_so_far, derived, "trial mint cap records the derived amount");

        // Trial usage PDA created and byte usage recorded (anti-abuse accounting).
        let tu_acct = banks.get_account(trial_usage_pda).await.unwrap().unwrap();
        let tu = TrialUsage::try_from_slice(&tu_acct.data[..TRIAL_USAGE_SIZE]).unwrap();
        assert_eq!(tu.used_bytes, bytes, "trial usage records the served bytes");
    }
}

#[cfg(test)]
mod reserve_batch_integration_tests {
    //! End-to-end for ReserveBatch (disc 1). Proves rewards-v2 derives each
    //! client's hold amount from `bytes × pinned routing_per_mb` (Task 8),
    //! forwards *exactly that* to the escrow hold CPI, and records it in the
    //! Reservation PDA — none of it relay-supplied.
    //!
    //! A mock program is registered at the escrow program id instead of the real
    //! user-escrow Anchor program. rewards-v2's responsibility is to derive and
    //! forward the correct amount (the Task 8 change); the mock captures the
    //! amount that crosses the CPI boundary by writing it into the `fund_hold`
    //! probe it owns. The real escrow's held-balance accounting is the escrow
    //! program's own concern (unchanged here) and is proven separately by the
    //! post-deploy devnet smoke test against a live escrow. reserve_batch does not
    //! check the escrow program id against a constant, so a mock at any id works.
    use super::*;
    use solana_program::{account_info::AccountInfo, entrypoint::ProgramResult};
    use solana_program_test::*;
    use solana_sdk::{
        account::Account,
        instruction::{AccountMeta, Instruction},
        signature::{Keypair, Signer},
        transaction::Transaction,
    };
    use crate::{id, process_instruction, RewardsInstruction};

    fn mock_escrow_id() -> Pubkey {
        Pubkey::new_from_array([7u8; 32])
    }

    /// Records the amount from the hold_client_funds CPI into the fund_hold probe.
    /// CPI data = [disc:8][amount:8 LE][claim_hash:32][session:16]; CPI accounts =
    /// [mint_authority, payer, user, user_escrow, fund_hold, spender_registry,
    /// system], so fund_hold is index 4.
    fn mock_escrow_process(_pid: &Pubkey, accounts: &[AccountInfo], data: &[u8]) -> ProgramResult {
        let amount = u64::from_le_bytes(data[8..16].try_into().unwrap());
        accounts[4].data.borrow_mut()[0..8].copy_from_slice(&amount.to_le_bytes());
        Ok(())
    }

    fn program_test() -> ProgramTest {
        let mut pt = ProgramTest::new("freeflow_rewards_v2", id(), processor!(process_instruction));
        pt.add_program("mock_escrow", mock_escrow_id(), processor!(mock_escrow_process));
        pt
    }

    fn commitment_account(
        relay:            &Pubkey,
        epoch:            u64,
        bandwidth_amount: u64,
        total_bytes:      u64,
        bump:             u8,
    ) -> Account {
        let c = ClaimCommitment {
            relay_pubkey:     relay.to_bytes(),
            claim_epoch:      epoch,
            merkle_root:      [0u8; 32],
            client_count:     1,
            bandwidth_amount,
            uptime_amount:    0,
            total_bytes,
            uptime_hours:     0,
            routing_per_mb:   DEFAULT_ROUTING_PER_MB,
            uptime_per_hour:  DEFAULT_UPTIME_PER_HOUR,
            committed_at:     0,
            uptime_paid:      false,
            reserved_count:   0,
            released_count:   0,
            released_amount:  0,
            released_bytes:   0,
            status:           ClaimCommitmentStatus::Active,
            dispute_deadline: 0,
            bump,
        };
        let data = borsh::to_vec(&c).expect("borsh commitment");
        let mut padded = vec![0u8; CLAIM_COMMITMENT_SIZE];
        padded[..data.len()].copy_from_slice(&data);
        Account { lamports: 10_000_000, data: padded, owner: id(), executable: false, rent_epoch: 0 }
    }

    /// A minimal account for a CPI passthrough slot.
    fn stub_account(owner: Pubkey, len: usize) -> Account {
        Account { lamports: 1_000_000, data: vec![0u8; len], owner, executable: false, rent_epoch: 0 }
    }

    #[tokio::test]
    async fn reserve_batch_derives_and_forwards_hold_amount() {
        let relay  = Keypair::new();
        let epoch  = 8_888u64;
        let client = [11u8; 32];
        let bytes  = 300_000_000u64; // 0.3 GB
        let derived = derive_reward_amount(bytes, DEFAULT_ROUTING_PER_MB);
        assert!(derived > 0, "test bytes must yield a nonzero hold");

        let entry = ReserveBatchEntry {
            client_pubkey:    client,
            highest_seq:      1,
            bytes,
            merkle_leaf_hash: [0u8; 32],
            session_id:       [5u8; 16],
            record_count:     1,
        };

        let (c_pda, c_bump) = Pubkey::find_program_address(
            &[b"claim_commitment", relay.pubkey().as_ref(), &epoch.to_le_bytes()], &id());
        let (service_auth, _) = Pubkey::find_program_address(&[b"mint_authority"], &id());
        let (claim_state_pda, _) = Pubkey::find_program_address(
            &[b"claim_state", &client, relay.pubkey().as_ref()], &id());
        let (reservation_pda, _) = Pubkey::find_program_address(&[b"reservation", &client], &id());

        let fund_hold        = Keypair::new().pubkey();
        let user_escrow      = Keypair::new().pubkey();
        let user_escrow_tok  = Keypair::new().pubkey();
        let spender_registry = Keypair::new().pubkey();
        let user_pk          = Pubkey::new_from_array(client);

        let mut pt = program_test();
        pt.add_account(c_pda, commitment_account(&relay.pubkey(), epoch, derived, bytes, c_bump));
        // fund_hold + user_escrow cross the CPI as WRITABLE; own them by the mock.
        pt.add_account(fund_hold,   stub_account(mock_escrow_id(), 8));
        pt.add_account(user_escrow, stub_account(mock_escrow_id(), 8));
        pt.add_account(user_escrow_tok,  stub_account(solana_sdk::system_program::id(), 0));
        pt.add_account(spender_registry, stub_account(solana_sdk::system_program::id(), 0));
        pt.add_account(user_pk,          stub_account(solana_sdk::system_program::id(), 0));

        let (mut banks, payer, bh) = pt.start().await;
        // Relay pays PDA rent for claim_state + reservation, and the tx fee.
        banks.process_transaction(Transaction::new_signed_with_payer(
            &[solana_sdk::system_instruction::transfer(&payer.pubkey(), &relay.pubkey(), 2_000_000_000)],
            Some(&payer.pubkey()), &[&payer], bh,
        )).await.expect("fund relay");
        let bh = banks.get_latest_blockhash().await.unwrap();

        let ix = Instruction {
            program_id: id(),
            accounts: vec![
                AccountMeta::new(relay.pubkey(), true),                             // 0  relay_wallet (payer/signer)
                AccountMeta::new(c_pda, false),                                     // 1  commitment
                AccountMeta::new_readonly(mock_escrow_id(), false),                 // 2  escrow_program
                AccountMeta::new_readonly(service_auth, false),                     // 3  service_authority (mint_authority PDA)
                AccountMeta::new_readonly(spender_registry, false),                 // 4  spender_registry
                AccountMeta::new_readonly(solana_sdk::system_program::id(), false), // 5  system_program
                // per-entry (6):
                AccountMeta::new_readonly(user_pk, false),                          // user
                AccountMeta::new(claim_state_pda, false),                           // claim_state (created)
                AccountMeta::new(user_escrow, false),                               // user_escrow (CPI-writable)
                AccountMeta::new(fund_hold, false),                                 // fund_hold (probe, CPI-writable)
                AccountMeta::new_readonly(user_escrow_tok, false),                  // user_escrow_token (unused)
                AccountMeta::new(reservation_pda, false),                           // reservation (created)
            ],
            data: borsh::to_vec(&RewardsInstruction::ReserveBatch {
                claim_epoch: epoch,
                entries:     vec![entry],
            })
            .expect("encode ReserveBatch"),
        };
        banks
            .process_transaction(Transaction::new_signed_with_payer(
                &[ix], Some(&relay.pubkey()), &[&relay], bh,
            ))
            .await
            .expect("ReserveBatch success path must place the hold");

        // 1. The amount that crossed the escrow-hold CPI boundary == contract-derived.
        let fh = banks.get_account(fund_hold).await.unwrap().unwrap();
        let forwarded = u64::from_le_bytes(fh.data[0..8].try_into().unwrap());
        assert_eq!(forwarded, derived, "reserve_batch must forward the DERIVED amount, not a relay figure");

        // 2. rewards-v2 recorded the same amount in the Reservation PDA.
        let res = banks.get_account(reservation_pda).await.unwrap().unwrap();
        let r = Reservation::try_from_slice(&res.data[..RESERVATION_SIZE]).unwrap();
        assert_eq!(r.reserved, derived, "Reservation.reserved == derived");
        assert_eq!(r.user, client, "Reservation keyed to the client");

        // 3. Commitment reserved_count advanced.
        let cacct = banks.get_account(c_pda).await.unwrap().unwrap();
        let c = ClaimCommitment::try_from_slice(&cacct.data[..CLAIM_COMMITMENT_SIZE]).unwrap();
        assert_eq!(c.reserved_count, 1, "commitment records the reservation");
    }

    /// The aggregate cap still bites: derived hold > bandwidth_amount is rejected.
    #[tokio::test]
    async fn reserve_batch_rejects_when_derived_exceeds_bandwidth_budget() {
        let relay  = Keypair::new();
        let epoch  = 8_889u64;
        let client = [12u8; 32];
        let bytes  = 300_000_000u64;
        let derived = derive_reward_amount(bytes, DEFAULT_ROUTING_PER_MB);

        let entry = ReserveBatchEntry {
            client_pubkey: client, highest_seq: 1, bytes,
            merkle_leaf_hash: [0u8; 32], session_id: [5u8; 16], record_count: 1,
        };

        let (c_pda, c_bump) = Pubkey::find_program_address(
            &[b"claim_commitment", relay.pubkey().as_ref(), &epoch.to_le_bytes()], &id());
        let (service_auth, _) = Pubkey::find_program_address(&[b"mint_authority"], &id());
        let (claim_state_pda, _) = Pubkey::find_program_address(
            &[b"claim_state", &client, relay.pubkey().as_ref()], &id());
        let (reservation_pda, _) = Pubkey::find_program_address(&[b"reservation", &client], &id());

        let fund_hold        = Keypair::new().pubkey();
        let user_escrow      = Keypair::new().pubkey();
        let user_escrow_tok  = Keypair::new().pubkey();
        let spender_registry = Keypair::new().pubkey();
        let user_pk          = Pubkey::new_from_array(client);

        let mut pt = program_test();
        // bandwidth_amount one base unit short of the derived hold.
        pt.add_account(c_pda, commitment_account(&relay.pubkey(), epoch, derived - 1, bytes, c_bump));
        pt.add_account(fund_hold,   stub_account(mock_escrow_id(), 8));
        pt.add_account(user_escrow, stub_account(mock_escrow_id(), 8));
        pt.add_account(user_escrow_tok,  stub_account(solana_sdk::system_program::id(), 0));
        pt.add_account(spender_registry, stub_account(solana_sdk::system_program::id(), 0));
        pt.add_account(user_pk,          stub_account(solana_sdk::system_program::id(), 0));

        let (mut banks, payer, bh) = pt.start().await;
        banks.process_transaction(Transaction::new_signed_with_payer(
            &[solana_sdk::system_instruction::transfer(&payer.pubkey(), &relay.pubkey(), 2_000_000_000)],
            Some(&payer.pubkey()), &[&payer], bh,
        )).await.expect("fund relay");
        let bh = banks.get_latest_blockhash().await.unwrap();

        let ix = Instruction {
            program_id: id(),
            accounts: vec![
                AccountMeta::new(relay.pubkey(), true),
                AccountMeta::new(c_pda, false),
                AccountMeta::new_readonly(mock_escrow_id(), false),
                AccountMeta::new_readonly(service_auth, false),
                AccountMeta::new_readonly(spender_registry, false),
                AccountMeta::new_readonly(solana_sdk::system_program::id(), false),
                AccountMeta::new_readonly(user_pk, false),
                AccountMeta::new(claim_state_pda, false),
                AccountMeta::new(user_escrow, false),
                AccountMeta::new(fund_hold, false),
                AccountMeta::new_readonly(user_escrow_tok, false),
                AccountMeta::new(reservation_pda, false),
            ],
            data: borsh::to_vec(&RewardsInstruction::ReserveBatch {
                claim_epoch: epoch, entries: vec![entry],
            }).expect("encode"),
        };
        let res = banks.process_transaction(Transaction::new_signed_with_payer(
            &[ix], Some(&relay.pubkey()), &[&relay], bh,
        )).await;
        assert!(res.is_err(), "a hold exceeding bandwidth_amount must be rejected");
    }
}

#[cfg(test)]
mod release_claim_integration_tests {
    //! End-to-end SUCCESS path for ReleaseClaim (disc 2) — the PAID release that
    //! burns the escrow hold and mints $FLOW 70/30. Changed in Task 9 (derive from
    //! pinned rate; cap on bandwidth_amount). Existing tests only covered its
    //! arithmetic/merkle logic; this drives the real mint through the runtime past
    //! the matured dispute window.
    //!
    //! Mock program at the escrow id absorbs the burn_held_funds CPI (rewards-v2's
    //! job is to derive + forward + mint; the escrow's burn accounting is its own).
    //! Sub-1 GB bytes skip the repflow-token CPI. SPL-Token mint is real.
    use super::*;
    use solana_program::{account_info::AccountInfo, entrypoint::ProgramResult,
        program_option::COption, program_pack::Pack};
    use solana_program_test::*;
    use solana_sdk::{
        account::Account,
        instruction::{AccountMeta, Instruction},
        signature::{Keypair, Signer},
        transaction::Transaction,
    };
    use crate::{id, process_instruction, RewardsInstruction};

    fn mock_escrow_id() -> Pubkey { Pubkey::new_from_array([7u8; 32]) }
    fn mock_ok(_pid: &Pubkey, _a: &[AccountInfo], _d: &[u8]) -> ProgramResult { Ok(()) }

    fn program_test() -> ProgramTest {
        let mut pt = ProgramTest::new("freeflow_rewards_v2", id(), processor!(process_instruction));
        pt.add_program("mock_escrow", mock_escrow_id(), processor!(mock_ok));
        pt
    }

    fn flow_mint_account(auth: &Pubkey) -> Account {
        let mut d = vec![0u8; spl_token::state::Mint::LEN];
        spl_token::state::Mint { mint_authority: COption::Some(*auth), supply: 0,
            decimals: FLOW_DECIMALS as u8, is_initialized: true, freeze_authority: COption::None }
            .pack_into_slice(&mut d);
        Account { lamports: 10_000_000, data: d, owner: spl_token::id(), executable: false, rent_epoch: 0 }
    }
    fn spl_token_account(mint: &Pubkey, owner: &Pubkey) -> Account {
        let mut d = vec![0u8; spl_token::state::Account::LEN];
        spl_token::state::Account { mint: *mint, owner: *owner, amount: 0, delegate: COption::None,
            state: spl_token::state::AccountState::Initialized, is_native: COption::None,
            delegated_amount: 0, close_authority: COption::None }.pack_into_slice(&mut d);
        Account { lamports: 10_000_000, data: d, owner: spl_token::id(), executable: false, rent_epoch: 0 }
    }
    fn repflow_user_account(balance: u64) -> Account {
        let mut d = vec![0u8; 48];
        d[40..48].copy_from_slice(&balance.to_le_bytes());
        // F-1: owned by the real repflow-token program (see uptime module note).
        Account { lamports: 1_000_000, data: d, owner: REPFLOW_PROGRAM_ID, executable: false, rent_epoch: 0 }
    }
    fn stub(owner: Pubkey, len: usize) -> Account {
        Account { lamports: 1_000_000, data: vec![0u8; len], owner, executable: false, rent_epoch: 0 }
    }
    async fn token_balance(banks: &mut BanksClient, pk: Pubkey) -> u64 {
        let a = banks.get_account(pk).await.unwrap().unwrap();
        spl_token::state::Account::unpack(&a.data).unwrap().amount
    }

    fn commitment_account(relay: &Pubkey, epoch: u64, root: [u8;32], bandwidth: u64, total_bytes: u64, bump: u8) -> Account {
        commitment_account_n(relay, epoch, root, bandwidth, total_bytes, bump, 1)
    }
    /// Same, with an explicit `reserved_count` so a multi-client epoch can be
    /// exercised — that is the only shape in which the Complete latch bites.
    fn commitment_account_n(
        relay: &Pubkey, epoch: u64, root: [u8;32], bandwidth: u64, total_bytes: u64,
        bump: u8, reserved: u32,
    ) -> Account {
        let c = ClaimCommitment {
            relay_pubkey: relay.to_bytes(), claim_epoch: epoch, merkle_root: root,
            client_count: reserved,
            bandwidth_amount: bandwidth, uptime_amount: 0, total_bytes, uptime_hours: 0,
            routing_per_mb: DEFAULT_ROUTING_PER_MB, uptime_per_hour: DEFAULT_UPTIME_PER_HOUR,
            committed_at: 0, uptime_paid: false, reserved_count: reserved, released_count: 0,
            released_amount: 0, released_bytes: 0, status: ClaimCommitmentStatus::Active,
            dispute_deadline: 0, bump, // deadline 0 => matured (now >= 0), releases allowed
        };
        let data = borsh::to_vec(&c).unwrap();
        let mut p = vec![0u8; CLAIM_COMMITMENT_SIZE]; p[..data.len()].copy_from_slice(&data);
        Account { lamports: 10_000_000, data: p, owner: id(), executable: false, rent_epoch: 0 }
    }
    fn claim_state_account(client: [u8;32], relay: &Pubkey, bump: u8) -> Account {
        let cs = UserRelayClaimState { user: client, relay: relay.to_bytes(), last_claimed_seq: 0,
            total_claimed_bytes: 0, last_claim_slot: 0, last_release_epoch: 0, bump };
        let data = borsh::to_vec(&cs).unwrap();
        let mut p = vec![0u8; USER_RELAY_CLAIM_STATE_SIZE]; p[..data.len()].copy_from_slice(&data);
        Account { lamports: 1_000_000, data: p, owner: id(), executable: false, rent_epoch: 0 }
    }

    #[tokio::test]
    async fn release_claim_success_mints_70_30_after_dispute_window() {
        let relay = Keypair::new();
        let epoch = 6_161u64;
        let client = [21u8; 32];
        let bytes = 400_000_000u64; // < 1 GB
        let derived = derive_reward_amount(bytes, DEFAULT_ROUTING_PER_MB);

        let release = ClientReleaseOnChain {
            client_pubkey: client, session_id: [2u8;16], batch_nonce: 1, total_bytes: bytes,
            merkle_proof: vec![], client_signature: [1u8;64], device_uuid: [0u8;16], record_count: 1,
        };
        let root = compute_merkle_leaf_hash_from_release(&release); // single-leaf tree

        let (c_pda, c_bump) = Pubkey::find_program_address(&[b"claim_commitment", relay.pubkey().as_ref(), &epoch.to_le_bytes()], &id());
        let (service_auth, _) = Pubkey::find_program_address(&[b"mint_authority"], &id());
        let (cs_pda, cs_bump) = Pubkey::find_program_address(&[b"claim_state", &client, relay.pubkey().as_ref()], &id());
        let flow_mint = Keypair::new().pubkey();
        let relay_tok = Keypair::new().pubkey();
        // H-1: reward_treasury must BE the foundation's canonical $FLOW ATA —
        // a random keypair now fails Custom(50). Derived from literal bytes,
        // not from constants.rs, so a wrong program id baked into the constants
        // is caught here rather than silently agreed with.
        let treas_tok = Pubkey::find_program_address(
            &[
                FOUNDATION_PUBKEY.as_ref(),
                spl_token::id().as_ref(),
                flow_mint.as_ref(),
            ],
            &Pubkey::new_from_array([
                140, 151, 37, 143, 78, 36, 137, 241, 187, 61, 16, 41, 20, 142, 13, 131,
                11, 90, 19, 153, 218, 255, 16, 132, 4, 142, 123, 216, 219, 233, 248, 89,
            ]),
        ).0;
        let repflow = Pubkey::find_program_address(&[b"repflow_user", relay.pubkey().as_ref()], &REPFLOW_PROGRAM_ID).0;
        let s = Keypair::new().pubkey();
        let fund_hold = Keypair::new().pubkey();
        let user_escrow = Keypair::new().pubkey();
        let user_escrow_tok = Keypair::new().pubkey();

        let mut pt = program_test();
        pt.add_account(c_pda, commitment_account(&relay.pubkey(), epoch, root, derived, bytes, c_bump));
        pt.add_account(cs_pda, claim_state_account(client, &relay.pubkey(), cs_bump));
        pt.add_account(repflow, repflow_user_account(MIN_RELAY_REPFLOW));
        pt.add_account(flow_mint, flow_mint_account(&service_auth));
        pt.add_account(relay_tok, spl_token_account(&flow_mint, &relay.pubkey()));
        pt.add_account(treas_tok, spl_token_account(&flow_mint, &FOUNDATION_PUBKEY));
        pt.add_account(fund_hold, stub(mock_escrow_id(), 8));       // burn CPI writable
        pt.add_account(user_escrow, stub(mock_escrow_id(), 8));      // burn CPI writable
        pt.add_account(user_escrow_tok, stub(mock_escrow_id(), 8));  // burn CPI writable

        let (mut banks, payer, bh) = pt.start().await;
        banks.process_transaction(Transaction::new_signed_with_payer(
            &[solana_sdk::system_instruction::transfer(&payer.pubkey(), &relay.pubkey(), 2_000_000_000)],
            Some(&payer.pubkey()), &[&payer], bh)).await.unwrap();
        let bh = banks.get_latest_blockhash().await.unwrap();

        let ix = Instruction { program_id: id(), accounts: vec![
            AccountMeta::new(relay.pubkey(), true),                              // 0 relay
            AccountMeta::new(c_pda, false),                                      // 1 commitment
            AccountMeta::new_readonly(mock_escrow_id(), false),                  // 2 escrow_program
            AccountMeta::new_readonly(service_auth, false),                      // 3 service_authority
            AccountMeta::new_readonly(s, false),                                 // 4 spender_registry
            AccountMeta::new_readonly(spl_token::id(), false),                   // 5 token_program
            AccountMeta::new(flow_mint, false),                                  // 6 flow_mint
            AccountMeta::new_readonly(s, false),                                 // 7 repflow_program
            AccountMeta::new_readonly(s, false),                                 // 8 repflow_config
            AccountMeta::new_readonly(repflow, false),                           // 9 relay_repflow_user
            AccountMeta::new_readonly(s, false),                                 // 10 slash_authority
            AccountMeta::new(relay_tok, false),                                  // 11 reward_relay
            AccountMeta::new(treas_tok, false),                                  // 12 reward_treasury
            AccountMeta::new_readonly(solana_sdk::system_program::id(), false),  // 13 system
            AccountMeta::new_readonly(Pubkey::new_from_array(client), false),    // user_wallet
            AccountMeta::new(cs_pda, false),                                     // claim_state
            AccountMeta::new(user_escrow, false),                               // user_escrow (burn w)
            AccountMeta::new(fund_hold, false),                                 // fund_hold (burn w)
            AccountMeta::new(user_escrow_tok, false),                          // user_escrow_token (burn w)
        ], data: borsh::to_vec(&RewardsInstruction::ReleaseClaim { claim_epoch: epoch, releases: vec![release] }).unwrap() };
        banks.process_transaction(Transaction::new_signed_with_payer(
            &[ix], Some(&relay.pubkey()), &[&relay], bh)).await.expect("ReleaseClaim success must mint");

        let want_relay = derived * RELAY_SPLIT_PCT / 100;
        assert_eq!(token_balance(&mut banks, relay_tok).await, want_relay, "relay 70%");
        assert_eq!(token_balance(&mut banks, treas_tok).await, derived - want_relay, "treasury 30%");
        let c = ClaimCommitment::try_from_slice(&banks.get_account(c_pda).await.unwrap().unwrap().data[..CLAIM_COMMITMENT_SIZE]).unwrap();
        assert_eq!(c.released_count, 1, "released_count advanced");
        assert_eq!(c.status, ClaimCommitmentStatus::Complete, "single client fully released -> Complete");
    }

    /// A relay must not be able to release ANOTHER relay's commitment.
    ///
    /// Nothing bound `claim_commitment` to the signer: the handler checked only
    /// `claim_epoch` and `status`, and did not pin `claim_state` either. Every
    /// other input is public — the victim's own ReserveBatch instruction data
    /// carries the whole leaf, a single-client epoch has an EMPTY proof with
    /// `root == leaf`, and `client_signature` is only checked non-zero. So an
    /// attacker could release a matured epoch it did not create, burning the
    /// client's escrow and minting the 70% into its own `reward_relay`.
    ///
    /// Here the attacker signs with its own keypair while passing the VICTIM's
    /// commitment PDA. Everything else is well-formed, so only the binding can
    /// reject it.
    #[tokio::test]
    async fn release_claim_rejects_another_relays_commitment() {
        let victim   = Keypair::new();
        let attacker = Keypair::new();
        let epoch = 911u64;
        let client = [23u8; 32];
        let bytes = 500_000_000u64;

        let release = ClientReleaseOnChain {
            client_pubkey: client, session_id: [2u8; 16], batch_nonce: 1,
            total_bytes: bytes, merkle_proof: vec![], client_signature: [1u8; 64],
            device_uuid: [0u8; 16], record_count: 1,
        };
        let root = compute_merkle_leaf_hash_from_release(&release);
        let derived = derive_reward_amount(bytes, DEFAULT_ROUTING_PER_MB);

        // The VICTIM's commitment PDA — public, derivable by anyone.
        let (victim_c_pda, c_bump) = Pubkey::find_program_address(
            &[b"claim_commitment", victim.pubkey().as_ref(), &epoch.to_le_bytes()], &id());
        let (service_auth, _) = Pubkey::find_program_address(&[b"mint_authority"], &id());
        // claim_state keyed to the ATTACKER, which is what made AlreadyReleased
        // useless as a defence.
        let (cs_pda, cs_bump) = Pubkey::find_program_address(
            &[b"claim_state", &client, attacker.pubkey().as_ref()], &id());
        let flow_mint = Keypair::new().pubkey();
        let attacker_tok = Keypair::new().pubkey();
        let treas_tok = Pubkey::find_program_address(
            &[FOUNDATION_PUBKEY.as_ref(), spl_token::id().as_ref(), flow_mint.as_ref()],
            &Pubkey::new_from_array([
                140, 151, 37, 143, 78, 36, 137, 241, 187, 61, 16, 41, 20, 142, 13, 131,
                11, 90, 19, 153, 218, 255, 16, 132, 4, 142, 123, 216, 219, 233, 248, 89,
            ]),
        ).0;
        let repflow = Pubkey::find_program_address(
            &[b"repflow_user", attacker.pubkey().as_ref()], &REPFLOW_PROGRAM_ID).0;
        let s = Keypair::new().pubkey();
        let fund_hold = Keypair::new().pubkey();
        let user_escrow = Keypair::new().pubkey();
        let user_escrow_tok = Keypair::new().pubkey();

        let mut pt = program_test();
        pt.add_account(victim_c_pda, commitment_account(&victim.pubkey(), epoch, root, derived, bytes, c_bump));
        pt.add_account(cs_pda, claim_state_account(client, &attacker.pubkey(), cs_bump));
        pt.add_account(repflow, repflow_user_account(MIN_RELAY_REPFLOW));
        pt.add_account(flow_mint, flow_mint_account(&service_auth));
        pt.add_account(attacker_tok, spl_token_account(&flow_mint, &attacker.pubkey()));
        pt.add_account(treas_tok, spl_token_account(&flow_mint, &FOUNDATION_PUBKEY));
        pt.add_account(fund_hold, stub(mock_escrow_id(), 8));
        pt.add_account(user_escrow, stub(mock_escrow_id(), 8));
        pt.add_account(user_escrow_tok, stub(mock_escrow_id(), 8));

        let (mut banks, payer, bh) = pt.start().await;
        banks.process_transaction(Transaction::new_signed_with_payer(
            &[solana_sdk::system_instruction::transfer(&payer.pubkey(), &attacker.pubkey(), 2_000_000_000)],
            Some(&payer.pubkey()), &[&payer], bh)).await.unwrap();
        let bh = banks.get_latest_blockhash().await.unwrap();

        let ix = Instruction { program_id: id(), accounts: vec![
            AccountMeta::new(attacker.pubkey(), true),      // signer = ATTACKER
            AccountMeta::new(victim_c_pda, false),          // commitment = VICTIM's
            AccountMeta::new_readonly(mock_escrow_id(), false),
            AccountMeta::new_readonly(service_auth, false),
            AccountMeta::new_readonly(s, false),
            AccountMeta::new_readonly(spl_token::id(), false),
            AccountMeta::new(flow_mint, false),
            AccountMeta::new_readonly(s, false),
            AccountMeta::new_readonly(s, false),
            AccountMeta::new_readonly(repflow, false),
            AccountMeta::new_readonly(s, false),
            AccountMeta::new(attacker_tok, false),          // reward_relay = ATTACKER's
            AccountMeta::new(treas_tok, false),
            AccountMeta::new_readonly(solana_sdk::system_program::id(), false),
            AccountMeta::new_readonly(Pubkey::new_from_array(client), false),
            AccountMeta::new(cs_pda, false),
            AccountMeta::new(user_escrow, false),
            AccountMeta::new(fund_hold, false),
            AccountMeta::new(user_escrow_tok, false),
        ], data: borsh::to_vec(&RewardsInstruction::ReleaseClaim {
            claim_epoch: epoch, releases: vec![release] }).unwrap() };

        banks.process_transaction(Transaction::new_signed_with_payer(
            &[ix], Some(&attacker.pubkey()), &[&attacker], bh)).await
            .expect_err(
                "a relay must NOT be able to release another relay's commitment — \
                 this is direct theft of the victim's 70% plus the client's escrow");

        assert_eq!(
            token_balance(&mut banks, attacker_tok).await, 0,
            "nothing may be minted to the attacker"
        );
    }

    /// H-1: `ReleaseClaim` must refuse a `reward_treasury` that is not the
    /// foundation's canonical ATA.
    ///
    /// The success test above does NOT cover this — verified by deleting the
    /// pin and watching it stay green, because it passes the correct ATA. Only
    /// a negative test guards the check, and this is the sink that arms the
    /// moment the paid path first succeeds.
    ///
    /// Unpinned, a relay passes a token account it owns and keeps the
    /// foundation's 30% on top of its own 70% — `cpi_mint_flow` validates
    /// nothing about the destination and signs with the program's own
    /// `mint_authority` PDA, so the mint simply succeeds.
    #[tokio::test]
    async fn release_claim_rejects_a_treasury_the_relay_controls() {
        let relay = Keypair::new();
        let epoch = 910u64;
        let client = [22u8; 32];
        let bytes = 500_000_000u64;

        let release = ClientReleaseOnChain {
            client_pubkey: client, session_id: [2u8; 16], batch_nonce: 1,
            total_bytes: bytes, merkle_proof: vec![], client_signature: [1u8; 64],
            device_uuid: [0u8; 16], record_count: 1,
        };
        let root = compute_merkle_leaf_hash_from_release(&release);
        let derived = derive_reward_amount(bytes, DEFAULT_ROUTING_PER_MB);

        let (c_pda, c_bump) = Pubkey::find_program_address(
            &[b"claim_commitment", relay.pubkey().as_ref(), &epoch.to_le_bytes()], &id());
        let (service_auth, _) = Pubkey::find_program_address(&[b"mint_authority"], &id());
        let (cs_pda, cs_bump) = Pubkey::find_program_address(
            &[b"claim_state", &client, relay.pubkey().as_ref()], &id());
        let flow_mint = Keypair::new().pubkey();
        let relay_tok = Keypair::new().pubkey();
        // The attack: a token account the RELAY owns, passed as the treasury.
        let rogue_treasury = Keypair::new().pubkey();
        let repflow = Pubkey::find_program_address(
            &[b"repflow_user", relay.pubkey().as_ref()], &REPFLOW_PROGRAM_ID).0;
        let s = Keypair::new().pubkey();
        let fund_hold = Keypair::new().pubkey();
        let user_escrow = Keypair::new().pubkey();
        let user_escrow_tok = Keypair::new().pubkey();

        let mut pt = program_test();
        pt.add_account(c_pda, commitment_account(&relay.pubkey(), epoch, root, derived, bytes, c_bump));
        pt.add_account(cs_pda, claim_state_account(client, &relay.pubkey(), cs_bump));
        pt.add_account(repflow, repflow_user_account(MIN_RELAY_REPFLOW));
        pt.add_account(flow_mint, flow_mint_account(&service_auth));
        pt.add_account(relay_tok, spl_token_account(&flow_mint, &relay.pubkey()));
        pt.add_account(rogue_treasury, spl_token_account(&flow_mint, &relay.pubkey()));
        pt.add_account(fund_hold, stub(mock_escrow_id(), 8));
        pt.add_account(user_escrow, stub(mock_escrow_id(), 8));
        pt.add_account(user_escrow_tok, stub(mock_escrow_id(), 8));

        let (mut banks, payer, bh) = pt.start().await;
        banks.process_transaction(Transaction::new_signed_with_payer(
            &[solana_sdk::system_instruction::transfer(&payer.pubkey(), &relay.pubkey(), 2_000_000_000)],
            Some(&payer.pubkey()), &[&payer], bh)).await.unwrap();
        let bh = banks.get_latest_blockhash().await.unwrap();

        let ix = Instruction { program_id: id(), accounts: vec![
            AccountMeta::new(relay.pubkey(), true),
            AccountMeta::new(c_pda, false),
            AccountMeta::new_readonly(mock_escrow_id(), false),
            AccountMeta::new_readonly(service_auth, false),
            AccountMeta::new_readonly(s, false),
            AccountMeta::new_readonly(spl_token::id(), false),
            AccountMeta::new(flow_mint, false),
            AccountMeta::new_readonly(s, false),
            AccountMeta::new_readonly(s, false),
            AccountMeta::new_readonly(repflow, false),
            AccountMeta::new_readonly(s, false),
            AccountMeta::new(relay_tok, false),
            AccountMeta::new(rogue_treasury, false),
            AccountMeta::new_readonly(solana_sdk::system_program::id(), false),
            AccountMeta::new_readonly(Pubkey::new_from_array(client), false),
            AccountMeta::new(cs_pda, false),
            AccountMeta::new(user_escrow, false),
            AccountMeta::new(fund_hold, false),
            AccountMeta::new(user_escrow_tok, false),
        ], data: borsh::to_vec(&RewardsInstruction::ReleaseClaim {
            claim_epoch: epoch, releases: vec![release] }).unwrap() };

        let err = banks.process_transaction(Transaction::new_signed_with_payer(
            &[ix], Some(&relay.pubkey()), &[&relay], bh)).await
            .expect_err("a relay-controlled treasury must be rejected");
        let want = format!("Custom({})", RewardsError::InvalidTreasuryAccount as u32);
        assert!(
            format!("{err:?}").contains(&want),
            "expected {want} (InvalidTreasuryAccount), got {err:?}"
        );
        assert_eq!(token_balance(&mut banks, rogue_treasury).await, 0, "nothing minted to it");
    }

    /// The Complete latch, at the CALL SITE.
    ///
    /// `complete_latch_tests` covers the predicate; this covers the wiring, and
    /// the two are not interchangeable — reverting the guard at the call site
    /// leaves the predicate tests green. Verified by doing exactly that.
    ///
    /// Two clients reserved, one released. The relay fits one paid release per
    /// transaction, so this is the real shape of a 2-client epoch. Before the
    /// guard, the commitment latched Complete here and the second transaction
    /// hit `_ => EpochComplete`, stranding the other client's FundHold with no
    /// instruction able to recover it.
    #[tokio::test]
    async fn first_release_of_a_two_client_epoch_leaves_it_releasing() {
        let relay = Keypair::new();
        let epoch = 909u64;
        let client = [21u8; 32];
        let bytes = 500_000_000u64;

        let release = ClientReleaseOnChain {
            client_pubkey: client, session_id: [2u8; 16], batch_nonce: 1,
            total_bytes: bytes, merkle_proof: vec![], client_signature: [1u8; 64],
            device_uuid: [0u8; 16], record_count: 1,
        };
        let root = compute_merkle_leaf_hash_from_release(&release);
        let derived = derive_reward_amount(bytes, DEFAULT_ROUTING_PER_MB);

        let (c_pda, c_bump) = Pubkey::find_program_address(
            &[b"claim_commitment", relay.pubkey().as_ref(), &epoch.to_le_bytes()], &id());
        let (service_auth, _) = Pubkey::find_program_address(&[b"mint_authority"], &id());
        let (cs_pda, cs_bump) = Pubkey::find_program_address(
            &[b"claim_state", &client, relay.pubkey().as_ref()], &id());
        let flow_mint = Keypair::new().pubkey();
        let relay_tok = Keypair::new().pubkey();
        let treas_tok = Pubkey::find_program_address(
            &[FOUNDATION_PUBKEY.as_ref(), spl_token::id().as_ref(), flow_mint.as_ref()],
            &Pubkey::new_from_array([
                140, 151, 37, 143, 78, 36, 137, 241, 187, 61, 16, 41, 20, 142, 13, 131,
                11, 90, 19, 153, 218, 255, 16, 132, 4, 142, 123, 216, 219, 233, 248, 89,
            ]),
        ).0;
        let repflow = Pubkey::find_program_address(
            &[b"repflow_user", relay.pubkey().as_ref()], &REPFLOW_PROGRAM_ID).0;
        let s = Keypair::new().pubkey();
        let fund_hold = Keypair::new().pubkey();
        let user_escrow = Keypair::new().pubkey();
        let user_escrow_tok = Keypair::new().pubkey();

        let mut pt = program_test();
        // TWO clients reserved — the shape that made this bite.
        pt.add_account(c_pda, commitment_account_n(&relay.pubkey(), epoch, root, derived * 2, bytes * 2, c_bump, 2));
        pt.add_account(cs_pda, claim_state_account(client, &relay.pubkey(), cs_bump));
        pt.add_account(repflow, repflow_user_account(MIN_RELAY_REPFLOW));
        pt.add_account(flow_mint, flow_mint_account(&service_auth));
        pt.add_account(relay_tok, spl_token_account(&flow_mint, &relay.pubkey()));
        pt.add_account(treas_tok, spl_token_account(&flow_mint, &FOUNDATION_PUBKEY));
        pt.add_account(fund_hold, stub(mock_escrow_id(), 8));
        pt.add_account(user_escrow, stub(mock_escrow_id(), 8));
        pt.add_account(user_escrow_tok, stub(mock_escrow_id(), 8));

        let (mut banks, payer, bh) = pt.start().await;
        banks.process_transaction(Transaction::new_signed_with_payer(
            &[solana_sdk::system_instruction::transfer(&payer.pubkey(), &relay.pubkey(), 2_000_000_000)],
            Some(&payer.pubkey()), &[&payer], bh)).await.unwrap();
        let bh = banks.get_latest_blockhash().await.unwrap();

        let ix = Instruction { program_id: id(), accounts: vec![
            AccountMeta::new(relay.pubkey(), true),
            AccountMeta::new(c_pda, false),
            AccountMeta::new_readonly(mock_escrow_id(), false),
            AccountMeta::new_readonly(service_auth, false),
            AccountMeta::new_readonly(s, false),
            AccountMeta::new_readonly(spl_token::id(), false),
            AccountMeta::new(flow_mint, false),
            AccountMeta::new_readonly(s, false),
            AccountMeta::new_readonly(s, false),
            AccountMeta::new_readonly(repflow, false),
            AccountMeta::new_readonly(s, false),
            AccountMeta::new(relay_tok, false),
            AccountMeta::new(treas_tok, false),
            AccountMeta::new_readonly(solana_sdk::system_program::id(), false),
            AccountMeta::new_readonly(Pubkey::new_from_array(client), false),
            AccountMeta::new(cs_pda, false),
            AccountMeta::new(user_escrow, false),
            AccountMeta::new(fund_hold, false),
            AccountMeta::new(user_escrow_tok, false),
        ], data: borsh::to_vec(&RewardsInstruction::ReleaseClaim {
            claim_epoch: epoch, releases: vec![release] }).unwrap() };
        banks.process_transaction(Transaction::new_signed_with_payer(
            &[ix], Some(&relay.pubkey()), &[&relay], bh)).await.expect("first release must land");

        let c = ClaimCommitment::try_from_slice(
            &banks.get_account(c_pda).await.unwrap().unwrap().data[..CLAIM_COMMITMENT_SIZE]).unwrap();
        assert_eq!(c.released_count, 1, "one of two released");
        assert_eq!(
            c.status, ClaimCommitmentStatus::Releasing,
            "1 of 2 reserved clients released — the commitment MUST stay Releasing. \
             Latching Complete here sends the second transaction to EpochComplete \
             and strands that client's FundHold permanently"
        );
    }

    // ── multi-transaction latch guards ──────────────────────────────────
    //
    // `first_release_of_a_two_client_epoch_leaves_it_releasing` above proves
    // transaction 1 does not latch. These two prove the consequence that
    // actually matters: transaction 2 LANDS, and the second client's FundHold
    // is really burned. They also cover the probationary branch (handlers.rs
    // :1217), which is the branch RackNerd takes and which nothing else
    // exercises.
    //
    // Unlike the other tests in this module these register a mock escrow that
    // WRITES — it stamps HoldStatus::Burned — so "the client was charged" is
    // asserted against account bytes rather than assumed from an Ok return.
    //
    // Mutation check (run before trusting these): revert either latch site to
    // an unconditional `commitment.status = Complete`. Transaction 1's
    // `assert_eq!(c.status, Releasing)` fails, and transaction 2 fails outright
    // with EpochComplete.


    use crate::merkle::hash_pair;

    /// FundHold (user-escrow) byte layout: 8 disc | 32 user | 8 amount |
    /// 32 claim_hash | 16 session_id | 8 created_at | 1 status = 105.
    const FH_LEN: usize = 105;
    /// The mock parks the claim_hash that crossed the CPI boundary on the
    /// user_escrow stub. It cannot leave it on the FundHold any more — that
    /// account is closed by the time the test looks.
    const UE_RECEIPT_LEN: usize = 32;

    /// Emulates user_escrow::burn_held_funds AFTER the close change: refunds the
    /// FundHold's rent to the recipient rewards-v2 forwarded, wipes its data, and
    /// records the claim_hash that crossed the CPI boundary on the user_escrow
    /// stub. Zero lamports ⇒ the runtime reaps the account, so
    /// `get_account(fund_hold)` is None afterwards.
    ///
    /// HONEST SCOPE: this is a STAND-IN and does NOT prove Anchor's
    /// `close = rent_recipient` works. The real user-escrow code never executes
    /// in this suite — there is no .so to load (the pinned solana_rbpf 0.8.3
    /// understands only SBPF v1/v2, and the built program is v3), so this
    /// registers a hand-written processor at the escrow id. What it DOES pin is
    /// the rewards-v2 half of the contract: the CPI carries exactly 9 accounts,
    /// and account 8 is a writable rent recipient the lamports can land on.
    /// The `close` itself is proven separately, on a real validator, by
    /// `tests/user-escrow.ts` — it cannot be executed here because the real .so
    /// will not load into ProgramTest (SBPF v3 vs the pinned rbpf).
    ///
    /// CPI data = [disc:8][claim_hash:32]; accounts =
    /// [mint_authority, user, user_escrow, user_escrow_token, fund_hold,
    ///  spender_registry, token_mint, token_program, rent_recipient]
    /// → fund_hold is index 4, rent_recipient index 8.
    fn mock_escrow_burn(_pid: &Pubkey, accounts: &[AccountInfo], data: &[u8]) -> ProgramResult {
        assert_eq!(data.len(), 40, "burn_held_funds CPI data must be disc+claim_hash");
        assert_eq!(
            accounts.len(), 9,
            "burn_held_funds must receive 9 accounts — the 9th is the rent recipient \
             the closed FundHold refunds to. Without it the 105-byte PDA is stranded."
        );

        {
            let mut ue = accounts[2].data.borrow_mut();
            assert!(ue.len() >= UE_RECEIPT_LEN,
                "the user_escrow stub must be wide enough to hold the burn receipt");
            ue[..UE_RECEIPT_LEN].copy_from_slice(&data[8..40]);
        }

        // Stand in for `close = rent_recipient`. No realloc(0): program-test runs
        // native processors over copied buffers, where AccountInfo::realloc's
        // length write past the data pointer is not valid.
        let hold = &accounts[4];
        let rent_recipient = &accounts[8];
        let refund = hold.lamports();
        **rent_recipient.try_borrow_mut_lamports()? += refund;
        **hold.try_borrow_mut_lamports()? -= refund;
        hold.data.borrow_mut().fill(0);
        Ok(())
    }

    fn program_test_burn() -> ProgramTest {
        let mut pt = ProgramTest::new("freeflow_rewards_v2", id(), processor!(process_instruction));
        pt.add_program("mock_escrow", mock_escrow_id(), processor!(mock_escrow_burn));
        pt
    }

    fn fund_hold_account() -> Account {
        Account { lamports: 1_000_000, data: vec![0u8; FH_LEN], owner: mock_escrow_id(),
                  executable: false, rent_epoch: 0 }
    }

    #[tokio::test]
    async fn two_paid_clients_both_burn_across_two_transactions() {
        let relay = Keypair::new();
        let epoch = 6_162u64;
        let c1 = [21u8; 32];
        let c2 = [31u8; 32];
        let bytes = 500_000_000u64; // < BYTES_PER_FLOW ⇒ repFlow CPI skipped
        let derived = derive_reward_amount(bytes, DEFAULT_ROUTING_PER_MB);

        let mut r1 = ClientReleaseOnChain {
            client_pubkey: c1, session_id: [2u8; 16], batch_nonce: 1, total_bytes: bytes,
            merkle_proof: vec![], client_signature: [1u8; 64], device_uuid: [0u8; 16], record_count: 1,
        };
        let mut r2 = ClientReleaseOnChain {
            client_pubkey: c2, session_id: [3u8; 16], batch_nonce: 2, total_bytes: bytes,
            merkle_proof: vec![], client_signature: [1u8; 64], device_uuid: [0u8; 16], record_count: 1,
        };
        let l1 = compute_merkle_leaf_hash_from_release(&r1);
        let l2 = compute_merkle_leaf_hash_from_release(&r2);
        let root = hash_pair(&l1, &l2);
        r1.merkle_proof = vec![l2];
        r2.merkle_proof = vec![l1];
        assert!(verify_merkle_proof(l1, &r1.merkle_proof, root));
        assert!(verify_merkle_proof(l2, &r2.merkle_proof, root));

        let (c_pda, c_bump) = Pubkey::find_program_address(
            &[b"claim_commitment", relay.pubkey().as_ref(), &epoch.to_le_bytes()], &id());
        let (service_auth, _) = Pubkey::find_program_address(&[b"mint_authority"], &id());
        let (cs1, cs1_b) = Pubkey::find_program_address(
            &[b"claim_state", &c1, relay.pubkey().as_ref()], &id());
        let (cs2, cs2_b) = Pubkey::find_program_address(
            &[b"claim_state", &c2, relay.pubkey().as_ref()], &id());
        let flow_mint = Keypair::new().pubkey();
        let relay_tok = Keypair::new().pubkey();
        let treas_tok = Pubkey::find_program_address(
            &[FOUNDATION_PUBKEY.as_ref(), spl_token::id().as_ref(), flow_mint.as_ref()],
            &Pubkey::new_from_array([
                140, 151, 37, 143, 78, 36, 137, 241, 187, 61, 16, 41, 20, 142, 13, 131,
                11, 90, 19, 153, 218, 255, 16, 132, 4, 142, 123, 216, 219, 233, 248, 89,
            ]),
        ).0;
        let repflow = Pubkey::find_program_address(
            &[b"repflow_user", relay.pubkey().as_ref()], &REPFLOW_PROGRAM_ID).0;
        let (cb_pda, _) = Pubkey::find_program_address(
            &[b"claimable_balance", relay.pubkey().as_ref(), &epoch.to_le_bytes()], &id());
        let s = Keypair::new().pubkey();
        let fh1 = Keypair::new().pubkey();
        let fh2 = Keypair::new().pubkey();
        let ue1 = Keypair::new().pubkey();
        let ue2 = Keypair::new().pubkey();
        let uet1 = Keypair::new().pubkey();
        let uet2 = Keypair::new().pubkey();

        let mut pt = program_test_burn();
        pt.add_account(c_pda, commitment_account_n(
            &relay.pubkey(), epoch, root, derived * 2, bytes * 2, c_bump, 2));
        pt.add_account(cs1, claim_state_account(c1, &relay.pubkey(), cs1_b));
        pt.add_account(cs2, claim_state_account(c2, &relay.pubkey(), cs2_b));
        pt.add_account(repflow, repflow_user_account(MIN_RELAY_REPFLOW));
        pt.add_account(flow_mint, flow_mint_account(&service_auth));
        pt.add_account(relay_tok, spl_token_account(&flow_mint, &relay.pubkey()));
        pt.add_account(treas_tok, spl_token_account(&flow_mint, &FOUNDATION_PUBKEY));
        pt.add_account(fh1, fund_hold_account());
        pt.add_account(fh2, fund_hold_account());
        pt.add_account(ue1, stub(mock_escrow_id(), UE_RECEIPT_LEN));
        pt.add_account(ue2, stub(mock_escrow_id(), UE_RECEIPT_LEN));
        pt.add_account(uet1, stub(mock_escrow_id(), 8));
        pt.add_account(uet2, stub(mock_escrow_id(), 8));

        let (mut banks, payer, bh) = pt.start().await;
        banks.process_transaction(Transaction::new_signed_with_payer(
            &[solana_sdk::system_instruction::transfer(&payer.pubkey(), &relay.pubkey(), 2_000_000_000)],
            Some(&payer.pubkey()), &[&payer], bh)).await.unwrap();
        let bh = banks.get_latest_blockhash().await.unwrap();

        let build = |rel: ClientReleaseOnChain, user: [u8; 32], cs: Pubkey,
                     ue: Pubkey, fh: Pubkey, uet: Pubkey| Instruction {
            program_id: id(),
            accounts: vec![
                AccountMeta::new(relay.pubkey(), true),
                AccountMeta::new(c_pda, false),
                AccountMeta::new_readonly(mock_escrow_id(), false),
                AccountMeta::new_readonly(service_auth, false),
                AccountMeta::new_readonly(s, false),
                AccountMeta::new_readonly(spl_token::id(), false),
                AccountMeta::new(flow_mint, false),
                AccountMeta::new_readonly(s, false),
                AccountMeta::new_readonly(s, false),
                AccountMeta::new_readonly(repflow, false),
                AccountMeta::new_readonly(s, false),
                AccountMeta::new(relay_tok, false),
                AccountMeta::new(treas_tok, false),
                AccountMeta::new_readonly(solana_sdk::system_program::id(), false),
                AccountMeta::new_readonly(Pubkey::new_from_array(user), false),
                AccountMeta::new(cs, false),
                AccountMeta::new(ue, false),
                AccountMeta::new(fh, false),
                AccountMeta::new(uet, false),
                // 19: claimable_balance — the relay sends this unconditionally
                // (sidecar solana.rs:2999) and the handler reads it only on the
                // probationary branch (handlers.rs:1176). Inert above the gate.
                AccountMeta::new(cb_pda, false),
            ],
            data: borsh::to_vec(&RewardsInstruction::ReleaseClaim {
                claim_epoch: epoch, releases: vec![rel] }).unwrap(),
        };

        // ── transaction 1 — client 1 ──
        banks.process_transaction(Transaction::new_signed_with_payer(
            &[build(r1.clone(), c1, cs1, ue1, fh1, uet1)],
            Some(&relay.pubkey()), &[&relay], bh)).await
            .expect("first paid release must land");

        let c = ClaimCommitment::try_from_slice(
            &banks.get_account(c_pda).await.unwrap().unwrap().data[..CLAIM_COMMITMENT_SIZE]).unwrap();
        assert_eq!(c.released_count, 1);
        assert_eq!(c.status, ClaimCommitmentStatus::Releasing,
            "1 of 2 reserved — must stay Releasing or tx2 hits EpochComplete");

        // ── transaction 2 — client 2, same commitment ──
        let bh2 = banks.get_new_latest_blockhash(&bh).await.unwrap();
        banks.process_transaction(Transaction::new_signed_with_payer(
            &[build(r2.clone(), c2, cs2, ue2, fh2, uet2)],
            Some(&relay.pubkey()), &[&relay], bh2)).await
            .expect("SECOND paid release must land — free network use if it reverts");

        let c = ClaimCommitment::try_from_slice(
            &banks.get_account(c_pda).await.unwrap().unwrap().data[..CLAIM_COMMITMENT_SIZE]).unwrap();
        assert_eq!(c.released_count, 2, "both paid clients released");
        assert_eq!(c.status, ClaimCommitmentStatus::Complete, "last release closes the epoch");
        assert_eq!(c.released_amount, derived * 2);
        assert_eq!(c.released_bytes, bytes * 2);

        // Both FundHolds actually burned, each with its own claim_hash. The hold
        // is now CLOSED rather than stamped Burned, so "the client was charged"
        // is asserted as the account's absence plus the receipt the mock parks
        // on user_escrow — the FundHold's own bytes are gone by then.
        for (fh, ue, rel) in [(fh1, ue1, &r1), (fh2, ue2, &r2)] {
            assert!(banks.get_account(fh).await.unwrap().is_none(),
                "every reserved client's FundHold must be closed, not merely marked Burned");
            let a = banks.get_account(ue).await.unwrap().unwrap();
            let want = compute_claim_hash(
                &rel.client_pubkey, &rel.session_id, rel.batch_nonce,
                &compute_merkle_leaf_hash_from_release(rel));
            assert_eq!(&a.data[..UE_RECEIPT_LEN], &want[..],
                "burn CPI must carry this client's claim_hash");
        }

        assert_eq!(token_balance(&mut banks, relay_tok).await, derived * 2 * RELAY_SPLIT_PCT / 100);
        assert_eq!(token_balance(&mut banks, treas_tok).await,
            derived * 2 - derived * 2 * RELAY_SPLIT_PCT / 100);
    }

    #[tokio::test]
    async fn probationary_two_clients_both_defer_across_two_transactions() {
        let relay = Keypair::new();
        let epoch = 6_163u64;
        let c1 = [41u8; 32];
        let c2 = [51u8; 32];
        let bytes = 500_000_000u64;
        let derived = derive_reward_amount(bytes, DEFAULT_ROUTING_PER_MB);

        let mut r1 = ClientReleaseOnChain {
            client_pubkey: c1, session_id: [2u8; 16], batch_nonce: 1, total_bytes: bytes,
            merkle_proof: vec![], client_signature: [1u8; 64], device_uuid: [0u8; 16], record_count: 1,
        };
        let mut r2 = ClientReleaseOnChain {
            client_pubkey: c2, session_id: [3u8; 16], batch_nonce: 2, total_bytes: bytes,
            merkle_proof: vec![], client_signature: [1u8; 64], device_uuid: [0u8; 16], record_count: 1,
        };
        let l1 = compute_merkle_leaf_hash_from_release(&r1);
        let l2 = compute_merkle_leaf_hash_from_release(&r2);
        let root = hash_pair(&l1, &l2);
        r1.merkle_proof = vec![l2];
        r2.merkle_proof = vec![l1];

        let (c_pda, c_bump) = Pubkey::find_program_address(
            &[b"claim_commitment", relay.pubkey().as_ref(), &epoch.to_le_bytes()], &id());
        let (service_auth, _) = Pubkey::find_program_address(&[b"mint_authority"], &id());
        let (cs1, cs1_b) = Pubkey::find_program_address(
            &[b"claim_state", &c1, relay.pubkey().as_ref()], &id());
        let (cs2, cs2_b) = Pubkey::find_program_address(
            &[b"claim_state", &c2, relay.pubkey().as_ref()], &id());
        let (cb_pda, _) = Pubkey::find_program_address(
            &[b"claimable_balance", relay.pubkey().as_ref(), &epoch.to_le_bytes()], &id());
        let flow_mint = Keypair::new().pubkey();
        let relay_tok = Keypair::new().pubkey();
        let treas_tok = Keypair::new().pubkey();
        let repflow = Pubkey::find_program_address(
            &[b"repflow_user", relay.pubkey().as_ref()], &REPFLOW_PROGRAM_ID).0;
        let s = Keypair::new().pubkey();
        let (fh1, fh2) = (Keypair::new().pubkey(), Keypair::new().pubkey());
        let (ue1, ue2) = (Keypair::new().pubkey(), Keypair::new().pubkey());
        let (uet1, uet2) = (Keypair::new().pubkey(), Keypair::new().pubkey());

        let mut pt = program_test_burn();
        pt.add_account(c_pda, commitment_account_n(
            &relay.pubkey(), epoch, root, derived * 2, bytes * 2, c_bump, 2));
        pt.add_account(cs1, claim_state_account(c1, &relay.pubkey(), cs1_b));
        pt.add_account(cs2, claim_state_account(c2, &relay.pubkey(), cs2_b));
        // BELOW the gate — the probationary branch.
        pt.add_account(repflow, repflow_user_account(MIN_RELAY_REPFLOW - 1));
        pt.add_account(flow_mint, flow_mint_account(&service_auth));
        pt.add_account(relay_tok, spl_token_account(&flow_mint, &relay.pubkey()));
        pt.add_account(treas_tok, spl_token_account(&flow_mint, &FOUNDATION_PUBKEY));
        pt.add_account(fh1, fund_hold_account());
        pt.add_account(fh2, fund_hold_account());
        pt.add_account(ue1, stub(mock_escrow_id(), UE_RECEIPT_LEN));
        pt.add_account(ue2, stub(mock_escrow_id(), UE_RECEIPT_LEN));
        pt.add_account(uet1, stub(mock_escrow_id(), 8));
        pt.add_account(uet2, stub(mock_escrow_id(), 8));
        // cb_pda deliberately NOT added: lamports == 0 ⇒ create_pda_account path.

        let (mut banks, payer, bh) = pt.start().await;
        banks.process_transaction(Transaction::new_signed_with_payer(
            &[solana_sdk::system_instruction::transfer(&payer.pubkey(), &relay.pubkey(), 2_000_000_000)],
            Some(&payer.pubkey()), &[&payer], bh)).await.unwrap();
        let bh = banks.get_latest_blockhash().await.unwrap();

        let build = |rel: ClientReleaseOnChain, user: [u8; 32], cs: Pubkey,
                     ue: Pubkey, fh: Pubkey, uet: Pubkey| Instruction {
            program_id: id(),
            accounts: vec![
                AccountMeta::new(relay.pubkey(), true),
                AccountMeta::new(c_pda, false),
                AccountMeta::new_readonly(mock_escrow_id(), false),
                AccountMeta::new_readonly(service_auth, false),
                AccountMeta::new_readonly(s, false),
                AccountMeta::new_readonly(spl_token::id(), false),
                AccountMeta::new(flow_mint, false),
                AccountMeta::new_readonly(s, false),
                AccountMeta::new_readonly(s, false),
                AccountMeta::new_readonly(repflow, false),
                AccountMeta::new_readonly(s, false),
                AccountMeta::new(relay_tok, false),
                AccountMeta::new(treas_tok, false),
                AccountMeta::new_readonly(solana_sdk::system_program::id(), false),
                AccountMeta::new_readonly(Pubkey::new_from_array(user), false),
                AccountMeta::new(cs, false),
                AccountMeta::new(ue, false),
                AccountMeta::new(fh, false),
                AccountMeta::new(uet, false),
                AccountMeta::new(cb_pda, false),
            ],
            data: borsh::to_vec(&RewardsInstruction::ReleaseClaim {
                claim_epoch: epoch, releases: vec![rel] }).unwrap(),
        };

        banks.process_transaction(Transaction::new_signed_with_payer(
            &[build(r1.clone(), c1, cs1, ue1, fh1, uet1)],
            Some(&relay.pubkey()), &[&relay], bh)).await
            .expect("first probationary release must land");
        let c = ClaimCommitment::try_from_slice(
            &banks.get_account(c_pda).await.unwrap().unwrap().data[..CLAIM_COMMITMENT_SIZE]).unwrap();
        assert_eq!(c.status, ClaimCommitmentStatus::Releasing,
            "probationary branch latches Complete too — handlers.rs:1217");

        let bh2 = banks.get_new_latest_blockhash(&bh).await.unwrap();
        banks.process_transaction(Transaction::new_signed_with_payer(
            &[build(r2.clone(), c2, cs2, ue2, fh2, uet2)],
            Some(&relay.pubkey()), &[&relay], bh2)).await
            .expect("SECOND probationary release must land");

        let c = ClaimCommitment::try_from_slice(
            &banks.get_account(c_pda).await.unwrap().unwrap().data[..CLAIM_COMMITMENT_SIZE]).unwrap();
        assert_eq!(c.released_count, 2);
        assert_eq!(c.status, ClaimCommitmentStatus::Complete);

        let cb = ClaimableBalance::try_from_slice(
            &banks.get_account(cb_pda).await.unwrap().unwrap().data[..CLAIMABLE_BALANCE_SIZE]).unwrap();
        assert_eq!(cb.pending_relay_flow, derived * 2 * RELAY_SPLIT_PCT / 100,
            "BOTH clients' deferred 70% accumulated");
        for fh in [fh1, fh2] {
            assert!(banks.get_account(fh).await.unwrap().is_none(),
                "the deferred branch must close the FundHold too — the rent is owed \
                 back whether or not the $FLOW mint was deferred");
        }
        assert_eq!(token_balance(&mut banks, relay_tok).await, 0, "nothing minted below the gate");
    }

    /// The FundHold's rent must come back. Before this change burn_held_funds
    /// set status = Burned and returned, leaving a 105-byte rent-exempt PDA
    /// (1,621,680 lamports) stranded forever — and because fund_hold is seeded
    /// by claim_hash, every epoch minted a fresh one per client.
    ///
    /// What this proves and what it does not: `mock_escrow_burn` stands in for
    /// user_escrow::burn_held_funds, so this asserts rewards-v2 forwards a
    /// writable rent recipient as the 9th CPI account and that the lamports land
    /// on the relay. It does NOT prove Anchor's `close = rent_recipient` works —
    /// only a real validator can, and no currently-passing test covers that yet.
    /// `tests/user-escrow.ts` still asserts the pre-close behavior (status ==
    /// Burned, account still present) and needs updating to expect the FundHold
    /// gone before it can own this claim.
    #[tokio::test]
    async fn burning_a_hold_returns_its_rent_to_the_relay() {
        let relay = Keypair::new();
        let epoch = 7_401u64;
        let c1 = [41u8; 32];
        let bytes = 500_000_000u64; // < BYTES_PER_FLOW ⇒ repFlow CPI skipped
        let derived = derive_reward_amount(bytes, DEFAULT_ROUTING_PER_MB);

        let r1 = ClientReleaseOnChain {
            client_pubkey: c1, session_id: [5u8; 16], batch_nonce: 1,
            total_bytes: bytes, merkle_proof: vec![], client_signature: [1u8; 64],
            device_uuid: [0u8; 16], record_count: 1,
        };
        let root = compute_merkle_leaf_hash_from_release(&r1); // single-leaf tree

        let (c_pda, c_bump) = Pubkey::find_program_address(
            &[b"claim_commitment", relay.pubkey().as_ref(), &epoch.to_le_bytes()], &id());
        let (cs1, cs1_b) = Pubkey::find_program_address(
            &[b"claim_state", &c1, relay.pubkey().as_ref()], &id());
        let (service_auth, _) = Pubkey::find_program_address(&[b"mint_authority"], &id());
        let (cb_pda, _) = Pubkey::find_program_address(
            &[b"claimable_balance", relay.pubkey().as_ref(), &epoch.to_le_bytes()], &id());
        let s = Keypair::new().pubkey();
        let flow_mint = Keypair::new().pubkey();
        let relay_tok = Keypair::new().pubkey();
        // Above the repFlow gate ⇒ the PAID branch, which mints. That makes
        // require_foundation_treasury bite, so reward_treasury must be the
        // foundation's canonical ATA (H-1) and relay_repflow_user the real
        // repflow-token PDA — a random pubkey fails before the burn CPI runs.
        let treas_tok = Pubkey::find_program_address(
            &[FOUNDATION_PUBKEY.as_ref(), spl_token::id().as_ref(), flow_mint.as_ref()],
            &Pubkey::new_from_array([
                140, 151, 37, 143, 78, 36, 137, 241, 187, 61, 16, 41, 20, 142, 13, 131,
                11, 90, 19, 153, 218, 255, 16, 132, 4, 142, 123, 216, 219, 233, 248, 89,
            ]),
        ).0;
        let repflow = Pubkey::find_program_address(
            &[b"repflow_user", relay.pubkey().as_ref()], &REPFLOW_PROGRAM_ID).0;
        let fh1 = Keypair::new().pubkey();
        let ue1 = Keypair::new().pubkey();
        let uet1 = Keypair::new().pubkey();

        let mut pt = program_test_burn();
        pt.add_account(c_pda, commitment_account_n(
            &relay.pubkey(), epoch, root, derived, bytes, c_bump, 1));
        pt.add_account(cs1, claim_state_account(c1, &relay.pubkey(), cs1_b));
        pt.add_account(repflow, repflow_user_account(MIN_RELAY_REPFLOW));
        pt.add_account(flow_mint, flow_mint_account(&service_auth));
        pt.add_account(relay_tok, spl_token_account(&flow_mint, &relay.pubkey()));
        pt.add_account(treas_tok, spl_token_account(&flow_mint, &FOUNDATION_PUBKEY));
        pt.add_account(fh1, fund_hold_account());
        pt.add_account(ue1, stub(mock_escrow_id(), UE_RECEIPT_LEN));
        pt.add_account(uet1, stub(mock_escrow_id(), 8));

        let (mut banks, payer, bh) = pt.start().await;
        banks.process_transaction(Transaction::new_signed_with_payer(
            &[solana_sdk::system_instruction::transfer(
                &payer.pubkey(), &relay.pubkey(), 2_000_000_000)],
            Some(&payer.pubkey()), &[&payer], bh)).await.unwrap();
        let bh = banks.get_latest_blockhash().await.unwrap();

        let relay_before = banks.get_balance(relay.pubkey()).await.unwrap();
        let hold_rent = banks.get_balance(fh1).await.unwrap();
        assert!(hold_rent > 0, "the FundHold fixture must be rent-bearing");

        let ix = Instruction {
            program_id: id(),
            accounts: vec![
                AccountMeta::new(relay.pubkey(), true),
                AccountMeta::new(c_pda, false),
                AccountMeta::new_readonly(mock_escrow_id(), false),
                AccountMeta::new_readonly(service_auth, false),
                AccountMeta::new_readonly(s, false),
                AccountMeta::new_readonly(spl_token::id(), false),
                AccountMeta::new(flow_mint, false),
                AccountMeta::new_readonly(s, false),
                AccountMeta::new_readonly(s, false),
                AccountMeta::new_readonly(repflow, false),
                AccountMeta::new_readonly(s, false),
                AccountMeta::new(relay_tok, false),
                AccountMeta::new(treas_tok, false),
                AccountMeta::new_readonly(solana_sdk::system_program::id(), false),
                AccountMeta::new_readonly(Pubkey::new_from_array(c1), false),
                AccountMeta::new(cs1, false),
                AccountMeta::new(ue1, false),
                AccountMeta::new(fh1, false),
                AccountMeta::new(uet1, false),
                AccountMeta::new(cb_pda, false),
            ],
            data: borsh::to_vec(&RewardsInstruction::ReleaseClaim {
                claim_epoch: epoch, releases: vec![r1] }).unwrap(),
        };
        banks.process_transaction(Transaction::new_signed_with_payer(
            &[ix], Some(&relay.pubkey()), &[&relay], bh)).await
            .expect("release must land");

        assert_eq!(
            banks.get_balance(fh1).await.unwrap(), 0,
            "the FundHold must be closed, not merely marked Burned"
        );
        let relay_after = banks.get_balance(relay.pubkey()).await.unwrap();
        assert!(
            relay_after > relay_before,
            "the relay paid this rent at reserve time and must get it back: \
             before={relay_before} after={relay_after}"
        );
    }
}

#[cfg(test)]
mod client_dispute_integration_tests {
    //! End-to-end for ClientDispute (disc 3). Exercises the Task-10 six-arg leaf
    //! reconstruction in a live dispute, both branches:
    //!   - honest relay (disputed leaf IS the committed root) -> no slash, Ok
    //!   - forgery (disputed leaf NOT in root) -> relay repFlow slashed
    //! If Task 10's leaf reconstruction had diverged from the committed leaf, the
    //! honest case would mis-reconstruct, miss the root, and wrongly slash — so the
    //! no-slash assertion is the real guard on leaf agreement.
    //!
    //! Mock program at the repflow id absorbs cpi_slash_repflow (rewards-v2's job
    //! is to detect the forgery and request the slash; the repflow effects are that
    //! program's own concern). The escrow mock is not a pure sink: it stands in for
    //! Anchor's `close = rent_recipient` so the release CPI's account list — and in
    //! particular that the foundation is the account the rent lands on — is pinned
    //! here. The `close` itself is proven on a validator in tests/user-escrow.ts;
    //! the real .so cannot be loaded into ProgramTest (SBPF v3 vs the pinned rbpf).
    use super::*;
    use solana_program::{account_info::AccountInfo, entrypoint::ProgramResult, hash::hashv};
    use solana_program_test::*;
    use solana_sdk::{
        account::Account,
        instruction::{AccountMeta, Instruction},
        signature::{Keypair, Signer},
        transaction::Transaction,
    };
    use crate::{id, process_instruction, RewardsInstruction};

    fn mock_escrow_id() -> Pubkey { Pubkey::new_from_array([7u8; 32]) }
    fn mock_repflow_id() -> Pubkey { Pubkey::new_from_array([8u8; 32]) }
    fn mock_ok(_pid: &Pubkey, _a: &[AccountInfo], _d: &[u8]) -> ProgramResult { Ok(()) }

    /// Stands in for user-escrow's `release_funds`, whose FundHold is
    /// `close = rent_recipient`. Pins the rewards-v2 half of the contract: the
    /// CPI carries exactly 6 accounts and account 5 is a writable rent recipient
    /// the lamports can land on.
    ///
    /// CPI data = [disc:8][claim_hash:32]; accounts =
    /// [mint_authority, user, user_escrow, fund_hold, spender_registry, rent_recipient]
    /// → fund_hold is index 3, rent_recipient index 5.
    fn mock_escrow_release(_pid: &Pubkey, accounts: &[AccountInfo], data: &[u8]) -> ProgramResult {
        assert_eq!(data.len(), 40, "release_funds CPI data must be disc+claim_hash");
        assert_eq!(
            accounts.len(), 6,
            "release_funds must receive 6 accounts — the 6th is the rent recipient \
             the closed FundHold refunds to. Without it the 105-byte PDA is stranded."
        );

        // Stand in for `close = rent_recipient`. No realloc(0): program-test runs
        // native processors over copied buffers, where AccountInfo::realloc's
        // length write past the data pointer is not valid.
        let hold = &accounts[3];
        let rent_recipient = &accounts[5];
        let refund = hold.lamports();
        **rent_recipient.try_borrow_mut_lamports()? += refund;
        **hold.try_borrow_mut_lamports()? -= refund;
        hold.data.borrow_mut().fill(0);
        Ok(())
    }

    fn program_test() -> ProgramTest {
        let mut pt = ProgramTest::new("freeflow_rewards_v2", id(), processor!(process_instruction));
        pt.add_program("mock_escrow", mock_escrow_id(), processor!(mock_escrow_release));
        pt.add_program("mock_repflow", mock_repflow_id(), processor!(mock_ok));
        pt
    }
    fn repflow_user_account(balance: u64) -> Account {
        let mut d = vec![0u8; 48]; d[40..48].copy_from_slice(&balance.to_le_bytes());
        // F-1: owned by the real repflow-token program (see uptime module note).
        Account { lamports: 1_000_000, data: d, owner: REPFLOW_PROGRAM_ID, executable: false, rent_epoch: 0 }
    }
    /// Every `stub` is funded with this, so it doubles as the rent a released
    /// FundHold refunds.
    const FH_LAMPORTS: u64 = 1_000_000;
    fn stub(owner: Pubkey, len: usize) -> Account {
        Account { lamports: FH_LAMPORTS, data: vec![0u8; len], owner, executable: false, rent_epoch: 0 }
    }
    /// A plain system-owned wallet — what the rent recipient must be. Pre-funded
    /// so the assertion is a delta on a live account rather than a create.
    fn system_wallet() -> Account {
        Account { lamports: 5_000_000, data: vec![], owner: solana_sdk::system_program::id(),
                  executable: false, rent_epoch: 0 }
    }
    fn commitment_account(relay: &Pubkey, epoch: u64, root: [u8;32], bump: u8) -> Account {
        let c = ClaimCommitment {
            relay_pubkey: relay.to_bytes(), claim_epoch: epoch, merkle_root: root, client_count: 1,
            bandwidth_amount: 1_000_000_000, uptime_amount: 0, total_bytes: 1_000_000_000, uptime_hours: 0,
            routing_per_mb: DEFAULT_ROUTING_PER_MB, uptime_per_hour: DEFAULT_UPTIME_PER_HOUR,
            committed_at: 0, uptime_paid: false, reserved_count: 1, released_count: 0,
            released_amount: 0, released_bytes: 0, status: ClaimCommitmentStatus::Active,
            dispute_deadline: i64::MAX, bump, // window OPEN (now < deadline)
        };
        let data = borsh::to_vec(&c).unwrap();
        let mut p = vec![0u8; CLAIM_COMMITMENT_SIZE]; p[..data.len()].copy_from_slice(&data);
        Account { lamports: 10_000_000, data: p, owner: id(), executable: false, rent_epoch: 0 }
    }

    struct Fixture { relay_pk: Pubkey, client: Keypair, cpk: [u8;32], session: [u8;16],
        nonce: u64, batch_hash: [u8;32], leaf: [u8;32] }
    fn build() -> Fixture {
        let relay_pk = Keypair::new().pubkey();
        let client = Keypair::new();
        let cpk = client.pubkey().to_bytes();
        let session = [4u8;16]; let nonce = 1u64;
        // batch_hash the same way ReserveBatch/off-chain compute it.
        let batch_hash = hashv(&[&cpk, &session, &nonce.to_le_bytes()]).to_bytes();
        // The six-arg leaf the dispute will reconstruct (Task 10 format).
        let leaf = compute_merkle_leaf_hash(&cpk, &session, nonce, &batch_hash, 500_000_000, 1);
        Fixture { relay_pk, client, cpk, session, nonce, batch_hash, leaf }
    }

    fn dispute_ix(f: &Fixture, c_pda: Pubkey, rep_pda: Pubkey, repflow: Pubkey, epoch: u64,
        fund_hold: Pubkey, user_escrow: Pubkey, rent_recipient: Pubkey) -> Instruction {
        let s = Pubkey::new_from_array([99u8;32]);
        // service_authority / slash_authority are PDAs rewards-v2 signs for via
        // invoke_signed in cpi_release_funds / cpi_slash_repflow — they MUST be the
        // real PDAs or the runtime rejects the signature as privilege escalation.
        let (service_auth, _) = Pubkey::find_program_address(&[b"mint_authority"], &id());
        let (slash_auth, _)   = Pubkey::find_program_address(&[b"slash_authority"], &id());
        Instruction { program_id: id(), accounts: vec![
            AccountMeta::new(f.client.pubkey(), true),                          // 0 client (signer)
            AccountMeta::new(c_pda, false),                                     // 1 commitment
            AccountMeta::new(rep_pda, false),                                   // 2 reputation
            AccountMeta::new_readonly(mock_escrow_id(), false),                 // 3 escrow_program
            AccountMeta::new_readonly(service_auth, false),                     // 4 service_authority
            AccountMeta::new_readonly(s, false),                                // 5 spender_registry
            AccountMeta::new_readonly(mock_repflow_id(), false),                // 6 repflow_program
            AccountMeta::new_readonly(s, false),                                // 7 repflow_config
            AccountMeta::new(repflow, false),                                   // 8 relay_repflow_user (slash CPI writable)
            AccountMeta::new_readonly(slash_auth, false),                       // 9 slash_authority
            AccountMeta::new_readonly(solana_sdk::system_program::id(), false), // 10 system
            AccountMeta::new(fund_hold, false),                                 // 11 fund_hold (release w)
            AccountMeta::new(user_escrow, false),                               // 12 user_escrow (release w)
            AccountMeta::new(rent_recipient, false),                            // 13 rent_recipient (close refund, w)
        ], data: borsh::to_vec(&RewardsInstruction::ClientDispute {
            claim_epoch: epoch, client_pubkey: f.cpk, session_id: f.session, batch_nonce: f.nonce,
            original_batch_hash: f.batch_hash, total_bytes: 500_000_000, record_count: 1,
            client_signature: [1u8;64], merkle_proof: vec![],
        }).unwrap() }
    }

    #[tokio::test]
    async fn dispute_of_committed_batch_does_not_slash() {
        let f = build();
        let epoch = 5_051u64;
        // Honest: committed root IS the reconstructed leaf -> in_tree -> no slash.
        let (c_pda, c_bump) = Pubkey::find_program_address(&[b"claim_commitment", f.relay_pk.as_ref(), &epoch.to_le_bytes()], &id());
        let (rep_pda, _) = Pubkey::find_program_address(&[b"relay_reputation", &f.relay_pk.to_bytes()], &id());
        let repflow = Pubkey::find_program_address(&[b"repflow_user", f.relay_pk.as_ref()], &REPFLOW_PROGRAM_ID).0;
        let fund_hold = Keypair::new().pubkey();
        let user_escrow = Keypair::new().pubkey();

        let mut pt = program_test();
        pt.add_account(c_pda, commitment_account(&f.relay_pk, epoch, f.leaf, c_bump));
        pt.add_account(repflow, repflow_user_account(10_000));
        pt.add_account(fund_hold, stub(mock_escrow_id(), 8));   // H-1: lamports != 0
        pt.add_account(user_escrow, stub(mock_escrow_id(), 8));
        pt.add_account(FOUNDATION_PUBKEY, system_wallet());

        let (mut banks, payer, bh) = pt.start().await;
        banks.process_transaction(Transaction::new_signed_with_payer(
            &[solana_sdk::system_instruction::transfer(&payer.pubkey(), &f.client.pubkey(), 2_000_000_000)],
            Some(&payer.pubkey()), &[&payer], bh)).await.unwrap();
        let bh = banks.get_latest_blockhash().await.unwrap();

        banks.process_transaction(Transaction::new_signed_with_payer(
            &[dispute_ix(&f, c_pda, rep_pda, repflow, epoch, fund_hold, user_escrow, FOUNDATION_PUBKEY)],
            Some(&f.client.pubkey()), &[&f.client], bh)).await.expect("honest-relay dispute must succeed as a no-op");

        assert!(banks.get_account(rep_pda).await.unwrap().is_none(),
            "no RelayReputation must be created when the batch verifies in the tree");
        assert_eq!(
            banks.get_account(fund_hold).await.unwrap().unwrap().lamports, FH_LAMPORTS,
            "an honest-relay dispute releases nothing, so the FundHold keeps its rent"
        );
    }

    #[tokio::test]
    async fn dispute_of_forged_batch_slashes_relay() {
        let f = build();
        let epoch = 5_052u64;
        // Forgery: committed root is NOT the reconstructed leaf -> slash.
        let (c_pda, c_bump) = Pubkey::find_program_address(&[b"claim_commitment", f.relay_pk.as_ref(), &epoch.to_le_bytes()], &id());
        let (rep_pda, _) = Pubkey::find_program_address(&[b"relay_reputation", &f.relay_pk.to_bytes()], &id());
        let repflow = Pubkey::find_program_address(&[b"repflow_user", f.relay_pk.as_ref()], &REPFLOW_PROGRAM_ID).0;
        let fund_hold = Keypair::new().pubkey();
        let user_escrow = Keypair::new().pubkey();

        let mut pt = program_test();
        pt.add_account(c_pda, commitment_account(&f.relay_pk, epoch, [0xAB;32], c_bump)); // root != leaf
        pt.add_account(repflow, repflow_user_account(10_000)); // >= SLASH_FIRST_OFFENSE
        pt.add_account(fund_hold, stub(mock_escrow_id(), 8));
        pt.add_account(user_escrow, stub(mock_escrow_id(), 8));
        pt.add_account(FOUNDATION_PUBKEY, system_wallet());

        let (mut banks, payer, bh) = pt.start().await;
        banks.process_transaction(Transaction::new_signed_with_payer(
            &[solana_sdk::system_instruction::transfer(&payer.pubkey(), &f.client.pubkey(), 2_000_000_000)],
            Some(&payer.pubkey()), &[&payer], bh)).await.unwrap();
        let bh = banks.get_latest_blockhash().await.unwrap();

        let foundation_before = banks.get_account(FOUNDATION_PUBKEY).await.unwrap().unwrap().lamports;

        banks.process_transaction(Transaction::new_signed_with_payer(
            &[dispute_ix(&f, c_pda, rep_pda, repflow, epoch, fund_hold, user_escrow, FOUNDATION_PUBKEY)],
            Some(&f.client.pubkey()), &[&f.client], bh)).await.expect("forgery dispute must succeed and slash");

        let acct = banks.get_account(rep_pda).await.unwrap().expect("RelayReputation must be created on a forgery");
        let rep = RelayReputation::try_from_slice(&acct.data[..RELAY_REPUTATION_SIZE]).unwrap();
        assert_eq!(rep.slash_count, 1, "first offense");
        assert_eq!(rep.lifetime_slashed, SLASH_FIRST_OFFENSE, "first-offense slash amount recorded");

        // The FundHold's rent went to the foundation, not to the disputing client
        // and not to the relay. The client is the fee payer here, so asserting on
        // the foundation's balance (never a fee payer) keeps this an exact delta.
        let foundation_after = banks.get_account(FOUNDATION_PUBKEY).await.unwrap().unwrap().lamports;
        assert_eq!(
            foundation_after - foundation_before, FH_LAMPORTS,
            "the closed FundHold's rent must land on the foundation wallet"
        );
    }

    /// The theft vector the pin exists to close. The disputing client signs this
    /// instruction, so without the `FOUNDATION_PUBKEY` check they could name any
    /// wallet — their own — as the account the closed FundHold refunds to, and walk
    /// away with the relay's rent on top of winning the dispute.
    #[tokio::test]
    async fn dispute_cannot_redirect_the_closed_holds_rent() {
        let f = build();
        let epoch = 5_053u64;
        let (c_pda, c_bump) = Pubkey::find_program_address(&[b"claim_commitment", f.relay_pk.as_ref(), &epoch.to_le_bytes()], &id());
        let (rep_pda, _) = Pubkey::find_program_address(&[b"relay_reputation", &f.relay_pk.to_bytes()], &id());
        let repflow = Pubkey::find_program_address(&[b"repflow_user", f.relay_pk.as_ref()], &REPFLOW_PROGRAM_ID).0;
        let fund_hold = Keypair::new().pubkey();
        let user_escrow = Keypair::new().pubkey();

        let mut pt = program_test();
        pt.add_account(c_pda, commitment_account(&f.relay_pk, epoch, [0xAB;32], c_bump)); // forgery
        pt.add_account(repflow, repflow_user_account(10_000));
        pt.add_account(fund_hold, stub(mock_escrow_id(), 8));
        pt.add_account(user_escrow, stub(mock_escrow_id(), 8));
        pt.add_account(FOUNDATION_PUBKEY, system_wallet());

        let (mut banks, payer, bh) = pt.start().await;
        banks.process_transaction(Transaction::new_signed_with_payer(
            &[solana_sdk::system_instruction::transfer(&payer.pubkey(), &f.client.pubkey(), 2_000_000_000)],
            Some(&payer.pubkey()), &[&payer], bh)).await.unwrap();
        let bh = banks.get_latest_blockhash().await.unwrap();

        // Everything else is a legitimate, winnable dispute; only account 13 is swapped.
        let err = banks.process_transaction(Transaction::new_signed_with_payer(
            &[dispute_ix(&f, c_pda, rep_pda, repflow, epoch, fund_hold, user_escrow, f.client.pubkey())],
            Some(&f.client.pubkey()), &[&f.client], bh)).await
            .expect_err("naming a rent recipient other than the foundation must revert");

        let want = format!("Custom({})", RewardsError::InvalidTreasuryAccount as u32);
        let got  = format!("{err:?}");
        assert!(got.contains(&want), "expected {want}, got {got}");
        assert_eq!(
            banks.get_account(fund_hold).await.unwrap().unwrap().lamports, FH_LAMPORTS,
            "the revert must leave the FundHold's rent where it was"
        );
    }
}
