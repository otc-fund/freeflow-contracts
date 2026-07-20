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

        // 3. Check AlreadyReleased.
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
    let repflow_balance = read_repflow_balance(relay_repflow_user)?;

    if repflow_balance >= MIN_RELAY_REPFLOW {
        // Mint $FLOW 70/30.
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

        commitment.status = ClaimCommitmentStatus::Complete;
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
        commitment.status = ClaimCommitmentStatus::Complete;
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

    // Tiered slash amount.
    let relay_repflow_balance = read_repflow_balance(relay_repflow_user)?;
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

    cpi_release_funds(
        escrow_program,
        service_authority,
        client,  // user_ai
        user_escrow_ai,
        fund_hold_ai,
        spender_registry,
        claim_hash,
        authority_bump,
    ).map_err(|_| RewardsError::CpiFailed)?;

    // L-4: do NOT set commitment to Disputed — that would freeze all other
    // clients' funds in this epoch.  H-1 already prevents repeat disputes on
    // the same batch (fund_hold lamports == 0 after release).  The commitment
    // stays Active so honest clients can still proceed to ReleaseClaim.
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
    let repflow_balance = read_repflow_balance(relay_repflow_user)?;
    if repflow_balance < MIN_RELAY_REPFLOW {
        return Err(RewardsError::RepFlowGateNotMet.into());
    }

    let (_, authority_bump) = Pubkey::find_program_address(&[b"mint_authority"], program_id);

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
    if commitment.claim_epoch != claim_epoch {
        return Err(ProgramError::InvalidArgument);
    }
    // C-1 / M-3: Guard against calling on an already-Complete commitment.
    // (ReleaseClaim does this via Active→Releasing state machine; trial path must
    // guard explicitly since it bypasses that machine.)
    if commitment.status == ClaimCommitmentStatus::Complete {
        return Err(RewardsError::EpochComplete.into());
    }

    // Check foundation kill switch. Legacy-tolerant — see read_foundation_config_compat.
    let foundation_config = read_foundation_config_compat(&foundation_config_ai.data.borrow())?;
    if !foundation_config.trial_enabled {
        return Err(RewardsError::TrialDisabled.into());
    }

    // repFlow gate.
    let repflow_balance = read_repflow_balance(relay_repflow_user)?;
    if repflow_balance < MIN_RELAY_REPFLOW {
        return Err(RewardsError::RepFlowGateNotMet.into());
    }

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
    cpi_mint_flow(token_program, flow_mint, reward_relay, service_authority, relay_amount, authority_bump)?;
    cpi_mint_flow(token_program, flow_mint, reward_treasury, service_authority, treasury_amount, authority_bump)?;

    // Mint bandwidth repFlow — use this transaction's bytes only, not commitment
    // cumulative. Using commitment.released_bytes here would double-mint repFlow
    // on every subsequent ReleaseTrialClaim call in the same epoch.
    let repflow_amount = total_released_bytes / BYTES_PER_FLOW;
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
    let relay_repflow_balance = read_repflow_balance(relay_repflow_user)?;
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
///   7: reward_relay       (writable)
///   8: reward_treasury    (writable)
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
    let uptime_enabled = if foundation_config_ai.lamports() == 0 {
        true // config not yet created — default enabled, matches CommitClaim
    } else {
        // Legacy-tolerant — see read_foundation_config_compat. A strict
        // FoundationConfig::try_from_slice fails on the live 34-byte PDA.
        read_foundation_config_compat(&foundation_config_ai.data.borrow())?.uptime_enabled
    };
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

    let repflow_balance = read_repflow_balance(relay_repflow_user)?;
    if repflow_balance < MIN_RELAY_REPFLOW {
        return Err(RewardsError::RepFlowGateNotMet.into());
    }

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
        Account { lamports: 1_000_000, data, owner: id(), executable: false, rent_epoch: 0 }
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
        Instruction {
            program_id: id(),
            accounts: vec![
                AccountMeta::new(relay.pubkey(), true),             // [0] relay_wallet
                AccountMeta::new(commitment_pk, false),              // [1] commitment
                AccountMeta::new_readonly(foundation_cfg_pk, false), // [2] foundation_config
                AccountMeta::new_readonly(repflow_user_pk, false),   // [3] relay_repflow_user
                AccountMeta::new_readonly(stub, false),              // [4] token_program
                AccountMeta::new(stub, false),                       // [5] flow_mint
                AccountMeta::new_readonly(stub, false),              // [6] service_authority
                AccountMeta::new(stub, false),                       // [7] reward_relay
                AccountMeta::new(stub, false),                       // [8] reward_treasury
            ],
            data: encode_ix(&RewardsInstruction::ClaimRelayUptime { claim_epoch }),
        }
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
        let repflow_pk = Keypair::new().pubkey();
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
