//! CPI helpers for rewards-v2.
//!
//! Covers:
//!   - user_escrow:    hold_client_funds, burn_held_funds, release_funds
//!   - repflow-token:  mint_repflow_from_rewards, slash_repflow_from_rewards
//!   - SPL Token:      mint_to ($FLOW)
//!
//! All user_escrow and repflow-token programs are Anchor-based.
//! CPI instruction data = anchor_ix_discriminator(name) + borsh args.
//!
//! PDA signer seeds used throughout: [b"mint_authority"] — same seeds as the
//! legacy rewards program. This PDA must be registered in user_escrow's
//! AuthorizedSpenderRegistry before any ReserveBatch can succeed.

use solana_program::{
    account_info::AccountInfo,
    entrypoint::ProgramResult,
    hash::hashv,
    instruction::{AccountMeta, Instruction},
    msg,
    program::invoke_signed,
    program_error::ProgramError,
    pubkey::Pubkey,
};

// ── Anchor discriminator helper ─────────────────────────────────────────────

/// Compute the Anchor instruction discriminator for `name`.
/// Formula: SHA-256("global:{name}")[0..8]
pub fn anchor_ix_discriminator(name: &[u8]) -> [u8; 8] {
    let mut prefixed = Vec::with_capacity(b"global:".len() + name.len());
    prefixed.extend_from_slice(b"global:");
    prefixed.extend_from_slice(name);
    let hash = hashv(&[&prefixed]);
    let mut disc = [0u8; 8];
    disc.copy_from_slice(&hash.to_bytes()[..8]);
    disc
}

// ── user_escrow CPIs ─────────────────────────────────────────────────────────

/// CPI to user_escrow::hold_client_funds.
///
/// Locks `amount` $FLOW in a FundHold PDA for the 7-day dispute window.
/// `mint_authority` PDA (seeds `[b"mint_authority"]`) must be in the
/// user_escrow AuthorizedSpenderRegistry.
///
/// Accounts passed:
///   service_authority (mint_authority PDA) — signer via invoke_signed
///   payer             (relay wallet)       — signer, pays FundHold rent
///   user              (client wallet)      — read-only (PDA seed)
///   user_escrow_state (UserEscrow PDA)     — writable
///   fund_hold         (FundHold PDA)       — writable, init
///   spender_registry  (AuthorizedSpenderRegistry PDA) — read-only
///   system_program
#[allow(clippy::too_many_arguments)]
#[inline(never)]
pub fn cpi_hold_client_funds<'a>(
    user_escrow_program_ai: &AccountInfo<'a>,
    mint_authority_ai:      &AccountInfo<'a>,
    payer_ai:               &AccountInfo<'a>,
    user_ai:                &AccountInfo<'a>,
    user_escrow_state_ai:   &AccountInfo<'a>,
    fund_hold_ai:           &AccountInfo<'a>,
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

    // [discriminator:8][amount:8 LE][claim_hash:32][session_id:16]
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

/// CPI to user_escrow::release_funds.
///
/// Decrements UserEscrow.held and marks FundHold as Released.
/// Called when client wins dispute — tokens stay in escrow (balance unchanged).
#[inline(never)]
pub fn cpi_release_funds<'a>(
    user_escrow_program_ai: &AccountInfo<'a>,
    mint_authority_ai:      &AccountInfo<'a>,
    user_ai:                &AccountInfo<'a>,
    user_escrow_state_ai:   &AccountInfo<'a>,
    fund_hold_ai:           &AccountInfo<'a>,
    spender_registry_ai:    &AccountInfo<'a>,
    claim_hash:             [u8; 32],
    mint_authority_bump:    u8,
) -> ProgramResult {
    // [discriminator:8][claim_hash:32]
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

/// CPI to user_escrow::burn_held_funds.
///
/// Decrements both UserEscrow.held and UserEscrow.balance, SPL-burns `amount`
/// from the escrow token account, marks FundHold as Burned.
/// Called at ReleaseClaim after the 7-day dispute window.
#[allow(clippy::too_many_arguments)]
#[inline(never)]
pub fn cpi_burn_held_funds<'a>(
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
    // [discriminator:8][claim_hash:32]
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

// ── SPL Token mint ───────────────────────────────────────────────────────────

/// Mint `amount` $FLOW to `destination_ai` via SPL Token mint_to CPI.
///
/// rewards-v2's `mint_authority` PDA (seeds `[b"mint_authority"]`) must be
/// the $FLOW SPL mint authority. This is set up once at deployment.
#[inline(never)]
pub fn cpi_mint_flow<'a>(
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

// ── repflow-token CPIs ───────────────────────────────────────────────────────

/// CPI to repflow-token::mint_repflow_from_rewards.
///
/// Credits `amount` repFlow to the relay's `repflow_user` PDA (PDA-only — no SPL).
/// Signs with rewards-v2's `mint_authority` PDA — repflow-token verifies
/// this is the rewards program by checking the PDA derivation.
///
/// Account layout matching `MintRepFlowFromRewards` in repflow-token:
///   0: repflow_config   (readonly)
///   1: repflow_user     (writable)
///   2: rewards_authority (signer — rewards-v2 PDA [b"mint_authority"])
///
/// Activity code is fixed to 2 (Bandwidth).
#[inline(never)]
pub fn cpi_mint_repflow_bandwidth<'a>(
    repflow_program_ai:  &AccountInfo<'a>,
    repflow_config_ai:   &AccountInfo<'a>,
    repflow_user_ai:     &AccountInfo<'a>,
    rewards_authority:   &AccountInfo<'a>,
    amount:              u64,
    mint_authority_bump: u8,
) -> ProgramResult {
    if amount == 0 {
        return Ok(());
    }

    // Anchor discriminator: sha256("global:mint_repflow_from_rewards")[0..8]
    let disc = anchor_ix_discriminator(b"mint_repflow_from_rewards");

    // instruction data: discriminator(8) + amount(u64 le)(8) + activity_code(u8)(1)
    let activity_code: u8 = 2; // Bandwidth
    let mut data = Vec::with_capacity(17);
    data.extend_from_slice(&disc);
    data.extend_from_slice(&amount.to_le_bytes());
    data.push(activity_code);

    let ix = Instruction {
        program_id: *repflow_program_ai.key,
        accounts: vec![
            AccountMeta::new_readonly(*repflow_config_ai.key, false), // 0: config (readonly)
            AccountMeta::new(*repflow_user_ai.key,            false), // 1: repflow_user
            AccountMeta::new_readonly(*rewards_authority.key, true),  // 2: rewards_authority (signer)
        ],
        data,
    };

    invoke_signed(
        &ix,
        &[
            repflow_config_ai.clone(),
            repflow_user_ai.clone(),
            rewards_authority.clone(),
            repflow_program_ai.clone(),
        ],
        &[&[b"mint_authority", &[mint_authority_bump]]],
    ).map_err(|e| {
        msg!("cpi_mint_repflow_bandwidth failed: {:?}", e);
        e
    })
}

/// CPI to repflow-token::slash_repflow_from_rewards.
///
/// Instant slash — no 72-hour appeal window. Used by `ClientDispute` (Merkle proof
/// failure) and `SlashTrialFraud` (foundation fraud audit). The `slash_authority`
/// PDA (seeds `[b"slash_authority"]` from this program) signs the CPI, which
/// repflow-token verifies to ensure only rewards-v2 can call this instruction.
///
/// Account layout matching `SlashRepFlowFromRewards` in repflow-token (PDA-only):
///   0: repflow_config   (readonly)
///   1: repflow_user     (writable)
///   2: slash_authority  (signer   — rewards-v2 PDA [b"slash_authority"])
#[inline(never)]
pub fn cpi_slash_repflow<'a>(
    repflow_program_ai:    &AccountInfo<'a>,
    repflow_config_ai:     &AccountInfo<'a>,
    repflow_user_ai:       &AccountInfo<'a>,
    slash_authority_ai:    &AccountInfo<'a>,
    amount:                u64,
    slash_authority_bump:  u8,
) -> ProgramResult {
    if amount == 0 {
        return Ok(());
    }

    // Anchor discriminator: sha256("global:slash_repflow_from_rewards")[0..8]
    let disc = anchor_ix_discriminator(b"slash_repflow_from_rewards");

    // instruction data: discriminator(8) + amount(u64 le)(8)
    let mut data = Vec::with_capacity(16);
    data.extend_from_slice(&disc);
    data.extend_from_slice(&amount.to_le_bytes());

    let ix = Instruction {
        program_id: *repflow_program_ai.key,
        accounts: vec![
            AccountMeta::new_readonly(*repflow_config_ai.key,  false), // 0: config (readonly)
            AccountMeta::new(         *repflow_user_ai.key,    false), // 1: repflow_user
            AccountMeta::new_readonly(*slash_authority_ai.key, true),  // 2: slash_authority (signer)
        ],
        data,
    };

    // M-2: accounts slice must match ix.accounts exactly (3 entries, 0-2).
    // repflow_program_ai is the CPI target, not an instruction account — omit it.
    invoke_signed(
        &ix,
        &[
            repflow_config_ai.clone(),
            repflow_user_ai.clone(),
            slash_authority_ai.clone(),
            repflow_program_ai.clone(),
        ],
        &[&[b"slash_authority", &[slash_authority_bump]]],
    ).map_err(|e| {
        msg!("cpi_slash_repflow failed: {:?}", e);
        e
    })
}

// ── Derive PDA helper ────────────────────────────────────────────────────────

/// Derive the mint_authority PDA for rewards-v2.
/// Seeds: [b"mint_authority"]
pub fn derive_mint_authority(program_id: &Pubkey) -> (Pubkey, u8) {
    Pubkey::find_program_address(&[b"mint_authority"], program_id)
}

/// Derive the slash_authority PDA for rewards-v2.
/// Seeds: [b"slash_authority"]
pub fn derive_slash_authority(program_id: &Pubkey) -> (Pubkey, u8) {
    Pubkey::find_program_address(&[b"slash_authority"], program_id)
}
