//! repFlow burning — slashing mechanism for misbehaving participants.
//!
//! Slashing follows a two-step process:
//!   1. `propose_slash` — burner submits evidence hash, starts 72h appeal window
//!   2. `execute_slash` — after window expires (or user waives), burn is applied
//!
//! This prevents accidental or malicious slashing without recourse.

use anchor_lang::prelude::*;

use crate::{
    error::RepFlowError,
    state::{RepFlowConfig, RepFlowUser, SlashRecord},
};

// ─── Instruction: propose_slash ───────────────────────────────────────────────

/// Propose a slash — starts the 72-hour appeal window.
///
/// Only authorised burners can propose slashes. The `evidence_hash` is a
/// SHA-256 of off-chain evidence stored for audit purposes.
pub fn propose_slash(
    ctx:           Context<ProposeSlash>,
    slash_amount:  u64,
    offense_code:  u8,
    evidence_hash: [u8; 32],
    slash_id:      u64,
) -> Result<()> {
    let config = &ctx.accounts.config;
    let now    = Clock::get()?.unix_timestamp;

    require!(!config.paused, RepFlowError::ProgramPaused);
    require!(
        config.is_burner(&ctx.accounts.burner.key()),
        RepFlowError::UnauthorizedBurner
    );

    // F1-H7: Validate slash_id is sequential — must equal user's current slash_count.
    // This prevents a burner from creating multiple parallel slash PDAs with
    // arbitrary IDs, which could obscure the true slash history.
    let user = &ctx.accounts.repflow_user;
    require!(
        slash_id == user.slash_count as u64,
        RepFlowError::InvalidSlashId
    );

    // Cap slash at current balance — cannot slash more than exists.
    let actual_slash = slash_amount.min(ctx.accounts.repflow_user.balance);
    require!(actual_slash > 0, RepFlowError::InsufficientBalanceForSlash);

    let record             = &mut ctx.accounts.slash_record;
    record.wallet          = ctx.accounts.repflow_user.wallet;
    record.slash_amount    = actual_slash;
    record.offense_code    = offense_code;
    record.evidence_hash   = evidence_hash;
    record.proposed_at     = now;
    record.appeal_deadline = now + SlashRecord::APPEAL_WINDOW_SECS;
    record.appeal_waived   = false;
    record.executed        = false;
    record.proposer        = ctx.accounts.burner.key();
    record.bump            = ctx.bumps.slash_record;

    emit!(SlashProposed {
        wallet:        record.wallet,
        slash_amount:  actual_slash,
        offense_code,
        evidence_hash,
        appeal_deadline: record.appeal_deadline,
        timestamp: now,
    });

    msg!(
        "Slash proposed: {} repFlow from {} (offense={}) — appeal window until {}",
        actual_slash, record.wallet, offense_code, record.appeal_deadline
    );

    Ok(())
}

#[derive(Accounts)]
#[instruction(slash_amount: u64, offense_code: u8, evidence_hash: [u8; 32], slash_id: u64)]
pub struct ProposeSlash<'info> {
    #[account(
        seeds = [b"repflow_config"],
        bump,  // canonical — config.bump may be 0 from old program
    )]
    pub config: Account<'info, RepFlowConfig>,

    #[account(
        mut,
        seeds = [b"repflow_user", repflow_user.wallet.as_ref()],
        bump  = repflow_user.bump,
    )]
    pub repflow_user: Account<'info, RepFlowUser>,

    #[account(
        init,
        payer = payer,
        space = 8 + SlashRecord::SIZE,
        seeds = [b"slash_record", repflow_user.wallet.as_ref(), &slash_id.to_le_bytes()],
        bump,
    )]
    pub slash_record: Account<'info, SlashRecord>,

    /// The burner (must be in config.burners).
    pub burner: Signer<'info>,

    #[account(mut)]
    pub payer: Signer<'info>,

    pub system_program: Program<'info, System>,
}

// ─── Instruction: waive_appeal ────────────────────────────────────────────────

/// User voluntarily waives their appeal window, allowing immediate slash.
pub fn waive_appeal(ctx: Context<WaiveAppeal>) -> Result<()> {
    require!(!ctx.accounts.slash_record.executed, RepFlowError::AppealWindowOpen);
    ctx.accounts.slash_record.appeal_waived = true;

    emit!(AppealWaived {
        wallet:   ctx.accounts.slash_record.wallet,
        slash_id: ctx.accounts.slash_record.proposed_at,
    });

    Ok(())
}

#[derive(Accounts)]
pub struct WaiveAppeal<'info> {
    #[account(
        mut,
        constraint = slash_record.wallet == wallet.key(),
    )]
    pub slash_record: Account<'info, SlashRecord>,
    pub wallet: Signer<'info>,
}

// ─── Instruction: execute_slash ───────────────────────────────────────────────

/// Execute a proposed slash after the appeal window has closed.
///
/// Can be called by any authorised burner. Deducts the repFlow from the user PDA.
pub fn execute_slash(ctx: Context<ExecuteSlash>, _slash_id: u64) -> Result<()> {
    let config = &ctx.accounts.config;
    let user   = &mut ctx.accounts.repflow_user;
    let record = &mut ctx.accounts.slash_record;
    let now    = Clock::get()?.unix_timestamp;

    require!(!config.paused, RepFlowError::ProgramPaused);
    require!(
        config.is_burner(&ctx.accounts.burner.key()),
        RepFlowError::UnauthorizedBurner
    );
    require!(!record.executed, RepFlowError::AppealWindowOpen);

    // Appeal window must have passed (unless waived).
    if !record.appeal_waived {
        require!(now >= record.appeal_deadline, RepFlowError::AppealWindowOpen);
    }

    let actual_slash = record.slash_amount.min(user.balance);

    // ── Update state (PDA only — no SPL burn, no shared counter) ───────────
    user.balance          = user.balance.saturating_sub(actual_slash);
    user.lifetime_slashed = user.lifetime_slashed.saturating_add(actual_slash);
    user.slash_count      = user.slash_count.saturating_add(1);
    record.executed       = true;

    emit!(RepFlowBurned {
        wallet:       user.wallet,
        amount:       actual_slash,
        offense_code: record.offense_code,
        new_balance:  user.balance,
        slash_count:  user.slash_count,
        timestamp:    now,
    });

    msg!(
        "Slash executed: {} repFlow burned from {} (offense={}) — new balance={}",
        actual_slash, user.wallet, record.offense_code, user.balance
    );

    Ok(())
}

#[derive(Accounts)]
#[instruction(slash_id: u64)]
pub struct ExecuteSlash<'info> {
    #[account(
        seeds = [b"repflow_config"],
        bump,  // canonical — config.bump may be 0 from old program
    )]
    pub config: Account<'info, RepFlowConfig>,

    #[account(
        mut,
        seeds = [b"repflow_user", repflow_user.wallet.as_ref()],
        bump  = repflow_user.bump,
    )]
    pub repflow_user: Account<'info, RepFlowUser>,

    #[account(
        mut,
        seeds = [b"slash_record", repflow_user.wallet.as_ref(), &slash_id.to_le_bytes()],
        bump  = slash_record.bump,
    )]
    pub slash_record: Account<'info, SlashRecord>,

    pub burner: Signer<'info>,
}

// ─── Instruction: slash_repflow_from_rewards ──────────────────────────────────

/// Instant slash via CPI from rewards-v2 — no 72-hour appeal window.
///
/// Called exclusively by rewards-v2 during `ClientDispute` (Merkle proof failure
/// confirmed) or `SlashTrialFraud` (foundation audit confirmed fake trial).
///
/// Signed by the rewards program's `slash_authority` PDA
/// (seeds: `[b"slash_authority"]` from `REWARDS_PROGRAM_ID`).
///
/// Unlike `propose_slash` + `execute_slash`, on-chain cryptographic evidence
/// (a failed Merkle proof or a foundation-verified fraud audit) is considered
/// sufficient without a 72-hour human appeal window.
///
/// Accounts (PDA-only — no SPL burn):
///   0: config         (readonly, seeds=[b"repflow_config"])
///   1: repflow_user   (writable, seeds=[b"repflow_user", wallet])
///   2: slash_authority (signer  — rewards-v2 PDA, seeds=[b"slash_authority"])
pub fn slash_repflow_from_rewards(
    ctx:    Context<SlashRepFlowFromRewards>,
    amount: u64,
) -> Result<()> {
    let config = &ctx.accounts.config;
    let user   = &mut ctx.accounts.repflow_user;

    require!(!config.paused, RepFlowError::ProgramPaused);

    // Verify slash_authority is the rewards program's slash_authority PDA.
    // Only rewards-v2 can produce a signer for this PDA — proves the caller is rewards-v2.
    let (expected_slash_auth, _) = Pubkey::find_program_address(
        &[b"slash_authority"],
        &crate::REWARDS_PROGRAM_ID,
    );
    require!(
        ctx.accounts.slash_authority.key() == expected_slash_auth,
        RepFlowError::UnauthorizedRewardsCPI,
    );

    // Cap at current balance — cannot slash more than exists.
    let actual_slash = amount.min(user.balance);
    if actual_slash == 0 {
        msg!("slash_repflow_from_rewards: balance is 0, nothing to slash");
        return Ok(());
    }

    // Update state (PDA only — no SPL burn, no shared counter).
    user.balance          = user.balance.saturating_sub(actual_slash);
    user.lifetime_slashed = user.lifetime_slashed.saturating_add(actual_slash);
    user.slash_count      = user.slash_count.saturating_add(1);

    let now = Clock::get()?.unix_timestamp;
    emit!(RepFlowBurned {
        wallet:       user.wallet,
        amount:       actual_slash,
        offense_code: 255, // 255 = automated slash from rewards program
        new_balance:  user.balance,
        slash_count:  user.slash_count,
        timestamp:    now,
    });

    msg!(
        "slash_repflow_from_rewards: {} repFlow burned from {} — new balance={}",
        actual_slash, user.wallet, user.balance,
    );
    Ok(())
}

#[derive(Accounts)]
pub struct SlashRepFlowFromRewards<'info> {
    #[account(
        seeds = [b"repflow_config"],
        bump,
    )]
    pub config: Account<'info, RepFlowConfig>,

    #[account(
        mut,
        seeds = [b"repflow_user", repflow_user.wallet.as_ref()],
        bump  = repflow_user.bump,
    )]
    pub repflow_user: Account<'info, RepFlowUser>,

    /// rewards-v2 slash_authority PDA — proves caller is the rewards program.
    /// Seeds: [b"slash_authority"] from REWARDS_PROGRAM_ID.
    pub slash_authority: Signer<'info>,
}

// ─── Events ───────────────────────────────────────────────────────────────────

#[event]
pub struct SlashProposed {
    pub wallet:          Pubkey,
    pub slash_amount:    u64,
    pub offense_code:    u8,
    pub evidence_hash:   [u8; 32],
    pub appeal_deadline: i64,
    pub timestamp:       i64,
}

#[event]
pub struct AppealWaived {
    pub wallet:   Pubkey,
    pub slash_id: i64,
}

#[event]
pub struct RepFlowBurned {
    pub wallet:       Pubkey,
    pub amount:       u64,
    pub offense_code: u8,
    pub new_balance:  u64,
    pub slash_count:  u32,
    pub timestamp:    i64,
}
