//! repFlow burning — slashing mechanism for misbehaving participants.
//!
//! Slashing follows a two-step process:
//!   1. `propose_slash` — burner submits evidence hash, starts 72h appeal window
//!   2. `execute_slash` — after window expires (or user waives), burn is applied
//!
//! This prevents accidental or malicious slashing without recourse.

use anchor_lang::prelude::*;
use anchor_spl::token_2022::{self, Burn, Token2022};

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
/// Can be called by any authorised burner. Burns the repFlow on-chain.
pub fn execute_slash(ctx: Context<ExecuteSlash>, _slash_id: u64) -> Result<()> {
    let config_bump = ctx.bumps.config;
    let config_info = ctx.accounts.config.to_account_info();
    let config = &mut ctx.accounts.config;
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

    // M-03: Validate that user_ata is owned by the slashed user's wallet.
    // SPL Token account layout: mint(32) | owner(32) | amount(8) | ...
    // If we allow any account here, a burner could burn from an unrelated token
    // account, or drain an account belonging to a different user.
    // Use `record.wallet` (already set from `user.wallet`) to avoid a second
    // borrow of `ctx.accounts.repflow_user` while `user` holds a mutable borrow.
    {
        let expected_owner = record.wallet; // == user.wallet
        let ata_data = ctx.accounts.user_ata.try_borrow_data()?;
        if ata_data.len() < 64 {
            return Err(RepFlowError::InvalidAta.into());
        }
        let ata_owner = Pubkey::try_from(&ata_data[32..64])
            .map_err(|_| RepFlowError::InvalidAta)?;
        require!(
            ata_owner == expected_owner,
            RepFlowError::InvalidAta
        );
    }

    let actual_slash = record.slash_amount.min(user.balance);

    // ── Burn via SPL Token-2022 ────────────────────────────────────────────
    let seeds  = &[b"repflow_config".as_ref(), &[config_bump]];
    let signer = &[&seeds[..]];

    token_2022::burn(
        CpiContext::new_with_signer(
            ctx.accounts.token_program.to_account_info(),
            Burn {
                mint:      ctx.accounts.mint.to_account_info(),
                from:      ctx.accounts.user_ata.to_account_info(),
                authority: config_info,
            },
            signer,
        ),
        actual_slash,
    )?;

    // ── Update state ───────────────────────────────────────────────────────
    user.balance          = user.balance.saturating_sub(actual_slash);
    user.lifetime_slashed = user.lifetime_slashed.saturating_add(actual_slash);
    user.slash_count      = user.slash_count.saturating_add(1);

    config.total_burned   = config.total_burned.saturating_add(actual_slash);
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
        mut,
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

    /// The repFlow SPL Token-2022 mint (must match config.mint).
    #[account(mut, constraint = mint.key() == config.mint @ crate::error::RepFlowError::InvalidMint)]
    pub mint: UncheckedAccount<'info>,

    #[account(mut)]
    pub user_ata: UncheckedAccount<'info>,

    pub burner: Signer<'info>,

    pub token_program:  Program<'info, Token2022>,
    pub system_program: Program<'info, System>,
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
/// Accounts:
///   0: config         (writable, seeds=[b"repflow_config"])
///   1: repflow_user   (writable, seeds=[b"repflow_user", wallet])
///   2: mint           (writable — repFlow Token-2022 mint)
///   3: user_ata       (writable — relay's repFlow ATA)
///   4: slash_authority (signer  — rewards-v2 PDA, seeds=[b"slash_authority"])
///   5: token_program
pub fn slash_repflow_from_rewards(
    ctx:    Context<SlashRepFlowFromRewards>,
    amount: u64,
) -> Result<()> {
    let config_bump = ctx.bumps.config;
    let config_info = ctx.accounts.config.to_account_info();
    let config = &mut ctx.accounts.config;
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

    // Burn via SPL Token-2022.
    let seeds  = &[b"repflow_config".as_ref(), &[config_bump]];
    let signer = &[&seeds[..]];

    token_2022::burn(
        CpiContext::new_with_signer(
            ctx.accounts.token_program.to_account_info(),
            Burn {
                mint:      ctx.accounts.mint.to_account_info(),
                from:      ctx.accounts.user_ata.to_account_info(),
                authority: config_info,
            },
            signer,
        ),
        actual_slash,
    )?;

    // Update state.
    user.balance          = user.balance.saturating_sub(actual_slash);
    user.lifetime_slashed = user.lifetime_slashed.saturating_add(actual_slash);
    user.slash_count      = user.slash_count.saturating_add(1);
    config.total_burned   = config.total_burned.saturating_add(actual_slash);

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
        mut,
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

    /// repFlow Token-2022 mint.
    #[account(mut)]
    pub mint: UncheckedAccount<'info>,

    /// The relay's repFlow ATA (Token-2022). Burned from this account.
    #[account(mut)]
    pub user_ata: UncheckedAccount<'info>,

    /// rewards-v2 slash_authority PDA — proves caller is the rewards program.
    /// Seeds: [b"slash_authority"] from REWARDS_PROGRAM_ID.
    pub slash_authority: Signer<'info>,

    pub token_program: Program<'info, Token2022>,
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
