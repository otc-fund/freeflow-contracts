//! repFlow minting — authorised minters only.
//!
//! Mint operations are triggered by verified on-chain events or
//! by the governance council submitting mint transactions.
//!
//! Rate limit: 100,000 repFlow per user per 24-hour window.

use anchor_lang::prelude::*;
use anchor_spl::token_2022::{self, MintTo, Token2022};

use crate::{
    error::RepFlowError,
    state::{RepFlowConfig, RepFlowUser},
};

// ─── Instruction: initialize_user ────────────────────────────────────────────

/// Create a RepFlowUser account for a new participant.
pub fn initialize_user(ctx: Context<InitializeUser>) -> Result<()> {
    let now  = Clock::get()?.unix_timestamp;
    let user = &mut ctx.accounts.repflow_user;

    user.wallet              = ctx.accounts.wallet.key();
    user.balance             = 0;
    user.lifetime_earned     = 0;
    user.lifetime_slashed    = 0;
    user.daily_minted        = 0;
    user.daily_window_start  = now;
    user.slash_count         = 0;
    user.last_earned_at      = 0;
    user.milestones_claimed  = 0;
    user.bump                = ctx.bumps.repflow_user;

    emit!(UserInitialized {
        wallet: user.wallet,
        timestamp: now,
    });

    Ok(())
}

#[derive(Accounts)]
pub struct InitializeUser<'info> {
    #[account(
        init,
        payer  = payer,
        space  = 8 + RepFlowUser::SIZE,
        seeds  = [b"repflow_user", wallet.key().as_ref()],
        bump,
    )]
    pub repflow_user: Account<'info, RepFlowUser>,

    /// The user whose reputation account is being created.
    pub wallet: SystemAccount<'info>,

    #[account(mut)]
    pub payer: Signer<'info>,

    pub system_program: Program<'info, System>,
}

// ─── Instruction: mint_repflow ────────────────────────────────────────────────

/// Mint repFlow to a user's token account.
///
/// Only authorised minters (governance council members) can call this.
/// Enforces a 100K daily rate limit per user.
pub fn mint_repflow(ctx: Context<MintRepFlow>, amount: u64, activity_code: u8) -> Result<()> {
    let config = &mut ctx.accounts.config;
    let user   = &mut ctx.accounts.repflow_user;
    let now    = Clock::get()?.unix_timestamp;

    // ── Pause check ────────────────────────────────────────────────────────
    require!(!config.paused, RepFlowError::ProgramPaused);

    // ── Minter authorisation ───────────────────────────────────────────────
    require!(
        config.is_minter(&ctx.accounts.minter.key()),
        RepFlowError::UnauthorizedMinter
    );

    // ── Daily rate limit ───────────────────────────────────────────────────
    user.refresh_daily_window(now);
    let new_daily = user.daily_minted
        .checked_add(amount)
        .ok_or(RepFlowError::Overflow)?;

    require!(
        new_daily <= RepFlowUser::MAX_DAILY_MINT,
        RepFlowError::DailyRateLimitExceeded
    );

    // ── Mint via SPL Token-2022 ────────────────────────────────────────────
    let seeds   = &[b"repflow_config".as_ref(), &[config.bump]];
    let signer  = &[&seeds[..]];

    token_2022::mint_to(
        CpiContext::new_with_signer(
            ctx.accounts.token_program.to_account_info(),
            MintTo {
                mint:      ctx.accounts.mint.to_account_info(),
                to:        ctx.accounts.recipient_ata.to_account_info(),
                authority: ctx.accounts.config.to_account_info(),
            },
            signer,
        ),
        amount,
    )?;

    // ── Update user state ──────────────────────────────────────────────────
    user.balance             = user.balance.checked_add(amount).ok_or(RepFlowError::Overflow)?;
    user.lifetime_earned     = user.lifetime_earned.checked_add(amount).ok_or(RepFlowError::Overflow)?;
    user.daily_minted        = new_daily;
    user.last_earned_at      = now;

    // ── Update global stats ───────────────────────────────────────────────
    config.total_minted      = config.total_minted.checked_add(amount).ok_or(RepFlowError::Overflow)?;

    emit!(RepFlowMinted {
        wallet:        user.wallet,
        amount,
        activity_code,
        new_balance:   user.balance,
        tier:          user.tier() as u8,
        timestamp:     now,
    });

    msg!(
        "repFlow minted: {} to {} (activity={}) new_balance={} tier={:?}",
        amount, user.wallet, activity_code, user.balance, user.tier()
    );

    Ok(())
}

#[derive(Accounts)]
pub struct MintRepFlow<'info> {
    #[account(
        mut,
        seeds = [b"repflow_config"],
        bump  = config.bump,
    )]
    pub config: Account<'info, RepFlowConfig>,

    #[account(
        mut,
        seeds  = [b"repflow_user", repflow_user.wallet.as_ref()],
        bump   = repflow_user.bump,
    )]
    pub repflow_user: Account<'info, RepFlowUser>,

    /// The repFlow mint (PDA-owned by config).
    #[account(mut, constraint = mint.key() == config.key() /* validated off-chain */)]
    pub mint: UncheckedAccount<'info>,

    /// Recipient's associated token account.
    #[account(mut)]
    pub recipient_ata: UncheckedAccount<'info>,

    /// The minter (must be in config.minters).
    pub minter: Signer<'info>,

    pub token_program:  Program<'info, Token2022>,
    pub system_program: Program<'info, System>,
}

// ─── Events ───────────────────────────────────────────────────────────────────

#[event]
pub struct UserInitialized {
    pub wallet:    Pubkey,
    pub timestamp: i64,
}

#[event]
pub struct RepFlowMinted {
    pub wallet:        Pubkey,
    pub amount:        u64,
    /// Numeric code for the earning activity (matches RepFlowEarningActivity discriminant).
    pub activity_code: u8,
    pub new_balance:   u64,
    /// Tier after minting.
    pub tier:          u8,
    pub timestamp:     i64,
}
