//! Client reputation — greenfield, PDA-only. Mirrors the relay RepFlowUser
//! patterns (per-user daily cap, daily-window refresh) with no SPL and no
//! shared global counter.

use anchor_lang::prelude::*;

use crate::{error::RepFlowError, state::{ClientRep, RepFlowConfig}};

/// Create a ClientRep account. User-funded: `payer == wallet` (the client).
pub fn initialize_client_rep(ctx: Context<InitializeClientRep>) -> Result<()> {
    let now    = Clock::get()?.unix_timestamp;
    let client = &mut ctx.accounts.client_rep;
    client.wallet             = ctx.accounts.wallet.key();
    client.balance            = 0;
    client.lifetime_earned    = 0;
    client.lifetime_slashed   = 0;
    client.disputes_won       = 0;
    client.disputes_lost      = 0;
    client.last_active_at     = now;
    client.daily_minted       = 0;
    client.daily_window_start = now;
    client.bump               = ctx.bumps.client_rep;
    client._reserved          = [0u8; 64];
    Ok(())
}

#[derive(Accounts)]
pub struct InitializeClientRep<'info> {
    #[account(
        init,
        payer  = payer,
        space  = 8 + ClientRep::SIZE,
        seeds  = [b"client_rep", wallet.key().as_ref()],
        bump,
    )]
    pub client_rep: Account<'info, ClientRep>,

    /// The client whose reputation account is created.
    pub wallet: SystemAccount<'info>,

    /// User-funded: the client pays its own rent.
    #[account(mut)]
    pub payer: Signer<'info>,

    pub system_program: Program<'info, System>,
}

/// Credit client repFlow — authorised via the rewards program's mint_authority PDA.
pub fn credit_client_rep(ctx: Context<CreditClientRep>, amount: u64) -> Result<()> {
    let config = &ctx.accounts.config;
    require!(!config.paused, RepFlowError::ProgramPaused);

    let (expected_auth, _) = Pubkey::find_program_address(
        &[b"mint_authority"], &crate::REWARDS_PROGRAM_ID);
    require!(
        ctx.accounts.rewards_authority.key() == expected_auth,
        RepFlowError::UnauthorizedRewardsCPI,
    );

    let now    = Clock::get()?.unix_timestamp;
    let client = &mut ctx.accounts.client_rep;
    client.refresh_daily_window(now);

    let new_daily = client.daily_minted.checked_add(amount).ok_or(RepFlowError::Overflow)?;
    require!(new_daily <= ClientRep::MAX_DAILY_MINT, RepFlowError::DailyRateLimitExceeded);

    client.balance         = client.balance.checked_add(amount).ok_or(RepFlowError::Overflow)?;
    client.lifetime_earned = client.lifetime_earned.checked_add(amount).ok_or(RepFlowError::Overflow)?;
    client.daily_minted    = new_daily;
    client.last_active_at   = now;
    Ok(())
}

#[derive(Accounts)]
pub struct CreditClientRep<'info> {
    #[account(seeds = [b"repflow_config"], bump)]
    pub config: Account<'info, RepFlowConfig>,

    #[account(
        mut,
        seeds = [b"client_rep", client_rep.wallet.as_ref()],
        bump  = client_rep.bump,
    )]
    pub client_rep: Account<'info, ClientRep>,

    pub rewards_authority: Signer<'info>,
}

/// Slash client repFlow — authorised via the rewards program's slash_authority PDA.
pub fn slash_client_rep(ctx: Context<SlashClientRep>, amount: u64) -> Result<()> {
    let config = &ctx.accounts.config;
    require!(!config.paused, RepFlowError::ProgramPaused);

    let (expected_auth, _) = Pubkey::find_program_address(
        &[b"slash_authority"], &crate::REWARDS_PROGRAM_ID);
    require!(
        ctx.accounts.slash_authority.key() == expected_auth,
        RepFlowError::UnauthorizedRewardsCPI,
    );

    let client = &mut ctx.accounts.client_rep;
    let actual = amount.min(client.balance);
    client.balance          = client.balance.saturating_sub(actual);
    client.lifetime_slashed = client.lifetime_slashed.saturating_add(actual);
    client.disputes_lost    = client.disputes_lost.saturating_add(1);
    Ok(())
}

#[derive(Accounts)]
pub struct SlashClientRep<'info> {
    #[account(seeds = [b"repflow_config"], bump)]
    pub config: Account<'info, RepFlowConfig>,

    #[account(
        mut,
        seeds = [b"client_rep", client_rep.wallet.as_ref()],
        bump  = client_rep.bump,
    )]
    pub client_rep: Account<'info, ClientRep>,

    pub slash_authority: Signer<'info>,
}
