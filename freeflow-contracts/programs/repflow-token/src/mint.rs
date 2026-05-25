//! repFlow minting — authorised minters only.
//!
//! Mint operations are triggered by verified on-chain events or
//! by the governance council submitting mint transactions.
//!
//! Rate limit: 200 repFlow per user per 24-hour window (uptime ≤ 50 + bandwidth 1 repFlow/GB).

use anchor_lang::prelude::*;
use anchor_spl::token_2022::{self, MintTo, Token2022};

use crate::{
    error::RepFlowError,
    state::{RepFlowConfig, RepFlowEarningActivity, RepFlowUser},
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
    user.uptime_daily_minted = 0;

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
/// Enforces a 200 repFlow daily rate limit per user (24-hour rolling window).
pub fn mint_repflow(ctx: Context<MintRepFlow>, amount: u64, activity_code: u8) -> Result<()> {
    // Extract config_info before mutable borrow
    let config_bump = ctx.accounts.config.bump;
    let config_info = ctx.accounts.config.to_account_info();
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
    let seeds   = &[b"repflow_config".as_ref(), &[config_bump]];
    let signer  = &[&seeds[..]];

    token_2022::mint_to(
        CpiContext::new_with_signer(
            ctx.accounts.token_program.to_account_info(),
            MintTo {
                mint:      ctx.accounts.mint.to_account_info(),
                to:        ctx.accounts.recipient_ata.to_account_info(),
                authority: config_info,
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

    // ── Supply cap check ──────────────────────────────────────────────────
    // If max_supply is set (non-zero), enforce the hard cap before minting.
    // This prevents total repFlow from exceeding the 1B tokenomics limit.
    let new_total = config.total_minted
        .checked_add(amount)
        .ok_or(RepFlowError::Overflow)?;
    if config.max_supply > 0 && new_total > config.max_supply {
        msg!(
            "mint_repflow: would exceed max_supply ({} + {} > {})",
            config.total_minted, amount, config.max_supply
        );
        return Err(RepFlowError::Overflow.into());
    }

    // ── Update global stats ───────────────────────────────────────────────
    config.total_minted = new_total;

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
    /// M-02: Removed the dead constraint `mint.key() == config.key()` — it compared
    /// the mint account's pubkey against the config PDA's pubkey, which can never be
    /// equal (different PDAs), so every mint_repflow call would have been rejected
    /// with a constraint violation. Proper mint validation is done via `config.mint_pubkey`
    /// in the tokenomics phase; for now we accept the caller-provided mint and rely on
    /// SPL Token-2022 to reject a mismatched mint authority.
    #[account(mut)]
    pub mint: UncheckedAccount<'info>,

    /// Recipient's associated token account.
    #[account(mut)]
    pub recipient_ata: UncheckedAccount<'info>,

    /// The minter (must be in config.minters).
    pub minter: Signer<'info>,

    pub token_program:  Program<'info, Token2022>,
    pub system_program: Program<'info, System>,
}

// ─── Instruction: mint_repflow_from_rewards ───────────────────────────────────

/// Mint repFlow as part of the automated rewards pipeline (CPI from rewards program).
///
/// Called exclusively by the rewards program via CPI, signed with the rewards
/// `mint_authority` PDA (seeds: `[b"mint_authority"]` from the rewards program).
/// The PDA signature proves the caller is the rewards program — no other program
/// can produce a valid signature for that PDA address.
///
/// Enforces:
///   - 200 repFlow/day total cap (all activities combined).
///   - 50 repFlow/day uptime sub-limit (when `activity_code = 1`).
///
/// Activity codes: 1 = Uptime, 2 = Bandwidth (1 repFlow/GB), 6 = DisputeWin.
pub fn mint_repflow_from_rewards(
    ctx:           Context<MintRepFlowFromRewards>,
    amount:        u64,
    activity_code: u8,
) -> Result<()> {
    let config_bump = ctx.accounts.config.bump;
    let config_info = ctx.accounts.config.to_account_info();
    let config = &mut ctx.accounts.config;
    let user   = &mut ctx.accounts.repflow_user;
    let now    = Clock::get()?.unix_timestamp;

    // ── Pause check ────────────────────────────────────────────────────────
    require!(!config.paused, RepFlowError::ProgramPaused);

    // ── Rewards authority verification ────────────────────────────────────
    // The rewards_authority account must be the rewards program's mint_authority PDA.
    // Only the rewards program can produce a signer for this PDA address, ensuring
    // this instruction is only callable via CPI from the rewards program.
    let (expected_auth, _) = anchor_lang::prelude::Pubkey::find_program_address(
        &[b"mint_authority"],
        &crate::REWARDS_PROGRAM_ID,
    );
    require!(
        ctx.accounts.rewards_authority.key() == expected_auth,
        RepFlowError::UnauthorizedRewardsCPI,
    );

    // ── Activity code validation ───────────────────────────────────────────
    let activity = RepFlowEarningActivity::try_from_code(activity_code)
        .ok_or(RepFlowError::InvalidActivityCode)?;

    // ── Daily window refresh ───────────────────────────────────────────────
    user.refresh_daily_window(now);

    // ── Uptime sub-limit check ─────────────────────────────────────────────
    if activity == RepFlowEarningActivity::Uptime {
        let new_uptime = user.uptime_daily_minted
            .checked_add(amount)
            .ok_or(RepFlowError::Overflow)?;
        require!(
            new_uptime <= RepFlowUser::MAX_DAILY_UPTIME,
            RepFlowError::UptimeDailyCapExceeded,
        );
    }

    // ── Total daily cap check ──────────────────────────────────────────────
    let new_daily = user.daily_minted
        .checked_add(amount)
        .ok_or(RepFlowError::Overflow)?;
    require!(
        new_daily <= RepFlowUser::MAX_DAILY_MINT,
        RepFlowError::DailyRateLimitExceeded,
    );

    // ── Supply cap check ──────────────────────────────────────────────────
    let new_total = config.total_minted
        .checked_add(amount)
        .ok_or(RepFlowError::Overflow)?;
    if config.max_supply > 0 && new_total > config.max_supply {
        msg!(
            "mint_repflow_from_rewards: would exceed max_supply ({} + {} > {})",
            config.total_minted, amount, config.max_supply
        );
        return Err(RepFlowError::Overflow.into());
    }

    // ── Mint via SPL Token-2022 ────────────────────────────────────────────
    let seeds  = &[b"repflow_config".as_ref(), &[config_bump]];
    let signer = &[&seeds[..]];

    token_2022::mint_to(
        CpiContext::new_with_signer(
            ctx.accounts.token_program.to_account_info(),
            MintTo {
                mint:      ctx.accounts.mint.to_account_info(),
                to:        ctx.accounts.recipient_ata.to_account_info(),
                authority: config_info,
            },
            signer,
        ),
        amount,
    )?;

    // ── Update user state ──────────────────────────────────────────────────
    if activity == RepFlowEarningActivity::Uptime {
        user.uptime_daily_minted = user.uptime_daily_minted
            .checked_add(amount)
            .ok_or(RepFlowError::Overflow)?;
    }
    user.balance         = user.balance.checked_add(amount).ok_or(RepFlowError::Overflow)?;
    user.lifetime_earned = user.lifetime_earned.checked_add(amount).ok_or(RepFlowError::Overflow)?;
    user.daily_minted    = new_daily;
    user.last_earned_at  = now;
    config.total_minted  = new_total;

    emit!(RepFlowMinted {
        wallet:        user.wallet,
        amount,
        activity_code,
        new_balance:   user.balance,
        tier:          user.tier() as u8,
        timestamp:     now,
    });

    msg!(
        "repFlow minted (rewards CPI): {} to {} (activity={}) new_balance={}",
        amount, user.wallet, activity_code, user.balance
    );

    Ok(())
}

#[derive(Accounts)]
pub struct MintRepFlowFromRewards<'info> {
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

    /// The repFlow mint (PDA-owned by config — Token-2022).
    #[account(mut)]
    pub mint: UncheckedAccount<'info>,

    /// Recipient's associated token account (relay's or challenger's repFlow ATA).
    #[account(mut)]
    pub recipient_ata: UncheckedAccount<'info>,

    /// Rewards program's `mint_authority` PDA (seeds: `[b"mint_authority"]` from rewards program).
    ///
    /// Must be a signer — only the rewards program can produce this signature via
    /// `invoke_signed`. This is the cross-program authorization mechanism.
    pub rewards_authority: Signer<'info>,

    pub token_program: Program<'info, Token2022>,
}

// ─── Instruction: claim_daily_uptime_repflow ──────────────────────────────────

/// Claim daily uptime repFlow — relay-signed, separate from the $FLOW release cycle.
///
/// The relay calls this instruction at most once per 24-hour window to earn uptime
/// repFlow (up to 50/day). The relay's wallet signature proves liveness.
///
/// This is "Approach 2" from DUAL-TOKEN-MINTING.md: uptime repFlow is not tied to
/// individual $FLOW claim releases (which fire every 7+ days). Instead the relay
/// sidecar triggers this daily.
///
/// `amount` repFlow to mint. Capped at:
///   - `50 - uptime_daily_minted` (uptime sub-limit)
///   - `200 - daily_minted` (total daily cap)
pub fn claim_daily_uptime_repflow(
    ctx:    Context<ClaimDailyUptimeRepflow>,
    amount: u64,
) -> Result<()> {
    let config_bump = ctx.accounts.config.bump;
    let config_info = ctx.accounts.config.to_account_info();
    let config = &mut ctx.accounts.config;
    let user   = &mut ctx.accounts.repflow_user;
    let now    = Clock::get()?.unix_timestamp;

    // ── Pause check ────────────────────────────────────────────────────────
    require!(!config.paused, RepFlowError::ProgramPaused);

    // ── Daily window refresh ───────────────────────────────────────────────
    user.refresh_daily_window(now);

    // ── Uptime sub-limit check ─────────────────────────────────────────────
    let new_uptime = user.uptime_daily_minted
        .checked_add(amount)
        .ok_or(RepFlowError::Overflow)?;
    require!(
        new_uptime <= RepFlowUser::MAX_DAILY_UPTIME,
        RepFlowError::UptimeDailyCapExceeded,
    );

    // ── Total daily cap check ──────────────────────────────────────────────
    let new_daily = user.daily_minted
        .checked_add(amount)
        .ok_or(RepFlowError::Overflow)?;
    require!(
        new_daily <= RepFlowUser::MAX_DAILY_MINT,
        RepFlowError::DailyRateLimitExceeded,
    );

    // ── Supply cap check ──────────────────────────────────────────────────
    let new_total = config.total_minted
        .checked_add(amount)
        .ok_or(RepFlowError::Overflow)?;
    if config.max_supply > 0 && new_total > config.max_supply {
        msg!(
            "claim_daily_uptime_repflow: would exceed max_supply ({} + {} > {})",
            config.total_minted, amount, config.max_supply
        );
        return Err(RepFlowError::Overflow.into());
    }

    // ── Mint via SPL Token-2022 ────────────────────────────────────────────
    let seeds  = &[b"repflow_config".as_ref(), &[config_bump]];
    let signer = &[&seeds[..]];

    token_2022::mint_to(
        CpiContext::new_with_signer(
            ctx.accounts.token_program.to_account_info(),
            MintTo {
                mint:      ctx.accounts.mint.to_account_info(),
                to:        ctx.accounts.relay_ata.to_account_info(),
                authority: config_info,
            },
            signer,
        ),
        amount,
    )?;

    // ── Update user state ──────────────────────────────────────────────────
    user.balance             = user.balance.checked_add(amount).ok_or(RepFlowError::Overflow)?;
    user.lifetime_earned     = user.lifetime_earned.checked_add(amount).ok_or(RepFlowError::Overflow)?;
    user.daily_minted        = new_daily;
    user.uptime_daily_minted = new_uptime;
    user.last_earned_at      = now;
    config.total_minted      = new_total;

    emit!(RepFlowMinted {
        wallet:        user.wallet,
        amount,
        activity_code: RepFlowEarningActivity::Uptime as u8,
        new_balance:   user.balance,
        tier:          user.tier() as u8,
        timestamp:     now,
    });

    msg!(
        "Daily uptime repFlow claimed: {} to {} new_balance={}",
        amount, user.wallet, user.balance
    );

    Ok(())
}

#[derive(Accounts)]
pub struct ClaimDailyUptimeRepflow<'info> {
    #[account(
        mut,
        seeds = [b"repflow_config"],
        bump  = config.bump,
    )]
    pub config: Account<'info, RepFlowConfig>,

    /// The relay's repFlow user account.
    /// PDA seeds enforce wallet == relay_wallet.key().
    #[account(
        mut,
        seeds  = [b"repflow_user", relay_wallet.key().as_ref()],
        bump   = repflow_user.bump,
    )]
    pub repflow_user: Account<'info, RepFlowUser>,

    /// The relay's wallet — signer — proves the relay is online (liveness).
    pub relay_wallet: Signer<'info>,

    /// The repFlow mint (Token-2022, PDA-owned by config).
    #[account(mut)]
    pub mint: UncheckedAccount<'info>,

    /// Relay's associated repFlow token account.
    #[account(mut)]
    pub relay_ata: UncheckedAccount<'info>,

    pub token_program: Program<'info, Token2022>,
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
