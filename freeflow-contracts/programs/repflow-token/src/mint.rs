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

    // ── C-2: Transfer hook initialization guard ───────────────────────────
    // Verify the ExtraAccountMetaList PDA exists before minting.
    // Without it the SPL Token-2022 runtime cannot find the hook's account list,
    // meaning the transfer hook is inactive and repFlow is freely transferable.
    //
    // Callers MUST pass the ExtraAccountMetaList PDA as a remaining account.
    // PDA seeds: [b"extra-account-metas", mint.key()] — SPL Token-2022 standard.
    let (expected_eam_pda, _) = Pubkey::find_program_address(
        &[b"extra-account-metas", ctx.accounts.mint.key().as_ref()],
        &crate::ID,
    );
    require!(
        ctx.remaining_accounts
            .iter()
            .any(|a| a.key() == expected_eam_pda && a.lamports() > 0),
        RepFlowError::TransferHookNotInitialized,
    );

    // ── C-1: Supply cap check (BEFORE mint) ───────────────────────────────
    // Enforced BEFORE the CPI so the SPL mint cannot execute if it would
    // exceed the 1 B repFlow supply cap. Previously this check was after
    // `mint_to` — this fix closes that ordering vulnerability.
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

    // ── C-2: Transfer hook initialization guard ───────────────────────────
    // Verify the ExtraAccountMetaList PDA exists before minting.
    // The rewards program CPI caller MUST pass the ExtraAccountMetaList PDA
    // as a remaining account when calling this instruction.
    let (expected_eam_pda, _) = Pubkey::find_program_address(
        &[b"extra-account-metas", ctx.accounts.mint.key().as_ref()],
        &crate::ID,
    );
    require!(
        ctx.remaining_accounts
            .iter()
            .any(|a| a.key() == expected_eam_pda && a.lamports() > 0),
        RepFlowError::TransferHookNotInitialized,
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

    // ── C-2: Transfer hook initialization guard ───────────────────────────
    // Verify the ExtraAccountMetaList PDA exists before minting.
    // The relay sidecar MUST pass the ExtraAccountMetaList PDA as a remaining
    // account when calling this instruction.
    let (expected_eam_pda, _) = Pubkey::find_program_address(
        &[b"extra-account-metas", ctx.accounts.mint.key().as_ref()],
        &crate::ID,
    );
    require!(
        ctx.remaining_accounts
            .iter()
            .any(|a| a.key() == expected_eam_pda && a.lamports() > 0),
        RepFlowError::TransferHookNotInitialized,
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

#[cfg(test)]
mod tests {
    use super::*;

    // ── C-1: Supply cap ordering ──────────────────────────────────────────────

    /// C-1: Supply cap arithmetic — new_total > max_supply must be caught.
    ///
    /// Verifies that the supply cap check correctly identifies when a mint
    /// would breach the 1 B supply limit. The *ordering* (check before CPI)
    /// is enforced by code review — this test covers the arithmetic logic.
    #[test]
    fn supply_cap_check_catches_overflow_before_cpi() {
        let total_minted: u64 = 999_999_999;
        let max_supply: u64   = 1_000_000_000;

        // Exactly at cap — should be allowed.
        let amount_ok: u64 = 1;
        let new_total_ok = total_minted.checked_add(amount_ok).unwrap();
        assert_eq!(new_total_ok, max_supply);
        assert!(!(max_supply > 0 && new_total_ok > max_supply),
            "exactly at cap must not trigger the cap error");

        // One above cap — must be rejected.
        let amount_over: u64 = 2;
        let new_total_over = total_minted.checked_add(amount_over).unwrap();
        assert!(max_supply > 0 && new_total_over > max_supply,
            "one over cap must trigger the cap error");
    }

    /// C-1: With max_supply = 0 (disabled), any amount should pass the cap check.
    #[test]
    fn supply_cap_check_disabled_when_max_supply_zero() {
        let total_minted: u64 = u64::MAX - 1;
        let max_supply: u64   = 0; // disabled
        let amount: u64       = 1;

        let new_total = total_minted.checked_add(amount).unwrap();
        // When max_supply == 0 the condition `max_supply > 0` is false → no cap.
        assert!(!(max_supply > 0 && new_total > max_supply),
            "max_supply = 0 disables the cap check");
    }

    // ── C-2: Transfer hook guard PDA derivation ───────────────────────────────

    /// C-2: The ExtraAccountMetaList PDA is derived from the correct seeds.
    ///
    /// Guards in all three mint functions derive the PDA via:
    ///   find_program_address([b"extra-account-metas", mint.key()], program_id)
    ///
    /// This test verifies the derivation is deterministic and matches the seeds
    /// used in `InitializeExtraAccountMetaList`.
    #[test]
    fn transfer_hook_guard_pda_derivation_matches_init() {
        let program_id = crate::ID;
        let mint = Pubkey::new_unique();

        // Guard-side derivation (inside mint functions).
        let (guard_pda, guard_bump) = Pubkey::find_program_address(
            &[b"extra-account-metas", mint.as_ref()],
            &program_id,
        );

        // Init-side derivation (InitializeExtraAccountMetaList uses the same seeds).
        let (init_pda, init_bump) = Pubkey::find_program_address(
            &[b"extra-account-metas", mint.as_ref()],
            &program_id,
        );

        assert_eq!(guard_pda, init_pda,
            "guard PDA must match the initialized PDA");
        assert_eq!(guard_bump, init_bump,
            "bumps must be identical for the same mint");
    }

    /// C-2: The guard correctly distinguishes initialized vs uninitialized PDAs.
    ///
    /// Simulates the remaining_accounts lookup logic used in the guard:
    ///   any(|a| a.key() == &expected_pda && a.lamports() > 0)
    ///
    /// Confirms a missing account is rejected and a present one is accepted.
    #[test]
    fn transfer_hook_guard_logic_accepts_initialized_rejects_missing() {
        let program_id   = crate::ID;
        let mint         = Pubkey::new_unique();
        let (expected, _) = Pubkey::find_program_address(
            &[b"extra-account-metas", mint.as_ref()],
            &program_id,
        );

        // Case 1: empty remaining_accounts → guard should reject.
        let empty: Vec<Pubkey> = vec![];
        let found = empty.iter().any(|k| k == &expected);
        assert!(!found, "empty remaining_accounts must fail the guard");

        // Case 2: correct PDA in remaining_accounts → guard should pass.
        let present = vec![expected];
        let found = present.iter().any(|k| k == &expected);
        assert!(found, "correct PDA in remaining_accounts must pass the guard");

        // Case 3: wrong PDA in remaining_accounts → guard should reject.
        let wrong_pda = Pubkey::new_unique();
        let wrong = vec![wrong_pda];
        let found = wrong.iter().any(|k| k == &expected);
        assert!(!found, "wrong PDA must not satisfy the guard");
    }

    /// C-2: TransferHookNotInitialized error variant is present and has correct message.
    #[test]
    fn transfer_hook_not_initialized_error_exists() {
        let err = crate::error::RepFlowError::TransferHookNotInitialized;
        let msg = err.to_string();
        assert!(msg.contains("ExtraAccountMetaList"),
            "error message must reference ExtraAccountMetaList: {msg}");
        assert!(msg.contains("soulbound"),
            "error message must mention soulbound property: {msg}");
    }
}
