//! repFlow Token Program — Non-Transferable Reputation Token for FreeFlow Network.
//!
//! repFlow (Reputation Flow) is an on-chain soulbound token that:
//!   - Cannot be transferred, bought, or sold (enforced via SPL Token-2022 Transfer Hook)
//!   - Is earned through genuine contributions (uptime, bandwidth, community, code)
//!   - Grants governance voting power (1–11 votes based on tier)
//!   - Increases $FLOW reward multipliers (0.9x–1.5x based on tier)
//!   - Gates premium network features (exit nodes, governance proposals)
//!   - Can be slashed (burned) for misbehavior via a 72-hour appeal process
//!
//! Program ID: RPFLxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx (replace before deploy)

use anchor_lang::prelude::*;

pub mod burn;
pub mod error;
pub mod mint;
pub mod state;
pub mod transfer_hook;

use burn::*;
use mint::*;
use transfer_hook::*;
use state::RepFlowConfig;

declare_id!("RPFLxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx");

#[program]
pub mod repflow_token {
    use super::*;

    // ── Admin / setup ───────────────────────────────────────────────────────

    /// Initialise the global repFlow config account.
    /// Called once at deployment. Sets the admin and initial minters/burners.
    pub fn initialize(
        ctx:           Context<Initialize>,
        minters:       Vec<Pubkey>,
        burners:       Vec<Pubkey>,
    ) -> Result<()> {
        let now    = Clock::get()?.unix_timestamp;
        let config = &mut ctx.accounts.config;

        config.admin       = ctx.accounts.admin.key();
        config.paused      = false;
        config.total_minted = 0;
        config.total_burned = 0;
        config.updated_at  = now;
        config.bump        = ctx.bumps.config;

        // Populate minters (max 9).
        let minter_count = minters.len().min(9);
        for (i, m) in minters.iter().take(minter_count).enumerate() {
            config.minters[i] = *m;
        }
        config.minter_count = minter_count as u8;

        // Populate burners (max 9).
        let burner_count = burners.len().min(9);
        for (i, b) in burners.iter().take(burner_count).enumerate() {
            config.burners[i] = *b;
        }
        config.burner_count = burner_count as u8;

        msg!(
            "repFlow config initialised: {} minters, {} burners",
            minter_count, burner_count
        );
        Ok(())
    }

    /// Toggle the emergency pause (admin only).
    pub fn set_paused(ctx: Context<AdminOnly>, paused: bool) -> Result<()> {
        ctx.accounts.config.paused     = paused;
        ctx.accounts.config.updated_at = Clock::get()?.unix_timestamp;
        msg!("repFlow program paused={}", paused);
        Ok(())
    }

    /// Add a new authorised minter (admin only, max 9).
    pub fn add_minter(ctx: Context<AdminOnly>, minter: Pubkey) -> Result<()> {
        let config = &mut ctx.accounts.config;
        let count  = config.minter_count as usize;
        require!(count < 9, error::RepFlowError::InvalidAuthorityConfig);
        config.minters[count] = minter;
        config.minter_count  += 1;
        config.updated_at     = Clock::get()?.unix_timestamp;
        msg!("Minter added: {}", minter);
        Ok(())
    }

    /// Add a new authorised burner (admin only, max 9).
    pub fn add_burner(ctx: Context<AdminOnly>, burner: Pubkey) -> Result<()> {
        let config = &mut ctx.accounts.config;
        let count  = config.burner_count as usize;
        require!(count < 9, error::RepFlowError::InvalidAuthorityConfig);
        config.burners[count] = burner;
        config.burner_count  += 1;
        config.updated_at     = Clock::get()?.unix_timestamp;
        msg!("Burner added: {}", burner);
        Ok(())
    }

    // ── User management ─────────────────────────────────────────────────────

    /// Create a repFlow user account for a new participant.
    pub fn initialize_user(ctx: Context<InitializeUser>) -> Result<()> {
        mint::initialize_user(ctx)
    }

    // ── Minting (earning) ───────────────────────────────────────────────────

    /// Mint repFlow to a user (authorised minters only).
    ///
    /// `activity_code` maps to `RepFlowEarningActivity` in the backend.
    pub fn mint_repflow(
        ctx:           Context<MintRepFlow>,
        amount:        u64,
        activity_code: u8,
    ) -> Result<()> {
        mint::mint_repflow(ctx, amount, activity_code)
    }

    // ── Slashing (burning) ──────────────────────────────────────────────────

    /// Propose a slash with evidence hash (starts 72h appeal window).
    pub fn propose_slash(
        ctx:           Context<ProposeSlash>,
        slash_amount:  u64,
        offense_code:  u8,
        evidence_hash: [u8; 32],
        slash_id:      u64,
    ) -> Result<()> {
        burn::propose_slash(ctx, slash_amount, offense_code, evidence_hash, slash_id)
    }

    /// User voluntarily waives their 72h appeal window.
    pub fn waive_appeal(ctx: Context<WaiveAppeal>) -> Result<()> {
        burn::waive_appeal(ctx)
    }

    /// Execute a slash after the appeal window has closed.
    pub fn execute_slash(ctx: Context<ExecuteSlash>, slash_id: u64) -> Result<()> {
        burn::execute_slash(ctx, slash_id)
    }

    // ── Transfer hook (SPL Token-2022 CPI) ─────────────────────────────────

    /// Transfer hook entry point — ALWAYS REJECTS.
    /// Called automatically by SPL Token-2022 on every transfer attempt.
    pub fn execute(ctx: Context<TransferHookExecute>, amount: u64) -> Result<()> {
        transfer_hook::execute_transfer_hook(ctx, amount)
    }
}

// ─── Account contexts (admin / shared) ───────────────────────────────────────

#[derive(Accounts)]
pub struct Initialize<'info> {
    #[account(
        init,
        payer  = admin,
        space  = 8 + RepFlowConfig::SIZE,
        seeds  = [b"repflow_config"],
        bump,
    )]
    pub config: Account<'info, RepFlowConfig>,

    #[account(mut)]
    pub admin: Signer<'info>,

    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct AdminOnly<'info> {
    #[account(
        mut,
        seeds  = [b"repflow_config"],
        bump   = config.bump,
        has_one = admin,
    )]
    pub config: Account<'info, RepFlowConfig>,

    pub admin: Signer<'info>,
}
