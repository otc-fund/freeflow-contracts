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

declare_id!("8K4GhPEQ1yy9vdTaMPTL83G5qr5ZHZiBm2VBQ58jJs5w");

/// Rewards program ID — used in `mint_repflow_from_rewards` to verify that the
/// CPI caller's authority PDA is derived from the rewards program.
pub const REWARDS_PROGRAM_ID: Pubkey = pubkey!("2yeVew5qq5jf5zuoqiE2svVLRE9HTN6J2GfB9LopdM1C");

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

        config.admin        = ctx.accounts.admin.key();
        config.paused       = false;
        config.total_minted = 0;
        config.total_burned = 0;
        config.updated_at   = now;
        config.bump         = ctx.bumps.config;
        // Set hard cap at 1 billion repFlow (tokenomics).
        config.max_supply   = crate::state::RepFlowConfig::MAX_SUPPLY;

        // Populate minters (max 5 for 3-of-5 multisig).
        let minter_count = minters.len().min(5);
        for (i, m) in minters.iter().take(minter_count).enumerate() {
            config.minters[i] = *m;
        }
        config.minter_count = minter_count as u8;

        // Populate burners (max 5 for 3-of-5 multisig).
        let burner_count = burners.len().min(5);
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

    /// Add a new authorised minter (admin only, max 5 for 3-of-5 multisig).
    pub fn add_minter(ctx: Context<AdminOnly>, minter: Pubkey) -> Result<()> {
        let config = &mut ctx.accounts.config;
        let count  = config.minter_count as usize;
        require!(count < 5, error::RepFlowError::InvalidAuthorityConfig);
        config.minters[count] = minter;
        config.minter_count  += 1;
        config.updated_at     = Clock::get()?.unix_timestamp;
        msg!("Minter added: {}", minter);
        Ok(())
    }

    /// Add a new authorised burner (admin only, max 5 for 3-of-5 multisig).
    pub fn add_burner(ctx: Context<AdminOnly>, burner: Pubkey) -> Result<()> {
        let config = &mut ctx.accounts.config;
        let count  = config.burner_count as usize;
        require!(count < 5, error::RepFlowError::InvalidAuthorityConfig);
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

    // ── Proof-of-Service (bootstrap path) ──────────────────────────────

    /// Submit a daily Proof-of-Service attestation for a relay.
    ///
    /// Call this before `claim_daily_uptime_repflow` to prove the relay served
    /// real client traffic. After the Stage 2 transition window, this is required.
    ///
    /// `date_bucket` must equal `unix_timestamp / 86_400` from the on-chain clock.
    /// The accounts constraint enforces this — callers cannot target a different day.
    pub fn submit_proof_of_service(
        ctx:          Context<SubmitProofOfService>,
        client_count: u32,
        bytes_routed: u64,
        period_start: i64,
        period_end:   i64,
        date_bucket:  i64,
    ) -> Result<()> {
        // date_bucket is validated in the accounts constraint.
        // It is not passed to the handler (the handler re-derives it from the clock).
        let _ = date_bucket;
        mint::submit_proof_of_service(ctx, client_count, bytes_routed, period_start, period_end)
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

    /// Mint repFlow via the rewards program CPI (automated earning pipeline).
    ///
    /// Only callable by the rewards program — verified by checking that
    /// `rewards_authority` is a signer whose key equals
    /// `find_pda([b"mint_authority"], REWARDS_PROGRAM_ID)`.
    ///
    /// Activity codes: 1=Uptime (≤50/day), 2=Bandwidth (1 per GB), 6=DisputeWin.
    pub fn mint_repflow_from_rewards(
        ctx:           Context<MintRepFlowFromRewards>,
        amount:        u64,
        activity_code: u8,
    ) -> Result<()> {
        mint::mint_repflow_from_rewards(ctx, amount, activity_code)
    }

    /// Claim daily uptime repFlow (relay-signed, separate from $FLOW release cycle).
    ///
    /// The relay wallet signs this instruction to prove liveness.
    /// Capped at 50/day (uptime sub-limit) plus 200/day (total daily cap).
    /// The relay sidecar triggers this once per 24-hour window.
    pub fn claim_daily_uptime_repflow(
        ctx:    Context<ClaimDailyUptimeRepflow>,
        amount: u64,
    ) -> Result<()> {
        mint::claim_daily_uptime_repflow(ctx, amount)
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

    /// Initialize the extra-account-metas PDA for the transfer hook.
    ///
    /// **Must be called once after the repFlow mint is created.** Until this PDA
    /// exists, the SPL Token-2022 runtime cannot locate the hook's account list and
    /// the transfer hook is not active — leaving repFlow transferable. Calling this
    /// instruction locks the mint as soulbound from that point forward.
    ///
    /// Accounts: see `InitializeExtraAccountMetaList` in `transfer_hook.rs`.
    pub fn initialize_extra_account_meta_list(
        ctx: Context<InitializeExtraAccountMetaList>,
    ) -> Result<()> {
        transfer_hook::initialize_extra_account_meta_list(ctx)
    }

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
        bump,  // canonical — config.bump may be 0 from old program
        has_one = admin,
    )]
    pub config: Account<'info, RepFlowConfig>,

    pub admin: Signer<'info>,
}
