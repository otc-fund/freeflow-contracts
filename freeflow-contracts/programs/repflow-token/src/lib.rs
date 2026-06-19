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
pub mod client_rep;
pub mod error;
pub mod mint;
pub mod state;
pub mod transfer_hook;

use burn::*;
use client_rep::*;
use mint::*;
use transfer_hook::*;
use state::{RepFlowConfig, RepFlowUser};
use error::RepFlowError;

declare_id!("8K4GhPEQ1yy9vdTaMPTL83G5qr5ZHZiBm2VBQ58jJs5w");

/// Rewards program ID — used in `mint_repflow_from_rewards` to verify that the
/// CPI caller's authority PDA is derived from the rewards program.
pub const REWARDS_PROGRAM_ID: Pubkey = pubkey!("26pFEqpZYeG5xxmAMc74ZsANo6Kdduf5HYq5qk7Y34eT");

#[program]
pub mod repflow_token {
    use super::*;

    // ── Admin / setup ───────────────────────────────────────────────────────

    /// Initialise the global repFlow config account.
    /// Called once at deployment. Sets the admin, the SPL Token-2022 mint address,
    /// and the initial minters/burners.
    pub fn initialize(
        ctx:           Context<Initialize>,
        mint:          Pubkey,
        minters:       Vec<Pubkey>,
        burners:       Vec<Pubkey>,
    ) -> Result<()> {
        let now    = Clock::get()?.unix_timestamp;
        let config = &mut ctx.accounts.config;

        config.admin        = ctx.accounts.admin.key();
        config.mint         = mint;
        config.paused       = false;
        config.updated_at   = now;
        config.bump         = ctx.bumps.config;

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

    /// Update the repFlow SPL Token-2022 mint address (admin only).
    ///
    /// Use this for migrations — e.g. replacing a mint that was deployed with
    /// wrong decimals. The new mint's authority MUST already be the
    /// `["repflow_config"]` PDA so the program can CPI mint to it.
    pub fn update_mint(ctx: Context<AdminOnly>, new_mint: Pubkey) -> Result<()> {
        let config = &mut ctx.accounts.config;
        let old    = config.mint;
        config.mint       = new_mint;
        config.updated_at = Clock::get()?.unix_timestamp;
        msg!("repFlow mint updated: {} → {}", old, new_mint);
        Ok(())
    }

    /// Full config reset — use after a layout migration where existing account
    /// data is stale (fields shifted when a new field was inserted mid-struct).
    ///
    /// Preserves `admin` (validated by the `has_one` constraint). Rewrites every
    /// other field so the account is back in a known-good state.
    ///
    /// `minters`    — list of authorised minter keys (max 5).
    pub fn reinitialize_config(
        ctx:        Context<AdminOnly>,
        new_mint:   Pubkey,
        minters:    Vec<Pubkey>,
    ) -> Result<()> {
        let config = &mut ctx.accounts.config;
        let now    = Clock::get()?.unix_timestamp;

        config.mint         = new_mint;
        config.paused       = false;
        config.updated_at   = now;
        config.bump         = ctx.bumps.config;

        config.minters = [Pubkey::default(); 5];
        let minter_count = minters.len().min(5);
        for (i, m) in minters.iter().take(minter_count).enumerate() {
            config.minters[i] = *m;
        }
        config.minter_count = minter_count as u8;

        config.burners      = [Pubkey::default(); 5];
        config.burner_count = 0;

        msg!(
            "repFlow config reinitialized: mint={} minters={}",
            new_mint, minter_count
        );
        Ok(())
    }

    // ── User management ─────────────────────────────────────────────────────

    /// Create a repFlow user account for a new participant.
    pub fn initialize_user(ctx: Context<InitializeUser>) -> Result<()> {
        mint::initialize_user(ctx)
    }

    // ── Client reputation (greenfield, PDA-only) ───────────────────────

    /// Create a client reputation account (client-funded).
    pub fn initialize_client_rep(ctx: Context<InitializeClientRep>) -> Result<()> {
        client_rep::initialize_client_rep(ctx)
    }

    /// Credit client repFlow (rewards-v2 CPI, mint_authority PDA).
    pub fn credit_client_rep(ctx: Context<CreditClientRep>, amount: u64) -> Result<()> {
        client_rep::credit_client_rep(ctx, amount)
    }

    /// Slash client repFlow (rewards-v2 CPI, slash_authority PDA).
    pub fn slash_client_rep(ctx: Context<SlashClientRep>, amount: u64) -> Result<()> {
        client_rep::slash_client_rep(ctx, amount)
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

    /// Instant slash via CPI from rewards-v2 (no appeal window).
    ///
    /// Called exclusively by rewards-v2 during `ClientDispute` or `SlashTrialFraud`.
    /// Signed by the rewards program's `slash_authority` PDA — no human appeal needed
    /// because the evidence is cryptographic (Merkle proof failure or audit hash).
    pub fn slash_repflow_from_rewards(
        ctx:    Context<SlashRepFlowFromRewards>,
        amount: u64,
    ) -> Result<()> {
        burn::slash_repflow_from_rewards(ctx, amount)
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

    // ── Fallback ─────────────────────────────────────────────────────────────

    /// Fallback handler — catches any unrecognised instruction discriminant.
    ///
    /// rewards-v2 may have been compiled against an older or differently-named
    /// repflow IDL. This fallback validates the caller is rewards-v2 via the
    /// `service_auth` PDA, then executes the same mint logic as
    /// `mint_repflow_from_rewards` regardless of which discriminant was sent.
    ///
    /// The received discriminant is logged so we can identify the correct
    /// instruction name for future IDL alignment.
    pub fn fallback<'info>(
        program_id: &Pubkey,
        accounts: &'info [AccountInfo<'info>],
        instruction_data: &[u8],
    ) -> Result<()> {
        // ── Log received discriminant for diagnostics ──
        msg!(
            "repflow_fallback: n_accts={} ilen={} disc={:?}",
            accounts.len(),
            instruction_data.len(),
            &instruction_data[..instruction_data.len().min(16)]
        );

        // ── Authorisation: service_auth (rewards-v2 PDA) must be a signer ──
        // service_auth = PDA(rewards-v2="26pFEq…", seed=b"mint_authority")
        //              = 8R4RWhw6ijFBu33WDXVnMTJnYB17n8mbUUwH33NDux2T
        const SERVICE_AUTH_BYTES: [u8; 32] = [
            0x6e, 0x2b, 0x9e, 0x2d, 0x0f, 0xe0, 0x46, 0x81,
            0xd4, 0xb4, 0x3f, 0x33, 0x7a, 0x94, 0x0c, 0x54,
            0xfa, 0xd7, 0x26, 0x20, 0x8e, 0x75, 0x40, 0x69,
            0xa2, 0x10, 0x7d, 0x51, 0x25, 0xbf, 0xf7, 0x90,
        ];
        let service_auth_key = Pubkey::from(SERVICE_AUTH_BYTES);
        let auth_ok = accounts
            .iter()
            .any(|a| *a.key == service_auth_key && a.is_signer);
        if !auth_ok {
            msg!("repflow_fallback: service_auth not present or not signer");
            return Err(error!(RepFlowError::UnauthorizedMinter));
        }

        // ── Parse amount from instruction data ──
        // Anchor CPI format: 8-byte discriminant + u64 amount (little-endian)
        if instruction_data.len() < 16 {
            msg!(
                "repflow_fallback: instruction_data too short ({})",
                instruction_data.len()
            );
            return Err(error!(RepFlowError::InvalidAuthorityConfig));
        }
        let amount =
            u64::from_le_bytes(instruction_data[8..16].try_into().unwrap());
        msg!("repflow_fallback: amount={}", amount);

        // ── Locate rf_config and rf_user by account discriminant ──
        // Discriminants = sha256("account:TypeName")[..8]
        // RepFlowConfig: 49a2b66790ccfb0e
        // RepFlowUser:   cdb8c87018a4d9b9
        const RF_CONFIG_DISC: [u8; 8] =
            [0x49, 0xa2, 0xb6, 0x67, 0x90, 0xcc, 0xfb, 0x0e];
        const RF_USER_DISC: [u8; 8] =
            [0xcd, 0xb8, 0xc8, 0x70, 0x18, 0xa4, 0xd9, 0xb9];

        let rf_config_info = accounts
            .iter()
            .find(|a| {
                if a.owner != program_id {
                    return false;
                }
                match a.try_borrow_data() {
                    Ok(d) => d.len() >= 8 && d[..8] == RF_CONFIG_DISC,
                    Err(_) => false,
                }
            })
            .ok_or_else(|| {
                msg!("repflow_fallback: rf_config account not found");
                error!(RepFlowError::InvalidAuthorityConfig)
            })?;

        let rf_user_info = accounts
            .iter()
            .find(|a| {
                if a.owner != program_id {
                    return false;
                }
                match a.try_borrow_data() {
                    Ok(d) => d.len() >= 8 && d[..8] == RF_USER_DISC,
                    Err(_) => false,
                }
            })
            .ok_or_else(|| {
                msg!("repflow_fallback: rf_user account not found");
                error!(RepFlowError::InvalidAuthorityConfig)
            })?;

        let now = Clock::get()?.unix_timestamp;

        // ── Pause check (read-only — PDA-only, no shared counter write) ──
        {
            let data = rf_config_info.try_borrow_data()?;
            let config = {
                let slice: &[u8] = &*data;
                RepFlowConfig::try_deserialize(&mut &*slice)?
            };
            require!(!config.paused, RepFlowError::ProgramPaused);
        }

        // ── Update rf_user balances ──
        {
            let mut data = rf_user_info.try_borrow_mut_data()?;
            let mut user = {
                let slice: &[u8] = &*data;
                RepFlowUser::try_deserialize(&mut &*slice)?
            };
            user.balance = user
                .balance
                .checked_add(amount)
                .ok_or(error!(RepFlowError::Overflow))?;
            user.lifetime_earned = user
                .lifetime_earned
                .checked_add(amount)
                .ok_or(error!(RepFlowError::Overflow))?;
            user.last_earned_at = now;
            let wallet  = user.wallet;
            let balance = user.balance;
            let mut writer: &mut [u8] = &mut *data;
            user.try_serialize(&mut writer)?;
            msg!(
                "repflow_fallback: minted {} to {} new_balance={}",
                amount, wallet, balance
            );
        }

        Ok(())
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
