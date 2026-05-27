//! FreeFlow User Escrow Program (Anchor / Solana).
//!
//! Permanent user escrow using the pre-mint model:
//!   - Treasury pre-mints 30,000,000 $FLOW at deployment
//!   - Phase 1: Users buy $FLOW from treasury at fixed $0.10/$FLOW
//!   - Phase 2: Users buy $FLOW on DEX → send to escrow
//!   - Relay claims mint NEW $FLOW (70:30 split) via rewards contract
//!   - User spend BURNS $FLOW (deflationary)
//!   - NO withdrawal code exists. NO cap. NO admin override.
//!
//! Instructions:
//!   initialize_registry         — Foundation initialises spender registry
//!   update_spender_registry     — Foundation multisig adds/removes spenders
//!   purchase_and_escrow         — Phase 1: user pays → $FLOW from treasury → escrow
//!   purchase_and_escrow_phase2  — Phase 2: user DEX-bought $FLOW → escrow
//!   spend_from_escrow           — Registry-verified spender burns $FLOW from escrow
//!
//! Authorization model:
//!   Authorized spenders stored in AuthorizedSpenderRegistry PDA.
//!   Only Foundation multisig (3-of-5) can add/remove spenders.
//!   NO per-user authorized_spender — prevents bank-run / phishing attacks.
//!   CPI redirect protection: relay wallet verified on every spend.
//!
//! Economics:
//!   Burn-on-spend keeps net supply neutral per cycle (minted = burned).
//!   Relay paid via 70:30 split on mint (rewards contract) — NOT via spend_from_escrow.

use anchor_lang::prelude::*;
use anchor_spl::token::{self, Burn, Mint, Token, TokenAccount, Transfer};

declare_id!("7PzcA2sNDzrvhTNLFScWZuNKS4g7jCCghsowZA9RsZ26");

// H-04: Foundation multisig pubkey — only this account may call admin instructions.
// Using solana_program::pubkey! validates the base58 string at compile time.
pub const FOUNDATION_PUBKEY: Pubkey =
    solana_program::pubkey!("8SL4dhnXU9tjvsbwfkVzQbfV99wGnVZBECoiuwrdbaJk");

/// Calculate referral reward without importing the referral crate.
///
/// Uses u128 to prevent overflow. Returns `min(amount * bps / 10_000, max_reward)`.
fn calculate_referral_reward(amount: u64, reward_bps: u16, max_reward: u64) -> u64 {
    let reward = (amount as u128)
        .saturating_mul(reward_bps as u128)
        .checked_div(10_000)
        .unwrap_or(0) as u64;
    reward.min(max_reward)
}

// ─── Program ─────────────────────────────────────────────────────────────────

#[program]
pub mod user_escrow {
    use super::*;

    // ── P0.5: Registry management ─────────────────────────────────────────────

    /// Initialize the global AuthorizedSpenderRegistry.
    /// Only the Foundation multisig can call this.
    pub fn initialize_registry(
        ctx: Context<InitializeRegistry>,
        initial_spender: Pubkey,
    ) -> Result<()> {
        let registry        = &mut ctx.accounts.registry;
        registry.authority  = ctx.accounts.foundation.key();
        registry.active_spenders = vec![initial_spender];
        registry.version    = 1;

        emit!(SpenderRegistryUpdated {
            add_spenders:    vec![initial_spender],
            remove_spenders: vec![],
            version:         registry.version,
        });

        Ok(())
    }

    /// Add or remove spenders from the registry.
    /// ONLY the Foundation multisig (registry.authority) can call this.
    pub fn update_spender_registry(
        ctx: Context<UpdateRegistry>,
        add_spenders:    Vec<Pubkey>,
        remove_spenders: Vec<Pubkey>,
    ) -> Result<()> {
        let registry = &mut ctx.accounts.registry;

        // Foundation-only guard (runtime check complements the Signer constraint)
        require!(
            registry.authority == ctx.accounts.foundation.key(),
            EscrowError::NotFoundation
        );

        for spender in &add_spenders {
            if !registry.active_spenders.contains(spender) {
                registry.active_spenders.push(*spender);
            }
        }
        registry.active_spenders.retain(|s| !remove_spenders.contains(s));
        registry.version += 1;

        emit!(SpenderRegistryUpdated {
            add_spenders,
            remove_spenders,
            version: registry.version,
        });

        Ok(())
    }

    // ── P1: Phase 1 purchase (treasury transfer) ──────────────────────────────

    /// Phase 1: User pays USD-equivalent → treasury transfers $FLOW → escrow.
    ///
    /// Fixed price: $0.10 / $FLOW.
    /// payment_amount is in USD cents (e.g. 300 = $3.00 = 30 $FLOW).
    ///
    /// When `referrer` is `Some(pubkey)`, a referral cut is split to `pool_vault`
    /// and only the remainder goes to escrow. Pass `None` for the original behaviour.
    ///
    /// When `referrer` is `None`, `pool_vault` and `referral_config` may be any
    /// pubkey (e.g. `SystemProgram::id()`); they are not accessed.
    ///
    /// NO cap check — permanent escrow makes sybil attacks harmless.
    /// NO withdrawal function — code does not exist.
    pub fn purchase_and_escrow(
        ctx:            Context<PurchaseAndEscrow>,
        payment_amount: u64,
        payment_type:   PaymentType,
        referrer:       Option<Pubkey>,
    ) -> Result<()> {
        require!(payment_amount > 0, EscrowError::InvalidPaymentAmount);

        // Phase 1 fixed price: $0.10 / $FLOW.
        // payment_amount is USD cents; $FLOW has 9 decimals.
        //   flow_lamports = (cents / 10_cents_per_FLOW) * 1e9
        //                 = (payment_amount * 1e9) / 10
        let flow_lamports = payment_amount
            .checked_mul(1_000_000_000)
            .and_then(|v| v.checked_div(10))
            .ok_or(EscrowError::InvalidPaymentAmount)?;

        require!(flow_lamports > 0, EscrowError::InvalidPaymentAmount);

        let bump = ctx.bumps.treasury_authority;

        // Determine how much goes to escrow vs. referral pool.
        let (escrow_amount, referral_reward) = if referrer.is_some() {
            // Read reward params from ReferralConfig at known raw-Borsh offsets:
            //   [0..2]  reward_bps:            u16
            //   [2..10] max_reward_lamports:   u64
            let config_data = ctx.accounts.referral_config.data.borrow();
            require!(config_data.len() >= 10, EscrowError::InvalidPaymentAmount);
            let reward_bps  = u16::from_le_bytes(config_data[0..2].try_into().unwrap());
            let max_reward  = u64::from_le_bytes(config_data[2..10].try_into().unwrap());
            drop(config_data);

            let reward = calculate_referral_reward(flow_lamports, reward_bps, max_reward);
            let remainder = flow_lamports
                .checked_sub(reward)
                .ok_or(EscrowError::InvalidPaymentAmount)?;
            (remainder, reward)
        } else {
            (flow_lamports, 0u64)
        };

        // Transfer referral cut to pool vault (treasury_authority PDA signs).
        if referral_reward > 0 {
            token::transfer(
                CpiContext::new_with_signer(
                    ctx.accounts.token_program.to_account_info(),
                    Transfer {
                        from:      ctx.accounts.treasury_vault_token.to_account_info(),
                        to:        ctx.accounts.pool_vault.to_account_info(),
                        authority: ctx.accounts.treasury_authority.to_account_info(),
                    },
                    &[&[b"treasury_authority", &[bump]]],
                ),
                referral_reward,
            )?;
        }

        // Transfer remainder (or full amount when no referral) to user escrow.
        if escrow_amount > 0 {
            token::transfer(
                CpiContext::new_with_signer(
                    ctx.accounts.token_program.to_account_info(),
                    Transfer {
                        from:      ctx.accounts.treasury_vault_token.to_account_info(),
                        to:        ctx.accounts.user_escrow_token.to_account_info(),
                        authority: ctx.accounts.treasury_authority.to_account_info(),
                    },
                    &[&[b"treasury_authority", &[bump]]],
                ),
                escrow_amount,
            )?;
        }

        // Update escrow state (escrow_amount, not full flow_lamports, when referral active).
        let escrow           = &mut ctx.accounts.user_escrow;
        escrow.user          = ctx.accounts.user.key();
        escrow.balance       = escrow
            .balance
            .checked_add(escrow_amount)
            .ok_or(EscrowError::InvalidPaymentAmount)?;
        escrow.last_topup_ts = Clock::get()?.unix_timestamp as u64;

        emit!(PurchaseAndEscrowed {
            user:             ctx.accounts.user.key(),
            payment_type,
            payment_amount,
            flow_amount:      flow_lamports,
            escrow_balance:   escrow.balance,
            referral_reward,
        });

        Ok(())
    }

    // ── P1b: Phase 2 purchase (DEX buy → escrow) ──────────────────────────────

    /// Phase 2: User already bought $FLOW on DEX, sends it to escrow.
    ///
    /// market-price — no oracle needed here (user bears slippage via min_flow_amount).
    ///
    /// When `referrer` is `Some(pubkey)`, a referral cut is split to `pool_vault`
    /// and only the remainder goes to escrow. Pass `None` for the original behaviour.
    pub fn purchase_and_escrow_phase2(
        ctx:             Context<PurchaseAndEscrowPhase2>,
        min_flow_amount: u64,
        flow_amount:     u64,
        referrer:        Option<Pubkey>,
    ) -> Result<()> {
        require!(flow_amount > 0, EscrowError::InvalidPaymentAmount);
        require!(flow_amount >= min_flow_amount, EscrowError::InvalidPaymentAmount);

        // Determine how much goes to escrow vs. referral pool.
        let (escrow_amount, referral_reward) = if referrer.is_some() {
            let config_data = ctx.accounts.referral_config.data.borrow();
            require!(config_data.len() >= 10, EscrowError::InvalidPaymentAmount);
            let reward_bps  = u16::from_le_bytes(config_data[0..2].try_into().unwrap());
            let max_reward  = u64::from_le_bytes(config_data[2..10].try_into().unwrap());
            drop(config_data);

            let reward = calculate_referral_reward(flow_amount, reward_bps, max_reward);
            let remainder = flow_amount
                .checked_sub(reward)
                .ok_or(EscrowError::InvalidPaymentAmount)?;
            (remainder, reward)
        } else {
            (flow_amount, 0u64)
        };

        // Transfer referral cut to pool vault (user signs directly — no PDA needed).
        if referral_reward > 0 {
            token::transfer(
                CpiContext::new(
                    ctx.accounts.token_program.to_account_info(),
                    Transfer {
                        from:      ctx.accounts.user_token.to_account_info(),
                        to:        ctx.accounts.pool_vault.to_account_info(),
                        authority: ctx.accounts.user.to_account_info(),
                    },
                ),
                referral_reward,
            )?;
        }

        // Transfer remainder (or full amount when no referral) to user escrow.
        if escrow_amount > 0 {
            token::transfer(
                CpiContext::new(
                    ctx.accounts.token_program.to_account_info(),
                    Transfer {
                        from:      ctx.accounts.user_token.to_account_info(),
                        to:        ctx.accounts.user_escrow_token.to_account_info(),
                        authority: ctx.accounts.user.to_account_info(),
                    },
                ),
                escrow_amount,
            )?;
        }

        let escrow           = &mut ctx.accounts.user_escrow;
        escrow.user          = ctx.accounts.user.key();
        escrow.balance       = escrow
            .balance
            .checked_add(escrow_amount)
            .ok_or(EscrowError::InvalidPaymentAmount)?;
        escrow.last_topup_ts = Clock::get()?.unix_timestamp as u64;

        emit!(PurchaseAndEscrowed {
            user:             ctx.accounts.user.key(),
            payment_type:     PaymentType::Dex,
            payment_amount:   flow_amount,
            flow_amount,
            escrow_balance:   escrow.balance,
            referral_reward,
        });

        Ok(())
    }

    // ── P2: Spend (burn) ──────────────────────────────────────────────────────

    /// Burn $FLOW from user escrow.
    ///
    /// ONLY verified spenders in AuthorizedSpenderRegistry can call this.
    /// Relay is paid via the 70:30 mint split in the rewards contract — NOT here.
    /// This function ONLY burns. No USD transfer. No relay payout.
    ///
    /// Authorization: service_authority must be in registry.active_spenders.
    /// CPI redirect protection: relay param must match ctx.accounts.relay.
    pub fn spend_from_escrow(
        ctx:    Context<SpendFromEscrow>,
        amount: u64,
        relay:  Pubkey,
    ) -> Result<()> {
        // 1. Verify caller is in the verified spender registry.
        require!(
            ctx.accounts.spender_registry.active_spenders
                .contains(&ctx.accounts.service_authority.key()),
            EscrowError::UnauthorizedCaller
        );

        // 2. CPI redirect protection: relay account must match the relay param
        //    AND the relay_token must be owned by that relay wallet.
        require!(
            ctx.accounts.relay.key() == relay,
            EscrowError::InvalidRelayWallet
        );
        require!(
            ctx.accounts.relay_token.owner == relay,
            EscrowError::InvalidRelayWallet
        );

        // 3. Sufficient balance check.
        require!(
            ctx.accounts.user_escrow.balance >= amount,
            EscrowError::InsufficientBalance
        );

        // 4. BURN $FLOW from user escrow token account.
        //    user_escrow PDA is the authority; sign with its seeds.
        let user_key  = ctx.accounts.user.key();
        let escrow_bump = ctx.bumps.user_escrow;
        token::burn(
            CpiContext::new_with_signer(
                ctx.accounts.token_program.to_account_info(),
                Burn {
                    mint:      ctx.accounts.token_mint.to_account_info(),
                    from:      ctx.accounts.user_escrow_token.to_account_info(),
                    authority: ctx.accounts.user_escrow.to_account_info(),
                },
                &[&[b"user_escrow", user_key.as_ref(), &[escrow_bump]]],
            ),
            amount,
        )?;

        // 5. Update escrow balance.
        ctx.accounts.user_escrow.balance = ctx
            .accounts
            .user_escrow
            .balance
            .checked_sub(amount)
            .ok_or(EscrowError::InsufficientBalance)?;

        let remaining = ctx.accounts.user_escrow.balance;
        let user      = ctx.accounts.user.key();

        emit!(SpentFromEscrow {
            user,
            amount,
            relay,
            remaining_balance: remaining,
        });

        Ok(())
    }

    /// Lock $FLOW in a 7-day dispute-window hold.
    ///
    /// Called via CPI from rewards program's `ClaimUsage`.
    /// Checks effective balance (`balance - held >= amount`), increments `held`,
    /// and creates a `FundHold` PDA in `Active` state.
    ///
    /// Does NOT debit `balance` — the SPL token account is untouched.
    /// `balance` is only decremented when tokens are actually burned (`BurnHeldFunds`).
    pub fn hold_client_funds(
        ctx:        Context<HoldClientFunds>,
        amount:     u64,
        claim_hash: [u8; 32],
        session_id: [u8; 16],
    ) -> Result<()> {
        require!(amount > 0, EscrowError::InvalidPaymentAmount);

        // 1. Verify caller is an authorized spender.
        require!(
            ctx.accounts.spender_registry.active_spenders
                .contains(&ctx.accounts.service_authority.key()),
            EscrowError::UnauthorizedCaller
        );

        let escrow = &mut ctx.accounts.user_escrow;

        // 2. Effective balance check: balance - held >= amount.
        let effective = escrow.balance.saturating_sub(escrow.held);
        require!(effective >= amount, EscrowError::InsufficientEffectiveBalance);

        // 3. Increment held (does NOT change balance).
        escrow.held = escrow.held
            .checked_add(amount)
            .ok_or(EscrowError::InvalidPaymentAmount)?;

        let total_held = escrow.held;

        // 4. Populate FundHold PDA.
        let hold        = &mut ctx.accounts.fund_hold;
        hold.user       = ctx.accounts.user.key().to_bytes();
        hold.amount     = amount;
        hold.claim_hash = claim_hash;
        hold.session_id = session_id;
        hold.created_at = Clock::get()?.unix_timestamp;
        hold.status     = HoldStatus::Active;

        emit!(FundsHeld {
            user: ctx.accounts.user.key(),
            amount,
            claim_hash,
            session_id,
            total_held,
        });

        Ok(())
    }

    /// Release a hold when the client wins a dispute.
    ///
    /// Called via CPI from rewards `ResolveDisputeRelaySlashed`.
    /// Decrements `held` only — `balance` is unchanged since it was never debited.
    pub fn release_funds(
        ctx:         Context<ReleaseFunds>,
        _claim_hash: [u8; 32],  // used only for PDA seed derivation in constraint
    ) -> Result<()> {
        // 1. Verify caller is an authorized spender.
        require!(
            ctx.accounts.spender_registry.active_spenders
                .contains(&ctx.accounts.service_authority.key()),
            EscrowError::UnauthorizedCaller
        );

        let hold   = &mut ctx.accounts.fund_hold;
        let escrow = &mut ctx.accounts.user_escrow;
        let amount = hold.amount;

        // 2. Decrement held (balance is NOT changed — tokens stay in escrow).
        escrow.held = escrow.held.saturating_sub(amount);

        // 3. Mark hold as Released.
        hold.status = HoldStatus::Released;

        emit!(FundsReleased {
            user:       ctx.accounts.user.key(),
            amount,
            claim_hash: hold.claim_hash,
            total_held: escrow.held,
        });

        Ok(())
    }

    /// Burn held $FLOW after the 7-day dispute window expires.
    ///
    /// Called via CPI from rewards `ReleaseRewards` and `ResolveDisputeChallengerSlashed`.
    /// Decrements both `held` and `balance`, then SPL-burns `amount` from the escrow
    /// token account. The rewards program enforces the 7-day timing.
    pub fn burn_held_funds(
        ctx:         Context<BurnHeldFunds>,
        _claim_hash: [u8; 32],  // used only for PDA seed derivation in constraint
    ) -> Result<()> {
        // 1. Verify caller is an authorized spender.
        require!(
            ctx.accounts.spender_registry.active_spenders
                .contains(&ctx.accounts.service_authority.key()),
            EscrowError::UnauthorizedCaller
        );

        let hold       = &ctx.accounts.fund_hold;
        let amount     = hold.amount;
        let claim_hash = hold.claim_hash;

        // 2. Decrement held and balance atomically.
        {
            let escrow = &mut ctx.accounts.user_escrow;
            escrow.held = escrow.held.saturating_sub(amount);
            escrow.balance = escrow.balance
                .checked_sub(amount)
                .ok_or(EscrowError::InsufficientBalance)?;
        }

        // 3. SPL burn from escrow token account. user_escrow PDA is the authority.
        let user_key    = ctx.accounts.user.key();
        let escrow_bump = ctx.bumps.user_escrow;
        token::burn(
            CpiContext::new_with_signer(
                ctx.accounts.token_program.to_account_info(),
                Burn {
                    mint:      ctx.accounts.token_mint.to_account_info(),
                    from:      ctx.accounts.user_escrow_token.to_account_info(),
                    authority: ctx.accounts.user_escrow.to_account_info(),
                },
                &[&[b"user_escrow", user_key.as_ref(), &[escrow_bump]]],
            ),
            amount,
        )?;

        // 4. Mark hold as Burned.
        ctx.accounts.fund_hold.status = HoldStatus::Burned;

        emit!(FundsBurned {
            user:              ctx.accounts.user.key(),
            amount,
            claim_hash,
            remaining_balance: ctx.accounts.user_escrow.balance,
        });

        Ok(())
    }
}

// ─── Account structs ──────────────────────────────────────────────────────────

/// Per-user permanent escrow account.
///
/// PDA: ["user_escrow", user_pubkey]
///
/// CRITICAL: No withdrawal fields. No cap fields. No authorized_spender field.
/// Authorization is registry-based (Foundation multisig controls registry).
///
/// Accounting invariant: usable = balance - held
///   balance = total $FLOW (always matches SPL token account)
///   held    = portion locked in active dispute-window claims
///   usable  = available for new claims and spend
#[account]
pub struct UserEscrow {
    /// Owner — the user's wallet.
    pub user:           Pubkey,
    /// $FLOW token balance in lamports (total deposited; always equals SPL token account).
    pub balance:        u64,
    /// Active session (if any). Set by the relay layer.
    pub session_id:     Option<[u8; 16]>,
    /// Unix timestamp of last escrow top-up.
    pub last_topup_ts:  u64,
    /// $FLOW base units locked in active holds (claims in 7-day dispute window).
    /// Invariant: held <= balance. Usable balance = balance - held.
    /// Only incremented by HoldClientFunds, decremented by ReleaseFunds/BurnHeldFunds.
    pub held:           u64,
    // NOTE: No withdrawals_enabled. No cap_enabled. No authorized_spender.
    //       Contract is immutable after deployment (set-upgrade-authority --final).
}

/// Lifecycle state of a `FundHold` PDA.
#[derive(AnchorSerialize, AnchorDeserialize, Clone, Copy, PartialEq, Eq, Debug)]
pub enum HoldStatus {
    /// Funds locked; 7-day dispute window open. Initial state.
    Active,
    /// Dispute won by client — funds returned to usable balance.
    Released,
    /// 7-day window elapsed — funds burned via BurnHeldFunds.
    Burned,
}

/// Per-claim token hold tracking locked $FLOW during the 7-day dispute window.
///
/// PDA seeds: ["fund_hold", user_wallet, claim_hash]
///
/// Created by `HoldClientFunds` (called via CPI from rewards `ClaimUsage`).
/// Settled by `ReleaseFunds` (dispute win) or `BurnHeldFunds` (timeout).
#[account]
pub struct FundHold {
    /// User wallet that owns the escrowed $FLOW.
    pub user:       [u8; 32],
    /// $FLOW base units locked in this hold.
    pub amount:     u64,
    /// 32-byte claim hash linking this hold to a PendingClaim in the rewards program.
    pub claim_hash: [u8; 32],
    /// Session ID from the usage record that generated this claim.
    pub session_id: [u8; 16],
    /// Unix timestamp when the hold was created.
    pub created_at: i64,
    /// Current lifecycle state.
    pub status:     HoldStatus,
}

impl FundHold {
    /// Borsh-serialized size (without Anchor discriminator).
    /// 32 (user) + 8 (amount) + 32 (claim_hash) + 16 (session_id) + 8 (created_at) + 1 (status) = 97
    pub const DATA_SIZE: usize = 97;

    /// On-chain account size including 8-byte Anchor discriminator.
    pub const ACCOUNT_SIZE: usize = 8 + Self::DATA_SIZE; // = 105
}

/// Global registry of Foundation-approved spender programs.
///
/// PDA: ["spender_registry"]
///
/// Only the Foundation multisig (3-of-5) can modify this registry.
/// All UserEscrow accounts read from this single registry at spend time.
#[account]
pub struct AuthorizedSpenderRegistry {
    /// Foundation multisig public key (3-of-5).
    pub authority:        Pubkey,
    /// List of approved spender program PDAs (e.g. rewards_v1_pda).
    pub active_spenders:  Vec<Pubkey>,
    /// Incremented on each add/remove operation for auditability.
    pub version:          u64,
}

// ─── Account contexts ─────────────────────────────────────────────────────────

#[derive(Accounts)]
pub struct InitializeRegistry<'info> {
    /// H-04: Constraint ensures only the Foundation multisig can bootstrap the registry.
    /// Without this, any signer can call `initialize_registry` and inject arbitrary spenders.
    #[account(
        mut,
        constraint = foundation.key() == FOUNDATION_PUBKEY @ EscrowError::NotFoundation
    )]
    pub foundation: Signer<'info>,

    #[account(
        init,
        payer = foundation,
        space = 8 + 32 + 4 + (32 * 10) + 8,   // 10 spenders max initially
        seeds = [b"spender_registry"],
        bump
    )]
    pub registry: Account<'info, AuthorizedSpenderRegistry>,

    /// CHECK: Initial spender PDA (e.g. rewards contract PDA). Not validated here.
    pub initial_spender: UncheckedAccount<'info>,

    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct UpdateRegistry<'info> {
    #[account(mut)]
    pub foundation: Signer<'info>,

    #[account(
        mut,
        seeds = [b"spender_registry"],
        bump
    )]
    pub registry: Account<'info, AuthorizedSpenderRegistry>,
}

#[derive(Accounts)]
pub struct PurchaseAndEscrow<'info> {
    #[account(mut)]
    pub user: Signer<'info>,

    /// User's escrow account (created on first purchase, reused on subsequent).
    #[account(
        init_if_needed,
        payer = user,
        space = 8 + 32 + 8 + 17 + 8 + 8,  // +8 for held: u64
        seeds = [b"user_escrow", user.key().as_ref()],
        bump
    )]
    pub user_escrow: Account<'info, UserEscrow>,

    /// Token account holding the user's escrowed $FLOW.
    /// Authority = user_escrow PDA (set up by caller before first purchase).
    #[account(
        mut,
        token::mint = token_mint
    )]
    pub user_escrow_token: Account<'info, TokenAccount>,

    /// Treasury vault holding the pre-minted 30M $FLOW.
    /// Authority = treasury_authority PDA.
    #[account(
        mut,
        token::mint = token_mint,
        token::authority = treasury_authority
    )]
    pub treasury_vault_token: Account<'info, TokenAccount>,

    /// PDA that is the authority for the treasury vault token account.
    /// Signs the transfer via invoke_signed.
    ///
    /// CHECK: PDA authority — validated by seeds constraint.
    #[account(seeds = [b"treasury_authority"], bump)]
    pub treasury_authority: UncheckedAccount<'info>,

    pub token_mint:    Account<'info, Mint>,
    pub token_program: Program<'info, Token>,
    pub system_program: Program<'info, System>,

    /// CHECK: Referral pool vault SPL token account.
    ///        Pass `SystemProgram::id()` when `referrer` is `None`.
    ///        When `referrer` is `Some`, must be the pool vault from ReferralConfig.
    #[account(mut)]
    pub pool_vault: UncheckedAccount<'info>,

    /// CHECK: ReferralConfig PDA from the referral program. Raw bytes read at offsets [0..10].
    ///        Pass `SystemProgram::id()` when `referrer` is `None`.
    pub referral_config: UncheckedAccount<'info>,
}

#[derive(Accounts)]
pub struct PurchaseAndEscrowPhase2<'info> {
    #[account(mut)]
    pub user: Signer<'info>,

    #[account(
        init_if_needed,
        payer = user,
        space = 8 + 32 + 8 + 17 + 8 + 8,  // +8 for held: u64
        seeds = [b"user_escrow", user.key().as_ref()],
        bump
    )]
    pub user_escrow: Account<'info, UserEscrow>,

    /// User's personal token account (DEX-bought $FLOW).
    #[account(
        mut,
        token::mint  = token_mint,
        token::authority = user
    )]
    pub user_token: Account<'info, TokenAccount>,

    /// User's escrow token account (receives $FLOW).
    #[account(
        mut,
        token::mint = token_mint
    )]
    pub user_escrow_token: Account<'info, TokenAccount>,

    pub token_mint:    Account<'info, Mint>,
    pub token_program: Program<'info, Token>,
    pub system_program: Program<'info, System>,

    /// CHECK: Referral pool vault SPL token account.
    ///        Pass `SystemProgram::id()` when `referrer` is `None`.
    #[account(mut)]
    pub pool_vault: UncheckedAccount<'info>,

    /// CHECK: ReferralConfig PDA from the referral program. Raw bytes read at offsets [0..10].
    ///        Pass `SystemProgram::id()` when `referrer` is `None`.
    pub referral_config: UncheckedAccount<'info>,
}

#[derive(Accounts)]
pub struct SpendFromEscrow<'info> {
    /// Must be a registered spender (verified in instruction logic).
    /// When called via CPI from rewards contract, invoke_signed makes this PDA a signer.
    pub service_authority: Signer<'info>,

    /// CHECK: User whose escrow is being spent from. Used only for PDA seed derivation.
    pub user: UncheckedAccount<'info>,

    #[account(
        mut,
        seeds = [b"user_escrow", user.key().as_ref()],
        bump,
        constraint = user_escrow.user == user.key() @ EscrowError::UnauthorizedCaller
    )]
    pub user_escrow: Account<'info, UserEscrow>,

    /// Escrow's token account. Authority = user_escrow PDA.
    #[account(
        mut,
        token::mint      = token_mint,
        token::authority = user_escrow
    )]
    pub user_escrow_token: Account<'info, TokenAccount>,

    /// Relay's token account — verified to be owned by `relay` param.
    /// Not transferred to (relay is paid via 70:30 mint split in rewards contract).
    /// Included for CPI redirect protection only.
    #[account(token::mint = token_mint)]
    pub relay_token: Account<'info, TokenAccount>,

    /// CHECK: Relay wallet — must match the `relay` instruction parameter.
    pub relay: UncheckedAccount<'info>,

    /// Global spender registry. Caller must be in active_spenders.
    #[account(seeds = [b"spender_registry"], bump)]
    pub spender_registry: Account<'info, AuthorizedSpenderRegistry>,

    #[account(mut)]
    pub token_mint: Account<'info, Mint>,

    pub token_program: Program<'info, Token>,
}

/// Context for locking $FLOW in a dispute-window hold.
///
/// Called via CPI from rewards program's `ClaimUsage` instruction.
/// `service_authority` must be in `spender_registry.active_spenders`.
#[derive(Accounts)]
#[instruction(amount: u64, claim_hash: [u8; 32], session_id: [u8; 16])]
pub struct HoldClientFunds<'info> {
    /// Authorized spender — must be in spender_registry (e.g. rewards mint_authority PDA).
    pub service_authority: Signer<'info>,

    /// Payer for FundHold PDA rent (relay wallet in practice).
    #[account(mut)]
    pub payer: Signer<'info>,

    /// CHECK: User wallet — used only as PDA seed. Not a signer.
    pub user: UncheckedAccount<'info>,

    /// User's escrow accounting state. NOT debited; only `held` is incremented.
    #[account(
        mut,
        seeds = [b"user_escrow", user.key().as_ref()],
        bump,
        constraint = user_escrow.user == user.key() @ EscrowError::UnauthorizedCaller
    )]
    pub user_escrow: Account<'info, UserEscrow>,

    /// FundHold PDA created here. Seeds: ["fund_hold", user, claim_hash].
    #[account(
        init,
        payer = payer,
        space = FundHold::ACCOUNT_SIZE,
        seeds = [b"fund_hold", user.key().as_ref(), claim_hash.as_ref()],
        bump
    )]
    pub fund_hold: Account<'info, FundHold>,

    /// Registry of Foundation-approved spenders. Caller must be listed here.
    #[account(seeds = [b"spender_registry"], bump)]
    pub spender_registry: Account<'info, AuthorizedSpenderRegistry>,

    pub system_program: Program<'info, System>,
}

/// Context for releasing a hold when the client wins a dispute.
#[derive(Accounts)]
#[instruction(claim_hash: [u8; 32])]
pub struct ReleaseFunds<'info> {
    /// Authorized spender — must be in spender_registry.
    pub service_authority: Signer<'info>,

    /// CHECK: User wallet — PDA seed only.
    pub user: UncheckedAccount<'info>,

    /// User's escrow accounting state. `held` is decremented here.
    #[account(
        mut,
        seeds = [b"user_escrow", user.key().as_ref()],
        bump,
        constraint = user_escrow.user == user.key() @ EscrowError::UnauthorizedCaller
    )]
    pub user_escrow: Account<'info, UserEscrow>,

    /// FundHold PDA to release. Must be in Active state.
    #[account(
        mut,
        seeds = [b"fund_hold", user.key().as_ref(), claim_hash.as_ref()],
        bump,
        constraint = fund_hold.status == HoldStatus::Active @ EscrowError::HoldNotActive,
        constraint = fund_hold.user == user.key().to_bytes() @ EscrowError::UnauthorizedCaller
    )]
    pub fund_hold: Account<'info, FundHold>,

    /// Registry of Foundation-approved spenders.
    #[account(seeds = [b"spender_registry"], bump)]
    pub spender_registry: Account<'info, AuthorizedSpenderRegistry>,
}

/// Context for burning held tokens after the 7-day dispute window.
#[derive(Accounts)]
#[instruction(claim_hash: [u8; 32])]
pub struct BurnHeldFunds<'info> {
    /// Authorized spender — must be in spender_registry.
    pub service_authority: Signer<'info>,

    /// CHECK: User wallet — PDA seed only.
    pub user: UncheckedAccount<'info>,

    /// User's escrow accounting state. Both `held` and `balance` are decremented.
    #[account(
        mut,
        seeds = [b"user_escrow", user.key().as_ref()],
        bump,
        constraint = user_escrow.user == user.key() @ EscrowError::UnauthorizedCaller
    )]
    pub user_escrow: Account<'info, UserEscrow>,

    /// Escrow token account. Authority = user_escrow PDA. Tokens are burned from here.
    #[account(
        mut,
        token::mint      = token_mint,
        token::authority = user_escrow
    )]
    pub user_escrow_token: Account<'info, TokenAccount>,

    /// FundHold PDA to burn. Must be in Active state.
    #[account(
        mut,
        seeds = [b"fund_hold", user.key().as_ref(), claim_hash.as_ref()],
        bump,
        constraint = fund_hold.status == HoldStatus::Active @ EscrowError::HoldNotActive,
        constraint = fund_hold.user == user.key().to_bytes() @ EscrowError::UnauthorizedCaller
    )]
    pub fund_hold: Account<'info, FundHold>,

    /// Registry of Foundation-approved spenders.
    #[account(seeds = [b"spender_registry"], bump)]
    pub spender_registry: Account<'info, AuthorizedSpenderRegistry>,

    #[account(mut)]
    pub token_mint: Account<'info, Mint>,

    pub token_program: Program<'info, Token>,
}

// ─── Types ────────────────────────────────────────────────────────────────────

#[derive(AnchorSerialize, AnchorDeserialize, Clone, Copy, PartialEq, Eq, Debug)]
pub enum PaymentType {
    /// SOL payment (lamports → treasury vault).
    Sol,
    /// USDC SPL token payment.
    Usdc,
    /// USDT SPL token payment.
    Usdt,
    /// Off-chain credit card (Stripe) — backend triggers on-chain transfer.
    CreditCard,
    /// Phase 2: DEX swap already performed; this deposits the result into escrow.
    Dex,
}

// ─── Events ───────────────────────────────────────────────────────────────────

#[event]
pub struct PurchaseAndEscrowed {
    pub user:             Pubkey,
    pub payment_type:     PaymentType,
    /// USD cents paid (e.g. 300 = $3.00).
    pub payment_amount:   u64,
    /// Total $FLOW lamports purchased (escrow_amount + referral_reward).
    pub flow_amount:      u64,
    /// New total escrow balance in $FLOW lamports.
    pub escrow_balance:   u64,
    /// $FLOW lamports transferred to referral pool vault. 0 when no referrer.
    pub referral_reward:  u64,
}

#[event]
pub struct SpentFromEscrow {
    pub user:              Pubkey,
    /// $FLOW lamports burned.
    pub amount:            u64,
    /// Relay that served the bandwidth (paid via mint split, NOT here).
    pub relay:             Pubkey,
    /// Remaining escrow balance after burn.
    pub remaining_balance: u64,
}

#[event]
pub struct SpenderRegistryUpdated {
    pub add_spenders:    Vec<Pubkey>,
    pub remove_spenders: Vec<Pubkey>,
    pub version:         u64,
}

#[event]
pub struct FundsHeld {
    pub user:       Pubkey,
    /// $FLOW base units locked.
    pub amount:     u64,
    pub claim_hash: [u8; 32],
    pub session_id: [u8; 16],
    /// New `UserEscrow.held` value after this hold.
    pub total_held: u64,
}

#[event]
pub struct FundsReleased {
    pub user:       Pubkey,
    pub amount:     u64,
    pub claim_hash: [u8; 32],
    /// New `UserEscrow.held` value after release.
    pub total_held: u64,
}

#[event]
pub struct FundsBurned {
    pub user:              Pubkey,
    pub amount:            u64,
    pub claim_hash:        [u8; 32],
    /// New `UserEscrow.balance` after burn.
    pub remaining_balance: u64,
}

// ─── Errors ───────────────────────────────────────────────────────────────────

#[error_code]
pub enum EscrowError {
    #[msg("Insufficient escrow balance")]
    InsufficientBalance,            // 6000

    #[msg("Caller is not in the verified spender registry")]
    UnauthorizedCaller,             // 6001

    #[msg("Invalid payment amount")]
    InvalidPaymentAmount,           // 6002

    #[msg("Relay wallet does not match expected destination")]
    InvalidRelayWallet,             // 6003

    #[msg("Only foundation multisig can update spender registry")]
    NotFoundation,                  // 6004

    #[msg("Hold is not in Active state")]
    HoldNotActive,                  // 6005

    #[msg("Insufficient effective balance (balance - held < amount)")]
    InsufficientEffectiveBalance,   // 6006
}
