//! ClaimReferralReward — discriminant 4
//!
//! Transfers all available (earned − claimed) $FLOW from the pool vault to the
//! referrer's ATA. The pool vault is a PDA-signed SPL token account whose
//! authority is the `rewards_pool` PDA (`[b"rewards_pool"]`).

use borsh::{BorshDeserialize, BorshSerialize};
use solana_program::{
    account_info::{next_account_info, AccountInfo},
    entrypoint::ProgramResult,
    program::invoke_signed,
    pubkey::Pubkey,
};

use crate::{
    errors::ReferralError,
    state::{ReferralConfig, ReferrerBalance, RewardsPool},
};

/// Accounts expected (in order):
/// 0. `[writable]` referrer_balance — `ReferrerBalance` PDA
/// 1. `[]`         config           — `ReferralConfig` PDA
/// 2. `[writable]` rewards_pool     — `RewardsPool` PDA
/// 3. `[signer]`   referrer         — must match `referrer_balance.referrer`
/// 4. `[writable]` vault            — SPL token vault holding pool $FLOW
/// 5. `[writable]` referrer_ata     — referrer's $FLOW ATA (receives payment)
/// 6. `[]`         token_program    — SPL Token program
pub fn process(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
) -> ProgramResult {
    let iter = &mut accounts.iter();
    let referrer_balance_info = next_account_info(iter)?;
    let config_info           = next_account_info(iter)?;
    let rewards_pool_info     = next_account_info(iter)?;
    let referrer_info         = next_account_info(iter)?;
    let vault_info            = next_account_info(iter)?;
    let referrer_ata_info     = next_account_info(iter)?;
    let token_program_info    = next_account_info(iter)?;

    if !referrer_info.is_signer {
        return Err(ReferralError::InvalidAuthority.into());
    }

    // ── 1. Validate referrer balance ────────────────────────────────────────
    let mut balance =
        ReferrerBalance::try_from_slice(&referrer_balance_info.data.borrow())?;
    if balance.referrer != referrer_info.key.to_bytes() {
        return Err(ReferralError::InvalidAuthority.into());
    }

    let available = balance
        .total_earned
        .checked_sub(balance.total_claimed)
        .ok_or(ReferralError::Overflow)?;
    if available == 0 {
        return Err(ReferralError::NoRewardsToClaim.into());
    }

    // ── 2. Validate config (read pool vault address for PDA seed check) ─────
    let config = ReferralConfig::try_from_slice(&config_info.data.borrow())?;
    if config.rewards_pool_vault != vault_info.key.to_bytes() {
        return Err(ReferralError::InvalidPurchaseProof.into());
    }

    // ── 3. Check vault has enough $FLOW ─────────────────────────────────────
    //   SPL token account layout: [mint:32][owner:32][amount:u64][...rest]
    {
        let vault_data = vault_info.data.borrow();
        let vault_balance =
            u64::from_le_bytes(vault_data[64..72].try_into().unwrap());
        if vault_balance < available {
            return Err(ReferralError::InsufficientPoolFunds.into());
        }
    }

    // ── 4. Derive pool PDA for signing ──────────────────────────────────────
    let (pool_pda, pool_bump) =
        Pubkey::find_program_address(&[b"rewards_pool"], program_id);

    // Confirm the rewards_pool account is the expected PDA
    if rewards_pool_info.key != &pool_pda {
        return Err(solana_program::program_error::ProgramError::InvalidSeeds);
    }

    // ── 5. Transfer from vault to referrer ATA ──────────────────────────────
    invoke_signed(
        &spl_token::instruction::transfer(
            token_program_info.key,
            vault_info.key,
            referrer_ata_info.key,
            &pool_pda,
            &[],
            available,
        )?,
        &[
            vault_info.clone(),
            referrer_ata_info.clone(),
            rewards_pool_info.clone(),
            token_program_info.clone(),
        ],
        &[&[b"rewards_pool", &[pool_bump]]],
    )?;

    // ── 6. Update accounting ────────────────────────────────────────────────
    balance.total_claimed = balance
        .total_claimed
        .checked_add(available)
        .ok_or(ReferralError::Overflow)?;
    balance.serialize(&mut *referrer_balance_info.data.borrow_mut())?;

    let mut pool = RewardsPool::try_from_slice(&rewards_pool_info.data.borrow())?;
    pool.total_distributed = pool
        .total_distributed
        .checked_add(available)
        .ok_or(ReferralError::Overflow)?;
    pool.serialize(&mut *rewards_pool_info.data.borrow_mut())?;

    Ok(())
}
