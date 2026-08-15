//! DepositRewardsPool — discriminant 8
//!
//! Allows the foundation authority to manually deposit $FLOW into the pool vault.
//! Primary use-case: bootstrapping before the first purchases arrive.

use borsh::{BorshDeserialize, BorshSerialize};
use solana_program::{
    account_info::{next_account_info, AccountInfo},
    entrypoint::ProgramResult,
    program::invoke,
    pubkey::Pubkey,
};

use crate::{errors::ReferralError, state::{ReferralConfig, RewardsPool}};

/// Instruction data (after discriminant).
#[derive(BorshDeserialize, BorshSerialize)]
pub struct DepositRewardsPoolArgs {
    pub amount: u64,
}

/// Accounts expected (in order):
/// 0. `[writable]` rewards_pool   — `RewardsPool` PDA (accounting update)
/// 1. `[]`         config         — `ReferralConfig` PDA (authority check)
/// 2. `[signer]`   authority      — must match `config.authority`
/// 3. `[writable]` authority_ata  — authority's $FLOW token account (source)
/// 4. `[writable]` vault          — pool vault SPL token account (destination)
/// 5. `[]`         token_program  — SPL Token program
pub fn process(
    _program_id: &Pubkey,
    accounts: &[AccountInfo],
    args: DepositRewardsPoolArgs,
) -> ProgramResult {
    let iter = &mut accounts.iter();
    let rewards_pool_info   = next_account_info(iter)?;
    let config_info         = next_account_info(iter)?;
    let authority_info      = next_account_info(iter)?;
    let authority_ata_info  = next_account_info(iter)?;
    let vault_info          = next_account_info(iter)?;
    let token_program_info  = next_account_info(iter)?;

    if !authority_info.is_signer {
        return Err(ReferralError::InvalidAuthority.into());
    }

    let config = ReferralConfig::try_from_slice(&config_info.data.borrow())?;
    if config.authority != authority_info.key.to_bytes() {
        return Err(ReferralError::InvalidAuthority.into());
    }

    // Transfer $FLOW from authority ATA to vault (authority signs directly)
    invoke(
        &spl_token::instruction::transfer(
            token_program_info.key,
            authority_ata_info.key,
            vault_info.key,
            authority_info.key,
            &[],
            args.amount,
        )?,
        &[
            authority_ata_info.clone(),
            vault_info.clone(),
            authority_info.clone(),
            token_program_info.clone(),
        ],
    )?;

    // Update pool tracking
    let mut pool = RewardsPool::try_from_slice(&rewards_pool_info.data.borrow())?;
    pool.total_deposited = pool
        .total_deposited
        .checked_add(args.amount)
        .ok_or(ReferralError::Overflow)?;
    pool.serialize(&mut *rewards_pool_info.data.borrow_mut())?;

    Ok(())
}
