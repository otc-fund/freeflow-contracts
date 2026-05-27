//! InitializeReferralConfig — discriminant 0
//!
//! Creates two singleton PDAs in one transaction:
//!   • `ReferralConfig` at `[b"referral_config"]`
//!   • `RewardsPool`    at `[b"rewards_pool"]`
//!
//! Can only be called once; subsequent calls return `ConfigAlreadyInitialized`.

use borsh::{BorshDeserialize, BorshSerialize};
use solana_program::{
    account_info::{next_account_info, AccountInfo},
    entrypoint::ProgramResult,
    program::invoke_signed,
    pubkey::Pubkey,
    rent::Rent,
    system_instruction,
    sysvar::Sysvar,
};

use crate::{
    errors::ReferralError,
    state::{ReferralConfig, RewardsPool},
};

/// Instruction data for InitializeReferralConfig (after the 1-byte discriminant).
#[derive(BorshSerialize, BorshDeserialize)]
pub struct InitializeReferralConfigArgs {
    pub reward_bps:            u16,
    pub max_reward_lamports:   u64,
    pub min_purchase_lamports: u64,
}

/// Accounts expected (in order):
/// 0. `[writable]`  config             — PDA `[b"referral_config"]` (will be created)
/// 1. `[writable]`  rewards_pool       — PDA `[b"rewards_pool"]`    (will be created)
/// 2. `[signer]`    authority          — payer; becomes `config.authority`
/// 3. `[]`          rewards_pool_vault — SPL token vault pubkey stored in config
/// 4. `[]`          system_program
pub fn process(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    args: InitializeReferralConfigArgs,
) -> ProgramResult {
    let iter = &mut accounts.iter();
    let config_info        = next_account_info(iter)?;
    let rewards_pool_info  = next_account_info(iter)?;
    let authority_info     = next_account_info(iter)?;
    let pool_vault_info    = next_account_info(iter)?;
    let system_program     = next_account_info(iter)?;

    // Validate signer
    if !authority_info.is_signer {
        return Err(ReferralError::InvalidAuthority.into());
    }

    // Validate params
    if args.reward_bps > 3_000 {
        return Err(ReferralError::RewardBpsTooHigh.into());
    }
    if args.max_reward_lamports == 0 {
        return Err(ReferralError::InvalidMaxReward.into());
    }

    // Check not already initialized
    if !config_info.data_is_empty() {
        return Err(ReferralError::ConfigAlreadyInitialized.into());
    }

    let rent = Rent::get()?;

    // ── Create ReferralConfig PDA ────────────────────────────────────────────
    let (expected_config_pda, config_bump) =
        Pubkey::find_program_address(&[b"referral_config"], program_id);
    if config_info.key != &expected_config_pda {
        return Err(solana_program::program_error::ProgramError::InvalidSeeds);
    }

    invoke_signed(
        &system_instruction::create_account(
            authority_info.key,
            config_info.key,
            rent.minimum_balance(ReferralConfig::SIZE),
            ReferralConfig::SIZE as u64,
            program_id,
        ),
        &[
            authority_info.clone(),
            config_info.clone(),
            system_program.clone(),
        ],
        &[&[b"referral_config", &[config_bump]]],
    )?;

    let config = ReferralConfig {
        reward_bps:            args.reward_bps,
        max_reward_lamports:   args.max_reward_lamports,
        min_purchase_lamports: args.min_purchase_lamports,
        authority:             authority_info.key.to_bytes(),
        rewards_pool_vault:    pool_vault_info.key.to_bytes(),
        bump:                  config_bump,
        _padding:              [0; 3],
    };
    config.serialize(&mut *config_info.data.borrow_mut())?;

    // ── Create RewardsPool PDA ───────────────────────────────────────────────
    let (expected_pool_pda, pool_bump) =
        Pubkey::find_program_address(&[b"rewards_pool"], program_id);
    if rewards_pool_info.key != &expected_pool_pda {
        return Err(solana_program::program_error::ProgramError::InvalidSeeds);
    }

    if rewards_pool_info.data_is_empty() {
        invoke_signed(
            &system_instruction::create_account(
                authority_info.key,
                rewards_pool_info.key,
                rent.minimum_balance(RewardsPool::SIZE),
                RewardsPool::SIZE as u64,
                program_id,
            ),
            &[
                authority_info.clone(),
                rewards_pool_info.clone(),
                system_program.clone(),
            ],
            &[&[b"rewards_pool", &[pool_bump]]],
        )?;
    }

    let pool = RewardsPool {
        vault_bump:        0,
        total_deposited:   0,
        total_distributed: 0,
        bump:              pool_bump,
        _padding:          [0; 6],
    };
    pool.serialize(&mut *rewards_pool_info.data.borrow_mut())?;

    Ok(())
}
