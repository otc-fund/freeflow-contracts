//! UpdateReferralConfig — discriminant 1
//!
//! Modifies reward_bps, max_reward_lamports, and min_purchase_lamports.
//! Only callable by the current `config.authority`.

use borsh::{BorshDeserialize, BorshSerialize};
use solana_program::{
    account_info::{next_account_info, AccountInfo},
    entrypoint::ProgramResult,
    pubkey::Pubkey,
};

use crate::{errors::ReferralError, state::ReferralConfig};

/// Instruction data (after discriminant).
#[derive(BorshSerialize, BorshDeserialize)]
pub struct UpdateReferralConfigArgs {
    pub reward_bps:            u16,
    pub max_reward_lamports:   u64,
    pub min_purchase_lamports: u64,
}

/// Accounts expected (in order):
/// 0. `[writable]` config    — existing `ReferralConfig` PDA
/// 1. `[signer]`   authority — must match `config.authority`
pub fn process(
    _program_id: &Pubkey,
    accounts: &[AccountInfo],
    args: UpdateReferralConfigArgs,
) -> ProgramResult {
    let iter = &mut accounts.iter();
    let config_info    = next_account_info(iter)?;
    let authority_info = next_account_info(iter)?;

    if !authority_info.is_signer {
        return Err(ReferralError::InvalidAuthority.into());
    }

    // Deserialize
    let mut config =
        ReferralConfig::try_from_slice(&config_info.data.borrow())?;

    // Validate authority
    if config.authority != authority_info.key.to_bytes() {
        return Err(ReferralError::InvalidAuthority.into());
    }

    // Validate new params
    if args.reward_bps > 3_000 {
        return Err(ReferralError::RewardBpsTooHigh.into());
    }
    if args.max_reward_lamports == 0 {
        return Err(ReferralError::InvalidMaxReward.into());
    }

    config.reward_bps            = args.reward_bps;
    config.max_reward_lamports   = args.max_reward_lamports;
    config.min_purchase_lamports = args.min_purchase_lamports;

    config.serialize(&mut *config_info.data.borrow_mut())?;

    Ok(())
}
