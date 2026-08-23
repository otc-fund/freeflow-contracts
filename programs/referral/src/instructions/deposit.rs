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

use crate::{errors::ReferralError, state::RewardsPool};

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
    program_id: &Pubkey,
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

    // C-2: prove the account IS the config before trusting `authority`.
    let config = crate::utils::load_verified_config(config_info, program_id)?;
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

// ─── Unit Tests ───────────────────────────────────────────────────────────────
#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::{
        forged_config_bytes, forged_config_rejection, install_syscall_stubs,
        rewards_pool_bytes, spl_token_account_bytes,
    };

    /// C-2: an attacker-owned config at the canonical PDA address, naming the
    /// attacker as `authority`. Before the fix the handler accepted it and ran
    /// the deposit CPI, crediting `RewardsPool.total_deposited` on a config no
    /// one authorised.
    #[test]
    fn test_deposit_rejects_foreign_owned_config() {
        install_syscall_stubs();

        let program_id       = Pubkey::new_unique();
        let attacker_program = Pubkey::new_unique();
        let attacker         = Pubkey::new_unique();
        let token_program_id = spl_token::id();
        let system_id        = solana_program::system_program::id();
        let ata_key          = Pubkey::new_unique();
        let vault_key        = Pubkey::new_unique();
        let (config_pda, _)  =
            Pubkey::find_program_address(&[b"referral_config"], &program_id);
        let (pool_pda, _)    =
            Pubkey::find_program_address(&[b"rewards_pool"], &program_id);

        let mut pool_lamports  = 1_000_000u64;
        let mut pool_data      = rewards_pool_bytes(0, 0);
        let mut cfg_lamports   = 1_000_000u64;
        let mut cfg_data       = forged_config_bytes(&attacker, &vault_key);
        let mut sig_lamports   = 1_000_000u64;
        let mut sig_data: Vec<u8> = Vec::new();
        let mut ata_lamports   = 1_000_000u64;
        let mut ata_data       = spl_token_account_bytes(10_000);
        let mut vault_lamports = 1_000_000u64;
        let mut vault_data     = spl_token_account_bytes(0);
        let mut tp_lamports    = 1_000_000u64;
        let mut tp_data: Vec<u8> = Vec::new();

        let accounts = [
            AccountInfo::new(
                &pool_pda, false, true,
                &mut pool_lamports, &mut pool_data, &program_id, false, 0,
            ),
            AccountInfo::new(
                &config_pda, false, false,
                &mut cfg_lamports, &mut cfg_data, &attacker_program, false, 0,
            ),
            AccountInfo::new(
                &attacker, true, false,
                &mut sig_lamports, &mut sig_data, &system_id, false, 0,
            ),
            AccountInfo::new(
                &ata_key, false, true,
                &mut ata_lamports, &mut ata_data, &token_program_id, false, 0,
            ),
            AccountInfo::new(
                &vault_key, false, true,
                &mut vault_lamports, &mut vault_data, &token_program_id, false, 0,
            ),
            AccountInfo::new(
                &token_program_id, false, false,
                &mut tp_lamports, &mut tp_data, &system_id, true, 0,
            ),
        ];

        let err = process(
            &program_id,
            &accounts,
            DepositRewardsPoolArgs { amount: 1_000 },
        )
        .expect_err("a foreign-owned config must never authorise a deposit");

        assert_eq!(err, forged_config_rejection());
    }
}
