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

use crate::errors::ReferralError;

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
    program_id: &Pubkey,
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
    // C-2: prove the account IS the config before trusting `authority`.
    let mut config = crate::utils::load_verified_config(config_info, program_id)?;

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

// ─── Unit Tests ───────────────────────────────────────────────────────────────
#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::{forged_config_bytes, forged_config_rejection};

    /// C-2: a config account owned by a program the attacker controls, parked at
    /// the canonical PDA address so that nothing but the owner check separates
    /// it from the genuine config. The attacker writes their own key into
    /// `authority` at offset 18..50 and signs. Before the fix this returned
    /// `Ok(())` — the handler read the forged bytes and believed them.
    ///
    /// The re-serialize writes back into *the account it was passed*, so this
    /// was never an escalation path: an attacker could only rewrite their own
    /// account. It is closed for consistency — no handler should read a config
    /// it has not authenticated.
    #[test]
    fn test_update_config_rejects_foreign_owned_config() {
        let program_id       = Pubkey::new_unique();
        let attacker_program = Pubkey::new_unique();
        let attacker         = Pubkey::new_unique();
        let vault            = Pubkey::new_unique();
        let system_id        = solana_program::system_program::id();
        let (config_pda, _)  =
            Pubkey::find_program_address(&[b"referral_config"], &program_id);

        let mut cfg_lamports = 1_000_000u64;
        let mut cfg_data     = forged_config_bytes(&attacker, &vault);
        let mut sig_lamports = 1_000_000u64;
        let mut sig_data: Vec<u8> = Vec::new();

        let accounts = [
            AccountInfo::new(
                &config_pda, false, true,
                &mut cfg_lamports, &mut cfg_data, &attacker_program, false, 0,
            ),
            AccountInfo::new(
                &attacker, true, false,
                &mut sig_lamports, &mut sig_data, &system_id, false, 0,
            ),
        ];

        let err = process(
            &program_id,
            &accounts,
            UpdateReferralConfigArgs {
                reward_bps:            3_000,
                max_reward_lamports:   u64::MAX,
                min_purchase_lamports: 0,
            },
        )
        .expect_err("a foreign-owned config must never authorise an update");

        assert_eq!(err, forged_config_rejection());
    }
}
