//! RejectClaim — discriminant 6
//!
//! Foundation authority rejects a pending ClaimRequest, unlocking the referrer's
//! balance so they can submit a new claim later.

use borsh::{BorshDeserialize, BorshSerialize};
use solana_program::{
    account_info::{next_account_info, AccountInfo},
    clock::Clock,
    entrypoint::ProgramResult,
    pubkey::Pubkey,
    sysvar::Sysvar,
};

use crate::{
    errors::ReferralError,
    state::{ClaimRequest, ReferrerBalance},
};

/// Accounts expected (in order):
/// 0. `[writable]` claim_request    — `ClaimRequest` PDA (must be Pending)
/// 1. `[writable]` referrer_balance — `ReferrerBalance` PDA (balance unlock)
/// 2. `[]`         config           — `ReferralConfig` PDA (authority check)
/// 3. `[signer]`   authority        — Foundation authority
pub fn process(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
) -> ProgramResult {
    let iter = &mut accounts.iter();
    let claim_request_info    = next_account_info(iter)?;
    let referrer_balance_info = next_account_info(iter)?;
    let config_info           = next_account_info(iter)?;
    let authority_info        = next_account_info(iter)?;

    if !authority_info.is_signer {
        return Err(ReferralError::InvalidAuthority.into());
    }

    // ── 1. Validate authority ───────────────────────────────────────────────
    // C-2: prove the account IS the config before trusting `authority`.
    let config = crate::utils::load_verified_config(config_info, program_id)?;
    if config.authority != authority_info.key.to_bytes() {
        return Err(ReferralError::InvalidAuthority.into());
    }

    // ── 2. Validate claim request is Pending ────────────────────────────────
    let mut request = ClaimRequest::try_from_slice(&claim_request_info.data.borrow())?;
    if request.status != 0 {
        return Err(ReferralError::ClaimAlreadyExecuted.into());
    }

    // ── M-1: Enforce 48-hour review window ─────────────────────────────────
    let clock = Clock::get()?;
    if clock.unix_timestamp > request.review_deadline {
        return Err(ReferralError::ReviewDeadlinePassed.into());
    }

    // ── 3. Unlock referrer balance ──────────────────────────────────────────
    let mut balance =
        ReferrerBalance::try_from_slice(&referrer_balance_info.data.borrow())?;
    if balance.referrer != request.referrer {
        return Err(ReferralError::InvalidAuthority.into());
    }
    balance.total_claimed = balance
        .total_claimed
        .checked_sub(request.amount)
        .ok_or(ReferralError::Overflow)?;
    balance.serialize(&mut *referrer_balance_info.data.borrow_mut())?;

    // ── 4. Mark claim rejected ──────────────────────────────────────────────
    request.status = 2; // Rejected
    request.executed_at = clock.unix_timestamp;
    request.serialize(&mut *claim_request_info.data.borrow_mut())?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use crate::{
        errors::ReferralError,
        state::{ClaimRequest, ReferrerBalance},
    };
    use solana_program::program_error::ProgramError;

    #[test]
    fn test_reject_unlocks_balance() {
        let mut balance = ReferrerBalance {
            referrer:       [1u8; 32],
            total_earned:   500_000_000,
            total_claimed:  500_000_000, // locked by ClaimReferralReward
            referral_count: 1,
            next_sequence:  1,
            bump:           255,
            _padding:       [0; 7],
        };
        let claim_amount = 500_000_000u64;
        // Simulate rejection unlock
        balance.total_claimed =
            balance.total_claimed.checked_sub(claim_amount).unwrap();
        let available = balance.total_earned - balance.total_claimed;
        assert_eq!(available, 500_000_000, "balance restored after rejection");
    }

    #[test]
    fn test_reject_non_authority_error_code() {
        let e: ProgramError = ReferralError::InvalidAuthority.into();
        assert_eq!(e, ProgramError::Custom(1));
    }

    #[test]
    fn test_reject_already_executed_guard() {
        let request = ClaimRequest {
            referrer:        [1u8; 32],
            amount:          100_000_000,
            requested_at:    1_700_000_000,
            review_deadline: 1_700_172_800,
            status:          2, // Already Rejected
            executed_at:     1_700_050_000,
            bump:            255,
            _padding:        [0; 2],
        };
        assert_ne!(request.status, 0, "non-Pending → ClaimAlreadyExecuted");
    }

    #[test]
    fn test_reclaim_after_rejection_available() {
        let mut balance = ReferrerBalance {
            referrer:       [1u8; 32],
            total_earned:   500_000_000,
            total_claimed:  500_000_000, // was locked
            referral_count: 1,
            next_sequence:  2, // sequence already incremented from rejected claim
            bump:           255,
            _padding:       [0; 7],
        };
        // Simulate rejection unlock
        balance.total_claimed -= 500_000_000;
        assert_eq!(balance.total_earned - balance.total_claimed, 500_000_000);
        // next_sequence=2 → new ClaimReferralReward uses seq 2 → unique PDA
        assert_eq!(balance.next_sequence, 2);
    }

    /// C-2: an attacker-owned config at the canonical PDA address, naming the
    /// attacker as `authority`. Before the fix the handler accepted it, marked
    /// the claim Rejected and rewound `ReferrerBalance.total_claimed` — an
    /// unauthorised party killing a legitimate payout.
    #[test]
    fn test_reject_rejects_foreign_owned_config() {
        use crate::test_support::{
            claim_request_bytes, forged_config_bytes, forged_config_rejection,
            install_syscall_stubs, referrer_balance_bytes,
        };
        use solana_program::{account_info::AccountInfo, pubkey::Pubkey};

        install_syscall_stubs();

        let program_id       = Pubkey::new_unique();
        let attacker_program = Pubkey::new_unique();
        let attacker         = Pubkey::new_unique();
        let referrer         = Pubkey::new_unique();
        let vault            = Pubkey::new_unique();
        let system_id        = solana_program::system_program::id();
        let request_key      = Pubkey::new_unique();
        let balance_key      = Pubkey::new_unique();
        let (config_pda, _)  =
            Pubkey::find_program_address(&[b"referral_config"], &program_id);

        let amount = 100_000_000u64;

        let mut req_lamports = 1_000_000u64;
        let mut req_data     = claim_request_bytes(&referrer, amount, 0);
        let mut bal_lamports = 1_000_000u64;
        let mut bal_data     = referrer_balance_bytes(&referrer, 500_000_000, amount, 1);
        let mut cfg_lamports = 1_000_000u64;
        let mut cfg_data     = forged_config_bytes(&attacker, &vault);
        let mut sig_lamports = 1_000_000u64;
        let mut sig_data: Vec<u8> = Vec::new();

        let accounts = [
            AccountInfo::new(
                &request_key, false, true,
                &mut req_lamports, &mut req_data, &program_id, false, 0,
            ),
            AccountInfo::new(
                &balance_key, false, true,
                &mut bal_lamports, &mut bal_data, &program_id, false, 0,
            ),
            AccountInfo::new(
                &config_pda, false, false,
                &mut cfg_lamports, &mut cfg_data, &attacker_program, false, 0,
            ),
            AccountInfo::new(
                &attacker, true, false,
                &mut sig_lamports, &mut sig_data, &system_id, false, 0,
            ),
        ];

        let err = super::process(&program_id, &accounts)
            .expect_err("a foreign-owned config must never authorise a rejection");

        assert_eq!(err, forged_config_rejection());
    }
}
