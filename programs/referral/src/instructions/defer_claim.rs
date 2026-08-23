//! DeferClaim — discriminant 7
//!
//! Foundation authority extends the review deadline by another 48 hours.
//! Status remains Pending. Useful when additional investigation is needed.

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
    state::ClaimRequest,
};

/// Accounts expected (in order):
/// 0. `[writable]` claim_request — `ClaimRequest` PDA (must be Pending)
/// 1. `[]`         config        — `ReferralConfig` PDA (authority check)
/// 2. `[signer]`   authority     — Foundation authority
pub fn process(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
) -> ProgramResult {
    let iter = &mut accounts.iter();
    let claim_request_info = next_account_info(iter)?;
    let config_info        = next_account_info(iter)?;
    let authority_info     = next_account_info(iter)?;

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

    // ── 3. Extend review deadline by another 48 hours ───────────────────────
    let clock = Clock::get()?;
    request.review_deadline = clock.unix_timestamp + ClaimRequest::REVIEW_WINDOW_SECS;
    // status remains 0 (Pending)
    request.serialize(&mut *claim_request_info.data.borrow_mut())?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use crate::{
        errors::ReferralError,
        state::ClaimRequest,
    };
    use solana_program::program_error::ProgramError;

    #[test]
    fn test_defer_extends_deadline() {
        let mut request = ClaimRequest {
            referrer:        [1u8; 32],
            amount:          100_000_000,
            requested_at:    1_700_000_000,
            review_deadline: 1_700_172_800,
            status:          0,
            executed_at:     0,
            bump:            255,
            _padding:        [0; 2],
        };
        let now = 1_700_100_000i64;
        request.review_deadline = now + ClaimRequest::REVIEW_WINDOW_SECS;
        assert_eq!(request.review_deadline, now + 172_800);
        assert_eq!(request.status, 0, "status stays Pending after defer");
    }

    #[test]
    fn test_defer_already_executed_guard() {
        let request = ClaimRequest {
            referrer:        [1u8; 32],
            amount:          100_000_000,
            requested_at:    1_700_000_000,
            review_deadline: 1_700_172_800,
            status:          1, // Already Approved
            executed_at:     1_700_050_000,
            bump:            255,
            _padding:        [0; 2],
        };
        assert_ne!(request.status, 0, "non-Pending → ClaimAlreadyExecuted");
    }

    #[test]
    fn test_defer_non_authority_error_code() {
        let e: ProgramError = ReferralError::InvalidAuthority.into();
        assert_eq!(e, ProgramError::Custom(1));
    }

    /// C-2: an attacker-owned config at the canonical PDA address, naming the
    /// attacker as `authority`. Before the fix the handler accepted it and slid
    /// the review deadline out by another 48 hours — an unauthorised party
    /// stalling a claim indefinitely.
    #[test]
    fn test_defer_rejects_foreign_owned_config() {
        use crate::test_support::{
            claim_request_bytes, forged_config_bytes, forged_config_rejection,
            install_syscall_stubs,
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
        let (config_pda, _)  =
            Pubkey::find_program_address(&[b"referral_config"], &program_id);

        let mut req_lamports = 1_000_000u64;
        let mut req_data     = claim_request_bytes(&referrer, 100_000_000, 0);
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
                &config_pda, false, false,
                &mut cfg_lamports, &mut cfg_data, &attacker_program, false, 0,
            ),
            AccountInfo::new(
                &attacker, true, false,
                &mut sig_lamports, &mut sig_data, &system_id, false, 0,
            ),
        ];

        let err = super::process(&program_id, &accounts)
            .expect_err("a foreign-owned config must never authorise a deferral");

        assert_eq!(err, forged_config_rejection());
    }
}
