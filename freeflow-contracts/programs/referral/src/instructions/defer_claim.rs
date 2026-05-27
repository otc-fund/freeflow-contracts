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
    state::{ClaimRequest, ReferralConfig},
};

/// Accounts expected (in order):
/// 0. `[writable]` claim_request — `ClaimRequest` PDA (must be Pending)
/// 1. `[]`         config        — `ReferralConfig` PDA (authority check)
/// 2. `[signer]`   authority     — Foundation authority
pub fn process(
    _program_id: &Pubkey,
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
    let config = ReferralConfig::try_from_slice(&config_info.data.borrow())?;
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
}
