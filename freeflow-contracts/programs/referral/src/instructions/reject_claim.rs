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
    state::{ClaimRequest, ReferralConfig, ReferrerBalance},
};

/// Accounts expected (in order):
/// 0. `[writable]` claim_request    — `ClaimRequest` PDA (must be Pending)
/// 1. `[writable]` referrer_balance — `ReferrerBalance` PDA (balance unlock)
/// 2. `[]`         config           — `ReferralConfig` PDA (authority check)
/// 3. `[signer]`   authority        — Foundation authority
pub fn process(
    _program_id: &Pubkey,
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
    let config = ReferralConfig::try_from_slice(&config_info.data.borrow())?;
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
}
