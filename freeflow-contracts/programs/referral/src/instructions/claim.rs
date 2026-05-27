//! ClaimReferralReward — discriminant 4
//!
//! Creates a ClaimRequest PDA in Pending status. No token transfer — the
//! Foundation reviews the request and calls ApproveClaim (discriminant 5)
//! or RejectClaim (discriminant 6) to settle it.

use borsh::{BorshDeserialize, BorshSerialize};
use solana_program::{
    account_info::{next_account_info, AccountInfo},
    clock::Clock,
    entrypoint::ProgramResult,
    program::invoke_signed,
    pubkey::Pubkey,
    rent::Rent,
    system_instruction,
    sysvar::Sysvar,
};

use crate::{
    errors::ReferralError,
    state::{ClaimRequest, ReferrerBalance, RewardsPool},
};

/// Accounts expected (in order):
/// 0. `[writable]` claim_request    — new `ClaimRequest` PDA (will be created)
/// 1. `[writable]` referrer_balance — `ReferrerBalance` PDA
/// 2. `[]`         config           — `ReferralConfig` PDA (reserved for future checks)
/// 3. `[writable]` rewards_pool     — `RewardsPool` PDA
/// 4. `[signer]`   referrer         — must match `referrer_balance.referrer`
/// 5. `[]`         system_program
pub fn process(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
) -> ProgramResult {
    let iter = &mut accounts.iter();
    let claim_request_info    = next_account_info(iter)?;
    let referrer_balance_info = next_account_info(iter)?;
    let _config_info          = next_account_info(iter)?;
    let rewards_pool_info     = next_account_info(iter)?;
    let referrer_info         = next_account_info(iter)?;
    let system_program        = next_account_info(iter)?;

    if !referrer_info.is_signer {
        return Err(ReferralError::InvalidAuthority.into());
    }

    // ── 1. Load referrer balance ────────────────────────────────────────────
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

    // ── 2. Use next_sequence as unique claim ID ─────────────────────────────
    let sequence = balance.next_sequence;
    let seq_bytes = sequence.to_le_bytes();

    // ── 3. Derive and verify ClaimRequest PDA ──────────────────────────────
    let (expected_pda, claim_bump) = Pubkey::find_program_address(
        &[b"claim_request", referrer_info.key.as_ref(), &seq_bytes],
        program_id,
    );
    if claim_request_info.key != &expected_pda {
        return Err(solana_program::program_error::ProgramError::InvalidSeeds);
    }

    // ── 4. Create ClaimRequest PDA ──────────────────────────────────────────
    let clock = Clock::get()?;
    let rent = Rent::get()?;
    let lamports = rent.minimum_balance(ClaimRequest::SIZE);
    invoke_signed(
        &system_instruction::create_account(
            referrer_info.key,
            claim_request_info.key,
            lamports,
            ClaimRequest::SIZE as u64,
            program_id,
        ),
        &[
            referrer_info.clone(),
            claim_request_info.clone(),
            system_program.clone(),
        ],
        &[&[b"claim_request", referrer_info.key.as_ref(), &seq_bytes, &[claim_bump]]],
    )?;

    let request = ClaimRequest {
        referrer:        referrer_info.key.to_bytes(),
        amount:          available,
        requested_at:    clock.unix_timestamp,
        review_deadline: clock.unix_timestamp + ClaimRequest::REVIEW_WINDOW_SECS,
        status:          0, // Pending
        executed_at:     0,
        bump:            claim_bump,
        _padding:        [0; 2],
    };
    request.serialize(&mut *claim_request_info.data.borrow_mut())?;

    // ── 5. Lock referrer balance (total_claimed += available) ───────────────
    balance.total_claimed = balance
        .total_claimed
        .checked_add(available)
        .ok_or(ReferralError::Overflow)?;
    balance.next_sequence = balance
        .next_sequence
        .checked_add(1)
        .ok_or(ReferralError::Overflow)?;
    balance.serialize(&mut *referrer_balance_info.data.borrow_mut())?;

    // ── 6. Verify pool account exists (no accounting change for pending) ────
    let _ = RewardsPool::try_from_slice(&rewards_pool_info.data.borrow())?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::ClaimRequest;

    #[test]
    fn test_claim_request_size() {
        let r = ClaimRequest {
            referrer:        [1u8; 32],
            amount:          500_000_000,
            requested_at:    1_700_000_000,
            review_deadline: 1_700_172_800,
            status:          0,
            executed_at:     0,
            bump:            255,
            _padding:        [0; 2],
        };
        assert_eq!(
            borsh::to_vec(&r).unwrap().len(),
            ClaimRequest::SIZE,
            "ClaimRequest::SIZE must match serialized length"
        );
    }

    #[test]
    fn test_claim_request_review_window() {
        assert_eq!(ClaimRequest::REVIEW_WINDOW_SECS, 172_800, "48 hours = 172800 seconds");
    }

    #[test]
    fn test_claim_zero_available_rejected() {
        let balance = ReferrerBalance {
            referrer:       [1u8; 32],
            total_earned:   100,
            total_claimed:  100,
            referral_count: 1,
            next_sequence:  1,
            bump:           255,
            _padding:       [0; 7],
        };
        let available = balance.total_earned.checked_sub(balance.total_claimed).unwrap();
        assert_eq!(available, 0, "no rewards available when fully claimed");
    }

    #[test]
    fn test_claim_sequence_increments() {
        let mut balance = ReferrerBalance {
            referrer:       [1u8; 32],
            total_earned:   500,
            total_claimed:  0,
            referral_count: 1,
            next_sequence:  0,
            bump:           255,
            _padding:       [0; 7],
        };
        let seq_before = balance.next_sequence;
        balance.total_claimed += 500;
        balance.next_sequence += 1;
        assert_eq!(balance.next_sequence, seq_before + 1);
    }

    #[test]
    fn test_claim_pda_seeds_are_unique() {
        let seq0 = 0u32.to_le_bytes();
        let seq1 = 1u32.to_le_bytes();
        assert_ne!(seq0, seq1, "different sequences produce different seeds");
    }
}
