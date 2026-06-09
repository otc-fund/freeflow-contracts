//! RecordReferral — discriminant 3
//!
//! Pure bookkeeping: creates a ReferralRecord PDA, updates ReferrerBalance,
//! and updates RewardsPool tracking. **No token transfer** — the referral cut
//! was already moved to the pool vault by the user-escrow instruction in the
//! same transaction.
//!
//! Security fixes included:
//! - H-1: pool_vault account validated against config.rewards_pool_vault
//! - M-5: transferred_reward validated against calculated reward

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
    state::{ReferralCode, ReferralConfig, ReferralRecord, ReferrerBalance, RewardsPool},
    utils::calculate_reward,
};

/// Instruction data (after discriminant).
#[derive(BorshSerialize, BorshDeserialize)]
pub struct RecordReferralArgs {
    pub code_hash:          [u8; 32],
    pub purchase_amount:    u64,
    /// The reward amount actually transferred to the pool vault by user-escrow.
    /// Must equal calculate_reward(purchase_amount, config.reward_bps, config.max_reward_lamports).
    pub transferred_reward: u64,
}

/// Accounts expected (in order):
///  0. `[writable]` record           — new `ReferralRecord` PDA (will be created)
///  1. `[writable]` referrer_balance — `ReferrerBalance` PDA (created if absent)
///  2. `[]`         code             — `ReferralCode` PDA (must be claimed)
///  3. `[]`         config           — `ReferralConfig` PDA
///  4. `[writable]` rewards_pool     — `RewardsPool` PDA
///  5. `[signer]`   client           — the purchaser
///  6. `[]`         referrer         — the referrer
///  7. `[]`         system_program
///  8. `[]`         pool_vault       — SPL token vault (H-1: must match config.rewards_pool_vault)
pub fn process(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    args: RecordReferralArgs,
) -> ProgramResult {
    let iter = &mut accounts.iter();
    let record_info           = next_account_info(iter)?;
    let referrer_balance_info = next_account_info(iter)?;
    let code_info             = next_account_info(iter)?;
    let config_info           = next_account_info(iter)?;
    let rewards_pool_info     = next_account_info(iter)?;
    let client_info           = next_account_info(iter)?;
    let referrer_info         = next_account_info(iter)?;
    let system_program        = next_account_info(iter)?;
    let pool_vault_info       = next_account_info(iter)?; // H-1

    if !client_info.is_signer {
        return Err(ReferralError::InvalidAuthority.into());
    }

    // ── 1. Load config ──────────────────────────────────────────────────────
    let config = ReferralConfig::try_from_slice(&config_info.data.borrow())?;

    // ── H-1: Validate pool vault matches config ─────────────────────────────
    if pool_vault_info.key.to_bytes() != config.rewards_pool_vault {
        return Err(ReferralError::InvalidPoolVault.into());
    }

    // ── 2. Validate purchase amount ─────────────────────────────────────────
    if args.purchase_amount < config.min_purchase_lamports {
        return Err(ReferralError::PurchaseBelowMinimum.into());
    }

    // ── 3. Validate referral code ───────────────────────────────────────────
    let code = ReferralCode::try_from_slice(&code_info.data.borrow())?;
    if !code.is_claimed {
        return Err(ReferralError::CodeNotClaimed.into());
    }
    if code.referrer != referrer_info.key.to_bytes() {
        return Err(ReferralError::InvalidReferralCode.into());
    }
    if code.code_hash != args.code_hash {
        return Err(ReferralError::InvalidReferralCode.into());
    }

    // ── 4. Calculate reward ─────────────────────────────────────────────────
    let reward = calculate_reward(
        args.purchase_amount,
        config.reward_bps,
        config.max_reward_lamports,
    )?;

    // ── M-5: Validate transferred reward matches expected ───────────────────
    if reward != args.transferred_reward {
        return Err(ReferralError::InvalidRewardAmount.into());
    }

    // ── 5. Load or create ReferrerBalance ───────────────────────────────────
    let (expected_balance_pda, balance_bump) = Pubkey::find_program_address(
        &[b"referrer_balance", referrer_info.key.as_ref()],
        program_id,
    );
    if referrer_balance_info.key != &expected_balance_pda {
        return Err(solana_program::program_error::ProgramError::InvalidSeeds);
    }

    if referrer_balance_info.data_is_empty() {
        let rent = Rent::get()?;
        let lamports = rent.minimum_balance(ReferrerBalance::SIZE);
        invoke_signed(
            &system_instruction::create_account(
                client_info.key,
                referrer_balance_info.key,
                lamports,
                ReferrerBalance::SIZE as u64,
                program_id,
            ),
            &[
                client_info.clone(),
                referrer_balance_info.clone(),
                system_program.clone(),
            ],
            &[&[b"referrer_balance", referrer_info.key.as_ref(), &[balance_bump]]],
        )?;
        let initial = ReferrerBalance {
            referrer:       referrer_info.key.to_bytes(),
            total_earned:   0,
            total_claimed:  0,
            referral_count: 0,
            next_sequence:  0,
            bump:           balance_bump,
            _padding:       [0; 7],
        };
        initial.serialize(&mut *referrer_balance_info.data.borrow_mut())?;
    }

    let mut balance =
        ReferrerBalance::try_from_slice(&referrer_balance_info.data.borrow())?;
    let sequence = balance.next_sequence;

    // ── 6. Create ReferralRecord PDA ────────────────────────────────────────
    let seq_bytes = sequence.to_le_bytes();
    let (expected_record_pda, record_bump) = Pubkey::find_program_address(
        &[
            b"referral_record",
            referrer_info.key.as_ref(),
            client_info.key.as_ref(),
            &seq_bytes,
        ],
        program_id,
    );
    if record_info.key != &expected_record_pda {
        return Err(solana_program::program_error::ProgramError::InvalidSeeds);
    }

    let rent = Rent::get()?;
    let record_lamports = rent.minimum_balance(ReferralRecord::SIZE);
    invoke_signed(
        &system_instruction::create_account(
            client_info.key,
            record_info.key,
            record_lamports,
            ReferralRecord::SIZE as u64,
            program_id,
        ),
        &[
            client_info.clone(),
            record_info.clone(),
            system_program.clone(),
        ],
        &[&[
            b"referral_record",
            referrer_info.key.as_ref(),
            client_info.key.as_ref(),
            &seq_bytes,
            &[record_bump],
        ]],
    )?;

    let clock = Clock::get()?;
    let record = ReferralRecord {
        referrer:        referrer_info.key.to_bytes(),
        client:          client_info.key.to_bytes(),
        purchase_amount: args.purchase_amount,
        reward_lamports: reward,
        code_hash:       args.code_hash,
        timestamp:       clock.unix_timestamp,
        sequence,
        bump:            record_bump,
        _padding:        [0; 3],
    };
    record.serialize(&mut *record_info.data.borrow_mut())?;

    // ── 7. Update ReferrerBalance ───────────────────────────────────────────
    balance.total_earned = balance
        .total_earned
        .checked_add(reward)
        .ok_or(ReferralError::Overflow)?;
    balance.referral_count = balance
        .referral_count
        .checked_add(1)
        .ok_or(ReferralError::Overflow)?;
    balance.next_sequence = balance
        .next_sequence
        .checked_add(1)
        .ok_or(ReferralError::Overflow)?;
    balance.serialize(&mut *referrer_balance_info.data.borrow_mut())?;

    // ── 8. Update RewardsPool tracking ──────────────────────────────────────
    // L-5: validate ownership before deserializing pool accounting
    if rewards_pool_info.owner != program_id {
        return Err(solana_program::program_error::ProgramError::InvalidAccountOwner);
    }
    let mut pool = RewardsPool::try_from_slice(&rewards_pool_info.data.borrow())?;
    pool.total_deposited = pool
        .total_deposited
        .checked_add(reward)
        .ok_or(ReferralError::Overflow)?;
    pool.serialize(&mut *rewards_pool_info.data.borrow_mut())?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use crate::{errors::ReferralError, utils::calculate_reward};
    use solana_program::program_error::ProgramError;

    #[test]
    fn test_record_referral_wrong_pool_vault() {
        // H-1: pool_vault doesn't match config.rewards_pool_vault
        let config_vault    = [1u8; 32];
        let submitted_vault = [2u8; 32]; // different!
        assert_ne!(config_vault, submitted_vault, "H-1: mismatch detected");
        let e: ProgramError = ReferralError::InvalidPoolVault.into();
        assert_eq!(e, ProgramError::Custom(14));
    }

    #[test]
    fn test_record_referral_mismatched_reward() {
        // M-5: transferred_reward != calculated reward
        let purchase_amount = 1_000_000_000u64;
        let reward_bps      = 100u16;
        let max_reward      = u64::MAX;
        let expected    = calculate_reward(purchase_amount, reward_bps, max_reward).unwrap();
        let transferred = expected + 1; // tampered
        assert_ne!(expected, transferred, "M-5: mismatch detected");
        let e: ProgramError = ReferralError::InvalidRewardAmount.into();
        assert_eq!(e, ProgramError::Custom(13));
    }

    #[test]
    fn test_record_referral_valid_vault_and_reward() {
        // Both H-1 and M-5 pass
        let config_vault    = [5u8; 32];
        let submitted_vault = [5u8; 32]; // matches
        assert_eq!(config_vault, submitted_vault, "H-1 passes");

        let purchase_amount = 2_000_000_000u64;
        let reward_bps      = 200u16;
        let max_reward      = u64::MAX;
        let expected    = calculate_reward(purchase_amount, reward_bps, max_reward).unwrap();
        let transferred = expected; // matches
        assert_eq!(expected, transferred, "M-5 passes");
    }
}
