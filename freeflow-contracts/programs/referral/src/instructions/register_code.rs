//! RegisterReferralCode — discriminant 2
//!
//! First-come, first-served: the first signer to call this instruction with a
//! given code string claims that code. The code hash is SHA-256 of the
//! uppercased bytes so "FLOW" and "flow" refer to the same code.

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

use crate::{errors::ReferralError, state::ReferralCode, utils::sha256_hash};

/// Instruction data (after discriminant).
#[derive(BorshSerialize, BorshDeserialize)]
pub struct RegisterReferralCodeArgs {
    pub code: Vec<u8>, // raw UTF-8 bytes; uppercased before hashing
}

/// Accounts expected (in order):
/// 0. `[writable]` code          — PDA `[b"referral_code", code_hash]` (will be created)
/// 1. `[signer]`   referrer      — becomes the owner of this code
/// 2. `[]`         config        — `ReferralConfig` PDA (not read here, included for future validation)
/// 3. `[]`         system_program
pub fn process(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    args: RegisterReferralCodeArgs,
) -> ProgramResult {
    let iter = &mut accounts.iter();
    let code_info      = next_account_info(iter)?;
    let referrer_info  = next_account_info(iter)?;
    let _config_info   = next_account_info(iter)?;
    let system_program = next_account_info(iter)?;

    if !referrer_info.is_signer {
        return Err(ReferralError::InvalidAuthority.into());
    }

    // Hash the uppercased code bytes for case-insensitive matching
    let uppercased: Vec<u8> = args.code.iter().map(|b| b.to_ascii_uppercase()).collect();
    let code_hash = sha256_hash(&uppercased);

    // Derive and verify PDA
    let (expected_pda, code_bump) =
        Pubkey::find_program_address(&[b"referral_code", &code_hash], program_id);
    if code_info.key != &expected_pda {
        return Err(solana_program::program_error::ProgramError::InvalidSeeds);
    }

    // Reject if already claimed
    if !code_info.data_is_empty() {
        let existing = ReferralCode::try_from_slice(&code_info.data.borrow())?;
        if existing.is_claimed {
            return Err(ReferralError::CodeAlreadyClaimed.into());
        }
    }

    // Create the account if it doesn't exist
    if code_info.data_is_empty() {
        let rent = Rent::get()?;
        let lamports = rent.minimum_balance(ReferralCode::SIZE);
        invoke_signed(
            &system_instruction::create_account(
                referrer_info.key,
                code_info.key,
                lamports,
                ReferralCode::SIZE as u64,
                program_id,
            ),
            &[
                referrer_info.clone(),
                code_info.clone(),
                system_program.clone(),
            ],
            &[&[b"referral_code", &code_hash, &[code_bump]]],
        )?;
    }

    let clock = Clock::get()?;
    let record = ReferralCode {
        code_hash,
        referrer:   referrer_info.key.to_bytes(),
        created_at: clock.unix_timestamp,
        is_claimed: true,
        bump:       code_bump,
        _padding:   [0; 6],
    };
    record.serialize(&mut *code_info.data.borrow_mut())?;

    Ok(())
}
