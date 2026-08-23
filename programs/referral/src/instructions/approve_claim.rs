//! ApproveClaim — discriminant 5
//!
//! Foundation authority approves a pending ClaimRequest, transferring $FLOW
//! from the pool vault to the referrer's ATA and marking the request Approved.

use borsh::{BorshDeserialize, BorshSerialize};
use solana_program::{
    account_info::{next_account_info, AccountInfo},
    clock::Clock,
    entrypoint::ProgramResult,
    program::invoke_signed,
    pubkey::Pubkey,
    sysvar::Sysvar,
};

use crate::{
    errors::ReferralError,
    state::{ClaimRequest, RewardsPool},
};

/// Accounts expected (in order):
/// 0. `[writable]` claim_request  — `ClaimRequest` PDA (must be Pending)
/// 1. `[writable]` rewards_pool   — `RewardsPool` PDA (accounting update)
/// 2. `[]`         config         — `ReferralConfig` PDA (authority check)
/// 3. `[writable]` vault          — pool SPL token vault (source)
/// 4. `[writable]` referrer_ata   — referrer's $FLOW ATA (destination)
/// 5. `[signer]`   authority      — Foundation authority (must match config.authority)
/// 6. `[]`         token_program  — SPL Token program
pub fn process(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
) -> ProgramResult {
    let iter = &mut accounts.iter();
    let claim_request_info = next_account_info(iter)?;
    let rewards_pool_info  = next_account_info(iter)?;
    let config_info        = next_account_info(iter)?;
    let vault_info         = next_account_info(iter)?;
    let referrer_ata_info  = next_account_info(iter)?;
    let authority_info     = next_account_info(iter)?;
    let token_program_info = next_account_info(iter)?;

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

    // ── 3. Check vault has enough $FLOW ─────────────────────────────────────
    {
        // L-1: verify vault is a genuine SPL token account before reading raw bytes
        if vault_info.owner != &spl_token::id() {
            return Err(solana_program::program_error::ProgramError::InvalidAccountOwner);
        }
        let vault_data = vault_info.data.borrow();
        let vault_balance =
            u64::from_le_bytes(vault_data[64..72].try_into().unwrap());
        if vault_balance < request.amount {
            return Err(ReferralError::InsufficientPoolFunds.into());
        }
    }

    // ── 4. Derive pool PDA for signing ──────────────────────────────────────
    let (pool_pda, pool_bump) =
        Pubkey::find_program_address(&[b"rewards_pool"], program_id);
    if rewards_pool_info.key != &pool_pda {
        return Err(solana_program::program_error::ProgramError::InvalidSeeds);
    }

    // ── 5. Transfer from vault to referrer ATA ──────────────────────────────
    invoke_signed(
        &spl_token::instruction::transfer(
            token_program_info.key,
            vault_info.key,
            referrer_ata_info.key,
            &pool_pda,
            &[],
            request.amount,
        )?,
        &[
            vault_info.clone(),
            referrer_ata_info.clone(),
            rewards_pool_info.clone(),
            token_program_info.clone(),
        ],
        &[&[b"rewards_pool", &[pool_bump]]],
    )?;

    // ── 6. Mark claim approved ──────────────────────────────────────────────
    request.status = 1; // Approved
    request.executed_at = clock.unix_timestamp;
    request.serialize(&mut *claim_request_info.data.borrow_mut())?;

    // ── 7. Update pool accounting ───────────────────────────────────────────
    let mut pool = RewardsPool::try_from_slice(&rewards_pool_info.data.borrow())?;
    pool.total_distributed = pool
        .total_distributed
        .checked_add(request.amount)
        .ok_or(ReferralError::Overflow)?;
    pool.serialize(&mut *rewards_pool_info.data.borrow_mut())?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use crate::{
        errors::ReferralError,
        state::{ClaimRequest, RewardsPool},
    };
    use solana_program::program_error::ProgramError;

    #[test]
    fn test_approve_non_authority_error_code() {
        let e: ProgramError = ReferralError::InvalidAuthority.into();
        assert_eq!(e, ProgramError::Custom(1));
    }

    #[test]
    fn test_approve_already_executed_error_code() {
        let e: ProgramError = ReferralError::ClaimAlreadyExecuted.into();
        assert_eq!(e, ProgramError::Custom(19));
    }

    #[test]
    fn test_approve_sets_status_approved() {
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
        assert_eq!(request.status, 0, "starts Pending");
        request.status = 1;
        request.executed_at = 1_700_050_000;
        assert_eq!(request.status, 1, "becomes Approved");
        assert_ne!(request.executed_at, 0);
    }

    #[test]
    fn test_approve_double_execute_guard() {
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
    fn test_approve_updates_pool_tracking() {
        let mut pool = RewardsPool {
            vault_bump:        0,
            total_deposited:   1_000_000_000,
            total_distributed: 0,
            bump:              255,
            _padding:          [0; 6],
        };
        let claim_amount = 100_000_000u64;
        pool.total_distributed =
            pool.total_distributed.checked_add(claim_amount).unwrap();
        assert_eq!(pool.total_distributed, claim_amount);
        // Solvency invariant holds
        assert!(pool.total_deposited >= pool.total_distributed);
    }

    /// C-2, the drain: an attacker-owned config at the canonical PDA address,
    /// naming the attacker as `authority`. Before the fix the handler read the
    /// forged `authority`, matched it against the attacker's own signature, and
    /// went on to sign the vault→ATA transfer with the `rewards_pool` PDA. Any
    /// pending claim could be approved by anyone.
    #[test]
    fn test_approve_rejects_foreign_owned_config() {
        use crate::test_support::{
            claim_request_bytes, forged_config_bytes, forged_config_rejection,
            install_syscall_stubs, rewards_pool_bytes, spl_token_account_bytes,
        };
        use solana_program::{account_info::AccountInfo, pubkey::Pubkey};

        install_syscall_stubs();

        let program_id       = Pubkey::new_unique();
        let attacker_program = Pubkey::new_unique();
        let attacker         = Pubkey::new_unique();
        let referrer         = Pubkey::new_unique();
        let token_program_id = spl_token::id();
        let system_id        = solana_program::system_program::id();
        let request_key      = Pubkey::new_unique();
        let vault_key        = Pubkey::new_unique();
        let ata_key          = Pubkey::new_unique();
        let (config_pda, _)  =
            Pubkey::find_program_address(&[b"referral_config"], &program_id);
        let (pool_pda, _)    =
            Pubkey::find_program_address(&[b"rewards_pool"], &program_id);

        let amount = 100_000_000u64;

        let mut req_lamports   = 1_000_000u64;
        let mut req_data       = claim_request_bytes(&referrer, amount, 0);
        let mut pool_lamports  = 1_000_000u64;
        let mut pool_data      = rewards_pool_bytes(1_000_000_000, 0);
        let mut cfg_lamports   = 1_000_000u64;
        let mut cfg_data       = forged_config_bytes(&attacker, &vault_key);
        let mut vault_lamports = 1_000_000u64;
        let mut vault_data     = spl_token_account_bytes(1_000_000_000);
        let mut ata_lamports   = 1_000_000u64;
        let mut ata_data       = spl_token_account_bytes(0);
        let mut sig_lamports   = 1_000_000u64;
        let mut sig_data: Vec<u8> = Vec::new();
        let mut tp_lamports    = 1_000_000u64;
        let mut tp_data: Vec<u8> = Vec::new();

        let accounts = [
            AccountInfo::new(
                &request_key, false, true,
                &mut req_lamports, &mut req_data, &program_id, false, 0,
            ),
            AccountInfo::new(
                &pool_pda, false, true,
                &mut pool_lamports, &mut pool_data, &program_id, false, 0,
            ),
            AccountInfo::new(
                &config_pda, false, false,
                &mut cfg_lamports, &mut cfg_data, &attacker_program, false, 0,
            ),
            AccountInfo::new(
                &vault_key, false, true,
                &mut vault_lamports, &mut vault_data, &token_program_id, false, 0,
            ),
            AccountInfo::new(
                &ata_key, false, true,
                &mut ata_lamports, &mut ata_data, &token_program_id, false, 0,
            ),
            AccountInfo::new(
                &attacker, true, false,
                &mut sig_lamports, &mut sig_data, &system_id, false, 0,
            ),
            AccountInfo::new(
                &token_program_id, false, false,
                &mut tp_lamports, &mut tp_data, &system_id, true, 0,
            ),
        ];

        let err = super::process(&program_id, &accounts)
            .expect_err("a foreign-owned config must never authorise a payout");

        assert_eq!(err, forged_config_rejection());
    }
}
