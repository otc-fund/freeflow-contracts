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
    program_pack::Pack, // brings `spl_token::state::Account::LEN` into scope
    pubkey::Pubkey,
    sysvar::Sysvar,
};

use crate::{
    errors::ReferralError,
    state::{ClaimRequest, RewardsPool},
};

/// Associated Token Account program (`ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL`).
///
/// Used only to *derive* the referrer's canonical ATA below; never CPI'd into,
/// and never added to the account list.
const ASSOCIATED_TOKEN_PROGRAM_ID: Pubkey =
    solana_program::pubkey!("ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL");

/// Accounts expected (in order):
/// 0. `[writable]` claim_request  — `ClaimRequest` PDA (must be Pending)
/// 1. `[writable]` rewards_pool   — `RewardsPool` PDA (accounting update)
/// 2. `[]`         config         — `ReferralConfig` PDA (authority check)
/// 3. `[writable]` vault          — pool SPL token vault (source)
/// 4. `[writable]` referrer_ata   — referrer's $FLOW ATA (destination). Must be
///    the canonical ATA of `claim_request.referrer` for the vault's mint;
///    derived, not trusted.
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

    // ── 3. Check vault has enough $FLOW, and learn the mint ─────────────────
    let flow_mint = {
        // L-1: verify vault is a genuine SPL token account before reading raw bytes
        if vault_info.owner != &spl_token::id() {
            return Err(solana_program::program_error::ProgramError::InvalidAccountOwner);
        }
        // A *mint* is also `spl_token`-owned and is only 82 bytes, so owner
        // alone does not say "token account". Length does, and it has to,
        // because the mint below is read from this account's bytes.
        let vault_data = vault_info.data.borrow();
        if vault_data.len() != spl_token::state::Account::LEN {
            return Err(solana_program::program_error::ProgramError::InvalidAccountData);
        }
        let vault_balance =
            u64::from_le_bytes(vault_data[64..72].try_into().unwrap());
        if vault_balance < request.amount {
            return Err(ReferralError::InsufficientPoolFunds.into());
        }
        // SPL token account layout: mint at 0..32. No new account — this is the
        // same one the balance was just read from.
        Pubkey::new_from_array(vault_data[0..32].try_into().unwrap())
    };

    // ── 4. Derive pool PDA for signing ──────────────────────────────────────
    let (pool_pda, pool_bump) =
        Pubkey::find_program_address(&[b"rewards_pool"], program_id);
    if rewards_pool_info.key != &pool_pda {
        return Err(solana_program::program_error::ProgramError::InvalidSeeds);
    }

    // ── 5. Bind the payout destination to the claim's referrer ──────────────
    // `referrer_ata_info` arrived from the caller and went into the transfer
    // below verbatim. On its own that needs a genuine authority signature, so
    // it is a misdirection risk rather than a drain — but it is the payout
    // vector that made C-2 a drain, and with C-2 closed it is what is left.
    //
    // Derive the canonical ATA instead of reading the destination's `owner`
    // field: deriving pins the mint and the token program too, and matches
    // `require_foundation_treasury` in rewards-v2. It rejects nothing
    // legitimate — the foundation already sends exactly this address
    // (freeflow-sidecar .../referral/authority.rs:157 calls
    // `derive_ata(referrer, flow_mint, token_program)`).
    //
    // $FLOW is a classic SPL mint, so the ATA is derived under `spl_token::id()`
    // — the id `vault_info.owner` is already pinned to above, and the only id
    // `spl_token::instruction::transfer` below accepts. Deriving from the
    // caller-supplied `token_program_info` would instead let the caller shift
    // the address this check expects.
    {
        let (expected_ata, _) = Pubkey::find_program_address(
            &[
                request.referrer.as_ref(),
                spl_token::id().as_ref(),
                flow_mint.as_ref(),
            ],
            &ASSOCIATED_TOKEN_PROGRAM_ID,
        );
        if referrer_ata_info.key != &expected_ata {
            return Err(ReferralError::InvalidReferrerAta.into());
        }
    }

    // ── 6. Transfer from vault to referrer ATA ──────────────────────────────
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

    // ── 7. Mark claim approved ──────────────────────────────────────────────
    request.status = 1; // Approved
    request.executed_at = clock.unix_timestamp;
    request.serialize(&mut *claim_request_info.data.borrow_mut())?;

    // ── 8. Update pool accounting ───────────────────────────────────────────
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
    use solana_program::{program_error::ProgramError, pubkey::Pubkey};

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

    // ── Task 4: the payout destination must belong to the claim's referrer ──

    /// Drive `ApproveClaim` end to end with everything well-formed *except*
    /// the payout destination, which the caller picks.
    ///
    /// Genuine config (program-owned, canonical PDA, `authority` == the signer),
    /// funded vault, open review window, Pending claim. `referrer_ata` is the
    /// only variable, so whatever this returns is a statement about the
    /// destination binding and nothing else.
    fn approve_paying_to(
        program_id:   &Pubkey,
        authority:    &Pubkey,
        referrer:     &Pubkey,
        mint:         &Pubkey,
        referrer_ata: &Pubkey,
    ) -> Result<(), ProgramError> {
        approve_with_vault(
            program_id,
            authority,
            referrer,
            mint,
            referrer_ata,
            crate::test_support::spl_token_account_bytes_for_mint(mint, 1_000_000_000),
        )
    }

    /// As `approve_paying_to`, but the bytes behind `vault_info` are the
    /// caller's too.
    ///
    /// I-3 needs that second variable: the vault is the account the handler
    /// reads both the balance and — since C-2 — the mint out of, so "is this
    /// really a token account" is a question only a caller-supplied `vault`
    /// can ask.
    fn approve_with_vault(
        program_id:   &Pubkey,
        authority:    &Pubkey,
        referrer:     &Pubkey,
        mint:         &Pubkey,
        referrer_ata: &Pubkey,
        vault_bytes:  Vec<u8>,
    ) -> Result<(), ProgramError> {
        use crate::test_support::{
            claim_request_bytes, config_bytes, install_syscall_stubs,
            rewards_pool_bytes, spl_token_account_bytes_for_mint,
        };
        use solana_program::account_info::AccountInfo;

        install_syscall_stubs();

        let token_program_id = spl_token::id();
        let system_id        = solana_program::system_program::id();
        let request_key      = Pubkey::new_unique();
        let vault_key        = Pubkey::new_unique();
        let (config_pda, _)  =
            Pubkey::find_program_address(&[b"referral_config"], program_id);
        let (pool_pda, _)    =
            Pubkey::find_program_address(&[b"rewards_pool"], program_id);

        let amount = 100_000_000u64;

        let mut req_lamports   = 1_000_000u64;
        let mut req_data       = claim_request_bytes(referrer, amount, 0);
        let mut pool_lamports  = 1_000_000u64;
        let mut pool_data      = rewards_pool_bytes(1_000_000_000, 0);
        let mut cfg_lamports   = 1_000_000u64;
        let mut cfg_data       = config_bytes(authority, &vault_key);
        let mut vault_lamports = 1_000_000u64;
        let mut vault_data     = vault_bytes;
        let mut ata_lamports   = 1_000_000u64;
        let mut ata_data       = spl_token_account_bytes_for_mint(mint, 0);
        let mut sig_lamports   = 1_000_000u64;
        let mut sig_data: Vec<u8> = Vec::new();
        let mut tp_lamports    = 1_000_000u64;
        let mut tp_data: Vec<u8> = Vec::new();

        let accounts = [
            AccountInfo::new(
                &request_key, false, true,
                &mut req_lamports, &mut req_data, program_id, false, 0,
            ),
            AccountInfo::new(
                &pool_pda, false, true,
                &mut pool_lamports, &mut pool_data, program_id, false, 0,
            ),
            AccountInfo::new(
                &config_pda, false, false,
                &mut cfg_lamports, &mut cfg_data, program_id, false, 0,
            ),
            AccountInfo::new(
                &vault_key, false, true,
                &mut vault_lamports, &mut vault_data, &token_program_id, false, 0,
            ),
            AccountInfo::new(
                referrer_ata, false, true,
                &mut ata_lamports, &mut ata_data, &token_program_id, false, 0,
            ),
            AccountInfo::new(
                authority, true, false,
                &mut sig_lamports, &mut sig_data, &system_id, false, 0,
            ),
            AccountInfo::new(
                &token_program_id, false, false,
                &mut tp_lamports, &mut tp_data, &system_id, true, 0,
            ),
        ];

        super::process(program_id, &accounts)
    }

    /// The derivation is only as strong as the program id it derives under, so
    /// pin the constant to its published address rather than trusting that a
    /// 32-byte literal was transcribed correctly.
    #[test]
    fn test_associated_token_program_id_is_the_published_one() {
        assert_eq!(
            super::ASSOCIATED_TOKEN_PROGRAM_ID.to_string(),
            "ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL",
        );
    }

    /// Task 4: a claim whose `referrer` is X, paid to an ATA belonging to Y,
    /// must be rejected.
    ///
    /// Note what is *genuine* here: the signature, the config, the vault, the
    /// claim. This is not the C-2 drain — it is the misdirection that made C-2
    /// pay out. `referrer_ata_info` went into the SPL transfer verbatim, so a
    /// signer could route any pending claim to an account of their choosing
    /// while the claim record still named X.
    #[test]
    fn test_approve_rejects_ata_of_a_different_referrer() {
        let program_id = Pubkey::new_unique();
        let authority  = Pubkey::new_unique();
        let mint       = Pubkey::new_unique();
        let referrer_x = Pubkey::new_unique();
        let referrer_y = Pubkey::new_unique();

        // Y's canonical ATA: a perfectly real, correctly derived token account
        // for the same mint — it simply is not X's. Derived by upstream (I-2),
        // so "correctly derived" is a claim about the ATA standard rather than
        // about this file's own arithmetic.
        let y_ata =
            spl_associated_token_account::get_associated_token_address(&referrer_y, &mint);

        let err = approve_paying_to(&program_id, &authority, &referrer_x, &mint, &y_ata)
            .expect_err("a claim naming X must never pay out to Y's ATA");

        assert_eq!(
            err,
            ProgramError::Custom(ReferralError::InvalidReferrerAta as u32),
            "the destination binding must be what rejects this, not some \
             earlier check — every other account in the fixture is genuine",
        );
    }

    /// The mirror, and the reason the check derives rather than rejecting
    /// broadly: X's own canonical ATA — the exact address the foundation sends
    /// (`freeflow-sidecar .../referral/authority.rs:157` calls
    /// `derive_ata(referrer, flow_mint, token_program)`) — still goes through.
    ///
    /// Without this, `return Err(..)` would satisfy the test above.
    ///
    /// I-2: the expected address comes from `spl_associated_token_account`, the
    /// crate that *defines* the convention, and deliberately not from re-running
    /// the handler's own `find_program_address` expression. A mirrored expected
    /// value proves only that the file agrees with itself: transpose the seeds
    /// in `process` and in the tests together and a mirrored suite still goes
    /// green, while the deployed program would reject every address the
    /// foundation sends — a total payout outage on a live program. Upstream
    /// does not move when this file moves, so it is an oracle, not an echo.
    #[test]
    fn test_approve_accepts_the_referrers_canonical_ata() {
        let program_id = Pubkey::new_unique();
        let authority  = Pubkey::new_unique();
        let mint       = Pubkey::new_unique();
        let referrer_x = Pubkey::new_unique();

        let x_ata =
            spl_associated_token_account::get_associated_token_address(&referrer_x, &mint);

        approve_paying_to(&program_id, &authority, &referrer_x, &mint, &x_ata)
            .expect(
                "the referrer's own canonical ATA must still be paid — if this \
                 fails, the seed order or the program id in `process` has \
                 drifted from the ATA standard",
            );
    }

    /// I-2, the other half: name the wrong seed order outright, so no edit to
    /// this file can quietly agree with it.
    ///
    /// `[token_program, referrer, mint]` is the transposition a careless edit
    /// produces; upstream's `get_associated_token_address_and_bump_seed_internal`
    /// uses `[wallet, token_program, mint]`. Swapping `process` over to the
    /// transposition and swapping the tests with it left the old suite at 63
    /// passing. This test has no mirror to swap.
    #[test]
    fn test_approve_rejects_a_transposed_ata_seed_order() {
        let program_id = Pubkey::new_unique();
        let authority  = Pubkey::new_unique();
        let mint       = Pubkey::new_unique();
        let referrer   = Pubkey::new_unique();

        let (transposed, _) = Pubkey::find_program_address(
            &[spl_token::id().as_ref(), referrer.as_ref(), mint.as_ref()],
            &super::ASSOCIATED_TOKEN_PROGRAM_ID,
        );
        assert_ne!(
            transposed,
            spl_associated_token_account::get_associated_token_address(&referrer, &mint),
            "the transposition has to change the address, or this test asserts \
             nothing",
        );

        let err = approve_paying_to(&program_id, &authority, &referrer, &mint, &transposed)
            .expect_err("a transposed seed order does not name the canonical ATA");

        assert_eq!(
            err,
            ProgramError::Custom(ReferralError::InvalidReferrerAta as u32),
        );
    }

    // ── I-3: `vault` must be a token account, not merely Tokenkeg-owned ──────

    /// An SPL **Mint** is owned by the token program exactly as a token account
    /// is, so the owner check that opens step 3 waves one straight through.
    /// What turns it away is the length pin — a mint is 82 bytes, a token
    /// account 165 — and that pin has to hold, because the handler goes on to
    /// read the vault balance (`[64..72]`) and, since C-2, the mint it derives
    /// the referrer's ATA from (`[0..32]`) out of these very bytes.
    ///
    /// Note where those offsets land inside an 82-byte mint: `[0..32]` is in
    /// `mint_authority` and `[64..72]` in `freeze_authority`. Both are in
    /// bounds, so nothing panics — without the pin the handler would simply
    /// read a balance and a mint out of a mint's authority fields and carry on.
    /// That is what makes the pin a real check rather than a formality, and it
    /// is why the second case below exists: give the mint a freeze authority
    /// whose bytes happen to read as a huge balance and the solvency check
    /// passes too, leaving an ATA derived from garbage as the only thing
    /// standing between a mint and a signed transfer.
    #[test]
    fn test_approve_rejects_a_mint_shaped_vault() {
        use crate::test_support::spl_mint_account_bytes;

        let program_id = Pubkey::new_unique();
        let authority  = Pubkey::new_unique();
        let mint       = Pubkey::new_unique();
        let referrer   = Pubkey::new_unique();

        // Genuine in every other respect, so the length pin is what is on trial.
        let ata =
            spl_associated_token_account::get_associated_token_address(&referrer, &mint);

        for (label, freeze_authority) in [
            ("a plain mint", None),
            (
                "a mint whose freeze authority reads as a huge balance",
                Some(Pubkey::new_from_array([0xFF; 32])),
            ),
        ] {
            let vault = spl_mint_account_bytes(1_000_000_000, 9, freeze_authority);
            assert_eq!(vault.len(), 82, "an SPL mint is 82 bytes");

            let err =
                approve_with_vault(&program_id, &authority, &referrer, &mint, &ata, vault)
                    .expect_err("an 82-byte mint must never serve as the pool vault");

            assert_eq!(
                err,
                ProgramError::InvalidAccountData,
                "the length pin must be what rejects {label}, not some later \
                 check reached on misread bytes",
            );
        }
    }
}
