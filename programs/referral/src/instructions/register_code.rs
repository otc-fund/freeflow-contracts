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
    instruction::{AccountMeta, Instruction},
    program::{invoke, invoke_signed},
    program_error::ProgramError,
    pubkey::Pubkey,
    rent::Rent,
    system_instruction,
    sysvar::Sysvar,
};

use crate::{
    errors::ReferralError,
    state::ReferralCode,
    utils::{sha256_hash, FLOW_MINT},
};

/// Associated Token Account program (`ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL`).
///
/// The same program `approve_claim` derives its payout destination under. The
/// two have to agree: this instruction creates the very account that one pays
/// into, so a divergence here is a payout outage there, not a local bug.
const ASSOCIATED_TOKEN_PROGRAM_ID: Pubkey =
    solana_program::pubkey!("ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL");

/// `CreateIdempotent` — discriminant 1 of `AssociatedTokenAccountInstruction`.
///
/// Deliberately not `Create` (0), which *errors* when the account already
/// exists. A referrer registering a second code, or one who already holds
/// $FLOW, has to find this a no-op rather than a failed transaction.
const ATA_CREATE_IDEMPOTENT: u8 = 1;

/// Instruction data (after discriminant).
#[derive(BorshSerialize, BorshDeserialize)]
pub struct RegisterReferralCodeArgs {
    pub code: Vec<u8>, // raw UTF-8 bytes; uppercased before hashing
}

/// Accounts expected (in order):
/// 0. `[writable]` code          — PDA `[b"referral_code", code_hash]` (will be created)
/// 1. `[writable, signer]` referrer — becomes the owner of this code, and funds
///    both the code PDA and their own $FLOW ATA (the latter ~0.00204 SOL of rent)
/// 2. `[]`         config        — `ReferralConfig` PDA (not read here, included for future validation)
/// 3. `[]`         system_program
/// 4. `[writable]` referrer_ata  — the referrer's canonical $FLOW ATA, created
///    idempotently below. Derived, not trusted.
/// 5. `[]`         flow_mint     — must be the canonical `$FLOW` mint
/// 6. `[]`         token_program — SPL Token program
/// 7. `[]`         associated_token_program
pub fn process(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    args: RegisterReferralCodeArgs,
) -> ProgramResult {
    let iter = &mut accounts.iter();
    let code_info         = next_account_info(iter)?;
    let referrer_info     = next_account_info(iter)?;
    let _config_info      = next_account_info(iter)?;
    let system_program    = next_account_info(iter)?;
    let referrer_ata_info = next_account_info(iter)?;
    let flow_mint_info    = next_account_info(iter)?;
    let token_program     = next_account_info(iter)?;
    let ata_program       = next_account_info(iter)?;

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

    // ── Guarantee the payout account exists ─────────────────────────────────
    // Registering a code is the prerequisite for ever earning a fee, so it is
    // the moment to make the referrer's $FLOW ATA an invariant. Nothing else in
    // this system creates one — the foundation's `derive_ata` only *computes*
    // an address — and `approve_claim` transfers into exactly this account, so
    // without this a first-time referrer's every approval fails on a
    // destination that was never opened.
    //
    // The referrer funds it, as they already fund the code PDA above.
    //
    // Each of the three ids below is pinned rather than trusted: together with
    // the referrer they *are* the ATA derivation, so any one of them left to
    // the caller would open an account at an address `approve_claim` does not
    // compute — rent spent for an ATA that can never be paid.
    if flow_mint_info.key != &FLOW_MINT {
        return Err(ReferralError::InvalidFlowMint.into());
    }
    if token_program.key != &spl_token::id()
        || ata_program.key != &ASSOCIATED_TOKEN_PROGRAM_ID
    {
        return Err(ProgramError::IncorrectProgramId);
    }

    // Seeds and program id mirror `approve_claim` exactly. $FLOW is a classic
    // SPL mint, so the ATA lives under `spl_token::id()` — the only id that
    // instruction's `spl_token::instruction::transfer` accepts, and the reason
    // it too derives under a hardcoded id rather than a caller-supplied one.
    let (referrer_ata, _ata_bump) = Pubkey::find_program_address(
        &[
            referrer_info.key.as_ref(),
            spl_token::id().as_ref(),
            FLOW_MINT.as_ref(),
        ],
        &ASSOCIATED_TOKEN_PROGRAM_ID,
    );
    if referrer_ata_info.key != &referrer_ata {
        return Err(ReferralError::InvalidReferrerAta.into());
    }

    invoke(
        &Instruction {
            program_id: ASSOCIATED_TOKEN_PROGRAM_ID,
            accounts:   vec![
                AccountMeta::new(*referrer_info.key, true),           // funding
                AccountMeta::new(referrer_ata, false),                // account created
                AccountMeta::new_readonly(*referrer_info.key, false), // wallet
                AccountMeta::new_readonly(FLOW_MINT, false),
                AccountMeta::new_readonly(solana_program::system_program::id(), false),
                AccountMeta::new_readonly(spl_token::id(), false),
            ],
            data:       vec![ATA_CREATE_IDEMPOTENT],
        },
        &[
            referrer_info.clone(),
            referrer_ata_info.clone(),
            flow_mint_info.clone(),
            system_program.clone(),
            token_program.clone(),
            ata_program.clone(),
        ],
    )?;

    Ok(())
}

// ─── Unit Tests ───────────────────────────────────────────────────────────────
#[cfg(test)]
mod tests {
    use solana_program::{
        account_info::AccountInfo, entrypoint::ProgramResult,
        program_error::ProgramError, pubkey::Pubkey,
    };

    use crate::{
        errors::ReferralError,
        state::ReferralCode,
        test_support::{
            claim_request_bytes, config_bytes, install_syscall_stubs, recorded_cpis_to,
            reset_cpi_log, rewards_pool_bytes, spl_mint_account_bytes,
            spl_token_account_bytes_for_mint,
        },
        utils::sha256_hash,
    };

    /// The canonical $FLOW mint, spelled out here rather than read back from
    /// `super::FLOW_MINT`.
    ///
    /// A test that echoes the constant it is checking proves only that the file
    /// agrees with itself: repoint the constant at another mint and a mirrored
    /// test follows it happily, while on chain every referrer would be handed
    /// an ATA that `approve_claim` — which derives from the *vault's* mint —
    /// can never pay into.
    ///
    /// Now that `FLOW_MINT` is one shared constant (`utils.rs`) rather than a
    /// private copy per file, this literal carries **more** weight, not less.
    /// Sharing removes the risk that the two derivations disagree with each
    /// other; it does nothing about them being wrong together, and this is the
    /// only place in the program where the value is checked against something
    /// outside itself.
    const CANONICAL_FLOW_MINT: &str = "7w6YxBZmXMZfuS4PJCwDmY5hX98RrpnR7xNEV9Ugwzxc";

    fn flow_mint() -> Pubkey {
        CANONICAL_FLOW_MINT.parse().expect("canonical mint must parse")
    }

    /// Run `RegisterReferralCode` over a fixture that is well-formed in every
    /// respect, varying only what a caller controls. Whatever it returns is a
    /// statement about those arguments and nothing else; the CPIs the handler
    /// issued are left in the thread-local log for the caller to inspect.
    fn register(
        program_id:    &Pubkey,
        referrer:      &Pubkey,
        mint_account:  &Pubkey,
        referrer_ata:  &Pubkey,
        token_program: &Pubkey,
        ata_program:   &Pubkey,
    ) -> ProgramResult {
        install_syscall_stubs();
        reset_cpi_log();

        let code: Vec<u8> = b"FREEFLOW".to_vec();
        let uppercased: Vec<u8> = code.iter().map(|b| b.to_ascii_uppercase()).collect();
        let code_hash = sha256_hash(&uppercased);

        let (code_pda, _) =
            Pubkey::find_program_address(&[b"referral_code", &code_hash], program_id);
        let (config_pda, _) =
            Pubkey::find_program_address(&[b"referral_config"], program_id);
        let system_id = solana_program::system_program::id();

        // The code PDA arrives pre-allocated at its full size. On chain the
        // `create_account` CPI in the handler does that; here CPIs have no
        // runtime, so an empty buffer would leave the closing `serialize`
        // writing 80 bytes into 0 and failing for a reason that has nothing to
        // do with what is under test. `is_claimed` stays false, so the
        // already-claimed guard does not fire either.
        let mut code_lamports  = 1_000_000u64;
        let mut code_data      = vec![0u8; ReferralCode::SIZE];
        let mut ref_lamports   = 1_000_000_000u64;
        let mut ref_data: Vec<u8> = Vec::new();
        let mut cfg_lamports   = 1_000_000u64;
        let mut cfg_data       = config_bytes(referrer, &Pubkey::default());
        let mut sys_lamports   = 1u64;
        let mut sys_data: Vec<u8> = Vec::new();
        let mut ata_lamports   = 0u64;
        let mut ata_data: Vec<u8> = Vec::new();
        let mut mint_lamports  = 1_000_000u64;
        let mut mint_data      = spl_mint_account_bytes(0, 9, None);
        let mut tp_lamports    = 1u64;
        let mut tp_data: Vec<u8> = Vec::new();
        let mut atap_lamports  = 1u64;
        let mut atap_data: Vec<u8> = Vec::new();

        let spl_token_id = spl_token::id();

        let accounts = [
            AccountInfo::new(
                &code_pda, false, true,
                &mut code_lamports, &mut code_data, program_id, false, 0,
            ),
            AccountInfo::new(
                referrer, true, true,
                &mut ref_lamports, &mut ref_data, &system_id, false, 0,
            ),
            AccountInfo::new(
                &config_pda, false, false,
                &mut cfg_lamports, &mut cfg_data, program_id, false, 0,
            ),
            AccountInfo::new(
                &system_id, false, false,
                &mut sys_lamports, &mut sys_data, &system_id, true, 0,
            ),
            AccountInfo::new(
                referrer_ata, false, true,
                &mut ata_lamports, &mut ata_data, &system_id, false, 0,
            ),
            AccountInfo::new(
                mint_account, false, false,
                &mut mint_lamports, &mut mint_data, &spl_token_id, false, 0,
            ),
            AccountInfo::new(
                token_program, false, false,
                &mut tp_lamports, &mut tp_data, &system_id, true, 0,
            ),
            AccountInfo::new(
                ata_program, false, false,
                &mut atap_lamports, &mut atap_data, &system_id, true, 0,
            ),
        ];

        super::process(
            program_id,
            &accounts,
            super::RegisterReferralCodeArgs { code },
        )
    }

    /// Registering a code must leave the referrer with a canonical $FLOW ATA.
    ///
    /// Nothing else in this system creates one — not the referral program, not
    /// the foundation crate, whose `derive_ata` only *computes* an address — so
    /// a first-time referrer reaches `approve_claim` with no token account and
    /// the SPL transfer into it fails. Registration is where that stops being
    /// possible.
    #[test]
    fn test_register_code_creates_the_referrers_flow_ata() {
        let program_id = Pubkey::new_unique();
        let referrer   = Pubkey::new_unique();
        let mint       = flow_mint();
        let ata =
            spl_associated_token_account::get_associated_token_address(&referrer, &mint);

        register(
            &program_id,
            &referrer,
            &mint,
            &ata,
            &spl_token::id(),
            &spl_associated_token_account::id(),
        )
        .expect("a well-formed registration must succeed");

        let ata_cpis = recorded_cpis_to(&spl_associated_token_account::id());
        assert_eq!(
            ata_cpis.len(),
            1,
            "registering a code must ask the ATA program to create the \
             referrer's $FLOW account exactly once",
        );

        // Byte for byte against the crate that *defines* the convention —
        // program id, all six account metas with their signer/writable flags,
        // and the data — rather than against a second copy of this file's own
        // arithmetic. `spl-associated-token-account` does not move when this
        // file moves, so it is an oracle rather than an echo.
        let expected = spl_associated_token_account::instruction::
            create_associated_token_account_idempotent(
                &referrer,        // funding: the referrer, who already funds the code PDA
                &referrer,        // wallet:  the account the ATA belongs to
                &mint,
                &spl_token::id(),
            );
        assert_eq!(
            ata_cpis[0].instruction, expected,
            "the CPI must be exactly upstream's CreateIdempotent instruction",
        );

        assert_eq!(
            ata_cpis[0].instruction.data,
            vec![1u8],
            "1 is CreateIdempotent; 0 is Create, which *errors* when the account \
             already exists — re-registering, or a referrer who already holds \
             $FLOW, has to be a no-op and not a failure",
        );
        assert_eq!(
            ata_cpis[0].instruction.accounts[1].pubkey, ata,
            "the account being created must be the referrer's canonical ATA",
        );
        assert!(
            ata_cpis[0].signers_seeds.is_empty(),
            "the referrer signs the transaction themselves; no PDA seeds apply",
        );
    }

    /// Drive `ApproveClaim` end to end with a genuine config, a funded vault
    /// whose mint is `mint`, an open review window and a Pending claim naming
    /// `referrer` — so the payout destination is the only thing on trial.
    fn approve_claim_paying_to(
        program_id:   &Pubkey,
        referrer:     &Pubkey,
        mint:         &Pubkey,
        referrer_ata: &Pubkey,
    ) -> ProgramResult {
        install_syscall_stubs();

        let authority        = Pubkey::new_unique();
        let token_program_id = spl_token::id();
        let system_id        = solana_program::system_program::id();
        let request_key      = Pubkey::new_unique();
        let vault_key        = Pubkey::new_unique();
        let (config_pda, _)  =
            Pubkey::find_program_address(&[b"referral_config"], program_id);
        let (pool_pda, _)    =
            Pubkey::find_program_address(&[b"rewards_pool"], program_id);

        let mut req_lamports   = 1_000_000u64;
        let mut req_data       = claim_request_bytes(referrer, 100_000_000, 0);
        let mut pool_lamports  = 1_000_000u64;
        let mut pool_data      = rewards_pool_bytes(1_000_000_000, 0);
        let mut cfg_lamports   = 1_000_000u64;
        let mut cfg_data       = config_bytes(&authority, &vault_key);
        let mut vault_lamports = 1_000_000u64;
        let mut vault_data     = spl_token_account_bytes_for_mint(mint, 1_000_000_000);
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
                &authority, true, false,
                &mut sig_lamports, &mut sig_data, &system_id, false, 0,
            ),
            AccountInfo::new(
                &token_program_id, false, false,
                &mut tp_lamports, &mut tp_data, &system_id, true, 0,
            ),
        ];

        crate::instructions::approve_claim::process(program_id, &accounts)
    }

    /// The account this instruction opens must be the account `approve_claim`
    /// pays into. Two files, two hardcoded derivations: if they disagree, every
    /// referrer is handed an ATA the approval path rejects — a payout outage on
    /// a live program, and one that no test of either file alone would catch.
    ///
    /// So rather than restate `approve_claim`'s arithmetic here — a mirror that
    /// a careless edit keeps in step while both halves drift from the standard
    /// together — this feeds the address the register handler actually asked
    /// the ATA program to create straight into `approve_claim::process`.
    #[test]
    fn test_the_created_ata_is_the_one_approve_claim_pays_into() {
        let program_id = Pubkey::new_unique();
        let referrer   = Pubkey::new_unique();
        let mint       = flow_mint();
        let ata =
            spl_associated_token_account::get_associated_token_address(&referrer, &mint);

        register(
            &program_id,
            &referrer,
            &mint,
            &ata,
            &spl_token::id(),
            &spl_associated_token_account::id(),
        )
        .expect("a well-formed registration must succeed");

        let created = recorded_cpis_to(&spl_associated_token_account::id())[0]
            .instruction
            .accounts[1]
            .pubkey;

        approve_claim_paying_to(&program_id, &referrer, &mint, &created).expect(
            "`approve_claim` must pay into the account registration creates — if \
             this fails, the two derivations have drifted apart and no referrer \
             can ever be paid",
        );
    }

    /// Only the canonical $FLOW mint may be registered.
    ///
    /// Left to the caller, a referrer could open an ATA for a mint they control
    /// — rent spent on an account `approve_claim`, which derives from the
    /// *vault's* mint, would never pay into.
    #[test]
    fn test_register_code_pins_the_flow_mint() {
        let program_id = Pubkey::new_unique();
        let referrer   = Pubkey::new_unique();
        let impostor   = Pubkey::new_unique();

        // Correctly derived *for that mint*, so the mint pin is the only thing
        // that can reject this.
        let ata = spl_associated_token_account::get_associated_token_address(
            &referrer, &impostor,
        );

        let err = register(
            &program_id,
            &referrer,
            &impostor,
            &ata,
            &spl_token::id(),
            &spl_associated_token_account::id(),
        )
        .expect_err("a mint that is not $FLOW must be refused");

        assert_eq!(
            err,
            ProgramError::Custom(ReferralError::InvalidFlowMint as u32),
            "the mint pin must be what rejects this, not the ATA address check",
        );
        assert!(
            recorded_cpis_to(&spl_associated_token_account::id()).is_empty(),
            "no rent may be spent opening an account for a mint that is not $FLOW",
        );
    }

    /// The ATA is derived, not trusted: a real, correctly derived ATA for the
    /// same mint that simply belongs to someone else must not be opened at the
    /// referrer's expense.
    #[test]
    fn test_register_code_rejects_someone_elses_ata() {
        let program_id = Pubkey::new_unique();
        let referrer   = Pubkey::new_unique();
        let stranger   = Pubkey::new_unique();
        let mint       = flow_mint();

        let someone_elses =
            spl_associated_token_account::get_associated_token_address(&stranger, &mint);

        let err = register(
            &program_id,
            &referrer,
            &mint,
            &someone_elses,
            &spl_token::id(),
            &spl_associated_token_account::id(),
        )
        .expect_err("only the referrer's own canonical ATA may be registered");

        assert_eq!(
            err,
            ProgramError::Custom(ReferralError::InvalidReferrerAta as u32),
        );
    }

    /// Token-2022 derives a *different* ATA for the same wallet and mint, and
    /// `approve_claim` transfers under `spl_token::id()`. A registration under
    /// any other token program therefore opens an account that can never be
    /// paid, so the token program is pinned rather than taken from the caller.
    #[test]
    fn test_register_code_rejects_a_foreign_token_program() {
        let program_id = Pubkey::new_unique();
        let referrer   = Pubkey::new_unique();
        let mint       = flow_mint();
        let ata =
            spl_associated_token_account::get_associated_token_address(&referrer, &mint);
        let token_2022: Pubkey = "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb"
            .parse()
            .expect("Token-2022's published id must parse");

        assert_ne!(
            spl_associated_token_account::get_associated_token_address_with_program_id(
                &referrer, &mint, &token_2022,
            ),
            ata,
            "the two token programs must derive different addresses, or this \
             test asserts nothing",
        );

        let err = register(
            &program_id,
            &referrer,
            &mint,
            &ata,
            &token_2022,
            &spl_associated_token_account::id(),
        )
        .expect_err("$FLOW is a classic SPL mint; only spl_token may be named");

        assert_eq!(err, ProgramError::IncorrectProgramId);
    }

    /// The CPI target is pinned too: an attacker-supplied "ATA program" would
    /// receive a `CreateIdempotent` call carrying the referrer's signature.
    #[test]
    fn test_register_code_rejects_a_foreign_ata_program() {
        let program_id = Pubkey::new_unique();
        let referrer   = Pubkey::new_unique();
        let mint       = flow_mint();
        let ata =
            spl_associated_token_account::get_associated_token_address(&referrer, &mint);

        let err = register(
            &program_id,
            &referrer,
            &mint,
            &ata,
            &spl_token::id(),
            &Pubkey::new_unique(),
        )
        .expect_err("the CPI may only ever go to the real ATA program");

        assert_eq!(err, ProgramError::IncorrectProgramId);
        assert!(
            recorded_cpis_to(&spl_associated_token_account::id()).is_empty(),
        );
    }

    /// A derivation is only as good as the ids it derives under, so pin both
    /// constants to their published addresses rather than trusting that a
    /// 32-byte literal was transcribed correctly.
    ///
    /// The two ids get there differently, on purpose. `ASSOCIATED_TOKEN_PROGRAM_ID`
    /// is still a private copy in each file, kept equal by both being checked
    /// against `spl_associated_token_account::id()` — the crate that defines
    /// the convention. `FLOW_MINT` has no such upstream to check against, so a
    /// per-file copy could only ever be kept in step by hand; it is one shared
    /// constant in `utils.rs` instead, and `super::FLOW_MINT` here resolves
    /// through this file's import of it.
    ///
    /// Which leaves this assertion as the whole of the external evidence for
    /// its value, and is why `CANONICAL_FLOW_MINT` above is written out rather
    /// than read from `super::FLOW_MINT`.
    #[test]
    fn test_pinned_ids_are_the_published_ones() {
        assert_eq!(
            super::ASSOCIATED_TOKEN_PROGRAM_ID.to_string(),
            "ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL",
        );
        assert_eq!(
            super::ASSOCIATED_TOKEN_PROGRAM_ID,
            spl_associated_token_account::id(),
            "and it must be the id the crate that defines the convention uses",
        );
        assert_eq!(super::FLOW_MINT.to_string(), CANONICAL_FLOW_MINT);
    }

    /// `InvalidFlowMint` is 24. Pinned so an inserted variant cannot silently
    /// renumber it onto `InvalidReferrerAta` (23) and make the mint test above
    /// satisfiable by the wrong branch.
    #[test]
    fn test_invalid_flow_mint_error_code_is_stable() {
        assert_eq!(
            ProgramError::from(ReferralError::InvalidFlowMint),
            ProgramError::Custom(24),
        );
        assert_eq!(
            ProgramError::from(ReferralError::InvalidReferrerAta),
            ProgramError::Custom(23),
        );
    }
}
