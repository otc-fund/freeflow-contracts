//! Test-only scaffolding for the handler-level security tests (C-2).
//!
//! These handlers are raw `solana-program` code, not Anchor, so a handler test
//! is just `process(&program_id, &accounts)` over hand-built `AccountInfo`s.
//! Two things stand between that and a realistic run:
//!
//!   * `Clock::get()` and `Rent::get()` return `UnsupportedSysvar` off-chain,
//!     so the stubs below supply a fixed clock and default rent;
//!   * CPIs have no runtime — but `sol_invoke_signed` already defaults to
//!     `Ok(())` in `solana_program::program_stubs`, which is exactly what these
//!     tests want. The token transfer is not what is under test; whether the
//!     handler *reached* it on a forged config is.
//!
//! With those in place a handler runs end to end in-process, so a forged-config
//! test can assert on the real return value rather than on a proxy.

#![cfg(test)]

use std::{cell::RefCell, sync::Once};

use solana_program::{
    account_info::AccountInfo,
    clock::Clock,
    entrypoint::{ProgramResult, SUCCESS},
    instruction::Instruction,
    program_error::ProgramError,
    program_stubs::{set_syscall_stubs, SyscallStubs},
    pubkey::Pubkey,
    rent::Rent,
};

use crate::{
    errors::ReferralError,
    state::{ClaimRequest, ReferralCode, ReferralConfig, ReferrerBalance, RewardsPool},
};

/// Fixed wall clock every handler test sees.
pub const TEST_NOW: i64 = 1_700_000_000;

struct TestSyscallStubs;

impl SyscallStubs for TestSyscallStubs {
    /// Silence handler logging so a failing assertion is readable.
    fn sol_log(&self, _message: &str) {}

    /// Record the CPI and return success, which is what the default stub does
    /// minus the recording.
    ///
    /// There is still no CPI runtime here, so the callee never executes and no
    /// account is really created or debited. What the recording *does* buy is
    /// the request: which program the handler asked for, with which accounts,
    /// flags and data. For a handler whose job is to issue a well-formed CPI —
    /// `register_code` and its ATA creation — that request is the behaviour
    /// under test, and asserting on it is the difference between testing the
    /// call and testing nothing.
    fn sol_invoke_signed(
        &self,
        instruction: &Instruction,
        _account_infos: &[AccountInfo],
        signers_seeds: &[&[&[u8]]],
    ) -> ProgramResult {
        CPI_LOG.with(|log| {
            log.borrow_mut().push(RecordedCpi {
                instruction: instruction.clone(),
                signers_seeds: signers_seeds
                    .iter()
                    .map(|seeds| seeds.iter().map(|seed| seed.to_vec()).collect())
                    .collect(),
            });
        });
        Ok(())
    }

    fn sol_get_clock_sysvar(&self, var_addr: *mut u8) -> u64 {
        let clock = Clock {
            slot: 1,
            epoch_start_timestamp: TEST_NOW,
            epoch: 1,
            leader_schedule_epoch: 1,
            unix_timestamp: TEST_NOW,
        };
        // The `impl_sysvar_get!` macro hands us a `&mut Clock` cast to `*mut u8`.
        unsafe { *(var_addr as *mut Clock) = clock };
        SUCCESS
    }

    fn sol_get_rent_sysvar(&self, var_addr: *mut u8) -> u64 {
        unsafe { *(var_addr as *mut Rent) = Rent::default() };
        SUCCESS
    }
}

static STUBS: Once = Once::new();

/// Install the syscall stubs. Idempotent: `cargo test` runs these tests in
/// parallel threads of a single process and the stub table is global.
pub fn install_syscall_stubs() {
    STUBS.call_once(|| {
        set_syscall_stubs(Box::new(TestSyscallStubs));
    });
}

/// One CPI a handler asked the runtime to make.
#[derive(Clone, Debug)]
pub struct RecordedCpi {
    pub instruction:   Instruction,
    pub signers_seeds: Vec<Vec<Vec<u8>>>,
}

thread_local! {
    /// CPIs seen on *this* thread. `cargo test` gives each test its own thread
    /// and the stub table is global, so per-thread is what keeps a parallel run
    /// from mixing one handler's CPIs into another's assertions.
    static CPI_LOG: RefCell<Vec<RecordedCpi>> = RefCell::new(Vec::new());
}

/// Drop anything recorded so far. Call immediately before the handler under
/// test, so the log describes that call and nothing else.
pub fn reset_cpi_log() {
    CPI_LOG.with(|log| log.borrow_mut().clear());
}

/// Every CPI issued on this thread since the last `reset_cpi_log`, in order.
pub fn recorded_cpis() -> Vec<RecordedCpi> {
    CPI_LOG.with(|log| log.borrow().clone())
}

/// The CPIs from `recorded_cpis` that targeted `program_id`.
pub fn recorded_cpis_to(program_id: &Pubkey) -> Vec<RecordedCpi> {
    recorded_cpis()
        .into_iter()
        .filter(|cpi| &cpi.instruction.program_id == program_id)
        .collect()
}

/// The error every handler must return when handed a config it did not verify.
pub fn forged_config_rejection() -> ProgramError {
    ReferralError::InvalidReferralConfigOwner.into()
}

/// The bytes an attacker writes into an 86-byte account their own program owns.
///
/// `authority` lands at offset 18..50 (after `u16 + u64 + u64`) — the field all
/// six handlers read and trust. `rewards_pool_vault` is attacker-chosen too,
/// which is how a forged config also walks straight through the H-1 vault check
/// in `record_referral`.
pub fn forged_config_bytes(authority: &Pubkey, rewards_pool_vault: &Pubkey) -> Vec<u8> {
    let bytes = borsh::to_vec(&ReferralConfig {
        reward_bps:            250,
        max_reward_lamports:   u64::MAX,
        min_purchase_lamports: 0,
        authority:             authority.to_bytes(),
        rewards_pool_vault:    rewards_pool_vault.to_bytes(),
        bump:                  255,
        _padding:              [0; 3],
    })
    .unwrap();
    assert_eq!(bytes.len(), ReferralConfig::SIZE, "forged config must be 86 bytes");
    assert_eq!(
        &bytes[18..50],
        authority.as_ref(),
        "authority must sit at offset 18..50 — that is the field being forged",
    );
    bytes
}

/// A well-formed `ClaimRequest`. `status` 0 = Pending; the deadline is an hour
/// past `TEST_NOW` so the M-1 review window is open.
pub fn claim_request_bytes(referrer: &Pubkey, amount: u64, status: u8) -> Vec<u8> {
    let bytes = borsh::to_vec(&ClaimRequest {
        referrer:        referrer.to_bytes(),
        amount,
        requested_at:    TEST_NOW - 60,
        review_deadline: TEST_NOW + 3_600,
        status,
        executed_at:     0,
        bump:            255,
        _padding:        [0; 2],
    })
    .unwrap();
    assert_eq!(bytes.len(), ClaimRequest::SIZE);
    bytes
}

/// A well-formed `ReferrerBalance`.
pub fn referrer_balance_bytes(
    referrer: &Pubkey,
    total_earned: u64,
    total_claimed: u64,
    next_sequence: u32,
) -> Vec<u8> {
    let bytes = borsh::to_vec(&ReferrerBalance {
        referrer: referrer.to_bytes(),
        total_earned,
        total_claimed,
        referral_count: 0,
        next_sequence,
        bump: 255,
        _padding: [0; 7],
    })
    .unwrap();
    assert_eq!(bytes.len(), ReferrerBalance::SIZE);
    bytes
}

/// A well-formed, claimed `ReferralCode`.
pub fn referral_code_bytes(referrer: &Pubkey, code_hash: [u8; 32]) -> Vec<u8> {
    let bytes = borsh::to_vec(&ReferralCode {
        code_hash,
        referrer: referrer.to_bytes(),
        created_at: TEST_NOW - 86_400,
        is_claimed: true,
        bump: 255,
        _padding: [0; 6],
    })
    .unwrap();
    assert_eq!(bytes.len(), ReferralCode::SIZE);
    bytes
}

/// A well-formed `RewardsPool`.
pub fn rewards_pool_bytes(total_deposited: u64, total_distributed: u64) -> Vec<u8> {
    let bytes = borsh::to_vec(&RewardsPool {
        vault_bump: 254,
        total_deposited,
        total_distributed,
        bump: 255,
        _padding: [0; 6],
    })
    .unwrap();
    assert_eq!(bytes.len(), RewardsPool::SIZE);
    bytes
}

/// The same 86 bytes as `forged_config_bytes`, for the case where the account
/// they land in IS the genuine config: program-owned, at the canonical PDA.
///
/// Only the account's provenance ever differs, never the bytes — which is
/// exactly why the provenance checks in `load_verified_config` have to exist.
pub fn config_bytes(authority: &Pubkey, rewards_pool_vault: &Pubkey) -> Vec<u8> {
    forged_config_bytes(authority, rewards_pool_vault)
}

/// A 165-byte SPL token account for `mint` holding `amount`.
///
/// Two fields matter to `approve_claim`: the mint at 0..32, which it derives
/// the referrer's canonical ATA from, and the amount at 64..72, which it reads
/// the vault balance from.
pub fn spl_token_account_bytes_for_mint(mint: &Pubkey, amount: u64) -> Vec<u8> {
    let mut data = vec![0u8; 165];
    data[0..32].copy_from_slice(mint.as_ref());
    data[64..72].copy_from_slice(&amount.to_le_bytes());
    data
}

/// As above with an all-zero mint, for the tests that never read it.
pub fn spl_token_account_bytes(amount: u64) -> Vec<u8> {
    spl_token_account_bytes_for_mint(&Pubkey::default(), amount)
}

/// A genuine 82-byte SPL **Mint**, packed by `spl_token` itself.
///
/// Tokenkeg owns a mint exactly as it owns a token account, so an owner check
/// cannot tell the two apart — only the length can, which is what the pin in
/// `approve_claim` step 3 is for. Packing through `Mint::pack_into_slice`
/// rather than hand-rolling the bytes keeps the fixture honest: this is what a
/// real mint on chain looks like, field for field.
///
/// `freeze_authority` is a parameter because the handler reads its vault
/// balance from `[64..72]`, and in an 82-byte mint that range falls inside the
/// freeze authority. A caller that wants "a mint that would sail past the
/// solvency check if the length pin were gone" passes `Some([0xFF; 32])`.
pub fn spl_mint_account_bytes(
    supply: u64,
    decimals: u8,
    freeze_authority: Option<Pubkey>,
) -> Vec<u8> {
    use solana_program::{program_option::COption, program_pack::Pack};

    let mut data = vec![0u8; spl_token::state::Mint::LEN];
    spl_token::state::Mint {
        mint_authority: COption::None,
        supply,
        decimals,
        is_initialized: true,
        freeze_authority: freeze_authority.map_or(COption::None, COption::Some),
    }
    .pack_into_slice(&mut data);
    assert_eq!(data.len(), 82, "an SPL mint is 82 bytes, not 165");
    data
}
