//! FreeFlow Staking Program (Solana on-chain).
//!
//! v2: Fixed minimum stake for ALL operators. repFlow tier determines FEATURES,
//! not stake amount. The old Mobile/Lightweight/Professional stake tiers are
//! replaced by a single 100 $FLOW minimum.
//!
//! Instructions:
//!   0x00  Stake       — lock $FLOW in escrow
//!   0x01  Unstake     — return stake after relay deregisters
//!   0x02  Slash       — governance-invoked penalty

use borsh::{BorshDeserialize, BorshSerialize};
use solana_program::{
    account_info::{next_account_info, AccountInfo},
    entrypoint,
    entrypoint::ProgramResult,
    msg,
    program::{invoke, invoke_signed},
    program_error::ProgramError,
    pubkey::Pubkey,
    rent::Rent,
    system_instruction,
    sysvar::Sysvar,
};
use thiserror::Error;

/// FreeFlow governance multisig address (Squads or SPL Governance).
/// Replace before mainnet deployment.
const GOVERNANCE_PUBKEY: &str = "GoVxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx";

/// FreeFlow network authority ed25519 public key (hex, for pool delta signing).
pub const NETWORK_AUTHORITY_PUBKEY: &str =
    "0000000000000000000000000000000000000000000000000000000000000000";

// ── Program ID ────────────────────────────────────────────────────────────────
solana_program::declare_id!("STAKxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx");

// ── Entrypoint ───────────────────────────────────────────────────────────────
entrypoint!(process_instruction);

pub fn process_instruction(
    program_id: &Pubkey,
    accounts:   &[AccountInfo],
    input:      &[u8],
) -> ProgramResult {
    let instruction = StakingInstruction::try_from_slice(input)
        .map_err(|_| ProgramError::InvalidInstructionData)?;

    match instruction {
        StakingInstruction::Stake { lamports, tier } => {
            process_stake(program_id, accounts, lamports, tier)
        }
        StakingInstruction::Unstake => {
            process_unstake(program_id, accounts)
        }
        StakingInstruction::Slash { slash_lamports, reason } => {
            process_slash(program_id, accounts, slash_lamports, reason)
        }
    }
}

// ── Instructions ─────────────────────────────────────────────────────────────

#[derive(BorshSerialize, BorshDeserialize, Debug)]
pub enum StakingInstruction {
    /// Lock $FLOW in escrow.
    /// Accounts: [relay_wallet (signer), stake_account (PDA), token_mint, token_program, system_program]
    Stake { lamports: u64, tier: u8 },

    /// Withdraw stake after deregistration.
    /// Accounts: [relay_wallet (signer), stake_account (PDA), system_program]
    Unstake,

    /// Governance-invoked slash.
    /// Accounts: [governance (signer), stake_account (PDA), treasury]
    Slash { slash_lamports: u64, reason: u8 },
}

// ── On-chain stake account state ─────────────────────────────────────────────

#[derive(BorshSerialize, BorshDeserialize, Debug, Clone)]
pub struct StakeAccount {
    /// Relay operator's public key.
    pub relay_wallet:              [u8; 32],
    /// Amount locked in lamports.
    pub staked_lamports:           u64,
    /// DEPRECATED — was Mobile/Lightweight/Professional. Kept for backwards compat.
    /// Going forward, repFlow tier determines features, not stake amount.
    pub tier:                      u8,
    /// Status: 0 = Locked, 1 = Unlocked, 2 = Slashed, 3 = Ejected.
    pub status:                    u8,
    /// Total slashed to date.
    pub slashed_lamports:          u64,
    /// Unix timestamp stake was locked.
    pub locked_at:                 i64,
    /// PDA bump seed.
    pub bump:                      u8,
    /// repFlow balance at stake time (oracle-attested).
    pub repflow_balance_snapshot:  u64,
}

impl StakeAccount {
    pub const SIZE: usize = 32 + 8 + 1 + 1 + 8 + 8 + 1 + 8;

    /// Fixed minimum stake for ALL relay operators (v2).
    /// repFlow tier determines features — not stake amount.
    pub const MIN_STAKE_LAMPORTS: u64 = 100_000_000_000; // 100 $FLOW

    /// Check if a repFlow balance allows running an exit node (Active tier+).
    pub fn can_run_exit_node(repflow_balance: u64) -> bool {
        repflow_balance >= 1_001
    }

    /// Check if a repFlow balance allows submitting governance proposals (Trusted+).
    pub fn can_submit_governance(repflow_balance: u64) -> bool {
        repflow_balance >= 5_001
    }
}

// ── Instruction processors ────────────────────────────────────────────────────

fn process_stake(
    program_id: &Pubkey,
    accounts:   &[AccountInfo],
    lamports:   u64,
    tier:       u8,
) -> ProgramResult {
    let accounts_iter = &mut accounts.iter();
    let relay_wallet  = next_account_info(accounts_iter)?;
    let stake_account = next_account_info(accounts_iter)?;
    let system_prog   = next_account_info(accounts_iter)?;

    // Caller must sign.
    if !relay_wallet.is_signer {
        return Err(ProgramError::MissingRequiredSignature);
    }

    // Fixed minimum stake (100 $FLOW) — same for all operators.
    // repFlow tier determines features, not stake amount.
    if lamports < StakeAccount::MIN_STAKE_LAMPORTS {
        msg!(
            "Insufficient stake: need {} lamports ({} $FLOW minimum for all operators)",
            StakeAccount::MIN_STAKE_LAMPORTS,
            StakeAccount::MIN_STAKE_LAMPORTS / 1_000_000_000
        );
        return Err(ProgramError::InsufficientFunds);
    }

    // Note: repFlow balance is not checked here — it's an oracle-attested field
    // passed in the instruction for informational purposes only.
    // Feature gates (exit node, governance) are enforced by the respective programs.

    // Derive stake account PDA: seeds = [b"stake", relay_wallet]
    let (pda, bump) = Pubkey::find_program_address(
        &[b"stake", relay_wallet.key.as_ref()],
        program_id,
    );

    if pda != *stake_account.key {
        return Err(ProgramError::InvalidAccountData);
    }

    // Create the stake account (if it doesn't exist).
    let rent     = Rent::get()?;
    let rent_min = rent.minimum_balance(StakeAccount::SIZE);

    if stake_account.lamports() == 0 {
        invoke_signed(
            &system_instruction::create_account(
                relay_wallet.key,
                stake_account.key,
                rent_min + lamports,
                StakeAccount::SIZE as u64,
                program_id,
            ),
            &[relay_wallet.clone(), stake_account.clone(), system_prog.clone()],
            &[&[b"stake", relay_wallet.key.as_ref(), &[bump]]],
        )?;
    } else {
        // Existing account — top up the lamport balance.
        invoke(
            &system_instruction::transfer(relay_wallet.key, stake_account.key, lamports),
            &[relay_wallet.clone(), stake_account.clone(), system_prog.clone()],
        )?;
    }

    // Write stake state.
    let clock = solana_program::clock::Clock::get()?;
    let state = StakeAccount {
        relay_wallet:             relay_wallet.key.to_bytes(),
        staked_lamports:          lamports,
        tier:                     1, // DEPRECATED — default Lightweight for compat
        status:                   0, // Locked
        slashed_lamports:         0,
        locked_at:                clock.unix_timestamp,
        bump,
        repflow_balance_snapshot: 0, // Updated by oracle after stake confirmed
    };
    let mut data = stake_account.try_borrow_mut_data()?;
    state.serialize(&mut &mut data[..])?;

    msg!("Stake locked: {} lamports ({} $FLOW) — repFlow tier determines features", lamports, lamports / 1_000_000_000);
    Ok(())
}

fn process_unstake(program_id: &Pubkey, accounts: &[AccountInfo]) -> ProgramResult {
    let accounts_iter = &mut accounts.iter();
    let relay_wallet  = next_account_info(accounts_iter)?;
    let stake_account = next_account_info(accounts_iter)?;

    if !relay_wallet.is_signer {
        return Err(ProgramError::MissingRequiredSignature);
    }

    let data  = stake_account.try_borrow_data()?;
    let state = StakeAccount::try_from_slice(&data)
        .map_err(|_| ProgramError::InvalidAccountData)?;
    drop(data);

    // Must be the stake owner.
    if state.relay_wallet != relay_wallet.key.to_bytes() {
        return Err(ProgramError::IllegalOwner);
    }

    // Status must be Unlocked (1) or Slashed (2) — not Locked (0).
    if state.status == 0 {
        msg!("Cannot unstake while relay is active");
        return Err(ProgramError::InvalidAccountData);
    }

    let returnable = state.staked_lamports.saturating_sub(state.slashed_lamports);

    // Transfer returnable lamports back to relay_wallet.
    **stake_account.try_borrow_mut_lamports()? -= returnable;
    **relay_wallet.try_borrow_mut_lamports()?  += returnable;

    msg!("Unstaked: {} lamports returned", returnable);
    Ok(())
}

fn process_slash(
    program_id:     &Pubkey,
    accounts:       &[AccountInfo],
    slash_lamports: u64,
    reason:         u8,
) -> ProgramResult {
    let accounts_iter = &mut accounts.iter();
    let governance    = next_account_info(accounts_iter)?;
    let stake_account = next_account_info(accounts_iter)?;
    let treasury      = next_account_info(accounts_iter)?;

    if !governance.is_signer {
        return Err(ProgramError::MissingRequiredSignature);
    }

    // Verify `governance` is the authorised FreeFlow governance multisig.
    // The governance key is stored in a dedicated PDA seeded by b"governance".
    // For now we check against the hard-coded devnet governance key.
    // Production: load from the governance config account passed as accounts[3].
    if cfg!(not(feature = "devnet-permissive")) {
        let governance_key = GOVERNANCE_PUBKEY;
        if governance.key.to_string() != governance_key {
            msg!("Unauthorized: signer {} is not governance {}", governance.key, governance_key);
            return Err(ProgramError::IllegalOwner);
        }
    }

    let mut data  = stake_account.try_borrow_mut_data()?;
    let mut state = StakeAccount::try_from_slice(&data)
        .map_err(|_| ProgramError::InvalidAccountData)?;

    let actual_slash = slash_lamports.min(state.staked_lamports - state.slashed_lamports);
    state.slashed_lamports += actual_slash;

    // Update status.
    if reason == 3 || state.slashed_lamports >= state.staked_lamports {
        state.status = 3; // Ejected
    } else {
        state.status = 2; // Slashed
    }

    state.serialize(&mut &mut data[..])?;
    drop(data);

    // Move slashed lamports to treasury.
    **stake_account.try_borrow_mut_lamports()? -= actual_slash;
    **treasury.try_borrow_mut_lamports()?      += actual_slash;

    msg!("Slashed: {} lamports (reason {})", actual_slash, reason);
    Ok(())
}
