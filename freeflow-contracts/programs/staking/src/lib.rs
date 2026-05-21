//! FreeFlow Staking Program (Solana on-chain).
//!
//! v3: $FLOW SPL token staking. 100 $FLOW (= 100_000_000_000 token base units)
//! is transferred from the relay's token account into an escrow token account
//! derived as a PDA of this program. repFlow tier determines FEATURES.
//!
//! Instructions:
//!   0x00  Stake   — lock 100 $FLOW in escrow PDA token account
//!   0x01  Unstake — return $FLOW after relay deregisters
//!   0x02  Slash   — governance-invoked penalty (burns or sends to treasury)
//!
//! Accounts for Stake:
//!   [0] relay_wallet      signer, writable  — pays rent and signs transfer
//!   [1] stake_account     writable          — PDA("stake", relay_wallet)
//!   [2] relay_flow_ata    writable          — relay's $FLOW token account (source)
//!   [3] escrow_flow_ata   writable          — PDA("escrow", relay_wallet) token acct
//!   [4] flow_mint         readonly          — $FLOW mint
//!   [5] token_program     readonly
//!   [6] system_program    readonly
//!
//! Accounts for Unstake:
//!   [0] relay_wallet      signer, writable
//!   [1] stake_account     writable          — PDA("stake", relay_wallet)
//!   [2] relay_flow_ata    writable          — destination for returned $FLOW
//!   [3] escrow_flow_ata   writable          — PDA("escrow", relay_wallet) token acct
//!   [4] flow_mint         readonly
//!   [5] token_program     readonly
//!   [6] system_program    readonly

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
use spl_token::instruction as token_ix;
use thiserror::Error;

/// FreeFlow governance multisig address (Foundation authority wallet).
const GOVERNANCE_PUBKEY: solana_program::pubkey::Pubkey =
    solana_program::pubkey!("8SL4dhnXU9tjvsbwfkVzQbfV99wGnVZBECoiuwrdbaJk");

pub const NETWORK_AUTHORITY_PUBKEY: &str =
    "0000000000000000000000000000000000000000000000000000000000000000";

solana_program::declare_id!("7N1JRX3LY3goVAZCyaJyH7kpZ3kboZvh3jteDmCq6Dz4");

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

#[derive(BorshSerialize, BorshDeserialize, Debug)]
pub enum StakingInstruction {
    /// Lock $FLOW in escrow token account.
    Stake { lamports: u64, tier: u8 },
    /// Withdraw $FLOW after deregistration.
    Unstake,
    /// Governance-invoked slash.
    Slash { slash_lamports: u64, reason: u8 },
}

#[derive(BorshSerialize, BorshDeserialize, Debug, Clone)]
pub struct StakeAccount {
    pub relay_wallet:              [u8; 32],
    /// Amount of $FLOW locked (in token base units, 9 decimals).
    pub staked_lamports:           u64,
    pub tier:                      u8,
    /// Status: 0 = Locked, 1 = Unlocked, 2 = Slashed, 3 = Ejected.
    pub status:                    u8,
    pub slashed_lamports:          u64,
    pub locked_at:                 i64,
    pub bump:                      u8,
    pub repflow_balance_snapshot:  u64,
}

impl StakeAccount {
    pub const SIZE: usize = 32 + 8 + 1 + 1 + 8 + 8 + 1 + 8;
    /// 100 $FLOW in token base units (9 decimals).
    pub const MIN_STAKE_LAMPORTS: u64 = 100_000_000_000;

    pub fn can_run_exit_node(repflow_balance: u64) -> bool {
        repflow_balance >= 1_001
    }

    pub fn can_submit_governance(repflow_balance: u64) -> bool {
        repflow_balance >= 5_001
    }
}

#[derive(Debug, Error)]
pub enum StakingError {
    #[error("already staked")]
    AlreadyStaked,
}

// ── Instruction processors ────────────────────────────────────────────────────

fn process_stake(
    program_id: &Pubkey,
    accounts:   &[AccountInfo],
    lamports:   u64,
    _tier:      u8,
) -> ProgramResult {
    let accounts_iter    = &mut accounts.iter();
    let relay_wallet     = next_account_info(accounts_iter)?;
    let stake_account    = next_account_info(accounts_iter)?;
    let relay_flow_ata   = next_account_info(accounts_iter)?;
    let escrow_flow_ata  = next_account_info(accounts_iter)?;
    let flow_mint        = next_account_info(accounts_iter)?;
    let token_program    = next_account_info(accounts_iter)?;
    let system_program   = next_account_info(accounts_iter)?;

    if !relay_wallet.is_signer {
        return Err(ProgramError::MissingRequiredSignature);
    }

    if lamports < StakeAccount::MIN_STAKE_LAMPORTS {
        msg!(
            "Insufficient stake: need {} token base units ({} $FLOW minimum)",
            StakeAccount::MIN_STAKE_LAMPORTS,
            StakeAccount::MIN_STAKE_LAMPORTS / 1_000_000_000
        );
        return Err(ProgramError::InsufficientFunds);
    }

    // Derive and validate stake PDA: seeds = [b"stake", relay_wallet]
    let (stake_pda, stake_bump) = Pubkey::find_program_address(
        &[b"stake", relay_wallet.key.as_ref()],
        program_id,
    );
    if stake_pda != *stake_account.key {
        msg!("Invalid stake account PDA");
        return Err(ProgramError::InvalidAccountData);
    }

    // Derive and validate escrow token account PDA: seeds = [b"escrow", relay_wallet]
    let (escrow_pda, escrow_bump) = Pubkey::find_program_address(
        &[b"escrow", relay_wallet.key.as_ref()],
        program_id,
    );
    if escrow_pda != *escrow_flow_ata.key {
        msg!("Invalid escrow PDA");
        return Err(ProgramError::InvalidAccountData);
    }

    let rent = Rent::get()?;
    let clock = solana_program::clock::Clock::get()?;

    // ── 1. Create stake state account (PDA) if new ────────────────────────────
    if stake_account.lamports() == 0 {
        let rent_min = rent.minimum_balance(StakeAccount::SIZE);
        invoke_signed(
            &system_instruction::create_account(
                relay_wallet.key,
                stake_account.key,
                rent_min,
                StakeAccount::SIZE as u64,
                program_id,
            ),
            &[relay_wallet.clone(), stake_account.clone(), system_program.clone()],
            &[&[b"stake", relay_wallet.key.as_ref(), &[stake_bump]]],
        )?;
    } else {
        // Validate ownership for top-up.
        if stake_account.owner != program_id {
            return Err(ProgramError::InvalidAccountOwner);
        }
        // Reject top-up on already-locked stake.
        let existing_data = stake_account.try_borrow_data()?;
        let existing = StakeAccount::try_from_slice(&existing_data)
            .map_err(|_| ProgramError::InvalidAccountData)?;
        if existing.status == 0 {
            msg!("Already staked and locked — unstake first to re-stake");
            return Err(ProgramError::Custom(1)); // AlreadyStaked
        }
    }

    // ── 2. Create escrow token account (PDA) if new ───────────────────────────
    if escrow_flow_ata.lamports() == 0 {
        let token_acct_rent = rent.minimum_balance(spl_token::state::Account::LEN);
        invoke_signed(
            &system_instruction::create_account(
                relay_wallet.key,
                escrow_flow_ata.key,
                token_acct_rent,
                spl_token::state::Account::LEN as u64,
                token_program.key,
            ),
            &[relay_wallet.clone(), escrow_flow_ata.clone(), system_program.clone()],
            &[&[b"escrow", relay_wallet.key.as_ref(), &[escrow_bump]]],
        )?;

        // Initialize the escrow token account: owner = stake_pda so only the
        // program (signing as stake_pda) can transfer tokens out on unstake.
        invoke(
            &token_ix::initialize_account3(
                token_program.key,
                escrow_flow_ata.key,
                flow_mint.key,
                &stake_pda,
            )?,
            &[escrow_flow_ata.clone(), flow_mint.clone()],
        )?;
    }

    // ── 3. Transfer $FLOW from relay_flow_ata → escrow ───────────────────────
    invoke(
        &token_ix::transfer(
            token_program.key,
            relay_flow_ata.key,
            escrow_flow_ata.key,
            relay_wallet.key,
            &[],
            lamports,
        )?,
        &[
            relay_flow_ata.clone(),
            escrow_flow_ata.clone(),
            relay_wallet.clone(),
            token_program.clone(),
        ],
    )?;

    // ── 4. Write stake state ──────────────────────────────────────────────────
    let state = StakeAccount {
        relay_wallet:             relay_wallet.key.to_bytes(),
        staked_lamports:          lamports,
        tier:                     1,
        status:                   0, // Locked
        slashed_lamports:         0,
        locked_at:                clock.unix_timestamp,
        bump:                     stake_bump,
        repflow_balance_snapshot: 0,
    };
    let mut data = stake_account.try_borrow_mut_data()?;
    state.serialize(&mut &mut data[..])?;

    msg!(
        "Stake locked: {} $FLOW token base units ({} $FLOW) in escrow {}",
        lamports,
        lamports / 1_000_000_000,
        escrow_pda
    );
    Ok(())
}

fn process_unstake(program_id: &Pubkey, accounts: &[AccountInfo]) -> ProgramResult {
    let accounts_iter   = &mut accounts.iter();
    let relay_wallet    = next_account_info(accounts_iter)?;
    let stake_account   = next_account_info(accounts_iter)?;
    let relay_flow_ata  = next_account_info(accounts_iter)?;
    let escrow_flow_ata = next_account_info(accounts_iter)?;
    let _flow_mint      = next_account_info(accounts_iter)?;
    let token_program   = next_account_info(accounts_iter)?;

    if !relay_wallet.is_signer {
        return Err(ProgramError::MissingRequiredSignature);
    }

    if stake_account.owner != program_id {
        return Err(ProgramError::InvalidAccountOwner);
    }

    let data  = stake_account.try_borrow_data()?;
    let state = StakeAccount::try_from_slice(&data)
        .map_err(|_| ProgramError::InvalidAccountData)?;
    drop(data);

    if state.relay_wallet != relay_wallet.key.to_bytes() {
        return Err(ProgramError::IllegalOwner);
    }

    if state.status == 0 {
        msg!("Cannot unstake while relay is active (status=Locked)");
        return Err(ProgramError::InvalidAccountData);
    }

    // Derive stake PDA bump (needed to sign as stake_pda authority).
    let (stake_pda, stake_bump) = Pubkey::find_program_address(
        &[b"stake", relay_wallet.key.as_ref()],
        program_id,
    );
    if stake_pda != *stake_account.key {
        return Err(ProgramError::InvalidAccountData);
    }

    let returnable = state.staked_lamports.saturating_sub(state.slashed_lamports);

    if returnable > 0 {
        // Transfer $FLOW from escrow back to relay_flow_ata.
        // Authority = stake_pda (the escrow token account's SPL owner).
        invoke_signed(
            &token_ix::transfer(
                token_program.key,
                escrow_flow_ata.key,
                relay_flow_ata.key,
                &stake_pda,
                &[],
                returnable,
            )?,
            &[
                escrow_flow_ata.clone(),
                relay_flow_ata.clone(),
                stake_account.clone(), // stake_pda acts as SPL authority
                token_program.clone(),
            ],
            &[&[b"stake", relay_wallet.key.as_ref(), &[stake_bump]]],
        )?;
    }

    msg!("Unstaked: {} $FLOW token base units returned", returnable);
    Ok(())
}

fn process_slash(
    program_id:     &Pubkey,
    accounts:       &[AccountInfo],
    slash_lamports: u64,
    reason:         u8,
) -> ProgramResult {
    let accounts_iter   = &mut accounts.iter();
    let governance      = next_account_info(accounts_iter)?;
    let stake_account   = next_account_info(accounts_iter)?;
    let escrow_flow_ata = next_account_info(accounts_iter)?;
    let treasury_ata    = next_account_info(accounts_iter)?;
    let token_program   = next_account_info(accounts_iter)?;

    if !governance.is_signer {
        return Err(ProgramError::MissingRequiredSignature);
    }

    if cfg!(not(feature = "devnet-permissive")) {
        if *governance.key != GOVERNANCE_PUBKEY {
            msg!("Unauthorized: signer is not governance");
            return Err(ProgramError::IllegalOwner);
        }
    }

    if stake_account.owner != program_id {
        return Err(ProgramError::InvalidAccountOwner);
    }

    let mut data  = stake_account.try_borrow_mut_data()?;
    let mut state = StakeAccount::try_from_slice(&data)
        .map_err(|_| ProgramError::InvalidAccountData)?;

    // Derive which relay this stake belongs to (for signing as stake_pda).
    let relay_wallet_key = Pubkey::from(state.relay_wallet);
    let (stake_pda, stake_bump) = Pubkey::find_program_address(
        &[b"stake", relay_wallet_key.as_ref()],
        program_id,
    );
    if stake_pda != *stake_account.key {
        return Err(ProgramError::InvalidAccountData);
    }

    let remaining    = state.staked_lamports.saturating_sub(state.slashed_lamports);
    let actual_slash = slash_lamports.min(remaining);
    state.slashed_lamports = state.slashed_lamports
        .checked_add(actual_slash)
        .ok_or(ProgramError::ArithmeticOverflow)?;

    if reason == 3 || state.slashed_lamports >= state.staked_lamports {
        state.status = 3; // Ejected
    } else {
        state.status = 2; // Slashed
    }

    state.serialize(&mut &mut data[..])?;
    drop(data);

    // Transfer slashed $FLOW from escrow → treasury.
    if actual_slash > 0 {
        invoke_signed(
            &token_ix::transfer(
                token_program.key,
                escrow_flow_ata.key,
                treasury_ata.key,
                &stake_pda,
                &[],
                actual_slash,
            )?,
            &[
                escrow_flow_ata.clone(),
                treasury_ata.clone(),
                stake_account.clone(),
                token_program.clone(),
            ],
            &[&[b"stake", relay_wallet_key.as_ref(), &[stake_bump]]],
        )?;
    }

    msg!("Slashed: {} $FLOW token base units (reason {})", actual_slash, reason);
    Ok(())
}
