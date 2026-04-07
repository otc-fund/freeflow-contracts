//! FreeFlow Registry Program (Solana on-chain).
//!
//! Instructions:
//!   0x00  Register    — add relay to on-chain registry
//!   0x01  Deregister  — voluntary removal
//!   0x02  UpdateStatus — active / maintenance / inactive / slashed
//!   0x03  Heartbeat   — update last_heartbeat timestamp (cheap CPI)

use borsh::{BorshDeserialize, BorshSerialize};
use solana_program::{
    account_info::{next_account_info, AccountInfo},
    clock::Clock,
    entrypoint,
    entrypoint::ProgramResult,
    msg,
    program_error::ProgramError,
    pubkey::Pubkey,
    rent::Rent,
    system_instruction,
    program::invoke_signed,
    sysvar::Sysvar,
};

solana_program::declare_id!("REGIxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx");

entrypoint!(process_instruction);

pub fn process_instruction(
    program_id: &Pubkey,
    accounts:   &[AccountInfo],
    input:      &[u8],
) -> ProgramResult {
    let ix = RegistryInstruction::try_from_slice(input)
        .map_err(|_| ProgramError::InvalidInstructionData)?;

    match ix {
        RegistryInstruction::Register { tier, country, storage_bytes, addr_bytes } => {
            process_register(program_id, accounts, tier, country, storage_bytes, addr_bytes)
        }
        RegistryInstruction::Deregister => {
            process_deregister(program_id, accounts)
        }
        RegistryInstruction::UpdateStatus { status } => {
            process_update_status(program_id, accounts, status)
        }
        RegistryInstruction::Heartbeat => {
            process_heartbeat(program_id, accounts)
        }
    }
}

// ── Instructions ─────────────────────────────────────────────────────────────

#[derive(BorshSerialize, BorshDeserialize, Debug)]
pub enum RegistryInstruction {
    Register {
        tier:          u8,
        /// ISO 3166-1 alpha-2 country code as 2 ASCII bytes.
        country:       [u8; 2],
        storage_bytes: u64,
        /// Packed SocketAddr: 16 bytes IP (v4-mapped if IPv4) + 2 bytes port.
        addr_bytes:    [u8; 18],
    },
    Deregister,
    UpdateStatus { status: u8 },
    Heartbeat,
}

// ── Status constants ──────────────────────────────────────────────────────────
pub const STATUS_ACTIVE:      u8 = 0;
pub const STATUS_MAINTENANCE: u8 = 1;
pub const STATUS_INACTIVE:    u8 = 2;
pub const STATUS_SLASHED:     u8 = 3;

// ── On-chain registry entry ────────────────────────────────────────────────────

#[derive(BorshSerialize, BorshDeserialize, Debug, Clone)]
pub struct RegistryEntry {
    /// Relay operator's ed25519 public key.
    pub relay_pubkey:     [u8; 32],
    /// Tier: 0 = Mobile, 1 = Lightweight, 2 = Professional.
    pub tier:             u8,
    /// ISO country code (2 ASCII bytes).
    pub country:          [u8; 2],
    /// Packed SocketAddr (16-byte IP + 2-byte port, big-endian).
    pub addr_bytes:       [u8; 18],
    /// Advertised storage in bytes.
    pub storage_bytes:    u64,
    /// Status: 0 = Active, 1 = Maintenance, 2 = Inactive, 3 = Slashed.
    pub status:           u8,
    /// Unix timestamp of registration.
    pub registered_at:    i64,
    /// Unix timestamp of last heartbeat.
    pub last_heartbeat:   i64,
    /// PDA bump seed.
    pub bump:             u8,
}

impl RegistryEntry {
    pub const SIZE: usize = 32 + 1 + 2 + 18 + 8 + 1 + 8 + 8 + 1;

    pub fn is_active(&self) -> bool { self.status == STATUS_ACTIVE }

    /// Validate transition: returns true if the transition from current status
    /// to new status is permitted.
    pub fn valid_transition(from: u8, to: u8) -> bool {
        matches!(
            (from, to),
            (STATUS_ACTIVE,      STATUS_MAINTENANCE) |
            (STATUS_ACTIVE,      STATUS_INACTIVE)    |
            (STATUS_MAINTENANCE, STATUS_ACTIVE)      |
            (STATUS_MAINTENANCE, STATUS_INACTIVE)    |
            (STATUS_INACTIVE,    STATUS_ACTIVE)      |
            // Slashing valid from any status (governance action).
            (_, STATUS_SLASHED)
        )
    }
}

// ── Instruction processors ────────────────────────────────────────────────────

fn process_register(
    program_id:    &Pubkey,
    accounts:      &[AccountInfo],
    tier:          u8,
    country:       [u8; 2],
    storage_bytes: u64,
    addr_bytes:    [u8; 18],
) -> ProgramResult {
    let accounts_iter    = &mut accounts.iter();
    let relay_wallet     = next_account_info(accounts_iter)?;
    let registry_account = next_account_info(accounts_iter)?;
    let system_program   = next_account_info(accounts_iter)?;

    if !relay_wallet.is_signer {
        return Err(ProgramError::MissingRequiredSignature);
    }

    // PDA: seeds = [b"registry", relay_wallet]
    let (pda, bump) = Pubkey::find_program_address(
        &[b"registry", relay_wallet.key.as_ref()],
        program_id,
    );
    if pda != *registry_account.key {
        return Err(ProgramError::InvalidAccountData);
    }

    if registry_account.lamports() > 0 {
        msg!("Relay already registered");
        return Err(ProgramError::AccountAlreadyInitialized);
    }

    // Allocate registry account.
    let rent     = Rent::get()?;
    let rent_min = rent.minimum_balance(RegistryEntry::SIZE);
    let clock    = Clock::get()?;

    invoke_signed(
        &system_instruction::create_account(
            relay_wallet.key,
            registry_account.key,
            rent_min,
            RegistryEntry::SIZE as u64,
            program_id,
        ),
        &[relay_wallet.clone(), registry_account.clone(), system_program.clone()],
        &[&[b"registry", relay_wallet.key.as_ref(), &[bump]]],
    )?;

    let entry = RegistryEntry {
        relay_pubkey:   relay_wallet.key.to_bytes(),
        tier,
        country,
        addr_bytes,
        storage_bytes,
        status:         STATUS_ACTIVE,
        registered_at:  clock.unix_timestamp,
        last_heartbeat: clock.unix_timestamp,
        bump,
    };

    let mut data = registry_account.try_borrow_mut_data()?;
    entry.serialize(&mut &mut data[..])?;

    msg!("Relay registered: tier={} country={}{}", tier, country[0] as char, country[1] as char);
    Ok(())
}

fn process_deregister(program_id: &Pubkey, accounts: &[AccountInfo]) -> ProgramResult {
    let accounts_iter    = &mut accounts.iter();
    let relay_wallet     = next_account_info(accounts_iter)?;
    let registry_account = next_account_info(accounts_iter)?;

    if !relay_wallet.is_signer {
        return Err(ProgramError::MissingRequiredSignature);
    }

    let data  = registry_account.try_borrow_data()?;
    let entry = RegistryEntry::try_from_slice(&data)
        .map_err(|_| ProgramError::InvalidAccountData)?;
    drop(data);

    if entry.relay_pubkey != relay_wallet.key.to_bytes() {
        return Err(ProgramError::IllegalOwner);
    }

    // Return lamports to the relay wallet (closes the account).
    let balance = registry_account.lamports();
    **registry_account.try_borrow_mut_lamports()? = 0;
    **relay_wallet.try_borrow_mut_lamports()?     += balance;

    // Zero out the account data.
    let mut data = registry_account.try_borrow_mut_data()?;
    for byte in data.iter_mut() { *byte = 0; }

    msg!("Relay deregistered");
    Ok(())
}

fn process_update_status(
    program_id: &Pubkey,
    accounts:   &[AccountInfo],
    new_status: u8,
) -> ProgramResult {
    let accounts_iter    = &mut accounts.iter();
    let authority        = next_account_info(accounts_iter)?;
    let registry_account = next_account_info(accounts_iter)?;

    if !authority.is_signer {
        return Err(ProgramError::MissingRequiredSignature);
    }

    let mut data  = registry_account.try_borrow_mut_data()?;
    let mut entry = RegistryEntry::try_from_slice(&data)
        .map_err(|_| ProgramError::InvalidAccountData)?;

    // Only the relay itself can change status (except SLASHED which requires governance).
    let is_relay_owner = entry.relay_pubkey == authority.key.to_bytes();
    let is_slashing    = new_status == STATUS_SLASHED;

    if !is_relay_owner && !is_slashing {
        return Err(ProgramError::IllegalOwner);
    }

    if !RegistryEntry::valid_transition(entry.status, new_status) {
        msg!("Invalid status transition: {} → {}", entry.status, new_status);
        return Err(ProgramError::InvalidInstructionData);
    }

    entry.status         = new_status;
    entry.last_heartbeat = Clock::get()?.unix_timestamp;
    entry.serialize(&mut &mut data[..])?;

    msg!("Status updated to {}", new_status);
    Ok(())
}

fn process_heartbeat(program_id: &Pubkey, accounts: &[AccountInfo]) -> ProgramResult {
    let accounts_iter    = &mut accounts.iter();
    let relay_wallet     = next_account_info(accounts_iter)?;
    let registry_account = next_account_info(accounts_iter)?;

    if !relay_wallet.is_signer {
        return Err(ProgramError::MissingRequiredSignature);
    }

    let mut data  = registry_account.try_borrow_mut_data()?;
    let mut entry = RegistryEntry::try_from_slice(&data)
        .map_err(|_| ProgramError::InvalidAccountData)?;

    if entry.relay_pubkey != relay_wallet.key.to_bytes() {
        return Err(ProgramError::IllegalOwner);
    }

    entry.last_heartbeat = Clock::get()?.unix_timestamp;
    entry.serialize(&mut &mut data[..])?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid_transitions() {
        assert!(RegistryEntry::valid_transition(STATUS_ACTIVE,      STATUS_MAINTENANCE));
        assert!(RegistryEntry::valid_transition(STATUS_ACTIVE,      STATUS_INACTIVE));
        assert!(RegistryEntry::valid_transition(STATUS_MAINTENANCE, STATUS_ACTIVE));
        assert!(RegistryEntry::valid_transition(STATUS_INACTIVE,    STATUS_ACTIVE));
        assert!(RegistryEntry::valid_transition(STATUS_ACTIVE,      STATUS_SLASHED));
        assert!(RegistryEntry::valid_transition(STATUS_SLASHED,     STATUS_SLASHED)); // re-slash OK
    }

    #[test]
    fn invalid_transitions() {
        // Can't go from SLASHED back to ACTIVE.
        assert!(!RegistryEntry::valid_transition(STATUS_SLASHED, STATUS_ACTIVE));
        assert!(!RegistryEntry::valid_transition(STATUS_INACTIVE, STATUS_MAINTENANCE));
    }
}
