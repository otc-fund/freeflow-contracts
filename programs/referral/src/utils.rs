//! Shared utility functions for the referral program.

use borsh::BorshDeserialize;
use solana_program::{
    account_info::AccountInfo,
    program_error::ProgramError,
    pubkey::Pubkey,
};

use crate::errors::ReferralError;
use crate::state::ReferralConfig;

/// Calculate the referral reward for a given purchase amount.
///
/// `reward_bps` is basis points (100 = 1%).
/// Returns `min(purchase_amount * reward_bps / 10_000, max_reward)`.
///
/// Uses u128 arithmetic to prevent overflow before the final clamp.
pub fn calculate_reward(
    purchase_amount: u64,
    reward_bps: u16,
    max_reward: u64,
) -> Result<u64, ProgramError> {
    let reward = (purchase_amount as u128)
        .checked_mul(reward_bps as u128)
        .ok_or(ReferralError::Overflow)?
        .checked_div(10_000)
        .ok_or(ReferralError::Overflow)? as u64;
    Ok(reward.min(max_reward))
}

/// Compute SHA-256 of the given bytes.
pub fn sha256_hash(data: &[u8]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().into()
}

/// Load the singleton `ReferralConfig`, proving the account is authentic first.
///
/// Rejects any account that is not program-owned AND the canonical
/// `[b"referral_config"]` PDA, closing the forged-config authority bypass (C-2).
///
/// Both checks are load-bearing for different reasons. The owner check stops a
/// foreign account: an attacker cannot write arbitrary bytes into an account this
/// program owns. The PDA check stops type confusion between this program's OWN
/// account types — today no sibling type is exactly `ReferralConfig::SIZE` (86)
/// bytes and borsh rejects trailing bytes, so confusion is blocked by an accident
/// of sizing rather than by design. Keep the PDA check so a future 86-byte type
/// cannot silently reopen it.
///
/// The two checks return **different** error codes on purpose (M-2). They once
/// shared `InvalidReferralConfigOwner`, which made every caller's test a weak
/// oracle: the six handler tests pin a foreign-owned account *at the canonical
/// PDA*, so asserting the shared code proved only "rejected" — never "the owner
/// branch rejected it". Change the seed here and all six would have stayed green
/// while silently exercising the address branch instead. Distinct codes make each
/// branch independently observable: delete one and only its own test goes red.
pub fn load_verified_config(
    config_info: &AccountInfo,
    program_id: &Pubkey,
) -> Result<ReferralConfig, ProgramError> {
    if config_info.owner != program_id {
        return Err(ReferralError::InvalidReferralConfigOwner.into());
    }
    let (pda, _) = Pubkey::find_program_address(&[b"referral_config"], program_id);
    if config_info.key != &pda {
        return Err(ReferralError::InvalidReferralConfigAddress.into());
    }
    if config_info.data_len() < ReferralConfig::SIZE {
        return Err(ReferralError::InvalidReferralConfigSize.into());
    }
    ReferralConfig::try_from_slice(&config_info.data.borrow())
        .map_err(|_| ReferralError::InvalidReferralConfigSize.into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_calculate_reward_basic() {
        // 100 bps (1%) of 1_000_000_000 lamports = 10_000_000
        let reward = calculate_reward(1_000_000_000, 100, u64::MAX).unwrap();
        assert_eq!(reward, 10_000_000);
    }

    #[test]
    fn test_calculate_reward_capped() {
        // 3000 bps (30%) of 1_000_000_000 = 300_000_000, but capped at 50_000_000
        let reward = calculate_reward(1_000_000_000, 3000, 50_000_000).unwrap();
        assert_eq!(reward, 50_000_000);
    }

    #[test]
    fn test_calculate_reward_overflow_protection() {
        // u64::MAX * u16::MAX should not panic — handled by u128 arithmetic
        let result = calculate_reward(u64::MAX, u16::MAX, u64::MAX);
        assert!(result.is_ok());
    }

    #[test]
    fn test_sha256_hash_deterministic() {
        let h1 = sha256_hash(b"FREEFLOW");
        let h2 = sha256_hash(b"FREEFLOW");
        assert_eq!(h1, h2);
    }

    #[test]
    fn test_sha256_hash_case_sensitive() {
        let h1 = sha256_hash(b"FREEFLOW");
        let h2 = sha256_hash(b"freeflow");
        assert_ne!(h1, h2, "hash is case-sensitive; callers must uppercase before hashing");
    }

    // ── C-2: load_verified_config ────────────────────────────────────────────

    /// Build an 86-byte buffer that borsh-deserializes into a `ReferralConfig`,
    /// with `authority` written at offset 18..50 (after `reward_bps: u16` and
    /// the two `u64`s). This is exactly the layout an attacker would forge.
    fn config_bytes(authority: [u8; 32]) -> Vec<u8> {
        let mut data = vec![0u8; ReferralConfig::SIZE];
        data[0..2].copy_from_slice(&250u16.to_le_bytes()); // reward_bps
        data[2..10].copy_from_slice(&1_000u64.to_le_bytes()); // max_reward_lamports
        data[10..18].copy_from_slice(&100u64.to_le_bytes()); // min_purchase_lamports
        data[18..50].copy_from_slice(&authority); // authority
        data[50..82].copy_from_slice(&[7u8; 32]); // rewards_pool_vault
        data[82] = 255; // bump
        data // [83..86] = _padding, left zero
    }

    /// Foreign-owned: right address, right size, perfectly well-formed bytes —
    /// but owned by a program the attacker controls, so every byte in it is
    /// attacker-chosen, `authority` included.
    #[test]
    fn test_load_verified_config_rejects_foreign_owner() {
        let program_id = Pubkey::new_unique();
        let attacker_program = Pubkey::new_unique();
        let (pda, _) = Pubkey::find_program_address(&[b"referral_config"], &program_id);

        let mut lamports = 1_000_000u64;
        let mut data = config_bytes([9u8; 32]);
        let info = AccountInfo::new(
            &pda,
            false,
            false,
            &mut lamports,
            &mut data,
            &attacker_program,
            false,
            0,
        );

        assert_eq!(
            load_verified_config(&info, &program_id).unwrap_err(),
            ProgramError::Custom(ReferralError::InvalidReferralConfigOwner as u32),
            "a foreign-owned account must never be accepted as the config — and the \
             code must name the OWNER branch. This fixture sits at the canonical PDA \
             precisely so the address branch cannot be what rejected it.",
        );
    }

    /// Program-owned but at the wrong address: guards type confusion between
    /// this program's own account types. Nothing but the canonical PDA counts.
    ///
    /// Program-owned on purpose, so the owner branch passes and only the address
    /// branch can be what rejects this.
    #[test]
    fn test_load_verified_config_rejects_wrong_address() {
        let program_id = Pubkey::new_unique();
        let not_the_pda = Pubkey::new_unique();

        let mut lamports = 1_000_000u64;
        let mut data = config_bytes([9u8; 32]);
        let info = AccountInfo::new(
            &not_the_pda,
            false,
            false,
            &mut lamports,
            &mut data,
            &program_id,
            false,
            0,
        );

        assert_eq!(
            load_verified_config(&info, &program_id).unwrap_err(),
            ProgramError::Custom(ReferralError::InvalidReferralConfigAddress as u32),
            "only the canonical [b\"referral_config\"] PDA may be read as the config",
        );
    }

    /// M-2: the two rejection paths must stay distinguishable. If these ever
    /// collapse back to one code, the pair of tests above stops being an oracle
    /// for *which* check fired and both could pass on the wrong branch.
    #[test]
    fn test_load_verified_config_branches_have_distinct_codes() {
        assert_ne!(
            ReferralError::InvalidReferralConfigOwner as u32,
            ReferralError::InvalidReferralConfigAddress as u32,
            "the owner check and the PDA check must never share an error code",
        );
    }

    /// The one account that is genuinely the config: program-owned, canonical
    /// PDA, exactly `ReferralConfig::SIZE` bytes.
    #[test]
    fn test_load_verified_config_accepts_canonical_pda() {
        let program_id = Pubkey::new_unique();
        let (pda, _) = Pubkey::find_program_address(&[b"referral_config"], &program_id);
        let authority = [42u8; 32];

        let mut lamports = 1_000_000u64;
        let mut data = config_bytes(authority);
        assert_eq!(data.len(), 86, "ReferralConfig::SIZE is 86");
        let info = AccountInfo::new(
            &pda,
            false,
            false,
            &mut lamports,
            &mut data,
            &program_id,
            false,
            0,
        );

        let config = load_verified_config(&info, &program_id)
            .expect("the canonical program-owned config PDA must load");
        assert_eq!(
            config.authority, authority,
            "authority must round-trip from bytes 18..50",
        );
        assert_eq!(config.reward_bps, 250);
        assert_eq!(config.max_reward_lamports, 1_000);
        assert_eq!(config.min_purchase_lamports, 100);
    }
}
