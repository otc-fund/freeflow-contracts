//! Shared utility functions for the referral program.

use solana_program::program_error::ProgramError;

use crate::errors::ReferralError;

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
}
