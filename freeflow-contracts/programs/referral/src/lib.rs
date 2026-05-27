//! FreeFlow Referral Program
//!
//! Raw Borsh program (no Anchor). Follows the staking/rewards pattern.
//!
//! Instructions:
//!   0 — InitializeReferralConfig
//!   1 — UpdateReferralConfig
//!   2 — RegisterReferralCode
//!   3 — RecordReferral
//!   4 — ClaimReferralReward
//!   5 — DepositRewardsPool

use borsh::{BorshDeserialize, BorshSerialize};
use solana_program::{
    account_info::AccountInfo,
    declare_id,
    entrypoint,
    entrypoint::ProgramResult,
    pubkey::Pubkey,
};

mod errors;
mod instructions;
mod state;
mod utils;

use instructions::{
    claim,
    deposit::{self, DepositRewardsPoolArgs},
    initialize::{self, InitializeReferralConfigArgs},
    record_referral::{self, RecordReferralArgs},
    register_code::{self, RegisterReferralCodeArgs},
    update_config::{self, UpdateReferralConfigArgs},
};

declare_id!("Fg6PaFpoGXkYsidMpWTK6W2BeZ7FEfcYkg476zPFsLnS");

entrypoint!(process_instruction);

/// Top-level instruction enum. Borsh serializes enum variants as a single leading byte.
#[derive(BorshSerialize, BorshDeserialize)]
pub enum ReferralInstruction {
    /// Discriminant 0
    InitializeReferralConfig {
        reward_bps:            u16,
        max_reward_lamports:   u64,
        min_purchase_lamports: u64,
    },
    /// Discriminant 1
    UpdateReferralConfig {
        reward_bps:            u16,
        max_reward_lamports:   u64,
        min_purchase_lamports: u64,
    },
    /// Discriminant 2 — variable-length code bytes
    RegisterReferralCode { code: Vec<u8> },
    /// Discriminant 3
    RecordReferral {
        code_hash:       [u8; 32],
        purchase_amount: u64,
    },
    /// Discriminant 4 — no data
    ClaimReferralReward,
    /// Discriminant 5
    DepositRewardsPool { amount: u64 },
}

pub fn process_instruction(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    input: &[u8],
) -> ProgramResult {
    let instruction = ReferralInstruction::try_from_slice(input)?;
    match instruction {
        ReferralInstruction::InitializeReferralConfig {
            reward_bps,
            max_reward_lamports,
            min_purchase_lamports,
        } => initialize::process(
            program_id,
            accounts,
            InitializeReferralConfigArgs {
                reward_bps,
                max_reward_lamports,
                min_purchase_lamports,
            },
        ),
        ReferralInstruction::UpdateReferralConfig {
            reward_bps,
            max_reward_lamports,
            min_purchase_lamports,
        } => update_config::process(
            program_id,
            accounts,
            UpdateReferralConfigArgs {
                reward_bps,
                max_reward_lamports,
                min_purchase_lamports,
            },
        ),
        ReferralInstruction::RegisterReferralCode { code } => {
            register_code::process(program_id, accounts, RegisterReferralCodeArgs { code })
        }
        ReferralInstruction::RecordReferral {
            code_hash,
            purchase_amount,
        } => record_referral::process(
            program_id,
            accounts,
            RecordReferralArgs {
                code_hash,
                purchase_amount,
            },
        ),
        ReferralInstruction::ClaimReferralReward => {
            claim::process(program_id, accounts)
        }
        ReferralInstruction::DepositRewardsPool { amount } => {
            deposit::process(program_id, accounts, DepositRewardsPoolArgs { amount })
        }
    }
}

// ─── Unit Tests ───────────────────────────────────────────────────────────────
#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        errors::ReferralError,
        state::{
            ReferralCode, ReferralConfig, ReferralRecord, ReferrerBalance, RewardsPool,
        },
        utils::{calculate_reward, sha256_hash},
    };

    // ── Reward calculation ───────────────────────────────────────────────────

    #[test]
    fn test_calculate_reward_basic() {
        // 100 bps (1%) of 1_000_000_000 = 10_000_000
        let r = calculate_reward(1_000_000_000, 100, u64::MAX).unwrap();
        assert_eq!(r, 10_000_000);
    }

    #[test]
    fn test_calculate_reward_capped() {
        // 3000 bps (30%) of 1_000_000_000 = 300_000_000, capped at 50_000_000
        let r = calculate_reward(1_000_000_000, 3_000, 50_000_000).unwrap();
        assert_eq!(r, 50_000_000);
    }

    #[test]
    fn test_calculate_reward_overflow() {
        // u64::MAX with u16::MAX bps should not panic
        let result = calculate_reward(u64::MAX, u16::MAX, u64::MAX);
        assert!(result.is_ok());
    }

    // ── SIZE constants match serialized byte lengths ─────────────────────────

    #[test]
    fn test_referral_config_size() {
        let s = ReferralConfig {
            reward_bps:            100,
            max_reward_lamports:   100_000_000_000,
            min_purchase_lamports: 0,
            authority:             [0u8; 32],
            rewards_pool_vault:    [0u8; 32],
            bump:                  255,
            _padding:              [0; 3],
        };
        assert_eq!(
            borsh::to_vec(&s).unwrap().len(),
            ReferralConfig::SIZE,
            "ReferralConfig::SIZE must match serialized length"
        );
    }

    #[test]
    fn test_referral_code_size() {
        let s = ReferralCode {
            code_hash:  [0u8; 32],
            referrer:   [0u8; 32],
            created_at: 0,
            is_claimed: false,
            bump:       0,
            _padding:   [0; 6],
        };
        assert_eq!(
            borsh::to_vec(&s).unwrap().len(),
            ReferralCode::SIZE,
            "ReferralCode::SIZE must match serialized length"
        );
    }

    #[test]
    fn test_referral_record_size() {
        let s = ReferralRecord {
            referrer:        [0u8; 32],
            client:          [0u8; 32],
            purchase_amount: 0,
            reward_lamports: 0,
            code_hash:       [0u8; 32],
            timestamp:       0,
            sequence:        0,
            bump:            0,
            _padding:        [0; 3],
        };
        assert_eq!(
            borsh::to_vec(&s).unwrap().len(),
            ReferralRecord::SIZE,
            "ReferralRecord::SIZE must match serialized length"
        );
    }

    #[test]
    fn test_referrer_balance_size() {
        let s = ReferrerBalance {
            referrer:       [0u8; 32],
            total_earned:   0,
            total_claimed:  0,
            referral_count: 0,
            next_sequence:  0,
            bump:           0,
            _padding:       [0; 7],
        };
        assert_eq!(
            borsh::to_vec(&s).unwrap().len(),
            ReferrerBalance::SIZE,
            "ReferrerBalance::SIZE must match serialized length"
        );
    }

    #[test]
    fn test_rewards_pool_size() {
        let s = RewardsPool {
            vault_bump:        0,
            total_deposited:   0,
            total_distributed: 0,
            bump:              0,
            _padding:          [0; 6],
        };
        assert_eq!(
            borsh::to_vec(&s).unwrap().len(),
            RewardsPool::SIZE,
            "RewardsPool::SIZE must match serialized length"
        );
    }

    // ── Error codes ──────────────────────────────────────────────────────────

    #[test]
    fn test_error_codes_are_stable() {
        use solana_program::program_error::ProgramError;
        let e: ProgramError = ReferralError::ConfigAlreadyInitialized.into();
        assert_eq!(e, ProgramError::Custom(0));
        let e: ProgramError = ReferralError::InvalidAuthority.into();
        assert_eq!(e, ProgramError::Custom(1));
        let e: ProgramError = ReferralError::PurchaseBelowMinimum.into();
        assert_eq!(e, ProgramError::Custom(12));
    }

    // ── SHA-256 helper ───────────────────────────────────────────────────────

    #[test]
    fn test_sha256_deterministic() {
        let h1 = sha256_hash(b"FREEFLOW");
        let h2 = sha256_hash(b"FREEFLOW");
        assert_eq!(h1, h2);
    }

    #[test]
    fn test_sha256_case_sensitivity() {
        // Callers uppercase before hashing — this test documents that the
        // hash function itself is case-sensitive; uppercasing is the caller's job.
        assert_ne!(sha256_hash(b"FLOW"), sha256_hash(b"flow"));
    }

    // ── Instruction serialization round-trips ────────────────────────────────

    #[test]
    fn test_init_config_roundtrip() {
        let ix = ReferralInstruction::InitializeReferralConfig {
            reward_bps:            100,
            max_reward_lamports:   100_000_000_000,
            min_purchase_lamports: 0,
        };
        let bytes = borsh::to_vec(&ix).unwrap();
        assert_eq!(bytes[0], 0, "discriminant must be 0");
        let decoded = ReferralInstruction::try_from_slice(&bytes).unwrap();
        if let ReferralInstruction::InitializeReferralConfig { reward_bps, .. } = decoded {
            assert_eq!(reward_bps, 100);
        } else {
            panic!("wrong variant");
        }
    }

    #[test]
    fn test_register_code_roundtrip() {
        let code = b"FREEFLOW-PROMO".to_vec();
        let ix = ReferralInstruction::RegisterReferralCode { code: code.clone() };
        let bytes = borsh::to_vec(&ix).unwrap();
        assert_eq!(bytes[0], 2, "discriminant must be 2");
        let decoded = ReferralInstruction::try_from_slice(&bytes).unwrap();
        if let ReferralInstruction::RegisterReferralCode { code: c } = decoded {
            assert_eq!(c, code);
        } else {
            panic!("wrong variant");
        }
    }

    #[test]
    fn test_record_referral_roundtrip() {
        let hash = sha256_hash(b"FREEFLOW");
        let ix = ReferralInstruction::RecordReferral {
            code_hash:       hash,
            purchase_amount: 5_000_000_000,
        };
        let bytes = borsh::to_vec(&ix).unwrap();
        assert_eq!(bytes[0], 3, "discriminant must be 3");
        let decoded = ReferralInstruction::try_from_slice(&bytes).unwrap();
        if let ReferralInstruction::RecordReferral { code_hash, purchase_amount } = decoded {
            assert_eq!(code_hash, hash);
            assert_eq!(purchase_amount, 5_000_000_000);
        } else {
            panic!("wrong variant");
        }
    }

    #[test]
    fn test_claim_reward_roundtrip() {
        let ix = ReferralInstruction::ClaimReferralReward;
        let bytes = borsh::to_vec(&ix).unwrap();
        assert_eq!(bytes[0], 4, "discriminant must be 4");
        let decoded = ReferralInstruction::try_from_slice(&bytes).unwrap();
        assert!(matches!(decoded, ReferralInstruction::ClaimReferralReward));
    }

    #[test]
    fn test_deposit_roundtrip() {
        let ix = ReferralInstruction::DepositRewardsPool { amount: 1_000_000_000 };
        let bytes = borsh::to_vec(&ix).unwrap();
        assert_eq!(bytes[0], 5, "discriminant must be 5");
        let decoded = ReferralInstruction::try_from_slice(&bytes).unwrap();
        if let ReferralInstruction::DepositRewardsPool { amount } = decoded {
            assert_eq!(amount, 1_000_000_000);
        } else {
            panic!("wrong variant");
        }
    }

    // ── ReferrerBalance invariant ────────────────────────────────────────────

    #[test]
    fn test_referrer_balance_invariant() {
        // Simulate the state after RecordReferral and partial ClaimReferralReward
        let mut balance = ReferrerBalance {
            referrer:       [1u8; 32],
            total_earned:   500_000_000,
            total_claimed:  200_000_000,
            referral_count: 5,
            next_sequence:  5,
            bump:           255,
            _padding:       [0; 7],
        };

        // Claim available
        let available = balance.total_earned - balance.total_claimed;
        assert_eq!(available, 300_000_000);
        balance.total_claimed += available;

        // Invariant: total_earned >= total_claimed
        assert!(balance.total_earned >= balance.total_claimed);
        assert_eq!(balance.total_earned - balance.total_claimed, 0);
    }

    // ── Pool tracking after record ───────────────────────────────────────────

    #[test]
    fn test_pool_tracking_after_record() {
        let mut pool = RewardsPool {
            vault_bump:        0,
            total_deposited:   0,
            total_distributed: 0,
            bump:              255,
            _padding:          [0; 6],
        };

        let reward = calculate_reward(1_000_000_000, 100, u64::MAX).unwrap();
        pool.total_deposited += reward;

        assert_eq!(pool.total_deposited, 10_000_000);
    }

    // ── reward_bps validation ────────────────────────────────────────────────

    #[test]
    fn test_reward_bps_too_high_error_code() {
        // 3001 bps should map to RewardBpsTooHigh (code 5)
        use solana_program::program_error::ProgramError;
        let e: ProgramError = ReferralError::RewardBpsTooHigh.into();
        assert_eq!(e, ProgramError::Custom(5));
    }
}
