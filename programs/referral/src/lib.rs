//! FreeFlow Referral Program
//!
//! Raw Borsh program (no Anchor). Follows the staking/rewards pattern.
//!
//! Instructions:
//!   0 — InitializeReferralConfig
//!   1 — UpdateReferralConfig
//!   2 — RegisterReferralCode
//!   3 — RecordReferral           (+ H-1, M-5 security checks)
//!   4 — ClaimReferralReward      (creates ClaimRequest PDA, no transfer)
//!   5 — ApproveClaim             (foundation approves → vault → referrer ATA)
//!   6 — RejectClaim              (foundation rejects → unlock balance)
//!   7 — DeferClaim               (extend review window)
//!   8 — DepositRewardsPool

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
#[cfg(test)]
mod test_support;
mod utils;

use instructions::{
    approve_claim,
    claim,
    defer_claim,
    deposit::{self, DepositRewardsPoolArgs},
    initialize::{self, InitializeReferralConfigArgs},
    record_referral::{self, RecordReferralArgs},
    register_code::{self, RegisterReferralCodeArgs},
    reject_claim,
    update_config::{self, UpdateReferralConfigArgs},
};

declare_id!("Bwx1U3WLcproQKAbCkWZBagjpq6ThwWU1psdmd9pmmeF");

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
        code_hash:          [u8; 32],
        purchase_amount:    u64,
        transferred_reward: u64,
    },
    /// Discriminant 4 — creates ClaimRequest PDA (no transfer)
    ClaimReferralReward,
    /// Discriminant 5 — foundation approves pending claim
    ApproveClaim,
    /// Discriminant 6 — foundation rejects pending claim, unlocks balance
    RejectClaim,
    /// Discriminant 7 — foundation extends review deadline
    DeferClaim,
    /// Discriminant 8
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
            transferred_reward,
        } => record_referral::process(
            program_id,
            accounts,
            RecordReferralArgs {
                code_hash,
                purchase_amount,
                transferred_reward,
            },
        ),
        ReferralInstruction::ClaimReferralReward => {
            claim::process(program_id, accounts)
        }
        ReferralInstruction::ApproveClaim => {
            approve_claim::process(program_id, accounts)
        }
        ReferralInstruction::RejectClaim => {
            reject_claim::process(program_id, accounts)
        }
        ReferralInstruction::DeferClaim => {
            defer_claim::process(program_id, accounts)
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
            ClaimRequest, ReferralCode, ReferralConfig, ReferralRecord, ReferrerBalance,
            RewardsPool,
        },
        utils::{calculate_reward, sha256_hash},
    };

    // ── Reward calculation ───────────────────────────────────────────────────

    #[test]
    fn test_calculate_reward_basic() {
        let r = calculate_reward(1_000_000_000, 100, u64::MAX).unwrap();
        assert_eq!(r, 10_000_000);
    }

    #[test]
    fn test_calculate_reward_capped() {
        let r = calculate_reward(1_000_000_000, 3_000, 50_000_000).unwrap();
        assert_eq!(r, 50_000_000);
    }

    #[test]
    fn test_calculate_reward_overflow() {
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
        assert_eq!(borsh::to_vec(&s).unwrap().len(), ReferralConfig::SIZE);
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
        assert_eq!(borsh::to_vec(&s).unwrap().len(), ReferralCode::SIZE);
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
        assert_eq!(borsh::to_vec(&s).unwrap().len(), ReferralRecord::SIZE);
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
        assert_eq!(borsh::to_vec(&s).unwrap().len(), ReferrerBalance::SIZE);
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
        assert_eq!(borsh::to_vec(&s).unwrap().len(), RewardsPool::SIZE);
    }

    #[test]
    fn test_claim_request_size() {
        let s = ClaimRequest {
            referrer:        [0u8; 32],
            amount:          0,
            requested_at:    0,
            review_deadline: 0,
            status:          0,
            executed_at:     0,
            bump:            0,
            _padding:        [0; 2],
        };
        assert_eq!(
            borsh::to_vec(&s).unwrap().len(),
            ClaimRequest::SIZE,
            "ClaimRequest::SIZE must match serialized length"
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
        // Security fixes
        let e: ProgramError = ReferralError::InvalidRewardAmount.into();
        assert_eq!(e, ProgramError::Custom(13));
        let e: ProgramError = ReferralError::InvalidPoolVault.into();
        assert_eq!(e, ProgramError::Custom(14));
        // Review-gated claim errors
        let e: ProgramError = ReferralError::ReviewPeriodNotExpired.into();
        assert_eq!(e, ProgramError::Custom(18));
        let e: ProgramError = ReferralError::ClaimAlreadyExecuted.into();
        assert_eq!(e, ProgramError::Custom(19));
        let e: ProgramError = ReferralError::InvalidClaimStatus.into();
        assert_eq!(e, ProgramError::Custom(20));
        // C-2 / M-2: the two config-verification branches, pinned apart so an
        // inserted variant cannot silently renumber one onto the other.
        let e: ProgramError = ReferralError::InvalidReferralConfigOwner.into();
        assert_eq!(e, ProgramError::Custom(15));
        let e: ProgramError = ReferralError::InvalidReferralConfigAddress.into();
        assert_eq!(e, ProgramError::Custom(22));
        let e: ProgramError = ReferralError::InvalidReferrerAta.into();
        assert_eq!(e, ProgramError::Custom(23));
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
        assert_ne!(sha256_hash(b"FLOW"), sha256_hash(b"flow"));
    }

    // ── Instruction discriminants ────────────────────────────────────────────

    #[test]
    fn test_init_config_roundtrip() {
        let ix = ReferralInstruction::InitializeReferralConfig {
            reward_bps:            100,
            max_reward_lamports:   100_000_000_000,
            min_purchase_lamports: 0,
        };
        let bytes = borsh::to_vec(&ix).unwrap();
        assert_eq!(bytes[0], 0, "InitializeReferralConfig discriminant must be 0");
    }

    #[test]
    fn test_register_code_roundtrip() {
        let code = b"FREEFLOW-PROMO".to_vec();
        let ix = ReferralInstruction::RegisterReferralCode { code: code.clone() };
        let bytes = borsh::to_vec(&ix).unwrap();
        assert_eq!(bytes[0], 2, "RegisterReferralCode discriminant must be 2");
        let decoded = ReferralInstruction::try_from_slice(&bytes).unwrap();
        if let ReferralInstruction::RegisterReferralCode { code: c } = decoded {
            assert_eq!(c, code);
        } else {
            panic!("wrong variant");
        }
    }

    #[test]
    fn test_record_referral_discriminant() {
        let ix = ReferralInstruction::RecordReferral {
            code_hash:          [0u8; 32],
            purchase_amount:    5_000_000_000,
            transferred_reward: 50_000_000,
        };
        let bytes = borsh::to_vec(&ix).unwrap();
        assert_eq!(bytes[0], 3, "RecordReferral discriminant must be 3");
    }

    #[test]
    fn test_claim_reward_discriminant() {
        let ix = ReferralInstruction::ClaimReferralReward;
        let bytes = borsh::to_vec(&ix).unwrap();
        assert_eq!(bytes[0], 4, "ClaimReferralReward discriminant must be 4");
        let decoded = ReferralInstruction::try_from_slice(&bytes).unwrap();
        assert!(matches!(decoded, ReferralInstruction::ClaimReferralReward));
    }

    #[test]
    fn test_approve_claim_discriminant() {
        let ix = ReferralInstruction::ApproveClaim;
        let bytes = borsh::to_vec(&ix).unwrap();
        assert_eq!(bytes[0], 5, "ApproveClaim discriminant must be 5");
    }

    #[test]
    fn test_reject_claim_discriminant() {
        let ix = ReferralInstruction::RejectClaim;
        let bytes = borsh::to_vec(&ix).unwrap();
        assert_eq!(bytes[0], 6, "RejectClaim discriminant must be 6");
    }

    #[test]
    fn test_defer_claim_discriminant() {
        let ix = ReferralInstruction::DeferClaim;
        let bytes = borsh::to_vec(&ix).unwrap();
        assert_eq!(bytes[0], 7, "DeferClaim discriminant must be 7");
    }

    #[test]
    fn test_deposit_discriminant() {
        let ix = ReferralInstruction::DepositRewardsPool { amount: 1_000_000_000 };
        let bytes = borsh::to_vec(&ix).unwrap();
        assert_eq!(bytes[0], 8, "DepositRewardsPool discriminant must be 8");
        let decoded = ReferralInstruction::try_from_slice(&bytes).unwrap();
        if let ReferralInstruction::DepositRewardsPool { amount } = decoded {
            assert_eq!(amount, 1_000_000_000);
        } else {
            panic!("wrong variant");
        }
    }

    // ── Invariants ───────────────────────────────────────────────────────────

    #[test]
    fn test_referrer_balance_invariant_with_pending() {
        // With review-gated claims, total_claimed represents LOCKED + DISTRIBUTED.
        // Invariant: total_earned >= total_claimed (enforced by ClaimReferralReward).
        let mut balance = ReferrerBalance {
            referrer:       [1u8; 32],
            total_earned:   500_000_000,
            total_claimed:  200_000_000, // 200M locked in a pending ClaimRequest
            referral_count: 5,
            next_sequence:  6,
            bump:           255,
            _padding:       [0; 7],
        };
        assert!(balance.total_earned >= balance.total_claimed, "invariant holds");
        // Rejection unlocks: total_claimed -= locked_amount
        let locked = 200_000_000u64;
        balance.total_claimed -= locked;
        let available = balance.total_earned - balance.total_claimed;
        assert_eq!(available, 500_000_000, "full amount available after rejection");
    }

    #[test]
    fn test_pool_solvency_invariant() {
        // vault_balance >= total_deposited - total_distributed
        let pool = RewardsPool {
            vault_bump:        0,
            total_deposited:   1_000_000_000,
            total_distributed: 300_000_000,
            bump:              255,
            _padding:          [0; 6],
        };
        let required = pool.total_deposited - pool.total_distributed;
        assert_eq!(required, 700_000_000);
        // Pending claims don't reduce vault — only ApproveClaim increments total_distributed
    }

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

    #[test]
    fn test_reward_bps_too_high_error_code() {
        use solana_program::program_error::ProgramError;
        let e: ProgramError = ReferralError::RewardBpsTooHigh.into();
        assert_eq!(e, ProgramError::Custom(5));
    }
}
