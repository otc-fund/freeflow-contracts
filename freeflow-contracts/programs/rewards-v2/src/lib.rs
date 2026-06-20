//! FreeFlow Rewards-v2 Program — Merkle-committed claims.
//!
//! Hard fork from the legacy rewards program. New program ID — coexists with
//! the legacy rewards program. Relays opt in by updating their sidecar config.
//!
//! ## Instructions
//!   0  CommitClaim         — relay publishes Merkle root (no repFlow gate)
//!   1  ReserveBatch        — CPI hold_client_funds, up to 10 clients per tx
//!   2  ReleaseClaim        — CPI burn_held_funds + mint 70/30 (repFlow gate at mint)
//!   3  ClientDispute       — tiered repFlow slash + release client funds
//!   4  ClaimPendingRewards — probationary relay mints deferred balance
//!   5  ReleaseTrialClaim   — direct mint for free trial users (no burn)
//!   6  SetTrialEnabled     — foundation kill switch for trial releases
//!   7  SlashTrialFraud     — foundation slashes relay for fabricated trial claims
//!
//! ## Architecture
//!   - Raw Borsh (no Anchor) — matches the legacy rewards program style
//!   - 12-hour epochs: claim_epoch = unix_timestamp / 43_200
//!   - 7-day dispute window before ReleaseClaim is allowed
//!   - repFlow gate (2001) checked ONLY at mint time (not at commit/reserve)

use borsh::{BorshDeserialize, BorshSerialize};
use solana_program::{
    account_info::AccountInfo,
    entrypoint,
    entrypoint::ProgramResult,
    program_error::ProgramError,
    pubkey::Pubkey,
};

pub mod constants;
pub mod errors;
pub mod types;
pub mod merkle;
pub mod cpi;
pub mod handlers;

#[cfg(test)]
mod test_merkle;
#[cfg(test)]
mod test_e2e;
#[cfg(test)]
mod test_trial;

use types::{ClientReleaseOnChain, ReserveBatchEntry};

// Placeholder program ID — replace with generated keypair at deployment.
// Run: solana-keygen new --no-bip39-passphrase -o rewards-v2-keypair.json
solana_program::declare_id!("Fg6PaFpoGXkYsidMpWTK6W2BeZ7FEfcYkg476zPFsLnS");

entrypoint!(process_instruction);

/// Top-level instruction enum — Borsh discriminant matches variant index (0-based).
#[derive(BorshSerialize, BorshDeserialize, Debug, Clone)]
pub enum RewardsInstruction {
    /// 0: CommitClaim — relay publishes Merkle root committing to all client batches.
    /// No repFlow gate. Any relay can commit.
    CommitClaim {
        merkle_root:  [u8; 32],
        client_count: u32,
        total_amount: u64,
        total_bytes:  u64,
        claim_epoch:  u64,
    },
    /// 1: ReserveBatch — CPI to user_escrow::hold_client_funds (up to 10 clients per tx).
    /// No repFlow gate. Double-spend protection is immediate.
    ReserveBatch {
        claim_epoch: u64,
        entries:     Vec<ReserveBatchEntry>,
    },
    /// 2: ReleaseClaim — CPI burn_held_funds + mint $FLOW 70/30.
    /// repFlow gate (2001) checked here only at mint time.
    /// After 7-day dispute window. Up to 5 releases per tx.
    ReleaseClaim {
        claim_epoch: u64,
        releases:    Vec<ClientReleaseOnChain>,
    },
    /// 3: ClientDispute — client disputes forged batches.
    /// Tiered repFlow slash on relay. Client funds released.
    ClientDispute {
        claim_epoch:         u64,
        client_pubkey:       [u8; 32],
        session_id:          [u8; 16],
        batch_nonce:         u64,
        original_batch_hash: [u8; 32],
        total_amount:        u64,
        total_bytes:         u64,
        record_count:        u32,
        client_signature:    [u8; 64],
        merkle_proof:        Vec<[u8; 32]>,
    },
    /// 4: ClaimPendingRewards — probationary relay (<2001 repFlow at release time)
    /// claims accumulated deferred $FLOW once eligible.
    ClaimPendingRewards {
        claim_epoch: u64,
    },
    /// 5: ReleaseTrialClaim — direct mint for free trial users (no $FLOW to burn).
    /// repFlow gate (2001) checked here. Uses TrialUsage PDA for verification.
    ReleaseTrialClaim {
        claim_epoch: u64,
        releases:    Vec<ClientReleaseOnChain>,
    },
    /// 6: SetTrialEnabled — foundation-only global kill switch for ReleaseTrialClaim.
    SetTrialEnabled {
        enabled: bool,
    },
    /// 7: SlashTrialFraud — foundation slashes relay for fabricated trial claims.
    /// Foundation audits off-chain; on-chain records device_uuid as audit evidence.
    SlashTrialFraud {
        claim_epoch:      u64,
        device_uuid:      [u8; 16],
        device_signature: [u8; 64],
    },
    /// 8: InitializeRewardRates — foundation creates the reward_rates PDA once.
    InitializeRewardRates {
        routing_per_mb:   u64,
        seeding_per_mb:   u64,
        uptime_per_hour:  u64,
        flow_price_cents: u64,
    },
    /// 9: UpdateRewardRates — foundation updates the reward_rates PDA.
    UpdateRewardRates {
        routing_per_mb:   u64,
        seeding_per_mb:   u64,
        uptime_per_hour:  u64,
        flow_price_cents: u64,
    },
}

pub fn process_instruction(
    program_id: &Pubkey,
    accounts:   &[AccountInfo],
    data:       &[u8],
) -> ProgramResult {
    let instruction = RewardsInstruction::try_from_slice(data)
        .map_err(|_| ProgramError::InvalidInstructionData)?;

    match instruction {
        RewardsInstruction::CommitClaim {
            merkle_root, client_count, total_amount, total_bytes, claim_epoch,
        } => handlers::process_commit_claim_ix(
            program_id, accounts, merkle_root, client_count, total_amount, total_bytes, claim_epoch,
        ),

        RewardsInstruction::ReserveBatch { claim_epoch, entries } =>
            handlers::process_reserve_batch_ix(program_id, accounts, claim_epoch, entries),

        RewardsInstruction::ReleaseClaim { claim_epoch, releases } =>
            handlers::process_release_claim_ix(program_id, accounts, claim_epoch, releases),

        RewardsInstruction::ClientDispute {
            claim_epoch, client_pubkey, session_id, batch_nonce,
            original_batch_hash, total_amount, total_bytes, record_count,
            client_signature, merkle_proof,
        } => handlers::process_client_dispute_ix(
            program_id, accounts, claim_epoch, client_pubkey, session_id, batch_nonce,
            original_batch_hash, total_amount, total_bytes, record_count,
            client_signature, merkle_proof,
        ),

        RewardsInstruction::ClaimPendingRewards { claim_epoch } =>
            handlers::process_claim_pending_ix(program_id, accounts, claim_epoch),

        RewardsInstruction::ReleaseTrialClaim { claim_epoch, releases } =>
            handlers::process_release_trial_claim_ix(program_id, accounts, claim_epoch, releases),

        RewardsInstruction::SetTrialEnabled { enabled } =>
            handlers::process_set_trial_enabled_ix(program_id, accounts, enabled),

        RewardsInstruction::SlashTrialFraud { claim_epoch, device_uuid, device_signature } =>
            handlers::process_slash_trial_fraud_ix(
                program_id, accounts, claim_epoch, device_uuid, device_signature,
            ),

        RewardsInstruction::InitializeRewardRates {
            routing_per_mb, seeding_per_mb, uptime_per_hour, flow_price_cents,
        } => handlers::process_initialize_reward_rates(
            program_id, accounts, routing_per_mb, seeding_per_mb, uptime_per_hour, flow_price_cents,
        ),

        RewardsInstruction::UpdateRewardRates {
            routing_per_mb, seeding_per_mb, uptime_per_hour, flow_price_cents,
        } => handlers::process_update_reward_rates(
            program_id, accounts, routing_per_mb, seeding_per_mb, uptime_per_hour, flow_price_cents,
        ),
    }
}
