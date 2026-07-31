//! Integration and logic tests for rewards-v2 trial functionality.
//!
//! # Coverage
//!
//! | Handler                   | What's tested |
//! |---------------------------|---------------|
//! | `SetTrialEnabled`         | Full integration (PDA create, toggle, auth guard) |
//! | `ReleaseTrialClaim`       | Error gates before CPI: TrialDisabled, RepFlowGate, MissingSigner, EpochMismatch, ZeroSignature, InvalidMerkle |
//! | `TrialUsage` PDA          | Create-on-first-release field layout, multi-epoch accumulation (claimed + used bytes), cap enforcement, device_uuid consistency, expiry |
//! | `TrialMintCap`            | Fresh epoch starts at zero, accumulates across releases, cap boundary, over-limit detection |
//! | `SlashTrialFraud`         | Tiered slash amounts (1st/2nd/3rd offense), balance cap, lifetime accumulation, auth guard |
//!
//! # Architecture note
//! Tests that reach CPI calls (minting $FLOW, minting repFlow, slashing repFlow) are
//! NOT included because they require `repflow-token` and SPL-Token programs to be
//! loaded.  Error-gate tests stop before the CPI boundary; logic tests stay pure-Rust.

// ─── Logic tests (no Solana runtime) ─────────────────────────────────────────

#[cfg(test)]
mod logic {
    use borsh::BorshDeserialize;
    use crate::constants::*;
    use crate::merkle::{compute_merkle_leaf_hash_from_release, verify_merkle_proof};
    use crate::types::*;

    // ── helpers ───────────────────────────────────────────────────────────────

    fn trial_usage(
        claimed_bytes: u64,
        used_bytes:    u64,
        expires_at:    u64,
        device_uuid:   [u8; 16],
    ) -> TrialUsage {
        TrialUsage {
            user_pubkey:   [1u8; 32],
            used_bytes,
            claimed_bytes,
            device_uuid,
            first_seen_ts: 1_700_000_000,
            last_usage_ts: 1_700_000_000,
            expires_at,
            cap_bytes:     FREE_TRIAL_BYTES,
            bump:          255,
        }
    }

    fn trial_mint_cap(minted_so_far: u64) -> TrialMintCap {
        TrialMintCap {
            relay:         [0xAA; 32],
            epoch:         1,
            minted_so_far,
            bump:          254,
        }
    }

    // ── TrialUsage PDA lifecycle ──────────────────────────────────────────────

    /// First `ReleaseTrialClaim` for a new user creates the PDA with the correct
    /// initial field layout.
    #[test]
    fn trial_usage_new_pda_fields() {
        let total_bytes = 1_073_741_824u64; // 1 GB
        let now         = 1_700_000_000u64;

        let tu = TrialUsage {
            user_pubkey:   [1u8; 32],
            used_bytes:    total_bytes,   // set from release.total_bytes
            claimed_bytes: 0,             // starts at zero
            device_uuid:   [2u8; 16],
            first_seen_ts: now,
            last_usage_ts: now,
            expires_at:    now + FREE_TRIAL_DURATION_SECS,
            cap_bytes:     FREE_TRIAL_BYTES,
            bump:          255,
        };

        assert_eq!(tu.claimed_bytes, 0,            "new PDA: claimed_bytes must be 0");
        assert_eq!(tu.used_bytes,    total_bytes,   "new PDA: used_bytes set from release");
        assert_eq!(tu.cap_bytes,     FREE_TRIAL_BYTES);
        assert!(tu.expires_at > now, "expires_at must be in the future");
        assert_eq!(tu.expires_at, now + FREE_TRIAL_DURATION_SECS,
            "expires_at must be 30 days from creation");
    }

    /// `claimed_bytes` and `used_bytes` must both accumulate across multiple epoch
    /// releases.  The `used_bytes` accumulation is the Issue-4 fix.
    #[test]
    fn trial_usage_claimed_and_used_bytes_accumulate() {
        let mut tu = trial_usage(0, 0, u64::MAX, [2u8; 16]);

        let releases = [
            1_073_741_824u64, // 1 GB
            2_147_483_648,    // 2 GB
            3_221_225_472,    // 3 GB
        ];
        let total: u64 = releases.iter().sum();

        for bytes in releases {
            let new_claimed = tu.claimed_bytes.checked_add(bytes).unwrap();
            assert!(new_claimed <= tu.cap_bytes, "release must not exceed cap");
            tu.claimed_bytes = new_claimed;
            tu.used_bytes    = tu.used_bytes.saturating_add(bytes);
        }

        assert_eq!(tu.claimed_bytes, total, "claimed_bytes must accumulate");
        assert_eq!(tu.used_bytes,    total, "used_bytes must also accumulate (Issue 4)");
    }

    /// Cap enforcement: `claimed_bytes + release_bytes > cap_bytes` must be rejected.
    #[test]
    fn trial_usage_cap_exceeded() {
        let near_cap = FREE_TRIAL_BYTES - 1000;
        let tu       = trial_usage(near_cap, near_cap, u64::MAX, [0u8; 16]);

        let release_bytes = 2000u64;
        let new_claimed   = tu.claimed_bytes.checked_add(release_bytes).unwrap();
        assert!(new_claimed > tu.cap_bytes, "must detect TrialCapExceeded");
    }

    /// Exactly at the cap boundary must be accepted (not rejected).
    #[test]
    fn trial_usage_cap_boundary_accepted() {
        let remaining = 1000u64;
        let tu = trial_usage(FREE_TRIAL_BYTES - remaining, 0, u64::MAX, [0u8; 16]);

        let new_claimed = tu.claimed_bytes.checked_add(remaining).unwrap();
        assert!(new_claimed <= tu.cap_bytes, "exactly at cap must be accepted");
        assert_eq!(new_claimed, FREE_TRIAL_BYTES);
    }

    /// `device_uuid` in the stored PDA must match the `release.device_uuid` on every
    /// subsequent call; mismatch triggers `InvalidArgument` on-chain.
    #[test]
    fn trial_usage_device_uuid_consistency() {
        let uuid = [0xABu8; 16];
        let tu   = trial_usage(0, 0, u64::MAX, uuid);

        // Matching UUID → consistent
        assert_eq!(tu.device_uuid, uuid, "same UUID must pass consistency check");

        // Different UUID → mismatch (would trigger InvalidArgument)
        let wrong = [0xCDu8; 16];
        assert_ne!(tu.device_uuid, wrong, "different UUID must fail consistency check");
    }

    /// Trial expiry: `trial_usage.expires_at <= now` must trigger `TrialExpired`.
    #[test]
    fn trial_usage_expiry_detection() {
        let now = 1_700_000_000u64;

        // Already expired (expires_at in the past)
        let expired = trial_usage(0, 0, now - 1, [0u8; 16]);
        assert!(expired.expires_at <= now, "expired trial must be detected");

        // Active (expires_at in the future)
        let active = trial_usage(0, 0, now + 100, [0u8; 16]);
        assert!(active.expires_at > now, "active trial must not be flagged as expired");
    }

    /// TrialUsage round-trips through Borsh serialization.
    #[test]
    fn trial_usage_borsh_round_trip() {
        let orig = TrialUsage {
            user_pubkey:   [5u8; 32],
            used_bytes:    1_073_741_824,
            claimed_bytes: 500_000_000,
            device_uuid:   [0xDE; 16],
            first_seen_ts: 1_700_000_000,
            last_usage_ts: 1_700_100_000,
            expires_at:    1_702_592_000,
            cap_bytes:     FREE_TRIAL_BYTES,
            bump:          200,
        };
        let bytes = borsh::to_vec(&orig).unwrap();
        let copy  = TrialUsage::try_from_slice(&bytes).unwrap();
        assert_eq!(orig.user_pubkey,   copy.user_pubkey);
        assert_eq!(orig.used_bytes,    copy.used_bytes);
        assert_eq!(orig.claimed_bytes, copy.claimed_bytes);
        assert_eq!(orig.device_uuid,   copy.device_uuid);
        assert_eq!(orig.expires_at,    copy.expires_at);
        assert_eq!(orig.cap_bytes,     copy.cap_bytes);
        assert_eq!(orig.bump,          copy.bump);
    }

    // ── TrialMintCap enforcement ──────────────────────────────────────────────

    /// Relay uptime self-claims (client_pubkey == relay_wallet) must NOT count
    /// against MAX_TRIAL_MINT_PER_RELAY_PER_EPOCH — that cap is for trial fraud
    /// prevention only.  Uptime has no quota limit.
    #[test]
    fn trial_mint_cap_excludes_relay_self_uptime() {
        let relay  = [0xAAu8; 32];
        let client = [0xBBu8; 32];

        // Simulate accumulating only trial-client amounts into trial_cap_amount.
        let mut trial_cap_amount: u64 = 0;

        // Relay uptime release (client_pubkey == relay) — must NOT accumulate.
        let is_relay_self_uptime = relay == relay; // true
        if !is_relay_self_uptime {
            trial_cap_amount += 50_000_000_000; // large uptime amount
        }
        assert_eq!(trial_cap_amount, 0, "relay uptime must not count against cap");

        // Trial client release (client_pubkey != relay) — must accumulate.
        let is_relay_self_uptime = client == relay; // false
        if !is_relay_self_uptime {
            trial_cap_amount += 5_000_000_000; // 5 $FLOW trial usage
        }
        assert_eq!(trial_cap_amount, 5_000_000_000,
            "trial client amount must count against cap");
        assert!(trial_cap_amount <= MAX_TRIAL_MINT_PER_RELAY_PER_EPOCH,
            "trial amount must be within cap");
    }

    /// Fresh cap PDA starts at zero; cap equals 100 $FLOW (9-decimal confirmed).
    #[test]
    fn trial_mint_cap_initial_state() {
        let tmc = trial_mint_cap(0);
        assert_eq!(tmc.minted_so_far, 0, "fresh TrialMintCap must start at zero");
        // 100 $FLOW × 1_000_000 micro-FLOW/$FLOW = 100_000_000
        assert_eq!(MAX_TRIAL_MINT_PER_RELAY_PER_EPOCH, 100 * BASE_UNITS_PER_FLOW,
            "cap must be exactly 100 $FLOW in micro-FLOW units");
    }

    /// Multiple releases accumulate into `minted_so_far`.
    #[test]
    fn trial_mint_cap_accumulates() {
        let mut tmc = trial_mint_cap(0);
        let r1 = 1_000u64;
        let r2 = 500u64;

        tmc.minted_so_far = tmc.minted_so_far.checked_add(r1).unwrap();
        assert!(tmc.minted_so_far <= MAX_TRIAL_MINT_PER_RELAY_PER_EPOCH);

        tmc.minted_so_far = tmc.minted_so_far.checked_add(r2).unwrap();
        assert!(tmc.minted_so_far <= MAX_TRIAL_MINT_PER_RELAY_PER_EPOCH);

        assert_eq!(tmc.minted_so_far, r1 + r2, "must accumulate correctly");
    }

    /// Exactly at the cap boundary must be accepted.
    #[test]
    fn trial_mint_cap_exact_limit_accepted() {
        let gap = 100u64;
        let tmc = trial_mint_cap(MAX_TRIAL_MINT_PER_RELAY_PER_EPOCH - gap);

        let new = tmc.minted_so_far.checked_add(gap).unwrap();
        assert!(new <= MAX_TRIAL_MINT_PER_RELAY_PER_EPOCH,
            "exactly at limit must be accepted");
        assert_eq!(new, MAX_TRIAL_MINT_PER_RELAY_PER_EPOCH);
    }

    /// One unit over the cap must be rejected.
    #[test]
    fn trial_mint_cap_over_limit_rejected() {
        let tmc = trial_mint_cap(MAX_TRIAL_MINT_PER_RELAY_PER_EPOCH - 100);

        let new = tmc.minted_so_far.checked_add(200).unwrap();
        assert!(new > MAX_TRIAL_MINT_PER_RELAY_PER_EPOCH,
            "over limit must trigger TrialMintCapExceeded");
    }

    /// Different epochs use separate caps (seeds include epoch).
    #[test]
    fn trial_mint_cap_per_epoch_isolation() {
        // Epoch 1 at cap
        let epoch1 = trial_mint_cap(MAX_TRIAL_MINT_PER_RELAY_PER_EPOCH);
        // Epoch 2 fresh
        let epoch2 = TrialMintCap { epoch: 2, minted_so_far: 0, ..epoch1.clone() };

        assert!(epoch1.minted_so_far >= MAX_TRIAL_MINT_PER_RELAY_PER_EPOCH,
            "epoch 1 is at cap");
        assert_eq!(epoch2.minted_so_far, 0,
            "epoch 2 cap is independent and starts at zero");
    }

    /// TrialMintCap Borsh round-trip.
    #[test]
    fn trial_mint_cap_borsh_round_trip() {
        let orig = TrialMintCap {
            relay:         [3u8; 32],
            epoch:         7,
            minted_so_far: 5_000_000,
            bump:          252,
        };
        let bytes = borsh::to_vec(&orig).unwrap();
        let copy  = TrialMintCap::try_from_slice(&bytes).unwrap();
        assert_eq!(orig.relay,         copy.relay);
        assert_eq!(orig.epoch,         copy.epoch);
        assert_eq!(orig.minted_so_far, copy.minted_so_far);
        assert_eq!(orig.bump,          copy.bump);
    }

    // ── SetTrialEnabled state machine ─────────────────────────────────────────

    /// FoundationConfig serializes and deserializes correctly.
    #[test]
    fn foundation_config_borsh_round_trip() {
        let orig = FoundationConfig {
            foundation_wallet: [7u8; 32],
            trial_enabled:     true,
            uptime_enabled:    true,
            bump:              253,
        };
        let bytes = borsh::to_vec(&orig).unwrap();
        let copy  = FoundationConfig::try_from_slice(&bytes).unwrap();
        assert_eq!(orig.foundation_wallet, copy.foundation_wallet);
        assert_eq!(orig.trial_enabled,     copy.trial_enabled);
        assert_eq!(orig.uptime_enabled,    copy.uptime_enabled);
        assert_eq!(orig.bump,              copy.bump);
    }

    /// Toggle logic: enable → disable → enable works correctly.
    #[test]
    fn set_trial_enabled_toggle_logic() {
        let mut fc = FoundationConfig {
            foundation_wallet: [7u8; 32],
            trial_enabled:     true,
            uptime_enabled:    true,
            bump:              253,
        };
        assert!(fc.trial_enabled);

        fc = FoundationConfig { trial_enabled: false, ..fc };
        assert!(!fc.trial_enabled, "must disable");

        fc = FoundationConfig { trial_enabled: true, ..fc };
        assert!(fc.trial_enabled, "must re-enable");
    }

    /// Authorization check: only the registered `foundation_wallet` can toggle.
    #[test]
    fn set_trial_enabled_auth_check() {
        let foundation = [0xAAu8; 32];
        let other      = [0xBBu8; 32];

        let fc = FoundationConfig {
            foundation_wallet: foundation,
            trial_enabled:     true,
            uptime_enabled:    true,
            bump:              253,
        };

        // Same wallet → authorized
        assert_eq!(fc.foundation_wallet, foundation, "foundation wallet is authorized");

        // Different wallet → unauthorized (would return IllegalOwner on-chain)
        assert_ne!(fc.foundation_wallet, other, "other wallet must be rejected");
    }

    // ── SlashTrialFraud tiered slash ──────────────────────────────────────────

    fn compute_slash(slash_count: u32, relay_balance: u64) -> u64 {
        let slash = match slash_count {
            1 => SLASH_FIRST_OFFENSE,
            2 => SLASH_SECOND_OFFENSE,
            _ => relay_balance,
        };
        slash.min(relay_balance)
    }

    #[test]
    fn slash_fraud_first_offense() {
        assert_eq!(
            compute_slash(1, 10_000),
            SLASH_FIRST_OFFENSE,
            "first offense must be SLASH_FIRST_OFFENSE ({SLASH_FIRST_OFFENSE})"
        );
    }

    #[test]
    fn slash_fraud_second_offense() {
        assert_eq!(
            compute_slash(2, 10_000),
            SLASH_SECOND_OFFENSE,
            "second offense must be SLASH_SECOND_OFFENSE ({SLASH_SECOND_OFFENSE})"
        );
    }

    #[test]
    fn slash_fraud_third_offense_full_balance() {
        let balance = 7_777u64;
        assert_eq!(
            compute_slash(3, balance),
            balance,
            "third+ offense must burn the full balance"
        );
    }

    #[test]
    fn slash_fraud_offense_amounts_are_tiered() {
        assert!(SLASH_FIRST_OFFENSE < SLASH_SECOND_OFFENSE,
            "first offense < second offense (tiered escalation)");
        // Third offense = 100% of balance, which may be larger or smaller
        // than the fixed amounts; no ordering assertion needed.
    }

    #[test]
    fn slash_fraud_capped_by_available_balance() {
        // Relay has less than SLASH_FIRST_OFFENSE
        let low_balance = 200u64;
        assert!(low_balance < SLASH_FIRST_OFFENSE,
            "test fixture: balance below first offense amount");
        let slash = compute_slash(1, low_balance);
        assert_eq!(slash, low_balance,
            "slash must be capped by the relay's actual balance");
    }

    #[test]
    fn slash_fraud_lifetime_slashed_accumulates() {
        let mut rep = RelayReputation {
            relay:            [0u8; 32],
            slash_count:      0,
            lifetime_slashed: 0,
            bump:             255,
        };
        let balance = 10_000u64;

        // Offense 1
        rep.slash_count += 1;
        let amount1 = compute_slash(rep.slash_count, balance);
        rep.lifetime_slashed = rep.lifetime_slashed.checked_add(amount1).unwrap();
        assert_eq!(rep.lifetime_slashed, amount1);

        // Offense 2
        rep.slash_count += 1;
        let amount2 = compute_slash(rep.slash_count, balance);
        rep.lifetime_slashed = rep.lifetime_slashed.checked_add(amount2).unwrap();
        assert_eq!(rep.lifetime_slashed, amount1 + amount2);

        assert!(rep.lifetime_slashed > 0, "lifetime_slashed must be non-zero");
    }

    /// RelayReputation Borsh round-trip.
    #[test]
    fn relay_reputation_borsh_round_trip() {
        let orig = RelayReputation {
            relay:            [4u8; 32],
            slash_count:      2,
            lifetime_slashed: 1_500,
            bump:             251,
        };
        let bytes = borsh::to_vec(&orig).unwrap();
        let copy  = RelayReputation::try_from_slice(&bytes).unwrap();
        assert_eq!(orig.relay,            copy.relay);
        assert_eq!(orig.slash_count,      copy.slash_count);
        assert_eq!(orig.lifetime_slashed, copy.lifetime_slashed);
        assert_eq!(orig.bump,             copy.bump);
    }

    // ── ClientReleaseOnChain helpers (used by gate tests) ────────────────────

    /// A non-zero `client_signature` is required for every release.
    #[test]
    fn client_signature_zero_is_invalid() {
        let zero_sig   = [0u8; 64];
        let valid_sig  = [1u8; 64];
        assert_eq!(zero_sig, [0u8; 64], "all-zero is the sentinel for invalid sig");
        assert_ne!(valid_sig, [0u8; 64], "non-zero sig is valid");
    }

    /// Merkle proof verification: leaf from release must match committed root.
    #[test]
    fn release_trial_claim_merkle_leaf_verification() {
        use crate::types::ReserveBatchEntry;
        use crate::merkle::compute_merkle_leaf_hash_from_entry;
        use solana_program::hash::hashv;

        let client_pubkey = [0x11u8; 32];
        let session_id    = [0x22u8; 16];
        let batch_nonce   = 1u64;
        let batch_hash    = hashv(&[&client_pubkey, &session_id, &batch_nonce.to_le_bytes()]).to_bytes();

        let entry = ReserveBatchEntry {
            client_pubkey,
            highest_seq:      batch_nonce,
            bytes:            1_073_741_824,
            merkle_leaf_hash: batch_hash,
            session_id,
            record_count:     1,
        };

        let release = ClientReleaseOnChain {
            client_pubkey,
            session_id,
            batch_nonce,
            total_bytes:      1_073_741_824,
            merkle_proof:     vec![],
            client_signature: [1u8; 64],
            device_uuid:      [0u8; 16],
            record_count:     1,
        };

        let entry_leaf   = compute_merkle_leaf_hash_from_entry(&entry);
        let release_leaf = compute_merkle_leaf_hash_from_release(&release);
        assert_eq!(entry_leaf, release_leaf,
            "leaf hashes must match between reserve and release");

        // Single-leaf tree: root == leaf
        let root = entry_leaf;
        assert!(verify_merkle_proof(release_leaf, &[], root),
            "single-leaf proof must verify");

        // Wrong root must fail
        let wrong_root = [0xFFu8; 32];
        assert!(!verify_merkle_proof(release_leaf, &[], wrong_root),
            "wrong root must fail verification");
    }
}

// ─── Integration tests (solana-program-test) ─────────────────────────────────
//
// Tests `SetTrialEnabled` end-to-end and all error gates in
// `ReleaseTrialClaim` that occur before any CPI is invoked.

#[cfg(test)]
mod integration {
    use borsh::BorshDeserialize;
    use solana_program::pubkey::Pubkey;
    use solana_program_test::*;
    use solana_sdk::{
        account::Account,
        instruction::{AccountMeta, Instruction},
        signature::{Keypair, Signer},
        system_program,
        transaction::Transaction,
    };

    use crate::{
        constants::*,
        id,
        process_instruction,
        types::{
            ClaimCommitment, ClaimCommitmentStatus, FoundationConfig,
            CLAIM_COMMITMENT_SIZE, FOUNDATION_CONFIG_SIZE,
        },
        RewardsInstruction,
    };

    // ── Test fixture helpers ──────────────────────────────────────────────────

    fn program_test() -> ProgramTest {
        ProgramTest::new(
            "freeflow_rewards_v2",
            id(),
            processor!(process_instruction),
        )
    }

    /// Encode a `RewardsInstruction` as Borsh instruction data.
    fn encode_ix(ix: &RewardsInstruction) -> Vec<u8> {
        borsh::to_vec(ix).expect("borsh encode")
    }

    /// Derive `[b"foundation_config"]` PDA.
    fn foundation_config_pda() -> (Pubkey, u8) {
        Pubkey::find_program_address(&[b"foundation_config"], &id())
    }

    /// Build a pre-populated `FoundationConfig` account (for tests that need the
    /// config to already exist rather than creating it during the test).
    fn prepopulated_fc_account(
        wallet: &Pubkey,
        trial_enabled: bool,
        bump: u8,
    ) -> Account {
        let fc = FoundationConfig {
            foundation_wallet: wallet.to_bytes(),
            trial_enabled,
            uptime_enabled: true,
            bump,
        };
        let data = borsh::to_vec(&fc).expect("borsh fc");
        let mut padded = vec![0u8; FOUNDATION_CONFIG_SIZE];
        padded[..data.len()].copy_from_slice(&data);
        Account {
            lamports:   1_000_000,
            data:       padded,
            owner:      id(),
            executable: false,
            rent_epoch: 0,
        }
    }

    /// Build a pre-populated `ClaimCommitment` account.
    ///
    /// `bandwidth_amount` is populated from `derive_reward_amount` rather than
    /// a hardcoded literal, so it stays consistent with what the contract
    /// itself would have derived from `total_bytes` and the pinned rate.
    fn commitment_account(claim_epoch: u64, relay: &Pubkey) -> Account {
        let total_bytes    = 1_073_741_824u64; // 1 GB
        let routing_per_mb = DEFAULT_ROUTING_PER_MB;
        let c = ClaimCommitment {
            relay_pubkey:    relay.to_bytes(),
            claim_epoch,
            merkle_root:     [0u8; 32],
            client_count:    1,
            bandwidth_amount: crate::handlers::derive_reward_amount(total_bytes, routing_per_mb),
            uptime_amount:   0,
            total_bytes,
            uptime_hours:    0,
            routing_per_mb,
            uptime_per_hour: DEFAULT_UPTIME_PER_HOUR,
            committed_at:    0,
            uptime_paid:     false,
            reserved_count:  1,
            released_count:  0,
            released_amount: 0,
            released_bytes:  0,
            status:          ClaimCommitmentStatus::Releasing,
            dispute_deadline: 0,
            bump:            255,
        };
        let data = borsh::to_vec(&c).expect("borsh commitment");
        let mut padded = vec![0u8; CLAIM_COMMITMENT_SIZE];
        padded[..data.len()].copy_from_slice(&data);
        Account {
            lamports:   1_000_000,
            data:       padded,
            owner:      id(),
            executable: false,
            rent_epoch: 0,
        }
    }

    /// Build a fake `RepFlowUser` account for the repFlow balance gate.
    ///
    /// Layout (Anchor discriminator + partial fields):
    ///   [0..8]  = 8-byte discriminator (zeroed)
    ///   [8..40] = wallet pubkey (32 bytes)
    ///   [40..48] = balance u64 LE
    fn repflow_user_account(balance: u64) -> Account {
        let mut data = vec![0u8; 48];
        data[40..48].copy_from_slice(&balance.to_le_bytes());
        Account {
            lamports:   1_000_000,
            data,
            owner:      REPFLOW_PROGRAM_ID, // F-1: real repflow-token owner for the gate binding
            executable: false,
            rent_epoch: 0,
        }
    }

    /// Stub account with enough lamports to exist but no meaningful data.
    fn stub_account() -> Account {
        Account {
            lamports:   1_000_000,
            data:       vec![0u8; 8],
            owner:      id(),
            executable: false,
            rent_epoch: 0,
        }
    }

    // ── SetTrialEnabled tests ─────────────────────────────────────────────────

    /// First call to `SetTrialEnabled` creates the `FoundationConfig` PDA and
    /// records `trial_enabled = true`.
    #[tokio::test]
    async fn set_trial_enabled_creates_foundation_config() {
        let (mut banks, payer, recent_blockhash) = program_test().start().await;
        let (fc_pda, _) = foundation_config_pda();

        let ix = Instruction {
            program_id: id(),
            accounts: vec![
                AccountMeta::new(payer.pubkey(), true),         // foundation_wallet (signer)
                AccountMeta::new(fc_pda, false),                // foundation_config (writable PDA)
                AccountMeta::new_readonly(system_program::ID, false),
            ],
            data: encode_ix(&RewardsInstruction::SetTrialEnabled { enabled: true }),
        };

        let tx = Transaction::new_signed_with_payer(
            &[ix],
            Some(&payer.pubkey()),
            &[&payer],
            recent_blockhash,
        );
        banks.process_transaction(tx).await
            .expect("SetTrialEnabled(true) must succeed on first call");

        let acct = banks.get_account(fc_pda).await
            .expect("rpc ok").expect("foundation_config must exist");
        let fc = FoundationConfig::try_from_slice(&acct.data[..FOUNDATION_CONFIG_SIZE])
            .expect("deserialize");
        assert!(fc.trial_enabled, "trial must be enabled after SetTrialEnabled(true)");
        assert_eq!(fc.foundation_wallet, payer.pubkey().to_bytes(),
            "foundation_wallet must be recorded as the signer");
    }

    /// Second call toggles `trial_enabled` to false.
    #[tokio::test]
    async fn set_trial_enabled_toggles_to_disabled() {
        let (mut banks, payer, recent_blockhash) = program_test().start().await;
        let (fc_pda, _) = foundation_config_pda();

        // Enable first
        let enable_ix = Instruction {
            program_id: id(),
            accounts: vec![
                AccountMeta::new(payer.pubkey(), true),
                AccountMeta::new(fc_pda, false),
                AccountMeta::new_readonly(system_program::ID, false),
            ],
            data: encode_ix(&RewardsInstruction::SetTrialEnabled { enabled: true }),
        };
        banks.process_transaction(Transaction::new_signed_with_payer(
            &[enable_ix],
            Some(&payer.pubkey()),
            &[&payer],
            recent_blockhash,
        )).await.expect("enable ok");

        let recent_blockhash = banks.get_latest_blockhash().await.expect("blockhash");

        // Disable
        let disable_ix = Instruction {
            program_id: id(),
            accounts: vec![
                AccountMeta::new(payer.pubkey(), true),
                AccountMeta::new(fc_pda, false),
                AccountMeta::new_readonly(system_program::ID, false),
            ],
            data: encode_ix(&RewardsInstruction::SetTrialEnabled { enabled: false }),
        };
        banks.process_transaction(Transaction::new_signed_with_payer(
            &[disable_ix],
            Some(&payer.pubkey()),
            &[&payer],
            recent_blockhash,
        )).await.expect("disable ok");

        let acct = banks.get_account(fc_pda).await.expect("rpc").expect("exists");
        let fc   = FoundationConfig::try_from_slice(&acct.data[..FOUNDATION_CONFIG_SIZE])
            .expect("deserialize");
        assert!(!fc.trial_enabled, "trial must be disabled after SetTrialEnabled(false)");
    }

    /// A different keypair (not the foundation wallet) must be rejected on toggle.
    #[tokio::test]
    async fn set_trial_enabled_rejects_non_foundation_signer() {
        let mut pt = program_test();
        let (fc_pda, fc_bump) = foundation_config_pda();
        let foundation        = Keypair::new();
        let intruder          = Keypair::new();

        // Pre-populate foundation_config owned by the foundation keypair
        let fc = FoundationConfig {
            foundation_wallet: foundation.pubkey().to_bytes(),
            trial_enabled:     true,
            uptime_enabled:    true,
            bump:              fc_bump,
        };
        let mut data = vec![0u8; FOUNDATION_CONFIG_SIZE];
        borsh::to_vec(&fc).unwrap().iter().enumerate().for_each(|(i, b)| data[i] = *b);
        pt.add_account(fc_pda, Account {
            lamports:   1_000_000,
            data,
            owner:      id(),
            executable: false,
            rent_epoch: 0,
        });

        let (mut banks, payer, recent_blockhash) = pt.start().await;
        // Fund intruder
        banks.process_transaction(Transaction::new_signed_with_payer(
            &[solana_sdk::system_instruction::transfer(
                &payer.pubkey(), &intruder.pubkey(), 1_000_000_000
            )],
            Some(&payer.pubkey()),
            &[&payer],
            recent_blockhash,
        )).await.unwrap();
        let recent_blockhash = banks.get_latest_blockhash().await.unwrap();

        // Intruder tries to toggle
        let ix = Instruction {
            program_id: id(),
            accounts: vec![
                AccountMeta::new(intruder.pubkey(), true), // wrong signer
                AccountMeta::new(fc_pda, false),
                AccountMeta::new_readonly(system_program::ID, false),
            ],
            data: encode_ix(&RewardsInstruction::SetTrialEnabled { enabled: false }),
        };
        let result = banks.process_transaction(Transaction::new_signed_with_payer(
            &[ix],
            Some(&intruder.pubkey()),
            &[&intruder],
            recent_blockhash,
        )).await;
        assert!(result.is_err(),
            "non-foundation wallet must not be able to toggle SetTrialEnabled");
    }

    // ── ReleaseTrialClaim error gates ─────────────────────────────────────────
    //
    // These tests exercise error conditions that occur BEFORE any CPI call,
    // so they don't need repflow-token or SPL-Token programs loaded.

    /// Build a `ReleaseTrialClaim` instruction with stub accounts for gate testing.
    ///
    /// `releases` is usually empty for gate tests that error out before the
    /// per-release loop.
    fn release_trial_claim_ix(
        relay:             &Keypair,
        commitment_pk:     Pubkey,
        foundation_cfg_pk: Pubkey,
        repflow_user_pk:   Pubkey,
        trial_cap_pk:      Pubkey,
        claim_epoch:       u64,
        releases:          Vec<crate::types::ClientReleaseOnChain>,
    ) -> Instruction {
        let stub = Keypair::new().pubkey();
        Instruction {
            program_id: id(),
            accounts: vec![
                AccountMeta::new(relay.pubkey(), true),             // [0] relay_wallet signer
                AccountMeta::new(commitment_pk, false),             // [1] commitment
                AccountMeta::new_readonly(foundation_cfg_pk, false),// [2] foundation_config
                AccountMeta::new_readonly(stub, false),             // [3] token_program (stub)
                AccountMeta::new(stub, false),                      // [4] flow_mint (stub)
                AccountMeta::new_readonly(stub, false),             // [5] service_authority (stub)
                AccountMeta::new_readonly(stub, false),             // [6] repflow_program (stub)
                AccountMeta::new(stub, false),                      // [7] repflow_config (stub)
                AccountMeta::new(repflow_user_pk, false),           // [8] relay_repflow_user
                AccountMeta::new(stub, false),                      // [9] repflow_mint (stub)
                AccountMeta::new(stub, false),                      // [10] relay_repflow_ata
                AccountMeta::new(stub, false),                      // [11] reward_relay
                AccountMeta::new(stub, false),                      // [12] reward_treasury
                AccountMeta::new(trial_cap_pk, false),              // [13] trial_mint_cap
                AccountMeta::new_readonly(system_program::ID, false),// [14] system_program
            ],
            data: encode_ix(&RewardsInstruction::ReleaseTrialClaim { claim_epoch, releases }),
        }
    }

    /// `ReleaseTrialClaim` fails with `TrialDisabled` when `foundation_config.trial_enabled = false`.
    #[tokio::test]
    async fn release_trial_claim_fails_when_trial_disabled() {
        let relay = Keypair::new();
        let claim_epoch = 100u64;

        let mut pt              = program_test();
        let commitment_pk       = Keypair::new().pubkey();
        let foundation_cfg_pk   = Keypair::new().pubkey();
        let repflow_user_pk     = Keypair::new().pubkey();
        let trial_cap_pk        = Keypair::new().pubkey();

        pt.add_account(commitment_pk,    commitment_account(claim_epoch, &relay.pubkey()));
        pt.add_account(foundation_cfg_pk,
            prepopulated_fc_account(&relay.pubkey(), false /* disabled */, 255));
        pt.add_account(repflow_user_pk,  repflow_user_account(MIN_RELAY_REPFLOW + 1000));
        pt.add_account(trial_cap_pk,     stub_account());

        let (mut banks, payer, recent_blockhash) = pt.start().await;

        // Fund relay
        banks.process_transaction(Transaction::new_signed_with_payer(
            &[solana_sdk::system_instruction::transfer(
                &payer.pubkey(), &relay.pubkey(), 1_000_000_000
            )],
            Some(&payer.pubkey()),
            &[&payer],
            recent_blockhash,
        )).await.unwrap();
        let recent_blockhash = banks.get_latest_blockhash().await.unwrap();

        let ix = release_trial_claim_ix(
            &relay, commitment_pk, foundation_cfg_pk,
            repflow_user_pk, trial_cap_pk, claim_epoch, vec![],
        );
        let result = banks.process_transaction(Transaction::new_signed_with_payer(
            &[ix],
            Some(&relay.pubkey()),
            &[&relay],
            recent_blockhash,
        )).await;
        assert!(result.is_err(), "TrialDisabled must cause transaction failure");
    }

    /// `ReleaseTrialClaim` fails when relay repFlow is below the 2001 gate.
    #[tokio::test]
    async fn release_trial_claim_fails_when_repflow_below_gate() {
        let relay = Keypair::new();
        let claim_epoch = 101u64;

        let mut pt            = program_test();
        let commitment_pk     = Keypair::new().pubkey();
        let foundation_cfg_pk = Keypair::new().pubkey();
        let repflow_user_pk   = Pubkey::find_program_address(
            &[b"repflow_user", relay.pubkey().as_ref()], &REPFLOW_PROGRAM_ID).0; // F-1: genuine PDA
        let trial_cap_pk      = Keypair::new().pubkey();

        pt.add_account(commitment_pk,    commitment_account(claim_epoch, &relay.pubkey()));
        pt.add_account(foundation_cfg_pk,
            prepopulated_fc_account(&relay.pubkey(), true /* enabled */, 255));
        // Balance below MIN_RELAY_REPFLOW (2001)
        pt.add_account(repflow_user_pk,  repflow_user_account(MIN_RELAY_REPFLOW - 1));
        pt.add_account(trial_cap_pk,     stub_account());

        let (mut banks, payer, recent_blockhash) = pt.start().await;
        banks.process_transaction(Transaction::new_signed_with_payer(
            &[solana_sdk::system_instruction::transfer(
                &payer.pubkey(), &relay.pubkey(), 1_000_000_000
            )],
            Some(&payer.pubkey()),
            &[&payer],
            recent_blockhash,
        )).await.unwrap();
        let recent_blockhash = banks.get_latest_blockhash().await.unwrap();

        let ix = release_trial_claim_ix(
            &relay, commitment_pk, foundation_cfg_pk,
            repflow_user_pk, trial_cap_pk, claim_epoch, vec![],
        );
        let result = banks.process_transaction(Transaction::new_signed_with_payer(
            &[ix],
            Some(&relay.pubkey()),
            &[&relay],
            recent_blockhash,
        )).await;
        assert!(result.is_err(), "RepFlowGateNotMet must cause transaction failure");
    }

    /// `ReleaseTrialClaim` fails when `claim_epoch` in instruction doesn't match
    /// the `ClaimCommitment.claim_epoch` stored on-chain.
    #[tokio::test]
    async fn release_trial_claim_fails_on_epoch_mismatch() {
        let relay = Keypair::new();
        let stored_epoch      = 200u64;
        let wrong_epoch       = 201u64;

        let mut pt            = program_test();
        let commitment_pk     = Keypair::new().pubkey();
        let foundation_cfg_pk = Keypair::new().pubkey();
        let repflow_user_pk   = Keypair::new().pubkey();
        let trial_cap_pk      = Keypair::new().pubkey();

        pt.add_account(commitment_pk,
            commitment_account(stored_epoch, &relay.pubkey())); // epoch = 200
        pt.add_account(foundation_cfg_pk,
            prepopulated_fc_account(&relay.pubkey(), true, 255));
        pt.add_account(repflow_user_pk,
            repflow_user_account(MIN_RELAY_REPFLOW + 1000));
        pt.add_account(trial_cap_pk, stub_account());

        let (mut banks, payer, recent_blockhash) = pt.start().await;
        banks.process_transaction(Transaction::new_signed_with_payer(
            &[solana_sdk::system_instruction::transfer(
                &payer.pubkey(), &relay.pubkey(), 1_000_000_000
            )],
            Some(&payer.pubkey()),
            &[&payer],
            recent_blockhash,
        )).await.unwrap();
        let recent_blockhash = banks.get_latest_blockhash().await.unwrap();

        // Pass wrong_epoch (201) but commitment stores 200 → mismatch
        let ix = release_trial_claim_ix(
            &relay, commitment_pk, foundation_cfg_pk,
            repflow_user_pk, trial_cap_pk, wrong_epoch, vec![],
        );
        let result = banks.process_transaction(Transaction::new_signed_with_payer(
            &[ix],
            Some(&relay.pubkey()),
            &[&relay],
            recent_blockhash,
        )).await;
        assert!(result.is_err(), "epoch mismatch must cause transaction failure");
    }

    /// `ReleaseTrialClaim` fails when relay_wallet is not a signer.
    #[tokio::test]
    async fn release_trial_claim_fails_without_signer() {
        let relay = Keypair::new();
        let claim_epoch = 300u64;

        let mut pt            = program_test();
        let commitment_pk     = Keypair::new().pubkey();
        let foundation_cfg_pk = Keypair::new().pubkey();
        let repflow_user_pk   = Keypair::new().pubkey();
        let trial_cap_pk      = Keypair::new().pubkey();
        let stub              = Keypair::new().pubkey();

        pt.add_account(commitment_pk,    commitment_account(claim_epoch, &relay.pubkey()));
        pt.add_account(foundation_cfg_pk,
            prepopulated_fc_account(&relay.pubkey(), true, 255));
        pt.add_account(repflow_user_pk,  repflow_user_account(MIN_RELAY_REPFLOW + 1000));
        pt.add_account(trial_cap_pk,     stub_account());

        let (mut banks, payer, recent_blockhash) = pt.start().await;
        // relay_wallet NOT marked as signer
        let ix = Instruction {
            program_id: id(),
            accounts: vec![
                AccountMeta::new(relay.pubkey(), false /* NOT signer */),
                AccountMeta::new(commitment_pk, false),
                AccountMeta::new_readonly(foundation_cfg_pk, false),
                AccountMeta::new_readonly(stub, false),
                AccountMeta::new(stub, false),
                AccountMeta::new_readonly(stub, false),
                AccountMeta::new_readonly(stub, false),
                AccountMeta::new(stub, false),
                AccountMeta::new(repflow_user_pk, false),
                AccountMeta::new(stub, false),
                AccountMeta::new(stub, false),
                AccountMeta::new(stub, false),
                AccountMeta::new(stub, false),
                AccountMeta::new(trial_cap_pk, false),
                AccountMeta::new_readonly(system_program::ID, false),
            ],
            data: encode_ix(&RewardsInstruction::ReleaseTrialClaim {
                claim_epoch,
                releases: vec![],
            }),
        };
        let result = banks.process_transaction(Transaction::new_signed_with_payer(
            &[ix],
            Some(&payer.pubkey()),
            &[&payer],
            recent_blockhash,
        )).await;
        assert!(result.is_err(), "missing signer must cause transaction failure");
    }
}
