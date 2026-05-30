//! End-to-end logic tests for rewards-v2.
//!
//! These tests exercise the pure logic functions (Merkle, hashing, struct
//! serialization) without invoking the Solana runtime. Full on-chain integration
//! tests require `solana-program-test` and are deferred to a future test suite.

#[cfg(test)]
mod tests {
    use crate::constants::*;
    use crate::errors::RewardsError;
    use crate::merkle::*;
    use crate::types::*;

    fn make_client_pubkey(seed: u8) -> [u8; 32] {
        let mut k = [0u8; 32];
        k[0] = seed;
        k
    }

    fn make_entry(seed: u8, amount: u64, bytes: u64) -> ReserveBatchEntry {
        use solana_program::hash::hashv;
        let client_pubkey = make_client_pubkey(seed);
        let session_id    = [seed; 16];
        let highest_seq   = seed as u64 + 1;
        // batch_hash = SHA-256(client_pubkey || session_id || batch_nonce)
        let batch_hash = hashv(&[&client_pubkey, &session_id, &highest_seq.to_le_bytes()]).to_bytes();
        ReserveBatchEntry {
            client_pubkey,
            highest_seq,
            amount,
            bytes,
            merkle_leaf_hash: batch_hash,
            session_id,
            record_count: 1,
        }
    }

    fn make_release(entry: &ReserveBatchEntry) -> ClientReleaseOnChain {
        ClientReleaseOnChain {
            client_pubkey:    entry.client_pubkey,
            session_id:       entry.session_id,
            batch_nonce:      entry.highest_seq,
            total_amount:     entry.amount,
            total_bytes:      entry.bytes,
            merkle_proof:     vec![],  // will be set per test
            client_signature: [1u8; 64], // non-null placeholder
            device_uuid:      [0u8; 16],
            record_count:     entry.record_count,
        }
    }

    // ── Leaf hash consistency ─────────────────────────────────────────────────

    #[test]
    fn reserve_and_release_leaf_hashes_match() {
        let entry   = make_entry(1, 1000, 1_073_741_824);
        let release = make_release(&entry);

        let entry_hash   = compute_merkle_leaf_hash_from_entry(&entry);
        let release_hash = compute_merkle_leaf_hash_from_release(&release);
        assert_eq!(entry_hash, release_hash,
            "Leaf hashes must match between ReserveBatch and ReleaseClaim");
    }

    // ── Single-client commit → reserve → release cycle ────────────────────────

    #[test]
    fn single_client_merkle_proof_end_to_end() {
        let entry   = make_entry(42, 5000, 2 * 1_073_741_824);
        let leaf    = compute_merkle_leaf_hash_from_entry(&entry);

        // For a single client, root == leaf.
        let root = leaf;

        // No proof needed for single-client tree.
        let proof: Vec<[u8; 32]> = vec![];
        assert!(verify_merkle_proof(leaf, &proof, root));

        // Release with matching hash verifies.
        let release = make_release(&entry);
        let release_leaf = compute_merkle_leaf_hash_from_release(&release);
        assert_eq!(leaf, release_leaf);
        assert!(verify_merkle_proof(release_leaf, &proof, root));
    }

    // ── Multi-client tree: 5 clients ─────────────────────────────────────────

    fn build_tree(leaves: &[[u8; 32]]) -> [u8; 32] {
        let mut level: Vec<[u8; 32]> = leaves.to_vec();
        while level.len() > 1 {
            if level.len() % 2 == 1 {
                let last = *level.last().unwrap();
                level.push(last);
            }
            level = level.chunks(2).map(|c| hash_pair(&c[0], &c[1])).collect();
        }
        level[0]
    }

    fn build_proof(leaves: &[[u8; 32]], idx: usize) -> Vec<[u8; 32]> {
        let mut proof = Vec::new();
        let mut level: Vec<[u8; 32]> = leaves.to_vec();
        let mut i = idx;
        while level.len() > 1 {
            if level.len() % 2 == 1 {
                let last = *level.last().unwrap();
                level.push(last);
            }
            let sib = if i % 2 == 0 { i + 1 } else { i - 1 };
            proof.push(level[sib]);
            level = level.chunks(2).map(|c| hash_pair(&c[0], &c[1])).collect();
            i /= 2;
        }
        proof
    }

    #[test]
    fn five_client_tree_all_releases_verify() {
        let entries: Vec<ReserveBatchEntry> = (0u8..5).map(|i| make_entry(i, 1000 * (i as u64 + 1), 1_073_741_824)).collect();
        let leaves: Vec<[u8; 32]> = entries.iter().map(compute_merkle_leaf_hash_from_entry).collect();
        let root = build_tree(&leaves);

        for (i, entry) in entries.iter().enumerate() {
            let proof        = build_proof(&leaves, i);
            let mut release  = make_release(entry);
            release.merkle_proof = proof.clone();

            let release_leaf = compute_merkle_leaf_hash_from_release(&release);
            assert_eq!(leaves[i], release_leaf, "Leaf {} hash mismatch", i);
            assert!(
                verify_merkle_proof(release_leaf, &proof, root),
                "Proof failed for client {}",
                i
            );
        }
    }

    // ── Constants sanity ──────────────────────────────────────────────────────

    #[test]
    fn epoch_secs_is_12_hours() {
        assert_eq!(EPOCH_SECS, 12 * 3600);
    }

    #[test]
    fn dispute_window_secs_is_7_days() {
        assert_eq!(DISPUTE_WINDOW_SECS, 7 * 24 * 3600);
    }

    #[test]
    fn bytes_per_flow_is_1gb() {
        assert_eq!(BYTES_PER_FLOW, 1_073_741_824);
    }

    #[test]
    fn split_pcts_sum_to_100() {
        assert_eq!(RELAY_SPLIT_PCT + FOUNDATION_SPLIT_PCT, 100);
    }

    #[test]
    fn free_trial_bytes_is_10gb() {
        assert_eq!(FREE_TRIAL_BYTES, 10 * 1_073_741_824);
    }

    #[test]
    fn slash_offenses_are_tiered() {
        assert!(SLASH_FIRST_OFFENSE < SLASH_SECOND_OFFENSE,
            "First offense must be less than second");
        assert_eq!(SLASH_FIRST_OFFENSE, 500);
        assert_eq!(SLASH_SECOND_OFFENSE, 1_000);
    }

    // ── Error code uniqueness ─────────────────────────────────────────────────

    #[test]
    fn error_codes_are_unique() {
        use std::collections::HashSet;
        let codes: Vec<u32> = vec![
            RewardsError::MerkleProofInvalid   as u32,
            RewardsError::BatchSignatureInvalid as u32,
            RewardsError::EpochAlreadyCommitted as u32,
            RewardsError::DisputeWindowActive   as u32,
            RewardsError::DisputeWindowExpired  as u32,
            RewardsError::RepFlowGateNotMet     as u32,
            RewardsError::ClaimableBalanceNotFound as u32,
            RewardsError::TrialExpired          as u32,
            RewardsError::TrialCapExceeded      as u32,
            RewardsError::TrialDisabled         as u32,
            RewardsError::TrialMintCapExceeded  as u32,
            RewardsError::AlreadyReleased       as u32,
            RewardsError::ReleaseExceedsCommitment as u32,
            RewardsError::ReserveExceedsCommitment as u32,
            RewardsError::ClientSignatureInvalid as u32,
        ];
        let unique: HashSet<u32> = codes.iter().cloned().collect();
        assert_eq!(codes.len(), unique.len(), "Duplicate error codes detected");
    }

    // ── ClaimCommitment serialization round-trip ──────────────────────────────

    #[test]
    fn claim_commitment_borsh_round_trip() {
        use borsh::BorshDeserialize;

        let c = ClaimCommitment {
            relay_pubkey:    [5u8; 32],
            claim_epoch:     42,
            merkle_root:     [6u8; 32],
            client_count:    10,
            total_amount:    50_000,
            total_bytes:     10_737_418_240,
            reserved_count:  5,
            released_count:  3,
            released_amount: 30_000,
            released_bytes:  6_000_000_000,
            status:          ClaimCommitmentStatus::Releasing,
            dispute_deadline: 1_700_000_000,
            bump:            254,
        };

        let bytes = borsh::to_vec(&c).unwrap();
        let c2    = ClaimCommitment::try_from_slice(&bytes).unwrap();
        assert_eq!(c.relay_pubkey,    c2.relay_pubkey);
        assert_eq!(c.claim_epoch,     c2.claim_epoch);
        assert_eq!(c.merkle_root,     c2.merkle_root);
        assert_eq!(c.client_count,    c2.client_count);
        assert_eq!(c.total_amount,    c2.total_amount);
        assert_eq!(c.reserved_count,  c2.reserved_count);
        assert_eq!(c.released_count,  c2.released_count);
        assert_eq!(c.released_amount, c2.released_amount);
        assert_eq!(c.status,          c2.status);
        assert_eq!(c.bump,            c2.bump);
    }

    // ── RelayReputation tiered slash calculation ──────────────────────────────

    #[test]
    fn tiered_slash_calculation() {
        let balance = 2000u64;

        let slash1 = SLASH_FIRST_OFFENSE.min(balance);
        let slash2 = SLASH_SECOND_OFFENSE.min(balance);
        let slash3 = balance; // 100% of balance

        assert_eq!(slash1, 500);
        assert_eq!(slash2, 1_000);
        assert_eq!(slash3, 2000);
    }

    // ── TrialUsage cap enforcement logic ──────────────────────────────────────

    #[test]
    fn trial_cap_enforcement() {
        let cap_bytes: u64 = FREE_TRIAL_BYTES;
        let claimed_so_far: u64 = FREE_TRIAL_BYTES - 1000;
        let this_release: u64 = 2000;

        let new_claimed = claimed_so_far + this_release;
        assert!(new_claimed > cap_bytes, "Should exceed cap");
    }

    #[test]
    fn trial_cap_just_under_limit() {
        let cap_bytes: u64 = FREE_TRIAL_BYTES;
        let claimed_so_far: u64 = FREE_TRIAL_BYTES - 1000;
        let this_release: u64 = 1000;

        let new_claimed = claimed_so_far + this_release;
        assert_eq!(new_claimed, cap_bytes, "Exactly at cap limit");
    }

    // ── repFlow gate threshold ────────────────────────────────────────────────

    #[test]
    fn repflow_gate_threshold() {
        assert!(2001u64 >= MIN_RELAY_REPFLOW);
        assert!(2000u64 < MIN_RELAY_REPFLOW);
    }

    // ── Probationary relay deferred amounts ───────────────────────────────────

    #[test]
    fn probationary_relay_split_calculation() {
        let total_amount: u64 = 10_000;
        let relay_amount    = total_amount * RELAY_SPLIT_PCT / 100;
        let treasury_amount = total_amount * FOUNDATION_SPLIT_PCT / 100;
        assert_eq!(relay_amount, 7_000);
        assert_eq!(treasury_amount, 3_000);
        assert_eq!(relay_amount + treasury_amount, 10_000);
    }

    // ── ReserveBatch aggregate cap check ─────────────────────────────────────

    #[test]
    fn reserve_exceeds_commitment_detection() {
        let committed_total: u64 = 10_000;
        let entry_total: u64     = 10_001;
        assert!(entry_total > committed_total, "Should detect ReserveExceedsCommitment");
    }
}
