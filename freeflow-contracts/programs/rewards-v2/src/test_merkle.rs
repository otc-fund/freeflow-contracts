//! Unit tests for Merkle proof verification and leaf hash computation.

#[cfg(test)]
mod tests {
    use crate::merkle::*;
    use crate::types::{ClientReleaseOnChain, ReserveBatchEntry};

    fn dummy_hash(seed: u8) -> [u8; 32] {
        let mut h = [0u8; 32];
        h[0] = seed;
        h[31] = seed.wrapping_add(1);
        h
    }

    // ── Basic hash_pair tests ─────────────────────────────────────────────────

    #[test]
    fn hash_pair_is_symmetric() {
        let a = dummy_hash(1);
        let b = dummy_hash(2);
        // sorted-pair convention: hash_pair(a,b) == hash_pair(b,a)
        assert_eq!(hash_pair(&a, &b), hash_pair(&b, &a));
    }

    #[test]
    fn hash_pair_different_inputs_differ() {
        let a = dummy_hash(10);
        let b = dummy_hash(20);
        let c = dummy_hash(30);
        assert_ne!(hash_pair(&a, &b), hash_pair(&a, &c));
    }

    // ── Single-leaf tree ──────────────────────────────────────────────────────

    #[test]
    fn merkle_tree_1_leaf_root_equals_leaf() {
        let leaf = dummy_hash(42);
        // Empty proof — root is the leaf itself.
        assert!(verify_merkle_proof(leaf, &[], leaf));
    }

    #[test]
    fn merkle_tree_1_leaf_wrong_root_fails() {
        let leaf     = dummy_hash(42);
        let bad_root = dummy_hash(99);
        assert!(!verify_merkle_proof(leaf, &[], bad_root));
    }

    // ── Two-leaf tree ─────────────────────────────────────────────────────────

    #[test]
    fn two_leaf_tree_both_proofs_verify() {
        let leaf0 = dummy_hash(1);
        let leaf1 = dummy_hash(2);
        let root  = hash_pair(&leaf0, &leaf1);

        // Proof for leaf0: sibling = leaf1
        assert!(verify_merkle_proof(leaf0, &[leaf1], root));
        // Proof for leaf1: sibling = leaf0 (sorted-pair — same root)
        assert!(verify_merkle_proof(leaf1, &[leaf0], root));
    }

    // ── Four-leaf tree ────────────────────────────────────────────────────────

    #[test]
    fn four_leaf_tree_all_proofs_verify() {
        let leaves: Vec<[u8; 32]> = (0u8..4).map(dummy_hash).collect();

        // Build tree.
        let l01 = hash_pair(&leaves[0], &leaves[1]);
        let l23 = hash_pair(&leaves[2], &leaves[3]);
        let root = hash_pair(&l01, &l23);

        // Proof for leaf[0]: sibling=leaf[1], then sibling=l23
        assert!(verify_merkle_proof(leaves[0], &[leaves[1], l23], root));
        // Proof for leaf[1]: sibling=leaf[0], then sibling=l23
        assert!(verify_merkle_proof(leaves[1], &[leaves[0], l23], root));
        // Proof for leaf[2]: sibling=leaf[3], then sibling=l01
        assert!(verify_merkle_proof(leaves[2], &[leaves[3], l01], root));
        // Proof for leaf[3]: sibling=leaf[2], then sibling=l01
        assert!(verify_merkle_proof(leaves[3], &[leaves[2], l01], root));
    }

    // ── 100-leaf tree — all proofs verify ────────────────────────────────────

    fn build_merkle_tree(leaves: &[[u8; 32]]) -> (Vec<[u8; 32]>, [u8; 32]) {
        assert!(!leaves.is_empty());
        let mut level: Vec<[u8; 32]> = leaves.to_vec();
        let all_leaves = leaves.to_vec();

        while level.len() > 1 {
            // Pad to even length by duplicating last element.
            if level.len() % 2 == 1 {
                let last = *level.last().unwrap();
                level.push(last);
            }
            let mut next = Vec::new();
            for chunk in level.chunks(2) {
                next.push(hash_pair(&chunk[0], &chunk[1]));
            }
            level = next;
        }
        (all_leaves, level[0])
    }

    fn merkle_proof_for(leaves: &[[u8; 32]], index: usize) -> Vec<[u8; 32]> {
        let mut proof = Vec::new();
        let mut level: Vec<[u8; 32]> = leaves.to_vec();
        let mut idx = index;

        while level.len() > 1 {
            if level.len() % 2 == 1 {
                let last = *level.last().unwrap();
                level.push(last);
            }
            let sibling_idx = if idx % 2 == 0 { idx + 1 } else { idx - 1 };
            proof.push(level[sibling_idx]);
            let mut next = Vec::new();
            for chunk in level.chunks(2) {
                next.push(hash_pair(&chunk[0], &chunk[1]));
            }
            level = next;
            idx /= 2;
        }
        proof
    }

    #[test]
    fn merkle_tree_100_leaves_all_proofs_verify() {
        let leaves: Vec<[u8; 32]> = (0u8..100).map(dummy_hash).collect();
        let (_, root) = build_merkle_tree(&leaves);

        for i in 0..100 {
            let proof = merkle_proof_for(&leaves, i);
            assert!(
                verify_merkle_proof(leaves[i], &proof, root),
                "Proof failed for leaf {}",
                i
            );
        }
    }

    // ── Compute leaf hash tests ───────────────────────────────────────────────

    #[test]
    fn compute_merkle_leaf_hash_deterministic() {
        let pubkey     = [1u8; 32];
        let session_id = [2u8; 16];
        let batch_nonce = 42u64;
        let batch_hash  = [3u8; 32];

        let h1 = compute_merkle_leaf_hash(&pubkey, &session_id, batch_nonce, &batch_hash, 500, 5);
        let h2 = compute_merkle_leaf_hash(&pubkey, &session_id, batch_nonce, &batch_hash, 500, 5);
        assert_eq!(h1, h2);
    }

    #[test]
    fn compute_merkle_leaf_hash_sensitive_to_bytes() {
        // The `amount` argument was removed from the leaf hash (the relay no
        // longer commits to a currency figure); `total_bytes` is now the sole
        // quantity driving value, so the leaf must still be sensitive to it.
        let pubkey     = [1u8; 32];
        let session_id = [2u8; 16];
        let batch_hash  = [3u8; 32];

        let h1 = compute_merkle_leaf_hash(&pubkey, &session_id, 42, &batch_hash, 1000, 5);
        let h2 = compute_merkle_leaf_hash(&pubkey, &session_id, 42, &batch_hash, 1001, 5);
        assert_ne!(h1, h2, "Leaf hash should differ when total_bytes differs");
    }

    #[test]
    fn entry_and_release_leaf_hashes_match() {
        // Simulate a full cycle: ReserveBatchEntry → compute hash,
        // ClientReleaseOnChain → compute same hash.
        let client_pubkey = [7u8; 32];
        let session_id    = [8u8; 16];
        let highest_seq   = 99u64;
        let merkle_leaf_hash = [9u8; 32]; // this IS the batch_hash for ReserveBatch

        let entry = ReserveBatchEntry {
            client_pubkey,
            highest_seq,
            bytes: 1_073_741_824, // 1 GB
            merkle_leaf_hash,
            session_id,
            record_count: 3,
        };

        // Simulate what ReleaseClaim does: compute batch_hash from client_pubkey || session_id || batch_nonce
        // In ReserveBatch, batch_nonce = highest_seq, batch_hash = merkle_leaf_hash
        // In ReleaseClaim, batch_hash = SHA-256(client_pubkey || session_id || batch_nonce)
        // These are DIFFERENT — but the leaf hashes should still match because they use the same fields.
        // The entry hash uses merkle_leaf_hash directly; release hash computes it.
        // For a matching test, we pre-compute what the release would produce:

        use solana_program::hash::hashv;
        let release_batch_hash = hashv(&[
            &client_pubkey,
            &session_id,
            &highest_seq.to_le_bytes(),
        ]).to_bytes();

        // For the hashes to match, entry.merkle_leaf_hash MUST equal the release's computed batch_hash.
        // In practice the relay sets merkle_leaf_hash = SHA-256(client_pubkey || session_id || batch_nonce).
        // For this test we need to construct an entry where merkle_leaf_hash matches.
        let entry_matching = ReserveBatchEntry {
            merkle_leaf_hash: release_batch_hash,
            ..entry.clone()
        };

        let release = ClientReleaseOnChain {
            client_pubkey,
            session_id,
            batch_nonce: highest_seq,
            total_bytes: 1_073_741_824,
            merkle_proof: vec![],
            client_signature: [0u8; 64],
            device_uuid: [0u8; 16],
            record_count: 3,
        };

        let entry_hash   = compute_merkle_leaf_hash_from_entry(&entry_matching);
        let release_hash = compute_merkle_leaf_hash_from_release(&release);
        assert_eq!(entry_hash, release_hash,
            "Entry leaf hash must equal release leaf hash for the same batch");
    }
}
