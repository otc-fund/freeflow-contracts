//! On-chain Merkle proof verification for rewards-v2.
//!
//! Uses sorted-pair hashing: `hash_pair(a, b)` always hashes min(a,b) || max(a,b).
//! This means `verify_merkle_proof` works without left/right position bits for
//! any leaf index. The off-chain tree builder (freeflow-relay-runtime::merkle_claim)
//! uses the same sorted-pair convention.

use solana_program::hash::hashv;
use crate::types::{ClientReleaseOnChain, ReserveBatchEntry};

/// Verify a Merkle proof on-chain.
///
/// # Arguments
/// - `leaf_hash`  — the computed hash of the leaf being proved
/// - `proof`      — sibling hashes from leaf to root (ordered bottom-to-top)
/// - `root`       — the expected root hash stored in ClaimCommitment
///
/// Uses sorted-pair hashing: at each level, hash(min(current, sibling) || max(current, sibling)).
/// This matches the off-chain tree builder and allows proofs without left/right position bits.
pub fn verify_merkle_proof(
    leaf_hash: [u8; 32],
    proof:     &[[u8; 32]],
    root:      [u8; 32],
) -> bool {
    let mut current = leaf_hash;
    for sibling in proof {
        current = hash_pair(&current, sibling);
    }
    current == root
}

/// Hash a pair of nodes using sorted-pair convention.
///
/// Always hashes `min(a, b) || max(a, b)` so the result is symmetric.
/// Used for tree building and proof verification.
pub fn hash_pair(a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
    if a <= b {
        hashv(&[a.as_slice(), b.as_slice()]).to_bytes()
    } else {
        hashv(&[b.as_slice(), a.as_slice()]).to_bytes()
    }
}

/// Compute the canonical Merkle leaf hash.
///
/// **Single shared function — used by both ReserveBatch and ReleaseClaim.**
/// This guarantees the leaf hash computed at tree-build time matches the
/// leaf hash recomputed at release time for Merkle proof verification.
///
/// ```text
/// Leaf[i] = SHA-256("freeflow-merkle-leaf-v1"
///                    || client_pubkey[32]
///                    || session_id[16]
///                    || batch_nonce[8]     (= highest_seq in ReserveBatchEntry)
///                    || batch_hash[32]     (= merkle_leaf_hash in ReserveBatchEntry)
///                    || total_bytes[8]
///                    || record_count[4])
/// ```
///
/// **No `amount` field.** The relay commits only to quantities (bytes,
/// record_count); the payable amount is derived on-chain from `total_bytes`
/// and a pinned rate. This keeps the relay from ever asserting a currency
/// figure directly in the leaf.
pub fn compute_merkle_leaf_hash(
    client_pubkey: &[u8; 32],
    session_id:    &[u8; 16],
    batch_nonce:   u64,
    batch_hash:    &[u8; 32],
    total_bytes:   u64,
    record_count:  u32,
) -> [u8; 32] {
    hashv(&[
        b"freeflow-merkle-leaf-v1",
        client_pubkey.as_slice(),
        session_id.as_slice(),
        &batch_nonce.to_le_bytes(),
        batch_hash.as_slice(),
        &total_bytes.to_le_bytes(),
        &record_count.to_le_bytes(),
    ]).to_bytes()
}

/// Convenience wrapper: compute leaf hash from a ReserveBatchEntry.
///
/// Maps: `batch_nonce = entry.highest_seq`.
///
/// **C-2 fix:** `batch_hash` is recomputed deterministically as
/// `SHA-256(client_pubkey || session_id || highest_seq)` — the same formula
/// used by `compute_merkle_leaf_hash_from_release` — instead of trusting the
/// relay-supplied `entry.merkle_leaf_hash`.  This ensures ReserveBatch and
/// ReleaseClaim always derive identical leaf hashes from the same session data.
/// The `merkle_leaf_hash` field of `ReserveBatchEntry` is no longer used in
/// the leaf hash computation and is ignored here.
pub fn compute_merkle_leaf_hash_from_entry(entry: &ReserveBatchEntry) -> [u8; 32] {
    // Recompute batch_hash identically to compute_merkle_leaf_hash_from_release.
    let batch_hash = hashv(&[
        entry.client_pubkey.as_slice(),
        entry.session_id.as_slice(),
        &entry.highest_seq.to_le_bytes(),
    ]).to_bytes();
    compute_merkle_leaf_hash(
        &entry.client_pubkey,
        &entry.session_id,
        entry.highest_seq,
        &batch_hash,
        entry.bytes,
        entry.record_count,
    )
}

/// Convenience wrapper: compute leaf hash from a ClientReleaseOnChain.
///
/// Internally computes `batch_hash = SHA-256(client_pubkey || session_id || batch_nonce)`.
pub fn compute_merkle_leaf_hash_from_release(release: &ClientReleaseOnChain) -> [u8; 32] {
    let batch_hash = hashv(&[
        release.client_pubkey.as_slice(),
        release.session_id.as_slice(),
        &release.batch_nonce.to_le_bytes(),
    ]).to_bytes();
    compute_merkle_leaf_hash(
        &release.client_pubkey,
        &release.session_id,
        release.batch_nonce,
        &batch_hash,
        release.total_bytes,
        release.record_count,
    )
}

#[cfg(test)]
mod leaf_without_amount_tests {
    use super::*;

    #[test]
    fn leaf_is_stable_and_amount_free() {
        let client  = [1u8; 32];
        let session = [2u8; 16];
        let batch   = [3u8; 32];
        let a = compute_merkle_leaf_hash(&client, &session, 5, &batch, 1_000_000, 7);
        let b = compute_merkle_leaf_hash(&client, &session, 5, &batch, 1_000_000, 7);
        assert_eq!(a, b, "leaf must be deterministic");
    }

    #[test]
    fn bytes_still_bind_the_leaf() {
        // bytes is now the sole quantity driving value, so it must be committed.
        let client  = [1u8; 32];
        let session = [2u8; 16];
        let batch   = [3u8; 32];
        let a = compute_merkle_leaf_hash(&client, &session, 5, &batch, 1_000_000, 7);
        let b = compute_merkle_leaf_hash(&client, &session, 5, &batch, 2_000_000, 7);
        assert_ne!(a, b, "different bytes must produce different leaves");
    }
}
