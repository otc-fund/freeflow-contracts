//! Foundation-signed reachability attestation verification (deadweight-relay gate).
//!
//! The relay's sidecar fetches a daily Ed25519 attestation from the foundation
//! (signed only for relays the foundation has actively probed as reachable) and
//! submits it as a Solana Ed25519SigVerify instruction in the same transaction
//! as `claim_daily_uptime_repflow`. The Solana runtime verifies the signature;
//! this module re-derives the expected message and checks the signer is the
//! foundation authority — so the relay cannot forge or replay it across days.

use anchor_lang::prelude::*;
use anchor_lang::solana_program::sysvar::instructions::{
    load_current_index_checked, load_instruction_at_checked,
};
use crate::error::RepFlowError;

pub const REACH_DOMAIN: &[u8] = b"ffreach:v1";

pub const ED25519_PROGRAM_ID: Pubkey =
    pubkey!("Ed25519SigVerify111111111111111111111111111");

/// Canonical 50-byte attestation message: domain || relay_wallet || date_bucket_le.
pub fn reachability_message(relay_wallet: &Pubkey, date_bucket: i64) -> [u8; 50] {
    let mut m = [0u8; 50];
    m[..10].copy_from_slice(REACH_DOMAIN);
    m[10..42].copy_from_slice(relay_wallet.as_ref());
    m[42..50].copy_from_slice(&date_bucket.to_le_bytes());
    m
}

/// Parse a single-signature Ed25519 instruction whose signature/pubkey/message
/// are embedded in its own data (the only shape the sidecar produces). Returns
/// `(signer_pubkey, message)`. None on any unexpected layout (multi-sig,
/// out-of-bounds, or offsets referencing other instructions).
pub fn parse_ed25519_ix(data: &[u8]) -> Option<([u8; 32], Vec<u8>)> {
    if data.len() < 16 || data[0] != 1 {
        return None; // need exactly one signature
    }
    let rd_u16 = |o: usize| u16::from_le_bytes([data[o], data[o + 1]]) as usize;
    let sig_off    = rd_u16(2);
    let sig_ix_idx = rd_u16(4);
    let pk_off     = rd_u16(6);
    let pk_ix_idx  = rd_u16(8);
    let msg_off    = rd_u16(10);
    let msg_size   = rd_u16(12);
    let msg_ix_idx = rd_u16(14);

    let here = u16::MAX as usize;
    if sig_ix_idx != here || pk_ix_idx != here || msg_ix_idx != here {
        return None; // we only accept self-contained instructions
    }
    let pk_end = pk_off.checked_add(32)?;
    let msg_end = msg_off.checked_add(msg_size)?;
    if sig_off.checked_add(64)? > data.len() || pk_end > data.len() || msg_end > data.len() {
        return None;
    }
    let mut pk = [0u8; 32];
    pk.copy_from_slice(&data[pk_off..pk_end]);
    Some((pk, data[msg_off..msg_end].to_vec()))
}

/// Verify that the transaction contains a foundation-signed reachability
/// attestation for `(relay_wallet, today's date_bucket)`. The Solana runtime has
/// already cryptographically verified the Ed25519 instruction; here we confirm
/// the signer identity and message match. `now` is the on-chain clock.
pub fn verify_reachability_attestation(
    instructions_sysvar: &AccountInfo,
    relay_wallet: &Pubkey,
    now: i64,
) -> Result<()> {
    let date_bucket = now / 86_400;
    let expected = reachability_message(relay_wallet, date_bucket);

    let current = load_current_index_checked(instructions_sysvar)? as usize;
    // Scan all instructions before the current one for the Ed25519 program ix.
    for i in 0..current {
        let ix = load_instruction_at_checked(i, instructions_sysvar)?;
        if ix.program_id != ED25519_PROGRAM_ID {
            continue;
        }
        if let Some((signer, msg)) = parse_ed25519_ix(&ix.data) {
            if signer == crate::REACHABILITY_AUTHORITY.to_bytes()
                && msg.as_slice() == expected.as_slice()
            {
                return Ok(());
            }
        }
    }
    Err(error!(RepFlowError::Unreachable))
}

#[cfg(test)]
mod tests {
    use super::*;
    use anchor_lang::prelude::Pubkey;

    #[test]
    fn message_layout_is_50_bytes() {
        let pk = Pubkey::new_from_array([3u8; 32]);
        let m = reachability_message(&pk, 19_700);
        assert_eq!(m.len(), 50);
        assert_eq!(&m[..10], b"ffreach:v1");
        assert_eq!(&m[10..42], &[3u8; 32]);
        assert_eq!(&m[42..50], &19_700i64.to_le_bytes());
    }

    // Build the exact byte layout the Solana Ed25519 program expects for a
    // single embedded signature, then parse it back.
    #[test]
    fn parse_roundtrips_embedded_ed25519_ix() {
        let pubkey = [7u8; 32];
        let sig = [9u8; 64];
        let msg = b"hello-reach".to_vec();

        // Header: count(1) + padding(1) + 6 * u16 offsets = 16 bytes, then
        // signature(64) || pubkey(32) || message(N), all in this ix's data.
        let mut data = Vec::new();
        data.push(1u8);                 // num signatures
        data.push(0u8);                 // padding
        let sig_off = 16u16;
        let pk_off  = sig_off + 64;
        let msg_off = pk_off + 32;
        let ix_idx  = u16::MAX;         // "this instruction"
        data.extend_from_slice(&sig_off.to_le_bytes());
        data.extend_from_slice(&ix_idx.to_le_bytes());   // sig ix index
        data.extend_from_slice(&pk_off.to_le_bytes());
        data.extend_from_slice(&ix_idx.to_le_bytes());   // pk ix index
        data.extend_from_slice(&msg_off.to_le_bytes());
        data.extend_from_slice(&(msg.len() as u16).to_le_bytes());
        data.extend_from_slice(&ix_idx.to_le_bytes());   // msg ix index
        data.extend_from_slice(&sig);
        data.extend_from_slice(&pubkey);
        data.extend_from_slice(&msg);

        let (got_pk, got_msg) = parse_ed25519_ix(&data).unwrap();
        assert_eq!(got_pk, pubkey);
        assert_eq!(got_msg, msg);
    }

    #[test]
    fn parse_rejects_multi_sig_or_external_refs() {
        let mut data = vec![2u8, 0u8]; // 2 signatures => unsupported
        data.extend_from_slice(&[0u8; 14]);
        assert!(parse_ed25519_ix(&data).is_none());
    }
}
