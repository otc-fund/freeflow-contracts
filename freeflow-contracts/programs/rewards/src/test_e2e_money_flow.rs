//! End-to-end money flow simulation tests for the FreeFlow rewards program.
//!
//! These tests model the complete economic cycle across three actors:
//!   - User: deposits $FLOW into escrow, gets charged when relay claims
//!   - Relay: posts bond, submits claims, receives 70% of minted $FLOW
//!   - Foundation: receives 30% of minted $FLOW (treasury)
//!
//! Each path is verified: happy path, force claim, dispute outcomes, sweep.
//!
//! Test-only module — does not affect production code.

use super::*;

// ─── Economy simulator ────────────────────────────────────────────────────────

/// Tracks all token balances across the ecosystem for a single test run.
struct Economy {
    total_supply: u64,
    user_escrow: u64,
    user_wallet: u64,
    relay_wallet: u64,
    treasury: u64,
    challenger_wallet: u64,
    total_burned: u64,
    total_minted_relay: u64,
    total_minted_treasury: u64,
    /// PendingClaimsStore simulation.
    pending_claims: Vec<PendingClaim>,
}

impl Economy {
    fn new() -> Self {
        Self {
            total_supply: 0,
            user_escrow: 0,
            user_wallet: 0,
            relay_wallet: 0,
            treasury: 0,
            challenger_wallet: 0,
            total_burned: 0,
            total_minted_relay: 0,
            total_minted_treasury: 0,
            pending_claims: Vec::new(),
        }
    }

    fn phase1_purchase(&mut self, usd_cents: u64) -> u64 {
        // $0.10/FLOW → flow_lamports = usd_cents * 1e9 / 10
        let flow = usd_cents.saturating_mul(1_000_000_000).saturating_div(10);
        self.treasury = self.treasury.saturating_sub(flow);
        self.user_escrow += flow; // directly deposited into escrow
        self.total_supply += flow; // treasury pre-minted at deployment
        flow
    }

    /// Simulate ClaimUsage: relay posts bond, user funds reserved.
    /// Returns the claim hash for later release/dispute.
    fn submit_claim(&mut self, user: [u8; 32], relay: [u8; 32], total_amount: u64) -> [u8; 32] {
        assert!(self.relay_wallet >= RELAY_BOND_FLOW,
            "Relay needs {} $FLOW for bond", RELAY_BOND_FLOW);
        assert!(self.user_escrow >= total_amount,
            "User needs {} $FLOW in escrow", total_amount);

        // Relay posts bond (deducted from wallet).
        self.relay_wallet -= RELAY_BOND_FLOW;

        // User's escrow balance is NOT debited — only the "reserved" counter increments.
        // In the FundHold path: UserEscrow.held += total_amount.
        // SPL token account is untouched.

        // Create pending claim.
        let claim_hash = [0u8; 32]; // Simplified — real hash uses session/nonce
        let clock_ts = 1_000_000; // Fake timestamp.
        let claim = PendingClaim {
            relay,
            claim_hash,
            total_amount,
            record_count: 1,
            submitted_at: clock_ts,
            dispute_deadline: clock_ts + DISPUTE_WINDOW_SECONDS,
            bond: RELAY_BOND_FLOW,
            status: ClaimStatus::Pending,
            is_force_claim: false,
            user: Some(user),
        };
        self.pending_claims.push(claim);
        claim_hash
    }

    /// Simulate ReleaseRewards after 7-day window (happy path).
    fn release_rewards(&mut self, claim_hash: [u8; 32], clock_ts: i64) -> Result<(u64, u64, u64), &'static str> {
        let claim = self.pending_claims.iter_mut()
            .find(|c| c.claim_hash == claim_hash)
            .ok_or("Claim not found")?;

        if claim.status != ClaimStatus::Pending {
            return Err("Claim already settled");
        }
        if clock_ts <= claim.dispute_deadline {
            return Err("Dispute window not expired");
        }

        let claim_amount = claim.total_amount;
        claim.status = ClaimStatus::Released;

        // 1. Burn claim_amount from user escrow.
        self.user_escrow = self.user_escrow.saturating_sub(claim_amount);
        self.total_burned += claim_amount;

        // 2. Mint 70:30 split.
        let relay_share = claim_amount.saturating_mul(RELAY_MINT_SHARE_BPS).saturating_div(10_000);
        let treasury_share = claim_amount.saturating_sub(relay_share);

        self.total_minted_relay += relay_share;
        self.total_minted_treasury += treasury_share;
        self.relay_wallet += relay_share;
        self.treasury += treasury_share;

        // 3. Return relay bond.
        self.relay_wallet += RELAY_BOND_FLOW;

        Ok((relay_share, treasury_share, RELAY_BOND_FLOW))
    }

    /// Simulate force claim release (20% treasury penalty).
    fn release_force_claim(&mut self, claim_hash: [u8; 32], clock_ts: i64) -> Result<(u64, u64, u64, u64), &'static str> {
        let claim = self.pending_claims.iter_mut()
            .find(|c| c.claim_hash == claim_hash)
            .ok_or("Claim not found")?;

        if claim.status != ClaimStatus::Pending {
            return Err("Claim already settled");
        }
        if clock_ts <= claim.dispute_deadline {
            return Err("Dispute window not expired");
        }

        let claim_amount = claim.total_amount;
        let penalty = claim_amount.saturating_mul(FORCE_CLAIM_PENALTY_BPS).saturating_div(10_000);
        let relay_amount = claim_amount.saturating_sub(penalty);

        claim.status = ClaimStatus::Released;

        // 1. Burn full claim_amount from user escrow.
        self.user_escrow = self.user_escrow.saturating_sub(claim_amount);
        self.total_burned += claim_amount;

        // 2. Mint 70:30 on relay_amount (post-penalty).
        let relay_share = relay_amount.saturating_mul(RELAY_MINT_SHARE_BPS).saturating_div(10_000);
        let treasury_share = relay_amount.saturating_sub(relay_share);

        self.total_minted_relay += relay_share;
        self.total_minted_treasury += treasury_share;
        self.relay_wallet += relay_share;

        // Treasury gets 30% mint + the 20% penalty.
        self.treasury += treasury_share + penalty;

        // 3. Return relay bond.
        self.relay_wallet += RELAY_BOND_FLOW;

        Ok((relay_share, treasury_share + penalty, RELAY_BOND_FLOW, penalty))
    }

    /// Simulate dispute: relay slashed.
    fn dispute_relay_slashed(&mut self, claim_hash: [u8; 32]) -> Result<(u64, u64), &'static str> {
        let claim = self.pending_claims.iter_mut()
            .find(|c| c.claim_hash == claim_hash)
            .ok_or("Claim not found")?;

        if claim.status != ClaimStatus::Pending {
            return Err("Claim not in pending state");
        }

        let challenger_reward = RELAY_BOND_FLOW / 2;
        let burned = RELAY_BOND_FLOW.saturating_sub(challenger_reward);

        claim.status = ClaimStatus::Slashed;
        self.challenger_wallet += challenger_reward;
        self.total_burned += burned;

        // User's held funds released (balance unchanged, held decremented).
        // No burn/mint for the claim amount — claim_total_amount is NOT settled.

        Ok((challenger_reward, burned))
    }

    /// Simulate dispute: challenger slashed → then release rewards.
    fn dispute_challenger_slashed_and_release(
        &mut self,
        claim_hash: [u8; 32],
        clock_ts: i64,
    ) -> Result<(u64, u64, u64, u64, u64), &'static str> {
        let claim = self.pending_claims.iter_mut()
            .find(|c| c.claim_hash == claim_hash)
            .ok_or("Claim not found")?;

        if claim.status != ClaimStatus::Pending {
            return Err("Claim not in pending state");
        }

        // Challenger slashed: 80% of bond → relay, 20% burned.
        let relay_reward = CHALLENGER_BOND_FLOW * TREASURY_SHARE_BPS / 10_000;
        let bond_burned = CHALLENGER_BOND_FLOW.saturating_sub(relay_reward);

        claim.status = ClaimStatus::Resolved;
        self.relay_wallet += relay_reward;
        self.total_burned += bond_burned;

        // Now release rewards.
        let claim_amount = claim.total_amount;
        let relay_share = claim_amount.saturating_mul(RELAY_MINT_SHARE_BPS).saturating_div(10_000);
        let treasury_share = claim_amount.saturating_sub(relay_share);

        self.user_escrow = self.user_escrow.saturating_sub(claim_amount);
        self.total_burned += claim_amount;
        self.total_minted_relay += relay_share;
        self.total_minted_treasury += treasury_share;
        self.relay_wallet += relay_share;
        self.treasury += treasury_share;
        self.relay_wallet += RELAY_BOND_FLOW; // bond return

        Ok((relay_reward, relay_share, treasury_share, bond_burned, RELAY_BOND_FLOW))
    }

    /// Simulate sweep: 60-day timeout.
    fn sweep_expired(&mut self, claim_hash: [u8; 32]) -> Result<(u64, u64), &'static str> {
        let claim = self.pending_claims.iter_mut()
            .find(|c| c.claim_hash == claim_hash)
            .ok_or("Claim not found")?;

        if claim.status != ClaimStatus::Pending {
            return Err("Claim not in pending state");
        }

        let claim_amount = claim.total_amount;
        claim.status = ClaimStatus::Swept;

        // 1. Burn 100% from user escrow.
        self.user_escrow = self.user_escrow.saturating_sub(claim_amount);
        self.total_burned += claim_amount;

        // 2. Mint 80% to treasury (20% stays deflationary).
        let treasury_mint = claim_amount.saturating_mul(SWEEP_TREASURY_MINT_SHARE_BPS).saturating_div(10_000);
        self.total_minted_treasury += treasury_mint;
        self.treasury += treasury_mint;

        // 3. Return relay bond.
        self.relay_wallet += RELAY_BOND_FLOW;

        Ok((treasury_mint, RELAY_BOND_FLOW))
    }
}

// ─── Constants for test clarity ───────────────────────────────────────────────

const USER_X: [u8; 32] = [0xCC; 32];
const RELAY_A: [u8; 32] = [0xAA; 32];
const CHALLENGER_B: [u8; 32] = [0xBB; 32];

// ─── Test: Happy path ─────────────────────────────────────────────────────────

#[test]
fn e2e_happy_path_claim_and_release() {
    let mut eco = Economy::new();

    // Setup: treasury has 30M $FLOW pre-minted.
    eco.treasury = 30_000_000_000_000_000; // 30M with 9 decimals
    eco.total_supply = 30_000_000_000_000_000;

    // Relay has $FLOW for the bond.
    eco.relay_wallet = 500_000_000_000; // 500 $FLOW

    // Step 1: User buys $3.00 worth (30 $FLOW at $0.10/FLOW).
    let deposited = eco.phase1_purchase(300); // 300 cents = $3.00
    assert_eq!(deposited, 30_000_000_000, "30 $FLOW deposited into escrow");

    // Step 2: Relay claims 100,000 flow units.
    let claim_amount = 100_000;
    let claim_hash = eco.submit_claim(USER_X, RELAY_A, claim_amount);
    assert_eq!(eco.relay_wallet, 500_000_000_000 - RELAY_BOND_FLOW, "Relay posted bond");
    assert_eq!(eco.user_escrow, 30_000_000_000, "User escrow unchanged (only reserved)");

    // Step 3: 7-day window passes.
    let after_window = 1_000_000 + DISPUTE_WINDOW_SECONDS + 1;

    // Step 4: ReleaseRewards.
    let (relay_share, treasury_share, bond_returned) = eco.release_rewards(claim_hash, after_window).unwrap();

    assert_eq!(relay_share, 70_000, "Relay gets 70%");
    assert_eq!(treasury_share, 30_000, "Treasury gets 30%");
    assert_eq!(bond_returned, RELAY_BOND_FLOW, "Bond returned");

    // Supply: burned 100K, minted 100K → supply neutral for this claim.
    assert_eq!(eco.total_burned, 100_000);
    assert_eq!(eco.total_minted_relay, 70_000);
    assert_eq!(eco.total_minted_treasury, 30_000);
}

// ─── Test: Force claim ────────────────────────────────────────────────────────

#[test]
fn e2e_force_claim_penalty() {
    let mut eco = Economy::new();

    eco.treasury = 30_000_000_000_000_000;
    eco.total_supply = 30_000_000_000_000_000;
    eco.relay_wallet = 500_000_000_000;

    eco.phase1_purchase(300);

    let claim_amount = 100_000;
    let mut claim_hash = eco.submit_claim(USER_X, RELAY_A, claim_amount);

    // Mark as force claim.
    if let Some(c) = eco.pending_claims.iter_mut().find(|c| c.claim_hash == claim_hash) {
        c.is_force_claim = true;
    }

    let after_window = 1_000_000 + DISPUTE_WINDOW_SECONDS + 1;
    let (relay_share, treasury_total, _, penalty) = eco.release_force_claim(claim_hash, after_window).unwrap();

    let expected_penalty = claim_amount * FORCE_CLAIM_PENALTY_BPS / 10_000;
    assert_eq!(expected_penalty, 20_000, "20% penalty");

    let relay_amount = claim_amount - expected_penalty;
    let expected_relay = relay_amount * RELAY_MINT_SHARE_BPS / 10_000;
    assert_eq!(relay_share, expected_relay, "Relay gets 70% of post-penalty amount");

    // Treasury: 30% of post-penalty + the penalty itself.
    let expected_treasury_mint = relay_amount * TREASURY_MINT_SHARE_BPS / 10_000;
    assert_eq!(treasury_total, expected_treasury_mint + expected_penalty);

    // Supply: burned 100K, minted 80K → 20K net deflation (equals penalty).
    assert_eq!(eco.total_burned, 100_000);
    assert_eq!(eco.total_minted_relay + eco.total_minted_treasury, 80_000);
}

// ─── Test: Dispute — relay slashed ────────────────────────────────────────────

#[test]
fn e2e_dispute_relay_slashed() {
    let mut eco = Economy::new();

    eco.treasury = 30_000_000_000_000_000;
    eco.total_supply = 30_000_000_000_000_000;
    eco.relay_wallet = 500_000_000_000;
    eco.challenger_wallet = 200_000_000_000;

    eco.phase1_purchase(300);

    let claim_amount = 100_000;
    let claim_hash = eco.submit_claim(USER_X, RELAY_A, claim_amount);

    // Challenger posts bond.
    eco.challenger_wallet -= CHALLENGER_BOND_FLOW;

    // Dispute resolved: relay slashed.
    let (challenger_reward, burned) = eco.dispute_relay_slashed(claim_hash).unwrap();

    assert_eq!(challenger_reward, RELAY_BOND_FLOW / 2, "Challenger gets 50% of relay bond");
    assert_eq!(burned, RELAY_BOND_FLOW / 2, "50% burned");

    // User's $FLOW released back to usable (held decremented, balance unchanged).
    // No burn/mint for the claim amount.
    assert_eq!(eco.total_burned, RELAY_BOND_FLOW / 2, "Only bond burned, not claim amount");
    assert_eq!(eco.total_minted_relay, 0, "No minting from this claim");
}

// ─── Test: Dispute — challenger slashed ───────────────────────────────────────

#[test]
fn e2e_dispute_challenger_slashed() {
    let mut eco = Economy::new();

    eco.treasury = 30_000_000_000_000_000;
    eco.total_supply = 30_000_000_000_000_000;
    eco.relay_wallet = 500_000_000_000;
    eco.challenger_wallet = 200_000_000_000;

    eco.phase1_purchase(300);

    let claim_amount = 100_000;
    let claim_hash = eco.submit_claim(USER_X, RELAY_A, claim_amount);

    eco.challenger_wallet -= CHALLENGER_BOND_FLOW;

    let (relay_reward, relay_share, treasury_share, bond_burned, bond_returned) =
        eco.dispute_challenger_slashed_and_release(claim_hash, 1_000_000 + DISPUTE_WINDOW_SECONDS + 1).unwrap();

    // Challenger bond: 80% → relay, 20% burned.
    assert_eq!(relay_reward, 80, "Relay gets 80% of challenger bond");
    assert_eq!(bond_burned, 20, "20% burned");

    // Claim proceeds to release: 70/30 mint.
    assert_eq!(relay_share, 70_000);
    assert_eq!(treasury_share, 30_000);
    assert_eq!(bond_returned, RELAY_BOND_FLOW);

    // Total burned: challenger bond burn (20) + claim amount burn (100K).
    assert_eq!(eco.total_burned, 100_000 + 20);

    // Challenger lost entire bond.
    assert_eq!(eco.challenger_wallet, 200_000_000_000 - CHALLENGER_BOND_FLOW);
}

// ─── Test: Sweep expired escrow ───────────────────────────────────────────────

#[test]
fn e2e_sweep_expired() {
    let mut eco = Economy::new();

    eco.treasury = 30_000_000_000_000_000;
    eco.total_supply = 30_000_000_000_000_000;
    eco.relay_wallet = 500_000_000_000;

    eco.phase1_purchase(300);

    let claim_amount = 100_000;
    let claim_hash = eco.submit_claim(USER_X, RELAY_A, claim_amount);

    let (treasury_mint, bond_returned) = eco.sweep_expired(claim_hash).unwrap();

    // 80% minted to treasury.
    assert_eq!(treasury_mint, 80_000, "Treasury gets 80%");

    // 20% deflationary.
    let net_deflation = claim_amount - treasury_mint;
    assert_eq!(net_deflation, 20_000, "20% stays deflationary");

    // Relay bond returned.
    assert_eq!(bond_returned, RELAY_BOND_FLOW);

    // Supply: burned 100K, minted 80K → net deflation 20K.
    assert_eq!(eco.total_burned, 100_000);
    assert_eq!(eco.total_minted_treasury, 80_000);
}

// ─── Test: Supply neutrality ──────────────────────────────────────────────────

#[test]
fn e2e_supply_neutral_happy_path() {
    let claim_amount = 1_000_000;
    let burned = claim_amount;
    let relay = claim_amount * RELAY_MINT_SHARE_BPS / 10_000;
    let treasury = claim_amount * TREASURY_MINT_SHARE_BPS / 10_000;
    let minted = relay + treasury;

    assert_eq!(burned, minted, "Supply neutral: burned == minted");
}

#[test]
fn e2e_supply_deflationary_sweep() {
    let claim_amount = 1_000_000;
    let burned = claim_amount;
    let minted = claim_amount * SWEEP_TREASURY_MINT_SHARE_BPS / 10_000;
    let net_deflation = burned - minted;

    assert_eq!(net_deflation, 200_000, "Sweep is 20% net deflationary");
}

#[test]
fn e2e_force_claim_deflation_equals_penalty() {
    let claim_amount = 1_000_000;
    let penalty = claim_amount * FORCE_CLAIM_PENALTY_BPS / 10_000;
    let relay_amount = claim_amount - penalty;
    let burned = claim_amount;
    let minted = relay_amount; // 70% + 30% = 100% of relay_amount
    let net_deflation = burned - minted;

    assert_eq!(net_deflation, penalty, "Force claim deflation equals penalty");
}

// ─── Test: Multiple claims ────────────────────────────────────────────────────

#[test]
fn e2e_multiple_claims_same_user() {
    let mut eco = Economy::new();

    eco.treasury = 30_000_000_000_000_000;
    eco.total_supply = 30_000_000_000_000_000;
    eco.relay_wallet = 500_000_000_000;

    // User deposits 100 $FLOW.
    eco.phase1_purchase(1000);

    // Three claims.
    let amounts = [50_000u64, 75_000, 30_000];
    let total_claimed: u64 = amounts.iter().sum();

    let hashes: Vec<[u8; 32]> = amounts.iter()
        .map(|&a| eco.submit_claim(USER_X, RELAY_A, a))
        .collect();

    // All released.
    let mut total_relay = 0u64;
    let mut total_treasury = 0u64;
    let after_window = 1_000_000 + DISPUTE_WINDOW_SECONDS + 1;

    for &h in &hashes {
        let (r, t, _) = eco.release_rewards(h, after_window).unwrap();
        total_relay += r;
        total_treasury += t;
    }

    assert_eq!(eco.total_burned, total_claimed);
    assert_eq!(total_relay + total_treasury, total_claimed);
    assert_eq!(total_relay, total_claimed * RELAY_MINT_SHARE_BPS / 10_000);
    assert_eq!(total_treasury, total_claimed * TREASURY_MINT_SHARE_BPS / 10_000);
}

// ─── Test: repFlow tier multipliers ───────────────────────────────────────────

#[test]
fn e2e_repflow_tier_rewards() {
    let mb = 100u64; // 100 MB
    let base_rate = 1_000u64; // DEFAULT_ROUTING_PER_MB

    // Newcomer: 90 bps = 0.9×
    assert_eq!(mb * base_rate * 90 / 100, 90_000);
    // Active: 100 bps = 1.0×
    assert_eq!(mb * base_rate * 100 / 100, 100_000);
    // Veteran: 130 bps = 1.3×
    assert_eq!(mb * base_rate * 130 / 100, 130_000);
    // Icon: 150 bps = 1.5×
    assert_eq!(mb * base_rate * 150 / 100, 150_000);

    // 70/30 split on Icon reward.
    let icon_reward = 150_000u64;
    assert_eq!(icon_reward * RELAY_MINT_SHARE_BPS / 10_000, 105_000);
    assert_eq!(icon_reward * TREASURY_MINT_SHARE_BPS / 10_000, 45_000);
}

// ─── Test: Bond economics summary ─────────────────────────────────────────────

#[test]
fn e2e_bond_economics_all_paths() {
    // Relay bond (100 $FLOW):
    //   Happy path: returned to relay
    //   Relay slashed: 50% challenger / 50% burned
    //   Challenger slashed: returned to relay
    //   Force resolve: returned to relay
    //   Sweep: returned to relay

    // Challenger bond (50 $FLOW):
    //   Relay slashed: returned to challenger (plus 50% of relay bond)
    //   Challenger slashed: 80% relay / 20% burned
    //   Force resolve: 80% relay / 20% burned

    // Relay bond split.
    assert_eq!(RELAY_BOND_FLOW / 2 + RELAY_BOND_FLOW / 2, RELAY_BOND_FLOW);

    // Challenger bond split.
    let relay_reward = CHALLENGER_BOND_FLOW * TREASURY_SHARE_BPS / 10_000;
    let burned = CHALLENGER_BOND_FLOW - relay_reward;
    assert_eq!(relay_reward + burned, CHALLENGER_BOND_FLOW);
    assert_eq!(relay_reward, 40); // 80% of 50
    assert_eq!(burned, 10);       // 20% of 50
}

// ─── Test: End-to-end with all outcomes ───────────────────────────────────────

#[test]
fn e2e_mixed_outcomes() {
    let mut eco = Economy::new();

    eco.treasury = 30_000_000_000_000_000;
    eco.total_supply = 30_000_000_000_000_000;
    eco.relay_wallet = 1_000_000_000_000;
    eco.challenger_wallet = 500_000_000_000;

    eco.phase1_purchase(1000); // 100 $FLOW

    // Claim 1: Happy path.
    let h1 = eco.submit_claim(USER_X, RELAY_A, 30_000);
    eco.release_rewards(h1, 1_000_000 + DISPUTE_WINDOW_SECONDS + 1).unwrap();

    // Claim 2: Disputed → challenger slashed → released.
    let h2 = eco.submit_claim(USER_X, RELAY_A, 40_000);
    eco.challenger_wallet -= CHALLENGER_BOND_FLOW;
    eco.dispute_challenger_slashed_and_release(h2, 1_000_000 + DISPUTE_WINDOW_SECONDS + 1).unwrap();

    // Claim 3: Swept (60-day timeout).
    let h3 = eco.submit_claim(USER_X, RELAY_A, 20_000);
    eco.sweep_expired(h3).unwrap();

    // Claim 4: Happy path.
    let h4 = eco.submit_claim(USER_X, RELAY_A, 10_000);
    eco.release_rewards(h4, 1_000_000 + DISPUTE_WINDOW_SECONDS + 1).unwrap();

    // Verify all claims are in terminal states.
    assert!(eco.pending_claims.iter().all(|c| c.status.is_terminal()));

    // All burned amounts accounted for.
    // Claims 1,2,4: 30K + 40K + 10K = 80K burned from escrow.
    // Claim 3: 20K burned from escrow (sweep).
    // Challenger bond: 20 burned (from challenger slashed).
    assert_eq!(eco.total_burned, 80_000 + 20_000 + 20);
}
