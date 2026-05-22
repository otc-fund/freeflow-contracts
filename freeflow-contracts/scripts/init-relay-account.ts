/**
 * init-relay-account.ts
 *
 * Pre-allocates a relay's reward_account using create_account_with_seed.
 *
 * D:/Solana canonical process_claim (ClaimRewards disc=0) writes to reward_account
 * but never allocates it — the account must exist and be owned by the rewards program
 * before the first ClaimRewards call or the transaction will fail.
 *
 * Derivation: SHA-256(relay_wallet || "freeflow-reward-v1" || rewards_program_id)
 * This matches create_with_seed(base=relay_wallet, seed="freeflow-reward-v1", program)
 * and the sidecar's derive_reward_account() function.
 *
 * Run once per relay, before their first claim:
 *
 *   set ANCHOR_WALLET=D:\Solana\Wallet\id.json   # payer (covers rent)
 *   set RELAY_PUBKEY=<relay base58 pubkey>
 *   set ANCHOR_PROVIDER_URL=https://api.devnet.solana.com
 *   set TS_NODE_TRANSPILE_ONLY=true
 *   node --no-experimental-strip-types node_modules\.bin\ts-node scripts\init-relay-account.ts
 *
 * Notes:
 *   - The payer covers rent (~0.0012 SOL for 99 bytes).
 *   - SystemProgram.createAccountWithSeed requires the base pubkey (relay_wallet) to sign.
 *     If the payer IS the relay wallet (self-hosted mode), pass only [PAYER] as signers.
 *     If payer ≠ relay wallet, load the relay keypair and pass [PAYER, RELAY_KP].
 *   - RewardAccount::SIZE = 99 bytes (D:/Solana canonical, v2 with repFlow fields).
 */

import {
  Connection, Keypair, PublicKey, Transaction,
  sendAndConfirmTransaction, SystemProgram, LAMPORTS_PER_SOL,
} from "@solana/web3.js";
import { createHash } from "crypto";
import * as fs from "fs";

// ── Config ────────────────────────────────────────────────────────────────────

const RPC_URL       = process.env.ANCHOR_PROVIDER_URL ?? "https://api.devnet.solana.com";
const WALLET_PATH   = process.env.ANCHOR_WALLET
  ?? `${process.env.USERPROFILE}\\.config\\solana\\id.json`;
const REWARDS_PROG  = new PublicKey(
  process.env.REWARDS_PROG_ID ?? "2yeVew5qq5jf5zuoqiE2svVLRE9HTN6J2GfB9LopdM1C"
);
const RELAY_PUBKEY_STR = process.env.RELAY_PUBKEY;
// Optional: path to relay keypair (needed if payer ≠ relay wallet).
// If unset, assumes payer IS the relay wallet (self-hosted single-relay setup).
const RELAY_KEYPAIR_PATH = process.env.RELAY_KEYPAIR_PATH;

// RewardAccount::SIZE = 32+8+8+8+8+8+8+1+1+8+1+8 = 99 bytes
// (relay_wallet + total_lamports_claimed + total_bytes_routed + total_bytes_seeded +
//  total_uptime_seconds + last_claim_ts + claim_count + tier + bump +
//  repflow_balance + repflow_tier + total_cashback_earned)
const REWARD_ACCOUNT_SIZE = 99;
const SEED                = "freeflow-reward-v1";

if (!RELAY_PUBKEY_STR) {
  console.error("ERROR: Set RELAY_PUBKEY env var to the relay's base58 public key");
  process.exit(1);
}

const conn    = new Connection(RPC_URL, "confirmed");
const PAYER   = Keypair.fromSecretKey(
  Uint8Array.from(JSON.parse(fs.readFileSync(WALLET_PATH, "utf-8")))
);
const relayPk = new PublicKey(RELAY_PUBKEY_STR);

// ── Derivation ────────────────────────────────────────────────────────────────

/**
 * Derive reward_account address using the same SHA-256 formula as the sidecar's
 * derive_reward_account() function (which mirrors Solana's create_with_seed).
 *
 * Formula: SHA-256(relay_wallet_bytes || "freeflow-reward-v1" || program_id_bytes)
 */
function deriveRewardAccount(relayPk: PublicKey, programId: PublicKey): PublicKey {
  const h = createHash("sha256");
  h.update(relayPk.toBytes());
  h.update(Buffer.from(SEED));
  h.update(programId.toBytes());
  return new PublicKey(h.digest());
}

// ── Main ──────────────────────────────────────────────────────────────────────

async function main() {
  const rewardAccount = deriveRewardAccount(relayPk, REWARDS_PROG);

  console.log("=== init-relay-account ===");
  console.log(`RPC:             ${RPC_URL}`);
  console.log(`Payer:           ${PAYER.publicKey.toBase58()}`);
  console.log(`Relay:           ${relayPk.toBase58()}`);
  console.log(`Rewards program: ${REWARDS_PROG.toBase58()}`);
  console.log(`reward_account:  ${rewardAccount.toBase58()}`);
  console.log(`Size:            ${REWARD_ACCOUNT_SIZE} bytes`);
  console.log("");

  // Check if already allocated
  const existing = await conn.getAccountInfo(rewardAccount);
  if (existing) {
    console.log(`Account already exists (${existing.data.length} bytes, owner: ${existing.owner.toBase58()}) — nothing to do.`);
    if (!existing.owner.equals(REWARDS_PROG)) {
      console.warn(`WARNING: account owner ${existing.owner.toBase58()} != rewards program ${REWARDS_PROG.toBase58()}`);
    }
    return;
  }

  const rent = await conn.getMinimumBalanceForRentExemption(REWARD_ACCOUNT_SIZE);
  const payerBalance = await conn.getBalance(PAYER.publicKey);
  console.log(`Rent required:   ${rent} lamports (~${(rent / LAMPORTS_PER_SOL).toFixed(6)} SOL)`);
  console.log(`Payer balance:   ${payerBalance} lamports`);

  if (payerBalance < rent + 5000) {
    throw new Error(`Payer balance too low: need at least ${rent + 5000} lamports`);
  }

  // Build the createAccountWithSeed instruction.
  // basePubkey = relayPk — relay_wallet must sign.
  // If payer IS the relay (self-hosted), PAYER.publicKey == relayPk and one signer suffices.
  const ix = SystemProgram.createAccountWithSeed({
    fromPubkey:      PAYER.publicKey,
    newAccountPubkey: rewardAccount,
    basePubkey:      relayPk,
    seed:            SEED,
    lamports:        rent,
    space:           REWARD_ACCOUNT_SIZE,
    programId:       REWARDS_PROG,
  });

  // Determine signers:
  // - If RELAY_KEYPAIR_PATH is set, load relay keypair (payer ≠ relay case)
  // - Otherwise assume payer IS the relay wallet
  let signers: Keypair[];
  if (RELAY_KEYPAIR_PATH) {
    const relayKp = Keypair.fromSecretKey(
      Uint8Array.from(JSON.parse(fs.readFileSync(RELAY_KEYPAIR_PATH, "utf-8")))
    );
    if (!relayKp.publicKey.equals(relayPk)) {
      throw new Error(
        `RELAY_KEYPAIR_PATH pubkey (${relayKp.publicKey.toBase58()}) ` +
        `does not match RELAY_PUBKEY (${relayPk.toBase58()})`
      );
    }
    signers = PAYER.publicKey.equals(relayPk) ? [PAYER] : [PAYER, relayKp];
    console.log("Using separate relay keypair from RELAY_KEYPAIR_PATH");
  } else {
    if (!PAYER.publicKey.equals(relayPk)) {
      throw new Error(
        `Payer (${PAYER.publicKey.toBase58()}) != relay (${relayPk.toBase58()}).\n` +
        `Set RELAY_KEYPAIR_PATH to the relay's keypair file, or set ANCHOR_WALLET ` +
        `to the relay's own keypair.`
      );
    }
    signers = [PAYER];
    console.log("Payer == relay wallet (self-hosted mode)");
  }

  console.log("\nAllocating reward_account...");
  const tx  = new Transaction().add(ix);
  const sig = await sendAndConfirmTransaction(conn, tx, signers);
  console.log(`OK — reward_account created.`);
  console.log(`Sig: ${sig}`);
  console.log(`Address: ${rewardAccount.toBase58()}`);
}

main().catch(e => { console.error(e); process.exit(1); });
