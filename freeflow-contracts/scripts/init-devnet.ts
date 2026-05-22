/**
 * init-devnet.ts
 *
 * One-time on-chain initialization for the D:/Solana canonical rewards program.
 * Must be run AFTER deploying upgraded programs and BEFORE any relay submits claims.
 *
 * Steps performed (in order):
 *   1. InitializeRewardsConfig  (disc=8)  — creates RewardsConfig PDA
 *   2. InitializeRewardRates    (disc=16) — creates ["reward_rates"] PDA with initial values
 *   3. InitializeTreasuryConfig (disc=18) — creates ["treasury_config"] PDA
 *   4. TransferMintAuthority             — sets $FLOW mint authority → ["mint_authority"] PDA
 *      ⚠️  Run ONLY after programs are deployed and verified
 *   5. (Manual) register mint_authority PDA in user-escrow spender registry
 *      → run scripts/register-spender.ts separately after verifying user-escrow disc
 *   6. (Manual, irreversible) SetMigrationMode(false) when ready to open ClaimUsage
 *
 * Prerequisites:
 *   - ANCHOR_WALLET   = path to foundation key (8SL4dhn…)
 *   - Programs upgraded on devnet
 *   - Foundation wallet has ≥ 0.5 SOL for rent + fees
 *
 * Run:
 *   set ANCHOR_WALLET=D:\Solana\Wallet\id.json
 *   set ANCHOR_PROVIDER_URL=https://api.devnet.solana.com
 *   set TS_NODE_TRANSPILE_ONLY=true
 *   node --no-experimental-strip-types node_modules\.bin\ts-node scripts\init-devnet.ts
 *
 * To skip the mint authority transfer (safest default on first run):
 *   set SKIP_MINT_AUTHORITY=1
 */

import {
  Connection, Keypair, PublicKey, Transaction,
  sendAndConfirmTransaction, SystemProgram, LAMPORTS_PER_SOL,
  TransactionInstruction,
} from "@solana/web3.js";
import * as spl from "@solana/spl-token";
import * as fs from "fs";

// ── Config ────────────────────────────────────────────────────────────────────

const RPC_URL      = process.env.ANCHOR_PROVIDER_URL ?? "https://api.devnet.solana.com";
const WALLET_PATH  = process.env.ANCHOR_WALLET
  ?? `${process.env.USERPROFILE}\\.config\\solana\\id.json`;
const REWARDS_PROG = new PublicKey(
  process.env.REWARDS_PROG_ID ?? "2yeVew5qq5jf5zuoqiE2svVLRE9HTN6J2GfB9LopdM1C"
);
// repflow_token_program_id and flow_mint are the same address
const FLOW_MINT    = new PublicKey("8K4GhPEQ1yy9vdTaMPTL83G5qr5ZHZiBm2VBQ58jJs5w");
const SKIP_MINT    = !!process.env.SKIP_MINT_AUTHORITY;

const conn       = new Connection(RPC_URL, "confirmed");
const FOUNDATION = Keypair.fromSecretKey(
  Uint8Array.from(JSON.parse(fs.readFileSync(WALLET_PATH, "utf-8")))
);

// ── Helpers ───────────────────────────────────────────────────────────────────

function log(step: string, msg: string) {
  console.log(`[${step}] ${msg}`);
}

async function skipIfExists(label: string, pdaKey: PublicKey): Promise<boolean> {
  const info = await conn.getAccountInfo(pdaKey);
  if (info && info.data.length > 0) {
    log(label, `already initialized (${info.data.length} bytes) — skipping`);
    return true;
  }
  return false;
}

async function sendIx(label: string, ix: TransactionInstruction): Promise<string> {
  const tx  = new Transaction().add(ix);
  const sig = await sendAndConfirmTransaction(conn, tx, [FOUNDATION]);
  log(label, `OK — sig: ${sig}`);
  return sig;
}

// ── Step 1: InitializeRewardsConfig (disc=8) ──────────────────────────────────
// Creates the RewardsConfig PDA ["rewards_config"].
// No fields in the instruction data beyond the discriminant.
async function step1_initRewardsConfig() {
  const [pda] = PublicKey.findProgramAddressSync(
    [Buffer.from("rewards_config")], REWARDS_PROG
  );
  log("1/6", `RewardsConfig PDA = ${pda.toBase58()}`);
  if (await skipIfExists("1/6", pda)) return;

  await sendIx("1/6", new TransactionInstruction({
    programId: REWARDS_PROG,
    keys: [
      { pubkey: FOUNDATION.publicKey, isSigner: true,  isWritable: true  },
      { pubkey: pda,                  isSigner: false, isWritable: true  },
      { pubkey: SystemProgram.programId, isSigner: false, isWritable: false },
    ],
    data: Buffer.from([8]), // disc=8 = InitializeRewardsConfig
  }));
}

// ── Step 2: InitializeRewardRates (disc=16) ───────────────────────────────────
// Creates the ["reward_rates"] PDA with initial rate values.
// Initial values match sidecar RewardRatesOnChain defaults:
//   routing_per_mb  = 1_000
//   seeding_per_mb  = 2_000
//   uptime_per_hour = 10_000_000
//   flow_price_cents = 0  (price oracle updates this separately)
async function step2_initRewardRates() {
  const [pda] = PublicKey.findProgramAddressSync(
    [Buffer.from("reward_rates")], REWARDS_PROG
  );
  log("2/6", `RewardRates PDA = ${pda.toBase58()}`);
  if (await skipIfExists("2/6", pda)) return;

  // disc=16 (1 byte) + 4 × u64le (32 bytes) = 33 bytes
  const data = Buffer.alloc(33);
  data.writeUInt8(16, 0);
  data.writeBigUInt64LE(1_000n, 1);          // routing_per_mb
  data.writeBigUInt64LE(2_000n, 9);          // seeding_per_mb
  data.writeBigUInt64LE(10_000_000n, 17);    // uptime_per_hour
  data.writeBigUInt64LE(0n, 25);             // flow_price_cents

  await sendIx("2/6", new TransactionInstruction({
    programId: REWARDS_PROG,
    keys: [
      { pubkey: FOUNDATION.publicKey, isSigner: true,  isWritable: true  },
      { pubkey: pda,                  isSigner: false, isWritable: true  },
      { pubkey: SystemProgram.programId, isSigner: false, isWritable: false },
    ],
    data,
  }));
}

// ── Step 3: InitializeTreasuryConfig (disc=18) ────────────────────────────────
// Creates ["treasury_config"] PDA with the foundation key as the sole treasury member.
// Borsh Vec<[u8;32]>: u32le length prefix + 32 bytes per element.
async function step3_initTreasuryConfig() {
  const [pda] = PublicKey.findProgramAddressSync(
    [Buffer.from("treasury_config")], REWARDS_PROG
  );
  log("3/6", `TreasuryConfig PDA = ${pda.toBase58()}`);
  if (await skipIfExists("3/6", pda)) return;

  const foundationBytes = FOUNDATION.publicKey.toBytes();
  // disc=18 (1) + u32le count (4) + 32-byte key (32) = 37 bytes
  const data = Buffer.alloc(37);
  data.writeUInt8(18, 0);
  data.writeUInt32LE(1, 1);   // 1 treasury key
  data.set(foundationBytes, 5);

  await sendIx("3/6", new TransactionInstruction({
    programId: REWARDS_PROG,
    keys: [
      { pubkey: FOUNDATION.publicKey, isSigner: true,  isWritable: true  },
      { pubkey: pda,                  isSigner: false, isWritable: true  },
      { pubkey: SystemProgram.programId, isSigner: false, isWritable: false },
    ],
    data,
  }));
}

// ── Step 4: Transfer $FLOW mint authority → ["mint_authority"] PDA ────────────
// Without this, ReleaseRewards / ForceResolve / SweepExpiredEscrow cannot mint $FLOW.
// The foundation key must currently hold mint authority.
// ⚠️  IRREVERSIBLE unless the new mint_authority PDA co-signs a second transfer.
async function step4_transferMintAuthority() {
  if (SKIP_MINT) {
    log("4/6", "skipped (SKIP_MINT_AUTHORITY=1) — run again without this env var when ready");
    return;
  }

  const [mintAuthorityPda] = PublicKey.findProgramAddressSync(
    [Buffer.from("mint_authority")], REWARDS_PROG
  );
  log("4/6", `mint_authority PDA = ${mintAuthorityPda.toBase58()}`);

  // Check current mint authority
  const mintInfo = await spl.getMint(conn, FLOW_MINT);
  if (!mintInfo.mintAuthority) {
    log("4/6", "FLOW mint has no mint authority — already frozen, skipping");
    return;
  }
  if (mintInfo.mintAuthority.equals(mintAuthorityPda)) {
    log("4/6", "mint authority already set to rewards PDA — skipping");
    return;
  }
  if (!mintInfo.mintAuthority.equals(FOUNDATION.publicKey)) {
    log("4/6", `WARNING: mint authority is ${mintInfo.mintAuthority.toBase58()}, not foundation — cannot transfer`);
    return;
  }

  log("4/6", `Transferring mint authority: ${FOUNDATION.publicKey.toBase58()} → ${mintAuthorityPda.toBase58()}`);
  const sig = await spl.setAuthority(
    conn,
    FOUNDATION,                      // payer + signer
    FLOW_MINT,                       // mint account
    FOUNDATION.publicKey,            // current authority
    spl.AuthorityType.MintTokens,    // authority type
    mintAuthorityPda,                // new authority
  );
  log("4/6", `OK — sig: ${sig}`);
}

// ── Step 5: Manual — register mint_authority PDA in user-escrow ───────────────
function step5_note() {
  const [mintAuthorityPda] = PublicKey.findProgramAddressSync(
    [Buffer.from("mint_authority")], REWARDS_PROG
  );
  log("5/6", "MANUAL STEP — register mint_authority PDA in user-escrow spender registry:");
  log("5/6", `  mint_authority PDA = ${mintAuthorityPda.toBase58()}`);
  log("5/6", "  Verify user-escrow UpdateSpenderRegistry discriminant, then run:");
  log("5/6", "  node --no-experimental-strip-types node_modules\\.bin\\ts-node scripts\\register-spender.ts");
}

// ── Step 6: Manual — SetMigrationMode(false) — IRREVERSIBLE ──────────────────
function step6_note() {
  log("6/6", "MANUAL STEP — SetMigrationMode(false) (disc=10) when ready to open ClaimUsage:");
  log("6/6", "  This is IRREVERSIBLE once set to false.");
  log("6/6", "  Data: [10, 0]  Accounts: [foundation(signer), rewards_config_pda]");
  log("6/6", "  Only run this when the full sidecar fix is deployed and verified.");
}

// ── Main ──────────────────────────────────────────────────────────────────────

async function main() {
  console.log("=== FreeFlow D:/Solana Canonical On-chain Initialization ===");
  console.log(`RPC:        ${RPC_URL}`);
  console.log(`Foundation: ${FOUNDATION.publicKey.toBase58()}`);
  console.log(`Rewards:    ${REWARDS_PROG.toBase58()}`);
  console.log(`FLOW mint:  ${FLOW_MINT.toBase58()}`);
  console.log(`Skip mint:  ${SKIP_MINT}`);
  console.log("");

  const balance = await conn.getBalance(FOUNDATION.publicKey);
  console.log(`Foundation balance: ${balance / LAMPORTS_PER_SOL} SOL`);
  if (balance < 0.1 * LAMPORTS_PER_SOL) {
    throw new Error(`Foundation balance too low (${balance} lamports) — needs at least 0.1 SOL`);
  }

  await step1_initRewardsConfig();
  await step2_initRewardRates();
  await step3_initTreasuryConfig();
  await step4_transferMintAuthority();
  step5_note();
  step6_note();

  console.log("\n=== Initialization complete ===");
  const [rewardsConfigPda]  = PublicKey.findProgramAddressSync([Buffer.from("rewards_config")],  REWARDS_PROG);
  const [rewardRatesPda]    = PublicKey.findProgramAddressSync([Buffer.from("reward_rates")],    REWARDS_PROG);
  const [treasuryConfigPda] = PublicKey.findProgramAddressSync([Buffer.from("treasury_config")], REWARDS_PROG);
  const [mintAuthorityPda]  = PublicKey.findProgramAddressSync([Buffer.from("mint_authority")],  REWARDS_PROG);
  console.log(`rewards_config PDA:  ${rewardsConfigPda.toBase58()}`);
  console.log(`reward_rates PDA:    ${rewardRatesPda.toBase58()}`);
  console.log(`treasury_config PDA: ${treasuryConfigPda.toBase58()}`);
  console.log(`mint_authority PDA:  ${mintAuthorityPda.toBase58()}`);
}

main().catch(e => { console.error(e); process.exit(1); });
