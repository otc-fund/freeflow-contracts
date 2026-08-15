/**
 * init-rewards.ts — One-shot initialization of rewards program PDAs.
 *
 * Runs InitializeRewardsConfig, InitializeTreasuryConfig, InitializeBondConfig,
 * then SetMigrationMode(false) so ClaimUsage is open for business.
 *
 * Usage (devnet):
 *   npx ts-node scripts/init-rewards.ts
 *
 * Or (to skip SetMigrationMode so migration window stays active):
 *   KEEP_MIGRATION=1 npx ts-node scripts/init-rewards.ts
 */

import * as fs from "fs";
import * as path from "path";
import * as os from "os";
import {
  Connection,
  Keypair,
  PublicKey,
  Transaction,
  TransactionInstruction,
  SystemProgram,
  sendAndConfirmTransaction,
} from "@solana/web3.js";

// ─── Config ───────────────────────────────────────────────────────────────────

const RPC = process.env.ANCHOR_PROVIDER_URL ?? "https://api.devnet.solana.com";
const REWARDS_PROG_ID = new PublicKey("2yeVew5qq5jf5zuoqiE2svVLRE9HTN6J2GfB9LopdM1C");
const FOUNDATION_PUBKEY = new PublicKey("8SL4dhnXU9tjvsbwfkVzQbfV99wGnVZBECoiuwrdbaJk");

const WALLET_PATH =
  process.env.ANCHOR_WALLET ??
  path.join(os.homedir(), ".config", "solana", "id.json");

// ─── Borsh helpers ────────────────────────────────────────────────────────────

/** Write 1 byte (enum discriminant). */
function u8(n: number): Buffer {
  const b = Buffer.alloc(1);
  b.writeUInt8(n, 0);
  return b;
}

/** Write 8 bytes little-endian u64. */
function u64le(n: bigint): Buffer {
  const b = Buffer.alloc(8);
  b.writeBigUInt64LE(n, 0);
  return b;
}

/** Write 4 bytes little-endian u32 (Borsh Vec length). */
function u32le(n: number): Buffer {
  const b = Buffer.alloc(4);
  b.writeUInt32LE(n, 0);
  return b;
}

function cat(...bufs: Buffer[]): Buffer {
  return Buffer.concat(bufs);
}

// ─── RewardsInstruction enum indices ─────────────────────────────────────────
// Borsh encodes enum variants as 1 u8 index + fields.
// Enum order (0-indexed):
//   0  LegacyClaimRewards (disabled) 7 ReleaseRewards   14 CancelReconciliation
//   1  RecordBytes             8  InitializeRewardsConfig 15 PreMintFoundation
//   2  ClaimUsage              9  InitializeReservation 16 InitializeRewardRates
//   3  DisputeClaim           10  SetMigrationMode      17 UpdateRewardRates
//   4  ResolveDisputeRelaySlashed 11 SweepExpiredEscrow 18 InitializeTreasuryConfig
//   5  ResolveDisputeChallengerSlashed 12 RequestReconciliation 19 UpdateTreasuryPool
//   6  ForceResolve           13  ExecuteReconciliation 20 InitializeBondConfig
//                                                       21 UpdateBondConfig

const INIT_REWARDS_CONFIG_IX   = 8;
const SET_MIGRATION_MODE_IX    = 10;
const INIT_TREASURY_CONFIG_IX  = 18;
const INIT_BOND_CONFIG_IX      = 20;

// ─── PDA derivation ───────────────────────────────────────────────────────────

async function findPDA(seeds: Buffer[], programId: PublicKey): Promise<[PublicKey, number]> {
  return PublicKey.findProgramAddressSync(
    seeds.map(s => Uint8Array.from(s)),
    programId,
  );
}

// ─── main ─────────────────────────────────────────────────────────────────────

async function main() {
  const conn = new Connection(RPC, "confirmed");

  // Load foundation wallet (must be 8SL4dhn...)
  const walletBytes = JSON.parse(fs.readFileSync(WALLET_PATH, "utf-8"));
  const foundation = Keypair.fromSecretKey(Uint8Array.from(walletBytes));
  console.log(`Foundation wallet: ${foundation.publicKey.toBase58()}`);
  if (foundation.publicKey.toBase58() !== FOUNDATION_PUBKEY.toBase58()) {
    console.error(`ERROR: loaded wallet ${foundation.publicKey.toBase58()} is not FOUNDATION_PUBKEY`);
    process.exit(1);
  }

  const balance = await conn.getBalance(foundation.publicKey);
  console.log(`Balance: ${balance / 1e9} SOL`);

  // Derive PDAs.
  const [rewardsConfigPDA] = PublicKey.findProgramAddressSync(
    [Buffer.from("rewards_config")],
    REWARDS_PROG_ID,
  );
  const [treasuryConfigPDA] = PublicKey.findProgramAddressSync(
    [Buffer.from("treasury_config")],
    REWARDS_PROG_ID,
  );
  const [bondConfigPDA] = PublicKey.findProgramAddressSync(
    [Buffer.from("bond_config")],
    REWARDS_PROG_ID,
  );

  console.log(`rewards_config PDA:  ${rewardsConfigPDA.toBase58()}`);
  console.log(`treasury_config PDA: ${treasuryConfigPDA.toBase58()}`);
  console.log(`bond_config PDA:     ${bondConfigPDA.toBase58()}`);

  // ── Step 1: InitializeRewardsConfig ────────────────────────────────────────

  const rcInfo = await conn.getAccountInfo(rewardsConfigPDA);
  if (rcInfo !== null && rcInfo.data.length >= 20) {
    console.log("✓ rewards_config already initialized — skipping");
  } else {
    console.log("\nSending InitializeRewardsConfig...");
    const ixData = u8(INIT_REWARDS_CONFIG_IX); // No fields for this variant

    const ix = new TransactionInstruction({
      programId: REWARDS_PROG_ID,
      keys: [
        { pubkey: foundation.publicKey, isSigner: true,  isWritable: true  },
        { pubkey: rewardsConfigPDA,     isSigner: false, isWritable: true  },
        { pubkey: SystemProgram.programId, isSigner: false, isWritable: false },
      ],
      data: ixData,
    });

    const tx = new Transaction().add(ix);
    const sig = await sendAndConfirmTransaction(conn, tx, [foundation], {
      commitment: "confirmed",
    });
    console.log(`  ✓ InitializeRewardsConfig: ${sig}`);
  }

  // ── Step 2: InitializeTreasuryConfig ───────────────────────────────────────

  const tcInfo = await conn.getAccountInfo(treasuryConfigPDA);
  if (tcInfo !== null && tcInfo.data.length >= 44) {
    console.log("✓ treasury_config already initialized — skipping");
  } else {
    console.log("\nSending InitializeTreasuryConfig...");
    // InitializeTreasuryConfig { initial_treasury_keys: Vec<[u8; 32]> }
    // Vec encoding: u32 length LE + each [u8; 32]
    const foundationKeyBytes = Buffer.from(FOUNDATION_PUBKEY.toBytes());
    const ixData = cat(
      u8(INIT_TREASURY_CONFIG_IX),
      u32le(1),            // Vec length = 1
      foundationKeyBytes,  // The single 32-byte key
    );

    const ix = new TransactionInstruction({
      programId: REWARDS_PROG_ID,
      keys: [
        { pubkey: foundation.publicKey, isSigner: true,  isWritable: true  },
        { pubkey: treasuryConfigPDA,    isSigner: false, isWritable: true  },
        { pubkey: SystemProgram.programId, isSigner: false, isWritable: false },
      ],
      data: ixData,
    });

    const tx = new Transaction().add(ix);
    const sig = await sendAndConfirmTransaction(conn, tx, [foundation], {
      commitment: "confirmed",
    });
    console.log(`  ✓ InitializeTreasuryConfig: ${sig}`);
  }

  // ── Step 3: InitializeBondConfig ───────────────────────────────────────────

  const bcInfo = await conn.getAccountInfo(bondConfigPDA);
  if (bcInfo !== null && bcInfo.data.length >= 65) {
    console.log("✓ bond_config already initialized — skipping");
  } else {
    console.log("\nSending InitializeBondConfig...");
    // InitializeBondConfig { challenger_bond_cents, min_stake_usd_cents,
    //                        stake_earnings_bps, max_stake_flow }
    // All 0 → use on-chain defaults
    const ixData = cat(
      u8(INIT_BOND_CONFIG_IX),
      u64le(0n),  // challenger_bond_cents  (0 = default $1.25 = 125_000 micro-cents)
      u64le(0n),  // min_stake_usd_cents    (0 = default $2,500)
      u64le(0n),  // stake_earnings_bps     (0 = default 10% = 1_000 bps)
      u64le(0n),  // max_stake_flow         (0 = default 100_000 $FLOW)
    );

    const ix = new TransactionInstruction({
      programId: REWARDS_PROG_ID,
      keys: [
        { pubkey: foundation.publicKey, isSigner: true,  isWritable: true  },
        { pubkey: bondConfigPDA,        isSigner: false, isWritable: true  },
        { pubkey: SystemProgram.programId, isSigner: false, isWritable: false },
      ],
      data: ixData,
    });

    const tx = new Transaction().add(ix);
    const sig = await sendAndConfirmTransaction(conn, tx, [foundation], {
      commitment: "confirmed",
    });
    console.log(`  ✓ InitializeBondConfig: ${sig}`);
  }

  // ── Step 4: SetMigrationMode(false) ────────────────────────────────────────
  // IRREVERSIBLE — only skip if KEEP_MIGRATION=1

  if (process.env.KEEP_MIGRATION === "1") {
    console.log("\n⚠  KEEP_MIGRATION=1 — skipping SetMigrationMode(false)");
    console.log("   ClaimUsage is BLOCKED until you call SetMigrationMode(false).");
    console.log("   Run again without KEEP_MIGRATION=1 when ready.");
  } else {
    // Check current migration mode before sending.
    const rcInfoNow = await conn.getAccountInfo(rewardsConfigPDA);
    if (rcInfoNow && rcInfoNow.data.length >= 2 && rcInfoNow.data[0] === 0) {
      // migration_mode == false (first bool in struct)
      console.log("✓ migration_mode already false — skipping SetMigrationMode");
    } else {
      console.log("\nSending SetMigrationMode(false)...");
      // SetMigrationMode { enabled: bool }
      // bool = 1 byte: 0 = false
      const ixData = cat(u8(SET_MIGRATION_MODE_IX), u8(0));

      const ix = new TransactionInstruction({
        programId: REWARDS_PROG_ID,
        keys: [
          { pubkey: foundation.publicKey, isSigner: true,  isWritable: true  },
          { pubkey: rewardsConfigPDA,     isSigner: false, isWritable: true  },
        ],
        data: ixData,
      });

      const tx = new Transaction().add(ix);
      const sig = await sendAndConfirmTransaction(conn, tx, [foundation], {
        commitment: "confirmed",
      });
      console.log(`  ✓ SetMigrationMode(false): ${sig}`);
      console.log("  ⚠  This is IRREVERSIBLE — migration_locked is now true permanently.");
    }
  }

  // ── Summary ─────────────────────────────────────────────────────────────────

  console.log("\n=== Post-init state ===");
  const rewardsConfigInfo = await conn.getAccountInfo(rewardsConfigPDA);
  if (rewardsConfigInfo) {
    const data = rewardsConfigInfo.data;
    console.log(`rewards_config (${rewardsConfigPDA.toBase58()}):`);
    console.log(`  migration_mode:   ${data[0] !== 0}`);
    console.log(`  migration_locked: ${data[1] !== 0}`);
    console.log(`  bump:             ${data[2]}`);
  } else {
    console.error("  ERROR: rewards_config not found after initialization!");
  }
  const tcInfoNow = await conn.getAccountInfo(treasuryConfigPDA);
  console.log(`treasury_config (${treasuryConfigPDA.toBase58()}): ${tcInfoNow ? `${tcInfoNow.data.length} bytes` : "NOT FOUND"}`);
  const bcInfoNow = await conn.getAccountInfo(bondConfigPDA);
  console.log(`bond_config (${bondConfigPDA.toBase58()}): ${bcInfoNow ? `${bcInfoNow.data.length} bytes` : "NOT FOUND"}`);
}

main().catch(err => {
  console.error("Fatal error:", err);
  process.exit(1);
});
