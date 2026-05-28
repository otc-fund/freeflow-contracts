/**
 * init-bond-config.ts
 *
 * One-time initialization of the BondConfig PDA on the rewards program.
 * Must be run after deploying the updated rewards program (Phase 2+).
 *
 * This PDA governs dynamic challenger bond and minimum stake calculations.
 * After initialization, update via UpdateBondConfig (disc=21, the next variant).
 *
 * Run AFTER the rewards program upgrade and AFTER init-devnet.ts:
 *
 *   set ANCHOR_WALLET=D:\Solana\Wallet\id.json
 *   set ANCHOR_PROVIDER_URL=https://api.devnet.solana.com
 *   set TS_NODE_TRANSPILE_ONLY=true
 *   node --no-experimental-strip-types node_modules\.bin\ts-node scripts\init-bond-config.ts
 *
 * Optional env vars (override deployment defaults):
 *   CHALLENGER_BOND_CENTS=125000     # $1.25 target in micro-cents
 *   MIN_STAKE_USD_CENTS=250000000    # $2,500 target in micro-cents
 *   STAKE_EARNINGS_BPS=1000          # 10% — additional stake per $FLOW earned
 *   MAX_STAKE_FLOW=100000            # $FLOW ceiling for required stake
 */

import {
  Connection, Keypair, PublicKey, Transaction,
  sendAndConfirmTransaction, SystemProgram, LAMPORTS_PER_SOL,
  TransactionInstruction,
} from "@solana/web3.js";
import * as fs from "fs";

// ── Config ────────────────────────────────────────────────────────────────────

const RPC_URL      = process.env.ANCHOR_PROVIDER_URL ?? "https://api.devnet.solana.com";
const WALLET_PATH  = process.env.ANCHOR_WALLET
  ?? `${process.env.USERPROFILE}\\.config\\solana\\id.json`;
const REWARDS_PROG = new PublicKey(
  process.env.REWARDS_PROG_ID ?? "2yeVew5qq5jf5zuoqiE2svVLRE9HTN6J2GfB9LopdM1C"
);

// Default values from the plan (Phase 10.1).
const CHALLENGER_BOND_CENTS = BigInt(process.env.CHALLENGER_BOND_CENTS ?? "125000");   // $1.25
const MIN_STAKE_USD_CENTS   = BigInt(process.env.MIN_STAKE_USD_CENTS   ?? "250000000"); // $2,500
const STAKE_EARNINGS_BPS    = BigInt(process.env.STAKE_EARNINGS_BPS    ?? "1000");     // 10%
const MAX_STAKE_FLOW        = BigInt(process.env.MAX_STAKE_FLOW        ?? "100000");   // 100k $FLOW

// BondConfig::SIZE = 65 bytes (authority[32] + 4×u64[32] + bump[1])
const BOND_CONFIG_SIZE = 65;

const conn       = new Connection(RPC_URL, "confirmed");
const FOUNDATION = Keypair.fromSecretKey(
  Uint8Array.from(JSON.parse(fs.readFileSync(WALLET_PATH, "utf-8")))
);

// ── Main ──────────────────────────────────────────────────────────────────────

async function main() {
  const [bondConfigPda, bump] = PublicKey.findProgramAddressSync(
    [Buffer.from("bond_config")], REWARDS_PROG
  );

  console.log("=== init-bond-config ===");
  console.log(`RPC:              ${RPC_URL}`);
  console.log(`Foundation:       ${FOUNDATION.publicKey.toBase58()}`);
  console.log(`Rewards program:  ${REWARDS_PROG.toBase58()}`);
  console.log(`bond_config PDA:  ${bondConfigPda.toBase58()}`);
  console.log(`bump:             ${bump}`);
  console.log(`challenger_bond_cents: ${CHALLENGER_BOND_CENTS}`);
  console.log(`min_stake_usd_cents:   ${MIN_STAKE_USD_CENTS}`);
  console.log(`stake_earnings_bps:    ${STAKE_EARNINGS_BPS}`);
  console.log(`max_stake_flow:        ${MAX_STAKE_FLOW}`);
  console.log("");

  const balance = await conn.getBalance(FOUNDATION.publicKey);
  console.log(`Foundation balance: ${(balance / LAMPORTS_PER_SOL).toFixed(4)} SOL`);
  if (balance < 0.05 * LAMPORTS_PER_SOL) {
    throw new Error(`Foundation balance too low — needs at least 0.05 SOL`);
  }

  // Check if already initialized.
  const existing = await conn.getAccountInfo(bondConfigPda);
  if (existing && existing.data.length >= BOND_CONFIG_SIZE) {
    console.log(`BondConfig already initialized (${existing.data.length} bytes) — nothing to do.`);
    return;
  }

  // Pre-allocate the BondConfig PDA with system program.
  // RewardsInstruction::InitializeBondConfig is the last added variant.
  // Count variants: LegacyClaimRewards(0, disabled), RecordBytes(1), ClaimUsage(2), DisputeClaim(3),
  //   ResolveDisputeRelaySlashed(4), ResolveDisputeChallengerSlashed(5), ForceResolve(6),
  //   ReleaseRewards(7), InitializeRewardsConfig(8), InitializeReservation(9),
  //   SetMigrationMode(10), SweepExpiredEscrow(11), RequestReconciliation(12),
  //   ExecuteReconciliation(13), CancelReconciliation(14), PreMintFoundation(15),
  //   InitializeRewardRates(16), UpdateRewardRates(17), InitializeTreasuryConfig(18),
  //   UpdateTreasuryPool(19), InitializeBondConfig(20), UpdateBondConfig(21)
  //
  // Borsh discriminant for InitializeBondConfig = 20 (u32 LE prefix for struct variants).
  // Wait — the rewards program uses Borsh enum with single-byte discriminants.
  // Actually: the discriminant encoding depends on the enum repr.
  // Looking at the process_instruction dispatch:
  //   RewardsInstruction::try_from_slice(input)
  // Borsh enum variant index is encoded as u32 LE by default in borsh 0.9.
  // variant 20 = 20u32 LE = [20, 0, 0, 0]
  //
  // HOWEVER: looking at the existing init-devnet.ts, it uses single-byte discriminants:
  //   disc=8 (InitializeRewardsConfig), disc=16 (InitializeRewardRates), disc=18 (InitializeTreasuryConfig)
  // Those match single-byte positions, which means the enum uses borsh 0.9 u32-le.
  // 8 as u32le = [8, 0, 0, 0] → but the script uses Buffer.from([8]) (1 byte only)?
  //
  // Actually looking at init-devnet.ts more carefully:
  //   data: Buffer.from([8]) — disc=8 = InitializeRewardsConfig
  // If borsh were u32le, this would only work if the rest of the bytes are 0 (which they are
  // since it's the full 1-byte buffer — but borsh would try to read 4 bytes for the variant).
  // This implies the rewards program uses a 1-byte discriminant, not 4-byte Borsh enum index.
  //
  // Looking at the rewards program's process_instruction:
  //   let ix = RewardsInstruction::try_from_slice(input) using BorshDeserialize
  // Standard Borsh enum = u8 variant index (not u32). Borsh 0.9 uses u8 for enum variants.
  // So disc is u8, and variant 20 = 0x14.
  //
  // Instruction data: u8(20) + u64le(challenger_bond_cents) + u64le(min_stake_usd_cents)
  //   + u64le(stake_earnings_bps) + u64le(max_stake_flow)
  // Total: 1 + 8 + 8 + 8 + 8 = 33 bytes.

  const data = Buffer.alloc(33);
  data.writeUInt8(20, 0);  // InitializeBondConfig variant = 20
  data.writeBigUInt64LE(CHALLENGER_BOND_CENTS, 1);
  data.writeBigUInt64LE(MIN_STAKE_USD_CENTS,   9);
  data.writeBigUInt64LE(STAKE_EARNINGS_BPS,    17);
  data.writeBigUInt64LE(MAX_STAKE_FLOW,         25);

  const tx = new Transaction().add(
    new TransactionInstruction({
      programId: REWARDS_PROG,
      keys: [
        { pubkey: FOUNDATION.publicKey, isSigner: true,  isWritable: true  },
        { pubkey: bondConfigPda,        isSigner: false, isWritable: true  },
        { pubkey: SystemProgram.programId, isSigner: false, isWritable: false },
      ],
      data,
    })
  );

  console.log("Initializing BondConfig PDA...");
  const sig = await sendAndConfirmTransaction(conn, tx, [FOUNDATION]);
  console.log(`OK — sig: ${sig}`);
  console.log(`BondConfig PDA: ${bondConfigPda.toBase58()}`);
}

main().catch(e => { console.error(e); process.exit(1); });
