#!/usr/bin/env ts-node
/**
 * Foundation tool — call UpdateRewardRates (disc=17) on the Rewards program.
 *
 * Updates the RewardRatesAccount PDA with target emission rates.
 * Must be signed by the Foundation keypair (FOUNDATION_PUBKEY in rewards/lib.rs).
 *
 * Default target rates:
 *   routing  = 1_000_000 base units / MB  (≈ 1 FLOW/GB)
 *   seeding  = 2_000_000 base units / MB  (≈ 2 FLOW/GB)
 *   uptime   = 10_000_000_000 base units / hr  (= 10 FLOW/hr)
 *
 * Usage:
 *   npx ts-node scripts/update-reward-rates.ts \
 *     --keypair   D:/Solana/Wallet/id.json \
 *     --program   2yeVew5qq5jf5zuoqiE2svVLRE9HTN6J2GfB9LopdM1C \
 *     --routing   1000000 \
 *     --seeding   2000000 \
 *     --uptime    10000000000 \
 *     --price     0 \
 *     --rpc       https://api.devnet.solana.com
 *
 * The --dry-run flag prints the instruction bytes and account list without
 * submitting a transaction.
 */
import {
  Connection,
  Keypair,
  PublicKey,
  Transaction,
  TransactionInstruction,
  sendAndConfirmTransaction,
} from "@solana/web3.js";
import * as fs from "fs";

// ─── Argument parsing ─────────────────────────────────────────────────────────

function usage(): never {
  console.error(`
Usage: npx ts-node scripts/update-reward-rates.ts \\
  --keypair  <path>          Foundation keypair JSON (required)
  --program  <base58>        Rewards program ID (required)
  --routing  <u64>           routing_per_mb  (default: 1000000)
  --seeding  <u64>           seeding_per_mb  (default: 2000000)
  --uptime   <u64>           uptime_per_hour (default: 10000000000)
  --price    <u64>           flow_price_cents (micro-cents; default: 0 = not set)
  --rpc      <url>           Solana RPC URL (default: devnet)
  --dry-run                  Print tx bytes without submitting
  `);
  process.exit(1);
}

function getArg(args: string[], flag: string, def?: string): string {
  const idx = args.indexOf(flag);
  if (idx >= 0 && idx + 1 < args.length) return args[idx + 1];
  if (def !== undefined) return def;
  console.error(`Missing required argument: ${flag}`);
  usage();
}

// ─── Instruction encoding ─────────────────────────────────────────────────────

function encodeU64LE(n: bigint): Buffer {
  const buf = Buffer.alloc(8);
  buf.writeBigUInt64LE(n);
  return buf;
}

/**
 * Encode UpdateRewardRates (disc=17) instruction data.
 *
 * Layout: [17u8][routing_per_mb:u64le][seeding_per_mb:u64le]
 *         [uptime_per_hour:u64le][flow_price_cents:u64le]
 * Total:  33 bytes
 */
function encodeUpdateRewardRates(
  routing: bigint,
  seeding: bigint,
  uptime:  bigint,
  price:   bigint,
): Buffer {
  return Buffer.concat([
    Buffer.from([17]),   // disc=17 = UpdateRewardRates
    encodeU64LE(routing),
    encodeU64LE(seeding),
    encodeU64LE(uptime),
    encodeU64LE(price),
  ]);
}

// ─── Main ─────────────────────────────────────────────────────────────────────

async function main() {
  const args   = process.argv.slice(2);
  const dryRun = args.includes("--dry-run");

  const keypairPath = getArg(args, "--keypair");
  const programId   = new PublicKey(getArg(args, "--program"));
  const routing     = BigInt(getArg(args, "--routing",  "1000000"));
  const seeding     = BigInt(getArg(args, "--seeding",  "2000000"));
  const uptime      = BigInt(getArg(args, "--uptime",   "10000000000"));
  const price       = BigInt(getArg(args, "--price",    "0"));
  const rpcUrl      = getArg(args, "--rpc", "https://api.devnet.solana.com");

  const keypair = Keypair.fromSecretKey(
    Uint8Array.from(JSON.parse(fs.readFileSync(keypairPath, "utf8")))
  );

  // Derive the RewardRatesAccount PDA: seeds = [b"reward_rates"]
  const [rewardRatesPDA] = PublicKey.findProgramAddressSync(
    [Buffer.from("reward_rates")],
    programId,
  );

  const data = encodeUpdateRewardRates(routing, seeding, uptime, price);

  console.log("─────────────────────────────────────────────");
  console.log("FreeFlow — UpdateRewardRates");
  console.log("─────────────────────────────────────────────");
  console.log(`Foundation pubkey : ${keypair.publicKey.toBase58()}`);
  console.log(`Program           : ${programId.toBase58()}`);
  console.log(`RewardRates PDA   : ${rewardRatesPDA.toBase58()}`);
  console.log(`Rates (new):`);
  console.log(`  routing_per_mb  = ${routing.toLocaleString()} base units/MB`);
  console.log(`  seeding_per_mb  = ${seeding.toLocaleString()} base units/MB`);
  console.log(`  uptime_per_hour = ${uptime.toLocaleString()} base units/hr`);
  console.log(`  flow_price_cents= ${price}`);
  console.log(`Instruction data  : ${data.toString("hex")}`);
  console.log("─────────────────────────────────────────────");

  if (dryRun) {
    console.log("--dry-run: skipping transaction submission.");
    return;
  }

  const connection = new Connection(rpcUrl, "confirmed");

  const ix = new TransactionInstruction({
    programId,
    keys: [
      // account[0]: foundation (signer, NOT writable — the program only checks it is signer)
      { pubkey: keypair.publicKey, isSigner: true,  isWritable: false },
      // account[1]: reward_rates PDA (writable)
      { pubkey: rewardRatesPDA,    isSigner: false, isWritable: true  },
    ],
    data,
  });

  const tx  = new Transaction().add(ix);
  const sig = await sendAndConfirmTransaction(connection, tx, [keypair], {
    commitment: "confirmed",
  });

  console.log(`\n✅ UpdateRewardRates confirmed: ${sig}`);
  console.log(`   routing=${routing}/MB  seeding=${seeding}/MB  uptime=${uptime}/hr  price=${price}`);
  console.log(`\nVerify on devnet:`);
  console.log(`  solana account ${rewardRatesPDA.toBase58()} --url devnet`);
}

main().catch(err => {
  console.error("Error:", err.message ?? err);
  process.exit(1);
});
