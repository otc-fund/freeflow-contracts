#!/usr/bin/env ts-node
/**
 * Admin tool — call reinitialize_config() on the repflow-token program.
 *
 * Rewrites all RepFlowConfig fields to known-good values after a layout migration
 * where the on-chain data is stale (fields shifted when mint: Pubkey was inserted
 * between admin and minters in the Jun-09 upgrade).
 *
 * Usage:
 *   npx ts-node scripts/reinitialize-config.ts \
 *     --keypair   D:/Solana/Wallet/id.json \
 *     --program   8K4GhPEQ1yy9vdTaMPTL83G5qr5ZHZiBm2VBQ58jJs5w \
 *     --mint      G8QRTf5PL2FFPzMCxSgaX3okgRLoE2jSseGAoTfGJ7YW \
 *     --minter    8SL4dhnXU9tjvsbwfkVzQbfV99wGnVZBECoiuwrdbaJk \
 *     --max-supply 1000000000 \
 *     --rpc       https://api.devnet.solana.com
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
import * as crypto from "crypto";

// ─── Argument parsing ─────────────────────────────────────────────────────────

function usage(): never {
  console.error(`
Usage: npx ts-node scripts/reinitialize-config.ts \\
  --keypair    <path>          Admin keypair JSON (required)
  --program    <base58>        repflow-token program ID (default: 8K4GhPEQ1yy9vdTaMPTL83G5qr5ZHZiBm2VBQ58jJs5w)
  --mint       <base58>        repFlow mint pubkey (default: G8QRTf5PL2FFPzMCxSgaX3okgRLoE2jSseGAoTfGJ7YW)
  --minter     <base58>        Minter pubkey to register (may repeat; default: admin pubkey)
  --max-supply <u64>           Hard cap in base units (default: 1000000000)
  --rpc        <url>           Solana RPC URL (default: https://api.devnet.solana.com)
  --dry-run                    Print instruction data without submitting
  `);
  process.exit(1);
}

const args = process.argv.slice(2);
let keypairPath  = "";
let programId    = "8K4GhPEQ1yy9vdTaMPTL83G5qr5ZHZiBm2VBQ58jJs5w";
let mintAddress  = "G8QRTf5PL2FFPzMCxSgaX3okgRLoE2jSseGAoTfGJ7YW";
const minterAddresses: string[] = [];
let maxSupply    = BigInt(1_000_000_000);
let rpcUrl       = "https://api.devnet.solana.com";
let dryRun       = false;

for (let i = 0; i < args.length; i++) {
  switch (args[i]) {
    case "--keypair":     keypairPath        = args[++i]; break;
    case "--program":     programId          = args[++i]; break;
    case "--mint":        mintAddress        = args[++i]; break;
    case "--minter":      minterAddresses.push(args[++i]); break;
    case "--max-supply":  maxSupply          = BigInt(args[++i]); break;
    case "--rpc":         rpcUrl             = args[++i]; break;
    case "--dry-run":     dryRun             = true;       break;
    default: console.error(`Unknown arg: ${args[i]}`); usage();
  }
}

if (!keypairPath) usage();

// ─── Anchor discriminant helper ───────────────────────────────────────────────

function anchorDisc(name: string): Buffer {
  const hash = crypto.createHash("sha256").update(`global:${name}`).digest();
  return hash.slice(0, 8);
}

// ─── Borsh serialization helpers ──────────────────────────────────────────────

function writeU32LE(n: number): Buffer {
  const b = Buffer.alloc(4);
  b.writeUInt32LE(n, 0);
  return b;
}

function writeU64LE(n: bigint): Buffer {
  const b = Buffer.alloc(8);
  b.writeBigUInt64LE(n, 0);
  return b;
}

// ─── Main ─────────────────────────────────────────────────────────────────────

async function main() {
  const connection = new Connection(rpcUrl, "confirmed");
  const rawKey     = JSON.parse(fs.readFileSync(keypairPath, "utf8"));
  const admin      = Keypair.fromSecretKey(Uint8Array.from(rawKey));

  // Default minter to admin if none specified
  const minters = minterAddresses.length > 0
    ? minterAddresses.map(a => new PublicKey(a))
    : [admin.publicKey];

  const program = new PublicKey(programId);
  const newMint = new PublicKey(mintAddress);

  const [configPda] = PublicKey.findProgramAddressSync(
    [Buffer.from("repflow_config")],
    program,
  );

  console.log(`Program:    ${program.toBase58()}`);
  console.log(`Admin:      ${admin.publicKey.toBase58()}`);
  console.log(`Config PDA: ${configPda.toBase58()}`);
  console.log(`Mint:       ${newMint.toBase58()}`);
  console.log(`Minters:    ${minters.map(m => m.toBase58()).join(", ")}`);
  console.log(`Max supply: ${maxSupply}`);

  // ── Build reinitialize_config instruction ──────────────────────────────────
  // Borsh encoding:
  //   disc        [u8; 8]
  //   new_mint    [u8; 32]   (Pubkey = 32 raw bytes)
  //   minters     u32 LE     (Vec<Pubkey> length prefix)
  //               [u8; 32]*N (each Pubkey)
  //   max_supply  u64 LE

  const disc = anchorDisc("reinitialize_config");
  console.log(`\nDiscriminant (reinitialize_config): ${disc.toString("hex")}`);

  const mintersData = Buffer.concat([
    writeU32LE(minters.length),
    ...minters.map(m => m.toBuffer()),
  ]);

  const data = Buffer.concat([
    disc,
    newMint.toBuffer(),
    mintersData,
    writeU64LE(maxSupply),
  ]);

  const ix = new TransactionInstruction({
    programId: program,
    keys: [
      { pubkey: configPda,       isSigner: false, isWritable: true },
      { pubkey: admin.publicKey, isSigner: true,  isWritable: false },
    ],
    data,
  });

  if (dryRun) {
    console.log("\n[dry-run] Instruction data:", data.toString("hex"));
    console.log("[dry-run] Accounts:", ix.keys.map(
      k => `${k.pubkey.toBase58()} signer=${k.isSigner} writable=${k.isWritable}`
    ));
    return;
  }

  const tx = new Transaction().add(ix);
  tx.feePayer = admin.publicKey;

  console.log("\nSubmitting reinitialize_config transaction...");
  const sig = await sendAndConfirmTransaction(connection, tx, [admin], {
    commitment: "confirmed",
  });

  console.log(`\n✓ reinitialize_config confirmed — tx: ${sig}`);
  console.log(`  Config PDA: ${configPda.toBase58()}`);
  console.log(`  Mint set to: ${newMint.toBase58()}`);
  console.log(`  Minters:     ${minters.map(m => m.toBase58()).join(", ")}`);
  console.log(`  total_minted reset to 0`);
}

main().catch((e) => {
  console.error("Error:", e);
  process.exit(1);
});
