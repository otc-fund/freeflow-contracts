#!/usr/bin/env ts-node
/**
 * Admin tool — call update_mint() on the repflow-token program.
 *
 * Writes the repFlow SPL Token-2022 mint address into the RepFlowConfig PDA
 * at the correct offset (after the new `mint` field was added in the Jun-09 upgrade).
 * Must be signed by the admin keypair stored in RepFlowConfig.
 *
 * Usage:
 *   npx ts-node scripts/update-mint.ts \
 *     --keypair   D:/Solana/Wallet/id.json \
 *     --program   8K4GhPEQ1yy9vdTaMPTL83G5qr5ZHZiBm2VBQ58jJs5w \
 *     --mint      G8QRTf5PL2FFPzMCxSgaX3okgRLoE2jSseGAoTfGJ7YW \
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
Usage: npx ts-node scripts/update-mint.ts \\
  --keypair  <path>          Admin keypair JSON (required)
  --program  <base58>        repflow-token program ID (default: 8K4GhPEQ1yy9vdTaMPTL83G5qr5ZHZiBm2VBQ58jJs5w)
  --mint     <base58>        New repFlow mint pubkey (default: G8QRTf5PL2FFPzMCxSgaX3okgRLoE2jSseGAoTfGJ7YW)
  --rpc      <url>           Solana RPC URL (default: https://api.devnet.solana.com)
  --dry-run                  Print tx bytes without submitting
  `);
  process.exit(1);
}

const args = process.argv.slice(2);
let keypairPath  = "";
let programId    = "8K4GhPEQ1yy9vdTaMPTL83G5qr5ZHZiBm2VBQ58jJs5w";
let mintAddress  = "G8QRTf5PL2FFPzMCxSgaX3okgRLoE2jSseGAoTfGJ7YW";
let rpcUrl       = "https://api.devnet.solana.com";
let dryRun       = false;

for (let i = 0; i < args.length; i++) {
  switch (args[i]) {
    case "--keypair":  keypairPath  = args[++i]; break;
    case "--program":  programId    = args[++i]; break;
    case "--mint":     mintAddress  = args[++i]; break;
    case "--rpc":      rpcUrl       = args[++i]; break;
    case "--dry-run":  dryRun       = true;       break;
    default: console.error(`Unknown arg: ${args[i]}`); usage();
  }
}

if (!keypairPath) usage();

// ─── Anchor discriminant helper ───────────────────────────────────────────────

function anchorDisc(name: string): Buffer {
  const hash = crypto.createHash("sha256").update(`global:${name}`).digest();
  return hash.slice(0, 8);
}

// ─── Main ─────────────────────────────────────────────────────────────────────

async function main() {
  const connection = new Connection(rpcUrl, "confirmed");
  const rawKey = JSON.parse(fs.readFileSync(keypairPath, "utf8"));
  const admin  = Keypair.fromSecretKey(Uint8Array.from(rawKey));

  const program     = new PublicKey(programId);
  const newMint     = new PublicKey(mintAddress);

  // Derive RepFlowConfig PDA: seeds = [b"repflow_config"]
  const [configPda] = PublicKey.findProgramAddressSync(
    [Buffer.from("repflow_config")],
    program,
  );

  console.log(`Program:    ${program.toBase58()}`);
  console.log(`Admin:      ${admin.publicKey.toBase58()}`);
  console.log(`Config PDA: ${configPda.toBase58()}`);
  console.log(`New mint:   ${newMint.toBase58()}`);

  // ── Instruction: update_mint ───────────────────────────────────────────────
  // Accounts: [0] config (writable), [1] admin (signer)
  // Args: new_mint: Pubkey (32 bytes LE)
  const disc = anchorDisc("update_mint");
  console.log(`Discriminant (update_mint): ${disc.toString("hex")}`);

  const data = Buffer.concat([disc, newMint.toBuffer()]);

  const ix = new TransactionInstruction({
    programId: program,
    keys: [
      { pubkey: configPda,          isSigner: false, isWritable: true },
      { pubkey: admin.publicKey,    isSigner: true,  isWritable: false },
    ],
    data,
  });

  if (dryRun) {
    console.log("\n[dry-run] Instruction data:", data.toString("hex"));
    console.log("[dry-run] Accounts:", ix.keys.map(k => `${k.pubkey.toBase58()} signer=${k.isSigner} writable=${k.isWritable}`));
    return;
  }

  const tx = new Transaction().add(ix);
  tx.feePayer = admin.publicKey;

  console.log("\nSubmitting update_mint transaction...");
  const sig = await sendAndConfirmTransaction(connection, tx, [admin], {
    commitment: "confirmed",
  });

  console.log(`✓ update_mint confirmed — tx: ${sig}`);
  console.log(`  RepFlowConfig.mint is now: ${newMint.toBase58()}`);
}

main().catch((e) => {
  console.error("Error:", e);
  process.exit(1);
});
