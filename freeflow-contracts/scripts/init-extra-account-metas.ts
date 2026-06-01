/**
 * init-extra-account-metas.ts
 *
 * One-time setup: calls `initialize_extra_account_meta_list` on repflow-token
 * to create the EAM PDA required by the transfer-hook guard in
 * `claim_daily_uptime_repflow` (and all other mint instructions).
 *
 * Run:
 *   set ANCHOR_WALLET=D:\Solana\Wallet\id.json
 *   set TS_NODE_TRANSPILE_ONLY=true
 *   node --no-experimental-strip-types node_modules\.bin\ts-node scripts\init-extra-account-metas.ts
 */

import {
  Connection, Keypair, PublicKey, Transaction,
  sendAndConfirmTransaction, SystemProgram, TransactionInstruction,
} from "@solana/web3.js";
import * as fs from "fs";
import * as crypto from "crypto";

const RPC_URL      = "https://api.devnet.solana.com";
const REPFLOW_PROG = new PublicKey("8K4GhPEQ1yy9vdTaMPTL83G5qr5ZHZiBm2VBQ58jJs5w");
const REPFLOW_MINT = new PublicKey("BFaMqKEjS57NZdP6naPoEHavzUQc1KHL27WqY5CZMkmN");

// Load wallet keypair
const walletPath = process.env.ANCHOR_WALLET || "D:\\Solana\\Wallet\\id.json";
const walletJson = JSON.parse(fs.readFileSync(walletPath, "utf-8"));
const payer = Keypair.fromSecretKey(Uint8Array.from(walletJson));

// Anchor discriminator for initialize_extra_account_meta_list
const disc = crypto.createHash("sha256")
  .update("global:initialize_extra_account_meta_list")
  .digest()
  .slice(0, 8);

// Derive EAM PDA: seeds = [b"extra-account-metas", mint.key()]
const [eamPda, eamBump] = PublicKey.findProgramAddressSync(
  [Buffer.from("extra-account-metas"), REPFLOW_MINT.toBuffer()],
  REPFLOW_PROG,
);

console.log("Payer:    ", payer.publicKey.toBase58());
console.log("Mint:     ", REPFLOW_MINT.toBase58());
console.log("EAM PDA:  ", eamPda.toBase58(), "bump =", eamBump);

async function main() {
  const conn = new Connection(RPC_URL, "confirmed");

  // Check if already initialized
  const existing = await conn.getAccountInfo(eamPda);
  if (existing) {
    console.log("EAM PDA already exists:", eamPda.toBase58(), `(${existing.data.length} bytes)`);
    process.exit(0);
  }

  const ix = new TransactionInstruction({
    programId: REPFLOW_PROG,
    keys: [
      { pubkey: REPFLOW_MINT,          isSigner: false, isWritable: true  }, // mint
      { pubkey: eamPda,                isSigner: false, isWritable: true  }, // extra_account_meta_list
      { pubkey: payer.publicKey,       isSigner: true,  isWritable: true  }, // payer
      { pubkey: SystemProgram.programId, isSigner: false, isWritable: false }, // system_program
    ],
    data: Buffer.from(disc),
  });

  const tx = new Transaction().add(ix);
  tx.feePayer = payer.publicKey;

  console.log("Sending initialize_extra_account_meta_list...");
  const sig = await sendAndConfirmTransaction(conn, tx, [payer], { commitment: "confirmed" });
  console.log("✓ EAM PDA initialized  tx =", sig);

  // Verify
  const account = await conn.getAccountInfo(eamPda);
  console.log("EAM PDA size:", account?.data.length, "bytes  lamports:", account?.lamports);
}

main().catch(err => { console.error("Error:", err); process.exit(1); });
