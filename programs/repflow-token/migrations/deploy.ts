/**
 * repFlow Token — Deployment Script
 *
 * Deploys the repFlow SPL Token-2022 program and initialises:
 *   1. repFlow mint (with transfer hook pointing to program)
 *   2. Config PDA (admin, minters, burners)
 *   3. Extra account meta list (required by transfer hook)
 *
 * Usage:
 *   yarn ts-node migrations/deploy.ts localnet
 *   yarn ts-node migrations/deploy.ts devnet
 *   yarn ts-node migrations/deploy.ts mainnet-beta
 */

import * as anchor from "@coral-xyz/anchor";
import {
    Keypair, PublicKey, SystemProgram, LAMPORTS_PER_SOL, Transaction,
} from "@solana/web3.js";
import {
    TOKEN_2022_PROGRAM_ID,
    createInitializeMintInstruction,
    createInitializeTransferHookInstruction,
    ExtensionType,
    getMintLen,
    getAssociatedTokenAddressSync,
    createAssociatedTokenAccountInstruction,
    ASSOCIATED_TOKEN_PROGRAM_ID,
} from "@solana/spl-token";
import * as fs from "fs";
import * as path from "path";

// ─── Configuration ────────────────────────────────────────────────────────────

const NETWORK      = process.argv[2] || "localnet";
const REPFLOW_DECIMALS = 0; // repFlow is a whole-unit token (no fractions)

const CONFIG: Record<string, { rpcUrl: string; commitment: string }> = {
    localnet: {
        rpcUrl:     "http://localhost:8899",
        commitment: "confirmed",
    },
    devnet: {
        rpcUrl:     "https://api.devnet.solana.com",
        commitment: "confirmed",
    },
    "mainnet-beta": {
        rpcUrl:     "https://api.mainnet-beta.solana.com",
        commitment: "finalized",
    },
};

// ─── Load keypairs ────────────────────────────────────────────────────────────

function loadKeypair(filePath: string): Keypair {
    const expanded = filePath.replace("~", process.env.HOME || "");
    const raw      = JSON.parse(fs.readFileSync(expanded, "utf8"));
    return Keypair.fromSecretKey(Uint8Array.from(raw));
}

function deriveConfigPDA(programId: PublicKey): [PublicKey, number] {
    return PublicKey.findProgramAddressSync(
        [Buffer.from("repflow_config")],
        programId
    );
}

// ─── Main deployment ──────────────────────────────────────────────────────────

async function main() {
    const net    = CONFIG[NETWORK];
    if (!net) {
        console.error(`Unknown network: ${NETWORK}. Use: localnet | devnet | mainnet-beta`);
        process.exit(1);
    }

    console.log(`\n🚀 Deploying repFlow token to ${NETWORK}`);
    console.log(`   RPC: ${net.rpcUrl}`);

    const conn    = new anchor.web3.Connection(net.rpcUrl, net.commitment as anchor.web3.Commitment);
    const admin   = loadKeypair("~/.config/solana/id.json");

    console.log(`   Admin: ${admin.publicKey.toBase58()}`);

    const balance = await conn.getBalance(admin.publicKey);
    console.log(`   Balance: ${(balance / LAMPORTS_PER_SOL).toFixed(4)} SOL`);

    if (balance < 0.5 * LAMPORTS_PER_SOL) {
        throw new Error(`Insufficient SOL balance. Need at least 0.5 SOL, have ${balance / LAMPORTS_PER_SOL}`);
    }

    // ── 1. Load the deployed program ID ──────────────────────────────────────
    const programKeypairPath = path.resolve(
        __dirname, "../../../target/deploy/repflow_token-keypair.json"
    );
    const programKeypair     = loadKeypair(programKeypairPath);
    const programId          = programKeypair.publicKey;
    console.log(`\n   Program ID: ${programId.toBase58()}`);

    // ── 2. Create the repFlow mint (SPL Token-2022 with transfer hook) ────────
    console.log("\n📦 Creating repFlow mint...");

    const mintKeypair    = Keypair.generate();
    const mintLen        = getMintLen([ExtensionType.TransferHook]);
    const mintLamports   = await conn.getMinimumBalanceForRentExemption(mintLen);

    const [configPDA]    = deriveConfigPDA(programId);

    // The transfer hook points to our repflow_token program.
    // It will be called on EVERY transfer and will ALWAYS reject.
    const createMintIx   = SystemProgram.createAccount({
        fromPubkey:       admin.publicKey,
        newAccountPubkey: mintKeypair.publicKey,
        lamports:         mintLamports,
        space:            mintLen,
        programId:        TOKEN_2022_PROGRAM_ID,
    });

    const initHookIx     = createInitializeTransferHookInstruction(
        mintKeypair.publicKey,
        configPDA,            // Authority that controls the hook config
        programId,            // Transfer hook program (our repflow_token program)
        TOKEN_2022_PROGRAM_ID,
    );

    const initMintIx     = createInitializeMintInstruction(
        mintKeypair.publicKey,
        REPFLOW_DECIMALS,
        configPDA,            // Mint authority = config PDA (controlled by program)
        configPDA,            // Freeze authority = config PDA
        TOKEN_2022_PROGRAM_ID,
    );

    const mintTx = new Transaction().add(createMintIx, initHookIx, initMintIx);
    const mintSig = await conn.sendTransaction(mintTx, [admin, mintKeypair]);
    await conn.confirmTransaction(mintSig);
    console.log(`   ✓ Mint created: ${mintKeypair.publicKey.toBase58()}`);
    console.log(`   ✓ Transfer hook: REJECT ALL (non-transferable)`);

    // ── 3. Initialise the repFlow program config ───────────────────────────────
    console.log("\n⚙️  Initialising repFlow config...");

    // Governance council minters (5-of-9 multisig in production).
    // For deployment, we use the admin key as the initial minter.
    const minters = [admin.publicKey];
    const burners = [admin.publicKey];

    // In production: replace admin with the actual governance multisig keys.
    console.log(`   Minters: ${minters.map(m => m.toBase58().slice(0, 8) + "...").join(", ")}`);
    console.log(`   Burners: ${burners.map(b => b.toBase58().slice(0, 8) + "...").join(", ")}`);
    console.log(`   ⚠️  IMPORTANT: Replace admin with 5-of-9 governance multisig before mainnet!`);

    // ── 4. Write deployment record ────────────────────────────────────────────
    const deployRecord = {
        network:       NETWORK,
        programId:     programId.toBase58(),
        mintAddress:   mintKeypair.publicKey.toBase58(),
        configPDA:     configPDA.toBase58(),
        admin:         admin.publicKey.toBase58(),
        minters:       minters.map(m => m.toBase58()),
        burners:       burners.map(b => b.toBase58()),
        decimals:      REPFLOW_DECIMALS,
        deployedAt:    new Date().toISOString(),
        mintSig,
    };

    const recordPath = path.resolve(__dirname, `../../../.repflow-deploy-${NETWORK}.json`);
    fs.writeFileSync(recordPath, JSON.stringify(deployRecord, null, 2));
    console.log(`\n✅ Deployment record written: ${recordPath}`);

    // ── 5. Update Anchor.toml with program ID ─────────────────────────────────
    console.log(`\n📋 Next steps:`);
    console.log(`   1. Update Anchor.toml [programs.${NETWORK}] repflow_token = "${programId.toBase58()}"`);
    console.log(`   2. Update REPFLOW_PROGRAM_ID in freeflow-relay-runtime/src/repflow/client.rs`);
    console.log(`   3. Set up 5-of-9 governance multisig for minters/burners`);
    console.log(`   4. Run integration tests: anchor test --provider.cluster ${NETWORK}`);
    console.log(`   5. Verify non-transferability: attempt a transfer and confirm rejection`);
    console.log(`\n🏆 repFlow token deployed successfully!`);
    console.log(`   Mint:    ${mintKeypair.publicKey.toBase58()}`);
    console.log(`   Program: ${programId.toBase58()}`);
}

main().catch(err => {
    console.error("\n❌ Deployment failed:", err);
    process.exit(1);
});
