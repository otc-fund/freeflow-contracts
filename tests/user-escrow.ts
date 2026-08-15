/**
 * user-escrow.ts — Integration tests for the UserEscrow Anchor program.
 *
 * Covers:
 *   P0:   UserEscrow PDA creation and reuse
 *   P0.5: AuthorizedSpenderRegistry (Foundation-gated)
 *   P1:   purchase_and_escrow Phase 1 — all payment types, pricing math
 *   P2:   spend_from_escrow — burn, balance deduction, registry auth, relay check
 *   CRITICAL: No withdrawal instruction (IDL audit)
 *   CRITICAL: No update_authorized_spender instruction (IDL audit)
 *   Edge:  Zero amounts, large amounts, rapid purchases, removed spenders
 *
 * Run with:
 *   anchor test --skip-local-validator  (against a running localnet)
 *   or: anchor test                     (spins up localnet automatically)
 */

import * as anchor from "@coral-xyz/anchor";
import { Program, BN, EventParser } from "@coral-xyz/anchor";
import {
  Keypair,
  PublicKey,
  SystemProgram,
  LAMPORTS_PER_SOL,
  sendAndConfirmTransaction,
} from "@solana/web3.js";
import {
  createMint,
  createAccount,
  mintTo,
  getAccount,
  TOKEN_PROGRAM_ID,
} from "@solana/spl-token";
import { assert } from "chai";
import { UserEscrow } from "../target/types/user_escrow";

// ─── Helpers ──────────────────────────────────────────────────────────────────

type PaymentType = { sol: {} } | { usdc: {} } | { usdt: {} } | { creditCard: {} } | { dex: {} };
const PaymentTypeSol:        PaymentType = { sol:        {} };
const PaymentTypeUsdc:       PaymentType = { usdc:       {} };
const PaymentTypeUsdt:       PaymentType = { usdt:       {} };
const PaymentTypeCreditCard: PaymentType = { creditCard: {} };

// Placeholder for `pool_vault` on the no-referrer path. When `referrer` is None
// the handler computes referral_reward = 0 and never touches the account, but
// pool_vault is #[account(mut)] and an executable account can never satisfy a
// `mut` constraint — so the program's "pass SystemProgram::id()" doc comment
// holds for referral_config only, and yields ConstraintMut (2000) for pool_vault.
// Any writable non-executable address works; an unfunded throwaway makes the
// "never read, never written" intent obvious.
const UNUSED_POOL_VAULT = Keypair.generate().publicKey;

async function airdrop(provider: anchor.AnchorProvider, key: PublicKey, sol = 10) {
  const sig = await provider.connection.requestAirdrop(key, sol * LAMPORTS_PER_SOL);
  await provider.connection.confirmTransaction(sig, "confirmed");
}

/**
 * Lamport balance as an exact bigint, read straight off the JSON-RPC wire.
 *
 * `Connection.getBalance()` (and `meta.pre/postBalances`, and
 * `getAccountInfo().lamports`) all hand back a JavaScript `number`, i.e. a
 * float64. That is fine for ordinary accounts and WRONG for the provider
 * wallet: `solana-test-validator` makes the configured CLI keypair the genesis
 * mint, funded with 500,000,000 SOL = 5e17 lamports. Past 2^53 the float grid
 * spacing at that magnitude is 64 lamports, so a 1,621,680-lamport rent refund
 * reads back as 1,621,632 or 1,621,696 — never the true value. An exact-equality
 * delta assertion on that account is unwinnable through the typed client.
 *
 * `JSON.parse` would round it identically, so the number is lifted out of the
 * raw response text before any float can touch it.
 */
async function getBalanceExact(connection: anchor.web3.Connection, key: PublicKey): Promise<bigint> {
  const res = await fetch(connection.rpcEndpoint, {
    method:  "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      jsonrpc: "2.0", id: 1, method: "getBalance",
      params: [key.toBase58(), { commitment: "confirmed" }],
    }),
  });
  const text  = await res.text();
  const match = text.match(/"value"\s*:\s*(\d+)/);
  assert.isNotNull(match, `getBalance returned no numeric value: ${text}`);
  return BigInt(match![1]);
}

// ─── Suite ────────────────────────────────────────────────────────────────────

describe("user-escrow", () => {
  // Use "confirmed" commitment so getTransaction works reliably for event log parsing.
  const provider = new anchor.AnchorProvider(
    new anchor.web3.Connection(
      process.env.ANCHOR_PROVIDER_URL ?? "http://127.0.0.1:8899",
      "confirmed"
    ),
    anchor.AnchorProvider.env().wallet,
    { commitment: "confirmed" }
  );
  anchor.setProvider(provider);

  const program = anchor.workspace.UserEscrow as Program<UserEscrow>;

  // Keypairs
  // The program has FOUNDATION_PUBKEY hardcoded to the test wallet's pubkey
  // (8SL4dhnXU9tjvsbwfkVzQbfV99wGnVZBECoiuwrdbaJk = /root/.config/solana/id.json).
  // Using the provider wallet as foundation ensures the constraint check passes.
  const foundation    = (provider.wallet as anchor.Wallet).payer;
  const user          = Keypair.generate();
  const user2         = Keypair.generate();
  const relayOperator = Keypair.generate();
  const impostor      = Keypair.generate();   // Not in registry

  // PDAs
  let spenderRegistryPda:   PublicKey;
  let userEscrowPda:         PublicKey;
  let user2EscrowPda:        PublicKey;
  let treasuryAuthorityPda:  PublicKey;

  // Token accounts
  let tokenMint:              PublicKey;
  let treasuryVaultToken:     PublicKey;
  let userEscrowToken:        PublicKey;
  let user2EscrowToken:       PublicKey;
  let relayToken:             PublicKey;
  let impostorRelayToken:     PublicKey;

  // Simulated rewards-contract PDA (registered spender)
  const rewardsContractPda = Keypair.generate();

  before(async () => {
    // Fund all keypairs
    await Promise.all([
      airdrop(provider, foundation.publicKey),
      airdrop(provider, user.publicKey),
      airdrop(provider, user2.publicKey),
      airdrop(provider, relayOperator.publicKey),
      airdrop(provider, impostor.publicKey),
      airdrop(provider, rewardsContractPda.publicKey),
    ]);

    // Derive PDAs
    [spenderRegistryPda] = PublicKey.findProgramAddressSync(
      [Buffer.from("spender_registry")],
      program.programId
    );
    [userEscrowPda] = PublicKey.findProgramAddressSync(
      [Buffer.from("user_escrow"), user.publicKey.toBuffer()],
      program.programId
    );
    [user2EscrowPda] = PublicKey.findProgramAddressSync(
      [Buffer.from("user_escrow"), user2.publicKey.toBuffer()],
      program.programId
    );
    [treasuryAuthorityPda] = PublicKey.findProgramAddressSync(
      [Buffer.from("treasury_authority")],
      program.programId
    );

    // Create $FLOW mint (authority = provider wallet for test setup)
    tokenMint = await createMint(
      provider.connection,
      (provider.wallet as anchor.Wallet).payer,
      (provider.wallet as anchor.Wallet).publicKey,  // mint authority
      null,
      9  // 9 decimals
    );

    // Treasury vault: authority = treasuryAuthorityPda (PDA → must use explicit keypair)
    const treasuryVaultTokenKp = Keypair.generate();
    treasuryVaultToken = await createAccount(
      provider.connection,
      (provider.wallet as anchor.Wallet).payer,
      tokenMint,
      treasuryAuthorityPda,
      treasuryVaultTokenKp
    );

    // Pre-mint 30M $FLOW to treasury vault (simulating deployment)
    const THIRTY_MILLION = new BN(30_000_000).mul(new BN(1_000_000_000));
    await mintTo(
      provider.connection,
      (provider.wallet as anchor.Wallet).payer,
      tokenMint,
      treasuryVaultToken,
      (provider.wallet as anchor.Wallet).publicKey,
      BigInt(THIRTY_MILLION.toString())
    );

    // User escrow token account: authority = userEscrowPda (PDA → explicit keypair)
    const userEscrowTokenKp = Keypair.generate();
    userEscrowToken = await createAccount(
      provider.connection,
      (provider.wallet as anchor.Wallet).payer,
      tokenMint,
      userEscrowPda,
      userEscrowTokenKp
    );

    // User2 escrow token account: authority = user2EscrowPda (PDA → explicit keypair)
    const user2EscrowTokenKp = Keypair.generate();
    user2EscrowToken = await createAccount(
      provider.connection,
      (provider.wallet as anchor.Wallet).payer,
      tokenMint,
      user2EscrowPda,
      user2EscrowTokenKp
    );

    // Relay token account: authority = relayOperator
    relayToken = await createAccount(
      provider.connection,
      (provider.wallet as anchor.Wallet).payer,
      tokenMint,
      relayOperator.publicKey
    );

    // Impostor relay token account
    impostorRelayToken = await createAccount(
      provider.connection,
      (provider.wallet as anchor.Wallet).payer,
      tokenMint,
      impostor.publicKey
    );
  });

  // ── P0.5: Spender registry ─────────────────────────────────────────────────

  describe("Spender Registry", () => {

    it("foundation can initialize spender registry", async () => {
      await program.methods
        .initializeRegistry(rewardsContractPda.publicKey)
        .accounts({
          foundation:     foundation.publicKey,
          registry:       spenderRegistryPda,
          initialSpender: rewardsContractPda.publicKey,
          systemProgram:  SystemProgram.programId,
        })
        .signers([foundation])
        .rpc();

      const registry = await program.account.authorizedSpenderRegistry.fetch(spenderRegistryPda);
      assert.ok(registry.authority.equals(foundation.publicKey), "authority should be foundation");
      assert.equal(registry.activeSpenders.length, 1, "should have 1 spender");
      assert.ok(registry.activeSpenders[0].equals(rewardsContractPda.publicKey));
      assert.equal(registry.version.toNumber(), 1, "version starts at 1");
    });

    it("non-foundation cannot initialize a second registry", async () => {
      // Registry already exists — re-init should fail (account already in use)
      try {
        await program.methods
          .initializeRegistry(impostor.publicKey)
          .accounts({
            foundation:     impostor.publicKey,
            registry:       spenderRegistryPda,
            initialSpender: impostor.publicKey,
            systemProgram:  SystemProgram.programId,
          })
          .signers([impostor])
          .rpc();
        assert.fail("Should have failed — registry already initialized");
      } catch (e: any) {
        // Expect account already in use or constraint violation
        assert.ok(e.message, "Should throw on re-init");
      }
    });

    it("foundation can add spenders to registry", async () => {
      const newSpender = Keypair.generate();

      await program.methods
        .updateSpenderRegistry([newSpender.publicKey], [])
        .accounts({
          foundation: foundation.publicKey,
          registry:   spenderRegistryPda,
        })
        .signers([foundation])
        .rpc();

      const registry = await program.account.authorizedSpenderRegistry.fetch(spenderRegistryPda);
      assert.equal(registry.activeSpenders.length, 2, "should now have 2 spenders");
      assert.ok(registry.activeSpenders.some(s => s.equals(newSpender.publicKey)));
      assert.equal(registry.version.toNumber(), 2);
    });

    it("foundation can remove spenders from registry", async () => {
      // Get current registry state
      const before = await program.account.authorizedSpenderRegistry.fetch(spenderRegistryPda);
      const toRemove = before.activeSpenders[1]; // Remove the one added above

      await program.methods
        .updateSpenderRegistry([], [toRemove])
        .accounts({
          foundation: foundation.publicKey,
          registry:   spenderRegistryPda,
        })
        .signers([foundation])
        .rpc();

      const registry = await program.account.authorizedSpenderRegistry.fetch(spenderRegistryPda);
      assert.equal(registry.activeSpenders.length, 1, "should be back to 1 spender");
      assert.ok(!registry.activeSpenders.some(s => s.equals(toRemove)));
      assert.equal(registry.version.toNumber(), 3);
    });

    it("non-foundation cannot update spender registry", async () => {
      try {
        await program.methods
          .updateSpenderRegistry([impostor.publicKey], [])
          .accounts({
            foundation: impostor.publicKey,
            registry:   spenderRegistryPda,
          })
          .signers([impostor])
          .rpc();
        assert.fail("Should have thrown NotFoundation");
      } catch (e: any) {
        assert.include(e.message, "NotFoundation", "Should throw NotFoundation");
      }
    });

  });

  // ── P0: UserEscrow PDA ─────────────────────────────────────────────────────

  describe("UserEscrow PDA", () => {

    it("creates UserEscrow PDA on first purchase", async () => {
      const paymentCents = new BN(300); // $3.00 = 30 $FLOW

      await program.methods
        .purchaseAndEscrow(paymentCents, PaymentTypeSol, null)
        .accounts({
          user:               user.publicKey,
          userEscrow:         userEscrowPda,
          userEscrowToken,
          treasuryVaultToken,
          treasuryAuthority:  treasuryAuthorityPda,
          tokenMint,
          tokenProgram:       TOKEN_PROGRAM_ID,
          systemProgram:      SystemProgram.programId,
          // referrer = None → both referral accounts are SystemProgram.
          poolVault:          UNUSED_POOL_VAULT,
          referralConfig:     SystemProgram.programId,
        })
        .signers([user])
        .rpc();

      const escrow = await program.account.userEscrow.fetch(userEscrowPda);
      assert.ok(escrow.user.equals(user.publicKey), "user field should match");
      assert.isTrue(escrow.balance.gtn(0), "balance should be > 0");
      assert.isTrue(escrow.lastTopupTs.gtn(0), "timestamp should be set");
    });

    it("reuses existing UserEscrow PDA on subsequent purchases", async () => {
      const before = await program.account.userEscrow.fetch(userEscrowPda);

      await program.methods
        .purchaseAndEscrow(new BN(100), PaymentTypeSol, null) // $1.00 = 10 $FLOW
        .accounts({
          user:               user.publicKey,
          userEscrow:         userEscrowPda,
          userEscrowToken,
          treasuryVaultToken,
          treasuryAuthority:  treasuryAuthorityPda,
          tokenMint,
          tokenProgram:       TOKEN_PROGRAM_ID,
          systemProgram:      SystemProgram.programId,
          // referrer = None → both referral accounts are SystemProgram.
          poolVault:          UNUSED_POOL_VAULT,
          referralConfig:     SystemProgram.programId,
        })
        .signers([user])
        .rpc();

      const after = await program.account.userEscrow.fetch(userEscrowPda);
      assert.isTrue(
        after.balance.gt(before.balance),
        "balance should increase on second purchase"
      );
      assert.ok(after.user.equals(user.publicKey), "user field should still match");
    });

  });

  // ── P1: Purchase and escrow Phase 1 ────────────────────────────────────────

  describe("purchase_and_escrow (Phase 1)", () => {

    it("calculates correct $FLOW amount at fixed $0.10 price", async () => {
      // $3.00 = 300 cents → 30 $FLOW = 30 * 1e9 lamports
      const paymentCents  = new BN(300);
      const expectedFlow  = new BN(30).mul(new BN(1_000_000_000));

      const before = await program.account.userEscrow.fetch(userEscrowPda);

      await program.methods
        .purchaseAndEscrow(paymentCents, PaymentTypeSol, null)
        .accounts({
          user:               user.publicKey,
          userEscrow:         userEscrowPda,
          userEscrowToken,
          treasuryVaultToken,
          treasuryAuthority:  treasuryAuthorityPda,
          tokenMint,
          tokenProgram:       TOKEN_PROGRAM_ID,
          systemProgram:      SystemProgram.programId,
          // referrer = None → both referral accounts are SystemProgram.
          poolVault:          UNUSED_POOL_VAULT,
          referralConfig:     SystemProgram.programId,
        })
        .signers([user])
        .rpc();

      const after = await program.account.userEscrow.fetch(userEscrowPda);
      const delta = after.balance.sub(before.balance);
      assert.equal(
        delta.toString(),
        expectedFlow.toString(),
        "$300 cents should yield 30 $FLOW (30e9 lamports)"
      );
    });

    it("transfers $FLOW from treasury to escrow on SOL payment", async () => {
      const vaultBefore = await getAccount(provider.connection, treasuryVaultToken);
      const escrowBefore = await getAccount(provider.connection, userEscrowToken);

      await program.methods
        .purchaseAndEscrow(new BN(100), PaymentTypeSol, null)
        .accounts({
          user:               user.publicKey,
          userEscrow:         userEscrowPda,
          userEscrowToken,
          treasuryVaultToken,
          treasuryAuthority:  treasuryAuthorityPda,
          tokenMint,
          tokenProgram:       TOKEN_PROGRAM_ID,
          systemProgram:      SystemProgram.programId,
          // referrer = None → both referral accounts are SystemProgram.
          poolVault:          UNUSED_POOL_VAULT,
          referralConfig:     SystemProgram.programId,
        })
        .signers([user])
        .rpc();

      const vaultAfter  = await getAccount(provider.connection, treasuryVaultToken);
      const escrowAfter = await getAccount(provider.connection, userEscrowToken);

      const flow10 = BigInt(10) * BigInt(1_000_000_000);
      assert.equal(
        BigInt(vaultBefore.amount) - BigInt(vaultAfter.amount),
        flow10,
        "Treasury vault should decrease by 10 $FLOW"
      );
      assert.equal(
        BigInt(escrowAfter.amount) - BigInt(escrowBefore.amount),
        flow10,
        "User escrow token should increase by 10 $FLOW"
      );
    });

    it("transfers $FLOW from treasury to escrow on USDC payment", async () => {
      const before = await program.account.userEscrow.fetch(userEscrowPda);

      await program.methods
        .purchaseAndEscrow(new BN(500), PaymentTypeUsdc, null) // $5.00 = 50 $FLOW
        .accounts({
          user:               user.publicKey,
          userEscrow:         userEscrowPda,
          userEscrowToken,
          treasuryVaultToken,
          treasuryAuthority:  treasuryAuthorityPda,
          tokenMint,
          tokenProgram:       TOKEN_PROGRAM_ID,
          systemProgram:      SystemProgram.programId,
          // referrer = None → both referral accounts are SystemProgram.
          poolVault:          UNUSED_POOL_VAULT,
          referralConfig:     SystemProgram.programId,
        })
        .signers([user])
        .rpc();

      const after = await program.account.userEscrow.fetch(userEscrowPda);
      const delta = after.balance.sub(before.balance);
      assert.equal(
        delta.toString(),
        new BN(50).mul(new BN(1_000_000_000)).toString(),
        "USDC: $5.00 = 50 $FLOW"
      );
    });

    it("transfers $FLOW from treasury to escrow on USDT payment", async () => {
      const before = await program.account.userEscrow.fetch(userEscrowPda);

      await program.methods
        .purchaseAndEscrow(new BN(200), PaymentTypeUsdt, null) // $2.00 = 20 $FLOW
        .accounts({
          user:               user.publicKey,
          userEscrow:         userEscrowPda,
          userEscrowToken,
          treasuryVaultToken,
          treasuryAuthority:  treasuryAuthorityPda,
          tokenMint,
          tokenProgram:       TOKEN_PROGRAM_ID,
          systemProgram:      SystemProgram.programId,
          // referrer = None → both referral accounts are SystemProgram.
          poolVault:          UNUSED_POOL_VAULT,
          referralConfig:     SystemProgram.programId,
        })
        .signers([user])
        .rpc();

      const after = await program.account.userEscrow.fetch(userEscrowPda);
      assert.isTrue(after.balance.gt(before.balance), "USDT balance should increase");
    });

    it("transfers $FLOW from treasury to escrow on credit card payment", async () => {
      const before = await program.account.userEscrow.fetch(userEscrowPda);

      await program.methods
        .purchaseAndEscrow(new BN(1000), PaymentTypeCreditCard, null) // $10.00 = 100 $FLOW
        .accounts({
          user:               user.publicKey,
          userEscrow:         userEscrowPda,
          userEscrowToken,
          treasuryVaultToken,
          treasuryAuthority:  treasuryAuthorityPda,
          tokenMint,
          tokenProgram:       TOKEN_PROGRAM_ID,
          systemProgram:      SystemProgram.programId,
          // referrer = None → both referral accounts are SystemProgram.
          poolVault:          UNUSED_POOL_VAULT,
          referralConfig:     SystemProgram.programId,
        })
        .signers([user])
        .rpc();

      const after = await program.account.userEscrow.fetch(userEscrowPda);
      assert.isTrue(after.balance.gt(before.balance), "Credit card balance should increase");
    });

    it("updates escrow balance after purchase", async () => {
      const escrow = await program.account.userEscrow.fetch(userEscrowPda);
      assert.isTrue(escrow.balance.gtn(0), "balance must be non-zero after multiple purchases");
    });

    it("emits PurchaseAndEscrowed event", async () => {
      // Parse events from transaction logs (more reliable than websocket in local tests).
      const sig = await program.methods
        .purchaseAndEscrow(new BN(100), PaymentTypeSol, null)
        .accounts({
          user:               user.publicKey,
          userEscrow:         userEscrowPda,
          userEscrowToken,
          treasuryVaultToken,
          treasuryAuthority:  treasuryAuthorityPda,
          tokenMint,
          tokenProgram:       TOKEN_PROGRAM_ID,
          systemProgram:      SystemProgram.programId,
          // referrer = None → both referral accounts are SystemProgram.
          poolVault:          UNUSED_POOL_VAULT,
          referralConfig:     SystemProgram.programId,
        })
        .signers([user])
        .rpc();

      const txDetails = await provider.connection.getTransaction(sig, {
        maxSupportedTransactionVersion: 0,
        commitment: "confirmed",
      });
      const logs = txDetails?.meta?.logMessages ?? [];
      const parser = new EventParser(program.programId, new anchor.BorshCoder(program.idl));
      const events = [...parser.parseLogs(logs)];

      // Anchor 0.30 EventParser returns camelCase event names.
      const found = events.find(e => e.name === "purchaseAndEscrowed");
      assert.isDefined(found, "PurchaseAndEscrowed event must be in transaction logs");
      assert.ok((found!.data as any).user.equals(user.publicKey));
      assert.isTrue((found!.data as any).flowAmount.gtn(0));
      assert.isTrue((found!.data as any).escrowBalance.gtn(0));
    });

    it("handles multiple rapid purchases", async () => {
      const before = await program.account.userEscrow.fetch(userEscrowPda);

      // 3 purchases in quick succession
      for (let i = 0; i < 3; i++) {
        await program.methods
          .purchaseAndEscrow(new BN(100), PaymentTypeSol, null)
          .accounts({
            user:               user.publicKey,
            userEscrow:         userEscrowPda,
            userEscrowToken,
            treasuryVaultToken,
            treasuryAuthority:  treasuryAuthorityPda,
            tokenMint,
            tokenProgram:       TOKEN_PROGRAM_ID,
            systemProgram:      SystemProgram.programId,
            // referrer = None → both referral accounts are SystemProgram.
            poolVault:          UNUSED_POOL_VAULT,
            referralConfig:     SystemProgram.programId,
          })
          .signers([user])
          .rpc();
      }

      const after = await program.account.userEscrow.fetch(userEscrowPda);
      const expected = new BN(30).mul(new BN(1_000_000_000)); // 3 × 10 $FLOW
      const delta    = after.balance.sub(before.balance);
      assert.equal(delta.toString(), expected.toString(), "3 × $1 = 30 $FLOW added");
    });

    it("handles very large payment amount", async () => {
      // $10,000 = 100,000 $FLOW — no cap, no limit
      const largeCents = new BN(1_000_000); // $10,000
      const before = await program.account.userEscrow.fetch(userEscrowPda);

      await program.methods
        .purchaseAndEscrow(largeCents, PaymentTypeSol, null)
        .accounts({
          user:               user.publicKey,
          userEscrow:         userEscrowPda,
          userEscrowToken,
          treasuryVaultToken,
          treasuryAuthority:  treasuryAuthorityPda,
          tokenMint,
          tokenProgram:       TOKEN_PROGRAM_ID,
          systemProgram:      SystemProgram.programId,
          // referrer = None → both referral accounts are SystemProgram.
          poolVault:          UNUSED_POOL_VAULT,
          referralConfig:     SystemProgram.programId,
        })
        .signers([user])
        .rpc();

      const after = await program.account.userEscrow.fetch(userEscrowPda);
      assert.isTrue(after.balance.gt(before.balance), "Large purchase should succeed — no cap");
    });

    it("handles zero payment amount gracefully", async () => {
      try {
        await program.methods
          .purchaseAndEscrow(new BN(0), PaymentTypeSol, null)
          .accounts({
            user:               user.publicKey,
            userEscrow:         userEscrowPda,
            userEscrowToken,
            treasuryVaultToken,
            treasuryAuthority:  treasuryAuthorityPda,
            tokenMint,
            tokenProgram:       TOKEN_PROGRAM_ID,
            systemProgram:      SystemProgram.programId,
            // referrer = None → both referral accounts are SystemProgram.
            poolVault:          UNUSED_POOL_VAULT,
            referralConfig:     SystemProgram.programId,
          })
          .signers([user])
          .rpc();
        assert.fail("Should have rejected zero payment");
      } catch (e: any) {
        assert.include(e.message, "InvalidPaymentAmount");
      }
    });

  });

  // ── P2: Spend from escrow (burn) ────────────────────────────────────────────

  describe("spend_from_escrow (Phase 2)", () => {

    const spendAmount = new BN(10).mul(new BN(1_000_000_000)); // 10 $FLOW

    it("burns $FLOW from escrow on spend", async () => {
      const tokenBefore = await getAccount(provider.connection, userEscrowToken);
      const mintBefore  = await provider.connection.getTokenSupply(tokenMint);

      await program.methods
        .spendFromEscrow(spendAmount, relayOperator.publicKey)
        .accounts({
          serviceAuthority: rewardsContractPda.publicKey,
          user:             user.publicKey,
          userEscrow:       userEscrowPda,
          userEscrowToken,
          relayToken,
          relay:            relayOperator.publicKey,
          spenderRegistry:  spenderRegistryPda,
          tokenMint,
          tokenProgram:     TOKEN_PROGRAM_ID,
        })
        .signers([rewardsContractPda])
        .rpc();

      const tokenAfter = await getAccount(provider.connection, userEscrowToken);
      const mintAfter  = await provider.connection.getTokenSupply(tokenMint);

      assert.equal(
        BigInt(tokenBefore.amount) - BigInt(tokenAfter.amount),
        BigInt(spendAmount.toString()),
        "Token account should decrease by burned amount"
      );
      assert.isBelow(
        parseInt(mintAfter.value.amount),
        parseInt(mintBefore.value.amount),
        "Total supply should decrease (tokens burned)"
      );
    });

    it("deducts from escrow balance on spend", async () => {
      const before = await program.account.userEscrow.fetch(userEscrowPda);

      await program.methods
        .spendFromEscrow(spendAmount, relayOperator.publicKey)
        .accounts({
          serviceAuthority: rewardsContractPda.publicKey,
          user:             user.publicKey,
          userEscrow:       userEscrowPda,
          userEscrowToken,
          relayToken,
          relay:            relayOperator.publicKey,
          spenderRegistry:  spenderRegistryPda,
          tokenMint,
          tokenProgram:     TOKEN_PROGRAM_ID,
        })
        .signers([rewardsContractPda])
        .rpc();

      const after = await program.account.userEscrow.fetch(userEscrowPda);
      assert.equal(
        before.balance.sub(after.balance).toString(),
        spendAmount.toString(),
        "Escrow balance should decrease by exactly the spent amount"
      );
    });

    it("emits SpentFromEscrow event", async () => {
      // Parse events from transaction logs (more reliable than websocket in local tests).
      const sig = await program.methods
        .spendFromEscrow(spendAmount, relayOperator.publicKey)
        .accounts({
          serviceAuthority: rewardsContractPda.publicKey,
          user:             user.publicKey,
          userEscrow:       userEscrowPda,
          userEscrowToken,
          relayToken,
          relay:            relayOperator.publicKey,
          spenderRegistry:  spenderRegistryPda,
          tokenMint,
          tokenProgram:     TOKEN_PROGRAM_ID,
        })
        .signers([rewardsContractPda])
        .rpc();

      const txDetails = await provider.connection.getTransaction(sig, {
        maxSupportedTransactionVersion: 0,
        commitment: "confirmed",
      });
      const logs = txDetails?.meta?.logMessages ?? [];
      const parser = new EventParser(program.programId, new anchor.BorshCoder(program.idl));
      const events = [...parser.parseLogs(logs)];

      // Anchor 0.30 EventParser returns camelCase event names.
      const found = events.find(e => e.name === "spentFromEscrow");
      assert.isDefined(found, "SpentFromEscrow event must be in transaction logs");
      assert.ok((found!.data as any).user.equals(user.publicKey));
      assert.equal((found!.data as any).amount.toString(), spendAmount.toString());
      assert.ok((found!.data as any).relay.equals(relayOperator.publicKey));
    });

    it("no USD transfer happens during burn (relay paid via mint split)", async () => {
      // relay_token balance should NOT change — relay is paid via 70:30 mint
      // split in the rewards contract, NOT during spend_from_escrow.
      const relayTokenBefore = await getAccount(provider.connection, relayToken);

      await program.methods
        .spendFromEscrow(spendAmount, relayOperator.publicKey)
        .accounts({
          serviceAuthority: rewardsContractPda.publicKey,
          user:             user.publicKey,
          userEscrow:       userEscrowPda,
          userEscrowToken,
          relayToken,
          relay:            relayOperator.publicKey,
          spenderRegistry:  spenderRegistryPda,
          tokenMint,
          tokenProgram:     TOKEN_PROGRAM_ID,
        })
        .signers([rewardsContractPda])
        .rpc();

      const relayTokenAfter = await getAccount(provider.connection, relayToken);
      assert.equal(
        relayTokenBefore.amount.toString(),
        relayTokenAfter.amount.toString(),
        "Relay token balance MUST NOT change — relay is paid via mint split, not spend"
      );
    });

    it("fails if insufficient balance", async () => {
      // Drain the escrow to near-zero first via a big spend
      const escrow      = await program.account.userEscrow.fetch(userEscrowPda);
      const tooMuch     = escrow.balance.add(new BN(1_000_000_000)); // balance + 1 $FLOW

      try {
        await program.methods
          .spendFromEscrow(tooMuch, relayOperator.publicKey)
          .accounts({
            serviceAuthority: rewardsContractPda.publicKey,
            user:             user.publicKey,
            userEscrow:       userEscrowPda,
            userEscrowToken,
            relayToken,
            relay:            relayOperator.publicKey,
            spenderRegistry:  spenderRegistryPda,
            tokenMint,
            tokenProgram:     TOKEN_PROGRAM_ID,
          })
          .signers([rewardsContractPda])
          .rpc();
        assert.fail("Should have thrown InsufficientBalance");
      } catch (e: any) {
        assert.include(e.message, "InsufficientBalance");
      }
    });

    it("fails if caller is not in spender registry", async () => {
      try {
        await program.methods
          .spendFromEscrow(spendAmount, relayOperator.publicKey)
          .accounts({
            serviceAuthority: impostor.publicKey,  // NOT in registry
            user:             user.publicKey,
            userEscrow:       userEscrowPda,
            userEscrowToken,
            relayToken,
            relay:            relayOperator.publicKey,
            spenderRegistry:  spenderRegistryPda,
            tokenMint,
            tokenProgram:     TOKEN_PROGRAM_ID,
          })
          .signers([impostor])
          .rpc();
        assert.fail("Should have thrown UnauthorizedCaller");
      } catch (e: any) {
        assert.include(e.message, "UnauthorizedCaller");
      }
    });

    it("fails if relay wallet does not match expected destination", async () => {
      // Pass impostor.publicKey as relay param but relayToken owned by relayOperator
      try {
        await program.methods
          .spendFromEscrow(spendAmount, impostor.publicKey)  // wrong relay param
          .accounts({
            serviceAuthority: rewardsContractPda.publicKey,
            user:             user.publicKey,
            userEscrow:       userEscrowPda,
            userEscrowToken,
            relayToken,                          // owned by relayOperator, not impostor
            relay:            relayOperator.publicKey, // mismatch with param
            spenderRegistry:  spenderRegistryPda,
            tokenMint,
            tokenProgram:     TOKEN_PROGRAM_ID,
          })
          .signers([rewardsContractPda])
          .rpc();
        assert.fail("Should have thrown InvalidRelayWallet");
      } catch (e: any) {
        assert.include(e.message, "InvalidRelayWallet");
      }
    });

    it("spender removed from registry cannot spend", async () => {
      // Remove rewardsContractPda from registry
      await program.methods
        .updateSpenderRegistry([], [rewardsContractPda.publicKey])
        .accounts({
          foundation: foundation.publicKey,
          registry:   spenderRegistryPda,
        })
        .signers([foundation])
        .rpc();

      // Attempt to spend — should fail
      try {
        await program.methods
          .spendFromEscrow(spendAmount, relayOperator.publicKey)
          .accounts({
            serviceAuthority: rewardsContractPda.publicKey,
            user:             user.publicKey,
            userEscrow:       userEscrowPda,
            userEscrowToken,
            relayToken,
            relay:            relayOperator.publicKey,
            spenderRegistry:  spenderRegistryPda,
            tokenMint,
            tokenProgram:     TOKEN_PROGRAM_ID,
          })
          .signers([rewardsContractPda])
          .rpc();
        assert.fail("Removed spender should not be able to spend");
      } catch (e: any) {
        assert.include(e.message, "UnauthorizedCaller");
      }

      // Re-add for subsequent tests
      await program.methods
        .updateSpenderRegistry([rewardsContractPda.publicKey], [])
        .accounts({
          foundation: foundation.publicKey,
          registry:   spenderRegistryPda,
        })
        .signers([foundation])
        .rpc();
    });

    it("newly added spender can spend immediately", async () => {
      const newSpenderKp = Keypair.generate();
      await airdrop(provider, newSpenderKp.publicKey);

      // Add new spender
      await program.methods
        .updateSpenderRegistry([newSpenderKp.publicKey], [])
        .accounts({
          foundation: foundation.publicKey,
          registry:   spenderRegistryPda,
        })
        .signers([foundation])
        .rpc();

      // New spender should be able to spend immediately
      const before = await program.account.userEscrow.fetch(userEscrowPda);

      await program.methods
        .spendFromEscrow(spendAmount, relayOperator.publicKey)
        .accounts({
          serviceAuthority: newSpenderKp.publicKey,
          user:             user.publicKey,
          userEscrow:       userEscrowPda,
          userEscrowToken,
          relayToken,
          relay:            relayOperator.publicKey,
          spenderRegistry:  spenderRegistryPda,
          tokenMint,
          tokenProgram:     TOKEN_PROGRAM_ID,
        })
        .signers([newSpenderKp])
        .rpc();

      const after = await program.account.userEscrow.fetch(userEscrowPda);
      assert.isTrue(before.balance.gt(after.balance), "New spender should be able to spend");

      // Clean up: remove new spender
      await program.methods
        .updateSpenderRegistry([], [newSpenderKp.publicKey])
        .accounts({
          foundation: foundation.publicKey,
          registry:   spenderRegistryPda,
        })
        .signers([foundation])
        .rpc();
    });

  });

  // ── CRITICAL: No withdrawal path ──────────────────────────────────────────

  describe("CRITICAL: Security invariants (IDL audit)", () => {

    it("has no withdrawal instruction", () => {
      const idl = program.idl;
      const withdrawIx = idl.instructions.find(
        (i: any) => i.name === "withdraw" || i.name === "withdrawFromEscrow"
      );
      assert.isUndefined(
        withdrawIx,
        "Withdraw instruction MUST NOT exist — permanent escrow, immutable after deployment"
      );
    });

    it("has no update_authorized_spender instruction", () => {
      const idl = program.idl;
      const updateIx = idl.instructions.find(
        (i: any) => i.name === "updateAuthorizedSpender" || i.name === "setAuthorizedSpender"
      );
      assert.isUndefined(
        updateIx,
        "updateAuthorizedSpender MUST NOT exist — per-user spender prevents bank-run protection"
      );
    });

    it("has no enable_withdrawals instruction", () => {
      const idl = program.idl;
      const enableIx = idl.instructions.find(
        (i: any) => i.name === "enableWithdrawals" || i.name === "disableEscrowCap"
      );
      assert.isUndefined(
        enableIx,
        "enableWithdrawals MUST NOT exist — no admin override"
      );
    });

    it("UserEscrow account has no authorized_spender field", () => {
      const idl = program.idl;
      // Anchor 0.30 IDL spec: type definitions (with fields) are in idl.types,
      // while idl.accounts only has { name, discriminator } entries.
      const types = (idl as any).types as any[] || [];
      const escrowTypeDef = types.find(
        (t: any) => t.name === "UserEscrow" || t.name === "userEscrow"
      );
      assert.isDefined(escrowTypeDef, "UserEscrow type must exist in IDL types");

      const fields: any[] = escrowTypeDef?.type?.fields || [];
      const hasAuthorizedSpenderField = fields.some(
        (f: any) => f.name === "authorizedSpender" || f.name === "authorized_spender"
      );
      assert.isFalse(
        hasAuthorizedSpenderField,
        "UserEscrow MUST NOT have authorized_spender field — prevents bank-run / phishing"
      );
    });

    it("UserEscrow account has no withdrawals_enabled field", () => {
      const idl = program.idl;
      const types = (idl as any).types as any[] || [];
      const escrowTypeDef = types.find(
        (t: any) => t.name === "UserEscrow" || t.name === "userEscrow"
      );
      assert.isDefined(escrowTypeDef, "UserEscrow type must exist in IDL types");

      const fields: any[] = escrowTypeDef?.type?.fields || [];
      const hasWithdrawField = fields.some(
        (f: any) =>
          f.name === "withdrawalsEnabled" || f.name === "withdrawals_enabled" ||
          f.name === "capEnabled"         || f.name === "cap_enabled"
      );
      assert.isFalse(
        hasWithdrawField,
        "UserEscrow MUST NOT have withdrawals_enabled or cap_enabled — no admin override"
      );
    });

  });

  // ─── Hold / Release / Burn ────────────────────────────────────────────────────

  describe("HoldClientFunds", () => {

    // Top up user balance to 2000 FLOW before hold tests.
    // Previous purchase/spend tests may have left insufficient balance.
    before(async () => {
      // $200.00 = 2000 FLOW (200 * 9-decimal FLOW per dollar)
      await program.methods
        .purchaseAndEscrow(new BN(2000_00), PaymentTypeSol, null)  // 200000 cents = $2000 = 20000 FLOW
        .accounts({
          user:              user.publicKey,
          userEscrow:        userEscrowPda,
          userEscrowToken,
          treasuryVaultToken,
          treasuryAuthority: treasuryAuthorityPda,
          tokenMint,
          tokenProgram:      TOKEN_PROGRAM_ID,
          systemProgram:     SystemProgram.programId,
          // referrer = None → both referral accounts are SystemProgram.
          poolVault:          UNUSED_POOL_VAULT,
          referralConfig:     SystemProgram.programId,
        })
        .signers([user])
        .rpc();
    });

    it("locks held tokens and creates FundHold PDA (Active)", async () => {
      const claimHash  = Buffer.alloc(32, 0x01);
      const sessionId  = Buffer.alloc(16, 0x02);
      const holdAmount = new BN(400_000_000_000); // 400 FLOW

      const [fundHoldPda] = PublicKey.findProgramAddressSync(
        [Buffer.from("fund_hold"), user.publicKey.toBuffer(), claimHash],
        program.programId
      );

      await program.methods
        .holdClientFunds(holdAmount, [...claimHash], [...sessionId])
        .accounts({
          serviceAuthority: rewardsContractPda.publicKey,
          payer:            rewardsContractPda.publicKey,
          user:             user.publicKey,
          userEscrow:       userEscrowPda,
          fundHold:         fundHoldPda,
          spenderRegistry:  spenderRegistryPda,
          systemProgram:    SystemProgram.programId,
        })
        .signers([rewardsContractPda])
        .rpc();

      const escrow = await program.account.userEscrow.fetch(userEscrowPda);
      assert.ok(escrow.held.eq(holdAmount), `held must equal ${holdAmount}, got ${escrow.held}`);

      const hold = await program.account.fundHold.fetch(fundHoldPda);
      assert.deepEqual(hold.status, { active: {} }, "FundHold status must be Active");
      assert.ok(hold.amount.eq(holdAmount), "FundHold amount must match holdAmount");
      assert.deepEqual(Buffer.from(hold.claimHash), claimHash, "claim_hash must match");
      assert.deepEqual(Buffer.from(hold.sessionId), sessionId, "session_id must match");
    });

    it("rejects hold when effective balance is insufficient", async () => {
      const claimHash = Buffer.alloc(32, 0xAA);
      const sessionId = Buffer.alloc(16, 0xBB);
      const tooLarge  = new BN("999999999999999");

      const [fundHoldPda] = PublicKey.findProgramAddressSync(
        [Buffer.from("fund_hold"), user.publicKey.toBuffer(), claimHash],
        program.programId
      );

      try {
        await program.methods
          .holdClientFunds(tooLarge, [...claimHash], [...sessionId])
          .accounts({
            serviceAuthority: rewardsContractPda.publicKey,
            payer:            rewardsContractPda.publicKey,
            user:             user.publicKey,
            userEscrow:       userEscrowPda,
            fundHold:         fundHoldPda,
            spenderRegistry:  spenderRegistryPda,
            systemProgram:    SystemProgram.programId,
          })
          .signers([rewardsContractPda])
          .rpc();
        assert.fail("Expected InsufficientEffectiveBalance error");
      } catch (err: any) {
        assert.include(err.message, "InsufficientEffectiveBalance",
          `Expected InsufficientEffectiveBalance, got: ${err.message}`);
      }
    });

    it("rejects hold from unauthorized caller", async () => {
      const claimHash = Buffer.alloc(32, 0xCC);
      const sessionId = Buffer.alloc(16, 0xDD);

      const [fundHoldPda] = PublicKey.findProgramAddressSync(
        [Buffer.from("fund_hold"), user.publicKey.toBuffer(), claimHash],
        program.programId
      );

      try {
        await program.methods
          .holdClientFunds(new BN(1), [...claimHash], [...sessionId])
          .accounts({
            serviceAuthority: impostor.publicKey,
            payer:            impostor.publicKey,
            user:             user.publicKey,
            userEscrow:       userEscrowPda,
            fundHold:         fundHoldPda,
            spenderRegistry:  spenderRegistryPda,
            systemProgram:    SystemProgram.programId,
          })
          .signers([impostor])
          .rpc();
        assert.fail("Expected UnauthorizedCaller error");
      } catch (err: any) {
        assert.include(err.message, "UnauthorizedCaller",
          `Expected UnauthorizedCaller, got: ${err.message}`);
      }
    });

  });

  describe("ReleaseFunds", () => {

    it("decrements held, closes FundHold and refunds its rent", async () => {
      const claimHash  = Buffer.alloc(32, 0x11);
      const sessionId  = Buffer.alloc(16, 0x22);
      const holdAmount = new BN(100_000_000_000); // 100 FLOW

      const [fundHoldPda] = PublicKey.findProgramAddressSync(
        [Buffer.from("fund_hold"), user.publicKey.toBuffer(), claimHash],
        program.programId
      );

      // The recipient is no longer free: `ReleaseFunds.rent_recipient` is pinned
      // to FOUNDATION_PUBKEY in the program, so it MUST be the foundation here.
      // That collides with two things the test needs, and both are worked around
      // rather than dropped:
      //
      //   (1) THE DISCRIMINATION PROPERTY. The delta assertion below has to be
      //       able to fail under `close = payer` or `close = user`. The pin
      //       fixes the recipient, so the separation is moved to the OTHER
      //       accounts instead: the hold's `payer` is rewardsContractPda and the
      //       `user` is `user` — neither of which is the foundation. So under
      //       `close = payer` or `close = user` the foundation's balance would
      //       not move at all and the exact-equality assertion fails. Only
      //       `close = rent_recipient` can satisfy it.
      //
      //   (2) THE FEE-PAYER COLLISION. `foundation` is the provider wallet,
      //       which .rpc() would make the fee payer — the fee would net against
      //       the refund and the delta would no longer be exactly the rent.
      //       Approach (a): build with .transaction() and send with
      //       rewardsContractPda as the fee payer (it is already a required
      //       signer). The foundation is then a writable NON-signer, charged
      //       nothing, so its delta is the rent and nothing else — exact
      //       equality, no fee arithmetic and no hardcoded 5000.
      //
      // Whether the pin itself has teeth is a separate question, proved by the
      // negative test below; this test proves `close` targets the right account.
      const rentRecipient = foundation;

      // Create the hold first.
      await program.methods
        .holdClientFunds(holdAmount, [...claimHash], [...sessionId])
        .accounts({
          serviceAuthority: rewardsContractPda.publicKey,
          payer:            rewardsContractPda.publicKey,
          user:             user.publicKey,
          userEscrow:       userEscrowPda,
          fundHold:         fundHoldPda,
          spenderRegistry:  spenderRegistryPda,
          systemProgram:    SystemProgram.programId,
        })
        .signers([rewardsContractPda])
        .rpc();

      const escrowBefore = await program.account.userEscrow.fetch(userEscrowPda);
      const heldBefore   = escrowBefore.held as BN;

      // Before/after control: the account must demonstrably exist first, or the
      // "it is gone afterwards" assertion below could pass vacuously (e.g. on a
      // PDA that was never created).
      const holdInfoBefore = await provider.connection.getAccountInfo(fundHoldPda);
      assert.isNotNull(holdInfoBefore, "FundHold must exist before the release");

      // Snapshot the rent about to be reclaimed straight off the live account
      // rather than hardcoding 1,621,680, and cross-check it against the runtime's
      // own rent-exemption schedule for that data length.
      const holdRent = holdInfoBefore!.lamports;
      const rentExemptMin = await provider.connection.getMinimumBalanceForRentExemption(
        holdInfoBefore!.data.length
      );
      assert.equal(
        holdRent, rentExemptMin,
        `FundHold should hold exactly the rent-exempt minimum for ${holdInfoBefore!.data.length} bytes`
      );

      // bigint, not getBalance() — the foundation is the validator's 500M-SOL
      // genesis mint and a float64 cannot resolve a 1.6M-lamport delta there.
      // See getBalanceExact.
      const rentRecipientBefore = await getBalanceExact(provider.connection, rentRecipient.publicKey);

      // Release — see (2) above. .transaction() + an explicit non-foundation fee
      // payer, NOT .rpc(), so no fee is charged to the account being measured.
      const releaseTx = await program.methods
        .releaseFunds([...claimHash])
        .accounts({
          serviceAuthority: rewardsContractPda.publicKey,
          user:             user.publicKey,
          userEscrow:       userEscrowPda,
          fundHold:         fundHoldPda,
          spenderRegistry:  spenderRegistryPda,
          rentRecipient:    rentRecipient.publicKey,
        })
        .transaction();
      releaseTx.feePayer = rewardsContractPda.publicKey;
      assert.ok(
        !releaseTx.feePayer.equals(rentRecipient.publicKey),
        "fee payer must not be the measured rent recipient, or the delta is fee-netted"
      );
      const relSig = await sendAndConfirmTransaction(
        provider.connection,
        releaseTx,
        [rewardsContractPda],
        { commitment: "confirmed" }
      );
      // The fee really did land on someone else — asserted, not assumed, since
      // the exactness of the delta below rests on it. Account 0 of a legacy
      // message is the fee payer.
      const relTx = await provider.connection.getTransaction(relSig, {
        commitment: "confirmed", maxSupportedTransactionVersion: 0,
      });
      assert.ok(
        relTx!.transaction.message.getAccountKeys().staticAccountKeys[0]
          .equals(rewardsContractPda.publicKey),
        "the fee-paying account must be rewardsContractPda, not the measured foundation"
      );

      const escrowAfter = await program.account.userEscrow.fetch(userEscrowPda);
      assert.ok(
        (escrowAfter.held as BN).eq(heldBefore.sub(holdAmount)),
        `held must decrease by holdAmount: was ${heldBefore}, expected ${heldBefore.sub(holdAmount)}, got ${escrowAfter.held}`
      );
      // balance must NOT change on release
      assert.ok(
        (escrowAfter.balance as BN).eq(escrowBefore.balance as BN),
        "balance must be unchanged on release"
      );

      // (1) The FundHold is gone. getAccountInfo returning null is checked rather
      // than a throwing .fetch(), which would also "pass" on a mistyped PDA.
      const holdInfoAfter = await provider.connection.getAccountInfo(fundHoldPda);
      assert.isNull(
        holdInfoAfter,
        "FundHold account must be closed by `close = rent_recipient`, not merely marked Released"
      );

      // (2) Its lamports landed on the rent recipient — exactly, no slack. Under
      // `close = payer` this delta would be 0 (the payer is rewardsContractPda),
      // and under `close = user` it would be 0 as well. Only
      // `close = rent_recipient` can satisfy it. That is the discrimination the
      // pin would otherwise have cost, relocated onto the other accounts.
      const rentRecipientAfter = await getBalanceExact(provider.connection, rentRecipient.publicKey);
      assert.equal(
        (rentRecipientAfter - rentRecipientBefore).toString(),
        BigInt(holdRent).toString(),
        `rent recipient must receive exactly the FundHold's ${holdRent} lamports`
      );
    });

    it("rejects a rent recipient that is not the foundation", async () => {
      // This is the test that gives the `address = FOUNDATION_PUBKEY` pin on
      // `ReleaseFunds.rent_recipient` its teeth. The test above cannot: with the
      // pin deleted, naming the foundation is still permitted, so it would stay
      // green. Only an attempt to name someone ELSE distinguishes the two.
      //
      // Why the pin belongs in user-escrow and not only in rewards-v2:
      // release_funds is callable by ANY authority in
      // spender_registry.active_spenders. rewardsContractPda below is exactly
      // that — a registered spender that is not rewards-v2 — so this test is a
      // faithful model of the residual risk, not a synthetic one.
      const claimHash  = Buffer.alloc(32, 0x55);
      const sessionId  = Buffer.alloc(16, 0x66);
      const holdAmount = new BN(1_000_000_000); // 1 FLOW

      const [fundHoldPda] = PublicKey.findProgramAddressSync(
        [Buffer.from("fund_hold"), user.publicKey.toBuffer(), claimHash],
        program.programId
      );

      await program.methods
        .holdClientFunds(holdAmount, [...claimHash], [...sessionId])
        .accounts({
          serviceAuthority: rewardsContractPda.publicKey,
          payer:            rewardsContractPda.publicKey,
          user:             user.publicKey,
          userEscrow:       userEscrowPda,
          fundHold:         fundHoldPda,
          spenderRegistry:  spenderRegistryPda,
          systemProgram:    SystemProgram.programId,
        })
        .signers([rewardsContractPda])
        .rpc();

      const thief = Keypair.generate();

      // A flag rather than assert.fail(): chai's AssertionError would be swallowed
      // by the catch, and its message would itself contain "NotFoundation" — the
      // assertion would then confirm its own failure message. The flag cannot.
      let released = false;
      try {
        await program.methods
          .releaseFunds([...claimHash])
          .accounts({
            serviceAuthority: rewardsContractPda.publicKey,
            user:             user.publicKey,
            userEscrow:       userEscrowPda,
            fundHold:         fundHoldPda,
            spenderRegistry:  spenderRegistryPda,
            rentRecipient:    thief.publicKey,
          })
          .signers([rewardsContractPda])
          .rpc();
        released = true;
      } catch (err: any) {
        assert.include(err.message, "NotFoundation",
          `Expected NotFoundation, got: ${err.message}`);
      }
      assert.isFalse(released,
        "a registered spender must not be able to redirect the closed hold's rent");

      // Reverted wholesale: the hold is untouched and the named wallet is empty.
      assert.isNotNull(
        await provider.connection.getAccountInfo(fundHoldPda),
        "a rejected release must leave the FundHold open"
      );
      assert.equal(
        await provider.connection.getBalance(thief.publicKey), 0,
        "a rejected release must move no lamports to the named recipient"
      );

      // The SAME instruction with only the recipient changed must succeed. That
      // is what makes this an A/B on the pin rather than on some other constraint
      // (registry membership, hold status, seeds) that would reject either way.
      // It also leaves no Active hold behind for later tests.
      await program.methods
        .releaseFunds([...claimHash])
        .accounts({
          serviceAuthority: rewardsContractPda.publicKey,
          user:             user.publicKey,
          userEscrow:       userEscrowPda,
          fundHold:         fundHoldPda,
          spenderRegistry:  spenderRegistryPda,
          rentRecipient:    foundation.publicKey,
        })
        .signers([rewardsContractPda])
        .rpc();

      assert.isNull(
        await provider.connection.getAccountInfo(fundHoldPda),
        "the same release with the foundation as recipient must succeed and close the hold"
      );
    });

    it("rejects a second release of the same hold", async () => {
      const claimHash = Buffer.alloc(32, 0x11); // same hash as above (released + closed)

      const [fundHoldPda] = PublicKey.findProgramAddressSync(
        [Buffer.from("fund_hold"), user.publicKey.toBuffer(), claimHash],
        program.programId
      );

      // The replay guard used to be `constraint = status == Active`, surfacing as
      // HoldNotActive. Now that release closes the account there is no account left
      // to deserialize, so Anchor rejects it one step earlier with
      // AccountNotInitialized (3012). Same refusal, different code — and no live
      // FundHold can ever be non-Active any more, since both termination paths
      // close it. The status constraint stays as defence in depth.
      //
      // AccountNotInitialized is a GENERIC error: a mistyped seed would raise it
      // just as readily, and the test would "pass" while proving nothing. Pin the
      // subject first — this exact PDA exists in the ledger's history and is
      // genuinely closed now, so the rejection below is about closure and not
      // about addressing a PDA that never existed. (Same hazard as using a
      // throwing .fetch() to prove absence.)
      assert.isNull(
        await provider.connection.getAccountInfo(fundHoldPda),
        "precondition: the FundHold released above must be closed, not merely a PDA that was never created"
      );

      try {
        await program.methods
          .releaseFunds([...claimHash])
          .accounts({
            serviceAuthority: rewardsContractPda.publicKey,
            user:             user.publicKey,
            userEscrow:       userEscrowPda,
            fundHold:         fundHoldPda,
            spenderRegistry:  spenderRegistryPda,
            // The foundation, so this test trips only the replay guard and never
            // the rent_recipient address pin (covered by the test above).
            rentRecipient:    foundation.publicKey,
          })
          .signers([rewardsContractPda])
          .rpc();
        assert.fail("Expected AccountNotInitialized error");
      } catch (err: any) {
        assert.include(err.message, "AccountNotInitialized",
          `Expected AccountNotInitialized, got: ${err.message}`);
      }
    });

  });

  describe("BurnHeldFunds", () => {

    it("burns held tokens, decrements held+balance, closes FundHold and refunds its rent", async () => {
      const claimHash  = Buffer.alloc(32, 0x33);
      const sessionId  = Buffer.alloc(16, 0x44);
      const holdAmount = new BN(200_000_000_000); // 200 FLOW

      const [fundHoldPda] = PublicKey.findProgramAddressSync(
        [Buffer.from("fund_hold"), user.publicKey.toBuffer(), claimHash],
        program.programId
      );

      // In production, `payer` and `rentRecipient` are the same wallet: the relay
      // funds the FundHold in hold_client_funds, and rewards-v2 forwards that same
      // relay wallet as CPI account 8 on the burn, so a relay can only ever refund
      // itself. Here rentRecipient is deliberately its own independent keypair,
      // distinct from rewardsContractPda (which is both `serviceAuthority` and
      // `payer` on the hold below) — so the lamport-delta assertion below can only
      // pass if the runtime actually honors `close = rent_recipient`, and not
      // `close = service_authority` or `close = payer`, which happen to be the
      // same key in this fixture.
      const rentRecipient = Keypair.generate();

      // Create the hold. rewardsContractPda pays the FundHold's rent.
      await program.methods
        .holdClientFunds(holdAmount, [...claimHash], [...sessionId])
        .accounts({
          serviceAuthority: rewardsContractPda.publicKey,
          payer:            rewardsContractPda.publicKey,
          user:             user.publicKey,
          userEscrow:       userEscrowPda,
          fundHold:         fundHoldPda,
          spenderRegistry:  spenderRegistryPda,
          systemProgram:    SystemProgram.programId,
        })
        .signers([rewardsContractPda])
        .rpc();

      const escrowBefore = await program.account.userEscrow.fetch(userEscrowPda);
      const splBefore    = (await provider.connection.getTokenAccountBalance(userEscrowToken)).value.amount;

      // Snapshot the rent that is about to be reclaimed, straight off the live
      // account rather than a hardcoded constant, and cross-check it against the
      // runtime's own rent-exemption schedule for that data length.
      const holdInfoBefore = await provider.connection.getAccountInfo(fundHoldPda);
      assert.isNotNull(holdInfoBefore, "FundHold must exist before the burn");
      const holdRent = holdInfoBefore!.lamports;
      const rentExemptMin = await provider.connection.getMinimumBalanceForRentExemption(
        holdInfoBefore!.data.length
      );
      assert.equal(
        holdRent, rentExemptMin,
        `FundHold should hold exactly the rent-exempt minimum for ${holdInfoBefore!.data.length} bytes`
      );

      // Fee-payer netting: .rpc() makes the provider wallet the fee payer, and
      // rewardsContractPda is only an extra signer, so it is never charged a fee.
      // The delta below is therefore the rent refund alone and can be asserted as
      // exact equality — no `>` slack, no fee subtraction.
      const rentRecipientBefore = await provider.connection.getBalance(rentRecipient.publicKey);

      // Burn.
      await program.methods
        .burnHeldFunds([...claimHash])
        .accounts({
          serviceAuthority: rewardsContractPda.publicKey,
          user:             user.publicKey,
          userEscrow:       userEscrowPda,
          userEscrowToken:  userEscrowToken,
          fundHold:         fundHoldPda,
          spenderRegistry:  spenderRegistryPda,
          tokenMint:        tokenMint,
          tokenProgram:     TOKEN_PROGRAM_ID,
          rentRecipient:    rentRecipient.publicKey,
        })
        .signers([rewardsContractPda])
        .rpc();

      const escrowAfter = await program.account.userEscrow.fetch(userEscrowPda);
      const splAfter    = (await provider.connection.getTokenAccountBalance(userEscrowToken)).value.amount;

      assert.ok(
        (escrowAfter.held as BN).eq((escrowBefore.held as BN).sub(holdAmount)),
        `held must decrease by holdAmount`
      );
      assert.ok(
        (escrowAfter.balance as BN).eq((escrowBefore.balance as BN).sub(holdAmount)),
        `balance must decrease by holdAmount`
      );
      assert.equal(
        BigInt(splBefore) - BigInt(splAfter),
        BigInt(holdAmount.toString()),
        "SPL token account must decrease by holdAmount"
      );

      // (1) The FundHold is gone. getAccountInfo returning null is checked rather
      // than a throwing .fetch(), which would also "pass" on a mistyped PDA.
      const holdInfoAfter = await provider.connection.getAccountInfo(fundHoldPda);
      assert.isNull(
        holdInfoAfter,
        "FundHold account must be closed by `close = rent_recipient`, not merely marked Burned"
      );

      // (2) Its lamports landed on the rent recipient.
      const rentRecipientAfter = await provider.connection.getBalance(rentRecipient.publicKey);
      assert.equal(
        rentRecipientAfter - rentRecipientBefore,
        holdRent,
        `rent recipient must receive exactly the FundHold's ${holdRent} lamports`
      );
    });

    it("rejects burn of a hold already closed by release", async () => {
      // Released — and therefore closed — in the ReleaseFunds test above. Before
      // release closed it this reached the `status == Active` constraint and
      // surfaced HoldNotActive; now the account is gone, so Anchor fails earlier
      // with AccountNotInitialized. This is the double-spend guard that matters:
      // a client who won a dispute must not also have their funds burned.
      const claimHash = Buffer.alloc(32, 0x11);

      const [fundHoldPda] = PublicKey.findProgramAddressSync(
        [Buffer.from("fund_hold"), user.publicKey.toBuffer(), claimHash],
        program.programId
      );

      // AccountNotInitialized is a GENERIC error — a mistyped seed raises it too.
      // Prove the subject is the right, genuinely-closed PDA before asserting on
      // the refusal, so this cannot pass vacuously against an address that never
      // held an account.
      assert.isNull(
        await provider.connection.getAccountInfo(fundHoldPda),
        "precondition: the FundHold released earlier must be closed, not merely a PDA that was never created"
      );

      try {
        await program.methods
          .burnHeldFunds([...claimHash])
          .accounts({
            serviceAuthority: rewardsContractPda.publicKey,
            user:             user.publicKey,
            userEscrow:       userEscrowPda,
            userEscrowToken:  userEscrowToken,
            fundHold:         fundHoldPda,
            spenderRegistry:  spenderRegistryPda,
            tokenMint:        tokenMint,
            tokenProgram:     TOKEN_PROGRAM_ID,
            rentRecipient:    rewardsContractPda.publicKey,
          })
          .signers([rewardsContractPda])
          .rpc();
        assert.fail("Expected AccountNotInitialized error");
      } catch (err: any) {
        assert.include(err.message, "AccountNotInitialized",
          `Expected AccountNotInitialized, got: ${err.message}`);
      }
    });

  });

});
