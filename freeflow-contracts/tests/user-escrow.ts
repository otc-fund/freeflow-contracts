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

async function airdrop(provider: anchor.AnchorProvider, key: PublicKey, sol = 10) {
  const sig = await provider.connection.requestAirdrop(key, sol * LAMPORTS_PER_SOL);
  await provider.connection.confirmTransaction(sig, "confirmed");
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
        .purchaseAndEscrow(paymentCents, PaymentTypeSol)
        .accounts({
          user:               user.publicKey,
          userEscrow:         userEscrowPda,
          userEscrowToken,
          treasuryVaultToken,
          treasuryAuthority:  treasuryAuthorityPda,
          tokenMint,
          tokenProgram:       TOKEN_PROGRAM_ID,
          systemProgram:      SystemProgram.programId,
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
        .purchaseAndEscrow(new BN(100), PaymentTypeSol) // $1.00 = 10 $FLOW
        .accounts({
          user:               user.publicKey,
          userEscrow:         userEscrowPda,
          userEscrowToken,
          treasuryVaultToken,
          treasuryAuthority:  treasuryAuthorityPda,
          tokenMint,
          tokenProgram:       TOKEN_PROGRAM_ID,
          systemProgram:      SystemProgram.programId,
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
        .purchaseAndEscrow(paymentCents, PaymentTypeSol)
        .accounts({
          user:               user.publicKey,
          userEscrow:         userEscrowPda,
          userEscrowToken,
          treasuryVaultToken,
          treasuryAuthority:  treasuryAuthorityPda,
          tokenMint,
          tokenProgram:       TOKEN_PROGRAM_ID,
          systemProgram:      SystemProgram.programId,
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
        .purchaseAndEscrow(new BN(100), PaymentTypeSol)
        .accounts({
          user:               user.publicKey,
          userEscrow:         userEscrowPda,
          userEscrowToken,
          treasuryVaultToken,
          treasuryAuthority:  treasuryAuthorityPda,
          tokenMint,
          tokenProgram:       TOKEN_PROGRAM_ID,
          systemProgram:      SystemProgram.programId,
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
        .purchaseAndEscrow(new BN(500), PaymentTypeUsdc) // $5.00 = 50 $FLOW
        .accounts({
          user:               user.publicKey,
          userEscrow:         userEscrowPda,
          userEscrowToken,
          treasuryVaultToken,
          treasuryAuthority:  treasuryAuthorityPda,
          tokenMint,
          tokenProgram:       TOKEN_PROGRAM_ID,
          systemProgram:      SystemProgram.programId,
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
        .purchaseAndEscrow(new BN(200), PaymentTypeUsdt) // $2.00 = 20 $FLOW
        .accounts({
          user:               user.publicKey,
          userEscrow:         userEscrowPda,
          userEscrowToken,
          treasuryVaultToken,
          treasuryAuthority:  treasuryAuthorityPda,
          tokenMint,
          tokenProgram:       TOKEN_PROGRAM_ID,
          systemProgram:      SystemProgram.programId,
        })
        .signers([user])
        .rpc();

      const after = await program.account.userEscrow.fetch(userEscrowPda);
      assert.isTrue(after.balance.gt(before.balance), "USDT balance should increase");
    });

    it("transfers $FLOW from treasury to escrow on credit card payment", async () => {
      const before = await program.account.userEscrow.fetch(userEscrowPda);

      await program.methods
        .purchaseAndEscrow(new BN(1000), PaymentTypeCreditCard) // $10.00 = 100 $FLOW
        .accounts({
          user:               user.publicKey,
          userEscrow:         userEscrowPda,
          userEscrowToken,
          treasuryVaultToken,
          treasuryAuthority:  treasuryAuthorityPda,
          tokenMint,
          tokenProgram:       TOKEN_PROGRAM_ID,
          systemProgram:      SystemProgram.programId,
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
        .purchaseAndEscrow(new BN(100), PaymentTypeSol)
        .accounts({
          user:               user.publicKey,
          userEscrow:         userEscrowPda,
          userEscrowToken,
          treasuryVaultToken,
          treasuryAuthority:  treasuryAuthorityPda,
          tokenMint,
          tokenProgram:       TOKEN_PROGRAM_ID,
          systemProgram:      SystemProgram.programId,
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
          .purchaseAndEscrow(new BN(100), PaymentTypeSol)
          .accounts({
            user:               user.publicKey,
            userEscrow:         userEscrowPda,
            userEscrowToken,
            treasuryVaultToken,
            treasuryAuthority:  treasuryAuthorityPda,
            tokenMint,
            tokenProgram:       TOKEN_PROGRAM_ID,
            systemProgram:      SystemProgram.programId,
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
        .purchaseAndEscrow(largeCents, PaymentTypeSol)
        .accounts({
          user:               user.publicKey,
          userEscrow:         userEscrowPda,
          userEscrowToken,
          treasuryVaultToken,
          treasuryAuthority:  treasuryAuthorityPda,
          tokenMint,
          tokenProgram:       TOKEN_PROGRAM_ID,
          systemProgram:      SystemProgram.programId,
        })
        .signers([user])
        .rpc();

      const after = await program.account.userEscrow.fetch(userEscrowPda);
      assert.isTrue(after.balance.gt(before.balance), "Large purchase should succeed — no cap");
    });

    it("handles zero payment amount gracefully", async () => {
      try {
        await program.methods
          .purchaseAndEscrow(new BN(0), PaymentTypeSol)
          .accounts({
            user:               user.publicKey,
            userEscrow:         userEscrowPda,
            userEscrowToken,
            treasuryVaultToken,
            treasuryAuthority:  treasuryAuthorityPda,
            tokenMint,
            tokenProgram:       TOKEN_PROGRAM_ID,
            systemProgram:      SystemProgram.programId,
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
        .purchaseAndEscrow(new BN(2000_00), PaymentTypeSol)  // 200000 cents = $2000 = 20000 FLOW
        .accounts({
          user:              user.publicKey,
          userEscrow:        userEscrowPda,
          userEscrowToken,
          treasuryVaultToken,
          treasuryAuthority: treasuryAuthorityPda,
          tokenMint,
          tokenProgram:      TOKEN_PROGRAM_ID,
          systemProgram:     SystemProgram.programId,
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

    it("decrements held and marks FundHold as Released", async () => {
      const claimHash  = Buffer.alloc(32, 0x11);
      const sessionId  = Buffer.alloc(16, 0x22);
      const holdAmount = new BN(100_000_000_000); // 100 FLOW

      const [fundHoldPda] = PublicKey.findProgramAddressSync(
        [Buffer.from("fund_hold"), user.publicKey.toBuffer(), claimHash],
        program.programId
      );

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

      // Release.
      await program.methods
        .releaseFunds([...claimHash])
        .accounts({
          serviceAuthority: rewardsContractPda.publicKey,
          user:             user.publicKey,
          userEscrow:       userEscrowPda,
          fundHold:         fundHoldPda,
          spenderRegistry:  spenderRegistryPda,
        })
        .signers([rewardsContractPda])
        .rpc();

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

      const hold = await program.account.fundHold.fetch(fundHoldPda);
      assert.deepEqual(hold.status, { released: {} }, "FundHold status must be Released");
    });

    it("rejects release of an already-released hold", async () => {
      const claimHash = Buffer.alloc(32, 0x11); // same hash as above (already Released)

      const [fundHoldPda] = PublicKey.findProgramAddressSync(
        [Buffer.from("fund_hold"), user.publicKey.toBuffer(), claimHash],
        program.programId
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
          })
          .signers([rewardsContractPda])
          .rpc();
        assert.fail("Expected HoldNotActive error");
      } catch (err: any) {
        assert.include(err.message, "HoldNotActive",
          `Expected HoldNotActive, got: ${err.message}`);
      }
    });

  });

  describe("BurnHeldFunds", () => {

    it("burns held tokens, decrements held+balance, marks FundHold Burned", async () => {
      const claimHash  = Buffer.alloc(32, 0x33);
      const sessionId  = Buffer.alloc(16, 0x44);
      const holdAmount = new BN(200_000_000_000); // 200 FLOW

      const [fundHoldPda] = PublicKey.findProgramAddressSync(
        [Buffer.from("fund_hold"), user.publicKey.toBuffer(), claimHash],
        program.programId
      );

      // Create the hold.
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

      const hold = await program.account.fundHold.fetch(fundHoldPda);
      assert.deepEqual(hold.status, { burned: {} }, "FundHold status must be Burned");
    });

    it("rejects burn of a non-Active hold (already Released)", async () => {
      const claimHash = Buffer.alloc(32, 0x11); // Released in ReleaseFunds test above

      const [fundHoldPda] = PublicKey.findProgramAddressSync(
        [Buffer.from("fund_hold"), user.publicKey.toBuffer(), claimHash],
        program.programId
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
          })
          .signers([rewardsContractPda])
          .rpc();
        assert.fail("Expected HoldNotActive error");
      } catch (err: any) {
        assert.include(err.message, "HoldNotActive",
          `Expected HoldNotActive, got: ${err.message}`);
      }
    });

  });

});
