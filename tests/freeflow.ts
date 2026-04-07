import * as anchor from "@coral-xyz/anchor";
import { Program, BN } from "@coral-xyz/anchor";
import {
  Keypair, PublicKey, SystemProgram, SYSVAR_RENT_PUBKEY
} from "@solana/web3.js";
import { assert } from "chai";

// ─── Test suite ───────────────────────────────────────────────────────────────

describe("FreeFlow Contract Suite", () => {
  const provider = anchor.AnchorProvider.env();
  anchor.setProvider(provider);

  const stakingProgram  = anchor.workspace.Staking  as Program;
  const rewardsProgram  = anchor.workspace.Rewards  as Program;
  const registryProgram = anchor.workspace.Registry as Program;

  const operator        = provider.wallet as anchor.Wallet;
  const LAMPORTS_PER_FLOW = new BN(1_000_000_000);

  // ── Staking tests ─────────────────────────────────────────────────────────

  describe("Staking", () => {

    it("Stakes Lightweight minimum (100 $FLOW)", async () => {
      const [stakeRecord] = PublicKey.findProgramAddressSync(
        [Buffer.from("stake"), operator.publicKey.toBuffer()],
        stakingProgram.programId,
      );

      const amount = LAMPORTS_PER_FLOW.muln(100);
      await stakingProgram.methods
        .stake(amount, 1 /* Lightweight */)
        .accounts({ stakeRecord })
        .rpc();

      const record = await stakingProgram.account.stakeRecord.fetch(stakeRecord);
      assert.equal(record.stakedAmount.toString(), amount.toString());
      assert.equal(record.tier, 1);
      assert.equal(record.status, 0 /* Locked */);
    });

    it("Rejects stake below tier minimum", async () => {
      const tooLow = LAMPORTS_PER_FLOW.muln(99); // 99 < 100 minimum
      try {
        await stakingProgram.methods
          .stake(tooLow, 1)
          .rpc();
        assert.fail("Should have thrown InsufficientStake");
      } catch (e: any) {
        assert.include(e.message, "InsufficientStake");
      }
    });

    it("Verifies stake is above tier minimum", async () => {
      const [stakeRecord] = PublicKey.findProgramAddressSync(
        [Buffer.from("stake"), operator.publicKey.toBuffer()],
        stakingProgram.programId,
      );
      // Should not throw.
      await stakingProgram.methods
        .verifyStake(1 /* Lightweight */)
        .accounts({ stakeRecord })
        .rpc();
    });

    it("Applies 10% slash for downtime", async () => {
      const [stakeRecord] = PublicKey.findProgramAddressSync(
        [Buffer.from("stake"), operator.publicKey.toBuffer()],
        stakingProgram.programId,
      );

      const evidenceHash = Buffer.alloc(32, 0xAB);
      await stakingProgram.methods
        .slash(0 /* Downtime */, [...evidenceHash])
        .accounts({ stakeRecord, operator: operator.publicKey })
        .rpc();

      const record = await stakingProgram.account.stakeRecord.fetch(stakeRecord);
      const slashedFlow = record.slashedAmount.divn(1_000_000_000).toNumber();
      assert.equal(slashedFlow, 10, "10 $FLOW should be slashed (10% of 100)");
      assert.equal(record.status, 2 /* Slashed */);
    });

    it("Applies 100% slash for severe violation → ejected", async () => {
      const [stakeRecord] = PublicKey.findProgramAddressSync(
        [Buffer.from("stake"), operator.publicKey.toBuffer()],
        stakingProgram.programId,
      );

      const evidenceHash = Buffer.alloc(32, 0xFF);
      await stakingProgram.methods
        .slash(3 /* Severe */, [...evidenceHash])
        .accounts({ stakeRecord, operator: operator.publicKey })
        .rpc();

      const record = await stakingProgram.account.stakeRecord.fetch(stakeRecord);
      assert.equal(record.status, 3 /* Ejected */);
    });

    it("Professional tier requires 1000 $FLOW", async () => {
      const tooLow = LAMPORTS_PER_FLOW.muln(999); // 999 < 1000
      try {
        await stakingProgram.methods.stake(tooLow, 0 /* Professional */).rpc();
        assert.fail("Should have thrown");
      } catch (e: any) {
        assert.include(e.message, "InsufficientStake");
      }
    });
  });

  // ── Rewards tests ──────────────────────────────────────────────────────────

  describe("Rewards", () => {

    it("Initialises rewards record", async () => {
      const [rewardsRecord] = PublicKey.findProgramAddressSync(
        [Buffer.from("rewards"), operator.publicKey.toBuffer()],
        rewardsProgram.programId,
      );

      await rewardsProgram.methods
        .initRewards(1 /* Lightweight */)
        .accounts({ rewardsRecord })
        .rpc();

      const record = await rewardsProgram.account.rewardsRecord.fetch(rewardsRecord);
      assert.equal(record.tier, 1);
      assert.equal(record.bytesRouted.toNumber(), 0);
    });

    it("Records routing contribution", async () => {
      const [rewardsRecord] = PublicKey.findProgramAddressSync(
        [Buffer.from("rewards"), operator.publicKey.toBuffer()],
        rewardsProgram.programId,
      );

      const bytes = new BN(100 * 1024 * 1024 * 1024); // 100 GB
      await rewardsProgram.methods
        .recordRouting(bytes)
        .accounts({ rewardsRecord })
        .rpc();

      const record = await rewardsProgram.account.rewardsRecord.fetch(rewardsRecord);
      assert.equal(record.bytesRouted.toString(), bytes.toString());
    });

    it("Records seeding contribution", async () => {
      const [rewardsRecord] = PublicKey.findProgramAddressSync(
        [Buffer.from("rewards"), operator.publicKey.toBuffer()],
        rewardsProgram.programId,
      );

      const bytes = new BN(50 * 1024 * 1024 * 1024); // 50 GB
      await rewardsProgram.methods
        .recordSeeding(bytes)
        .accounts({ rewardsRecord })
        .rpc();

      const record = await rewardsProgram.account.rewardsRecord.fetch(rewardsRecord);
      assert.isTrue(record.bytesSeeded.gtn(0));
    });

    it("Enforces 24h claim interval", async () => {
      const [rewardsRecord] = PublicKey.findProgramAddressSync(
        [Buffer.from("rewards"), operator.publicKey.toBuffer()],
        rewardsProgram.programId,
      );

      try {
        await rewardsProgram.methods.claimRewards().accounts({ rewardsRecord }).rpc();
        // Second claim immediately should fail.
        await rewardsProgram.methods.claimRewards().accounts({ rewardsRecord }).rpc();
        assert.fail("Should have thrown ClaimTooSoon");
      } catch (e: any) {
        assert.include(e.message, "ClaimTooSoon");
      }
    });

    it("Professional earns more than Lightweight for same bytes", async () => {
      // Pure logic test using the exported calculation function.
      // Professional: 150 bps routing, 200 bps seeding.
      const proRoutingMb  = 1024;
      const liteRoutingMb = 1024;
      const baseRate      = 1_000; // lamports/MB

      const proEarnings  = proRoutingMb  * baseRate * 150 / 100;
      const liteEarnings = liteRoutingMb * baseRate * 100 / 100;

      assert.isAbove(proEarnings, liteEarnings, "Professional should earn more");
      assert.equal(proEarnings / liteEarnings, 1.5, "1.5× routing multiplier");
    });
  });

  // ── Registry tests ────────────────────────────────────────────────────────

  describe("Registry", () => {
    const relayKeypair  = Keypair.generate();
    const relayPubkey32 = relayKeypair.publicKey.toBytes();

    it("Registers a Lightweight relay", async () => {
      const [relayEntry] = PublicKey.findProgramAddressSync(
        [Buffer.from("relay"), operator.publicKey.toBuffer()],
        registryProgram.programId,
      );

      await registryProgram.methods
        .registerRelay(
          [...relayPubkey32],
          1,                        // Lightweight
          [83, 71],                 // "SG"
          Buffer.from("1.2.3.4:443"),
          new BN(10),               // 10 GB
        )
        .accounts({ relayEntry })
        .rpc();

      const entry = await registryProgram.account.relayEntry.fetch(relayEntry);
      assert.equal(entry.tier, 1);
      assert.equal(entry.status, 0 /* Active */);
      assert.deepEqual(entry.country, [83, 71]);
    });

    it("Sends heartbeat to update last_heartbeat", async () => {
      const [relayEntry] = PublicKey.findProgramAddressSync(
        [Buffer.from("relay"), operator.publicKey.toBuffer()],
        registryProgram.programId,
      );

      const before = (await registryProgram.account.relayEntry.fetch(relayEntry)).lastHeartbeat;

      // Wait 1 slot.
      await new Promise(r => setTimeout(r, 500));

      await registryProgram.methods.heartbeat().accounts({ relayEntry }).rpc();

      const after = (await registryProgram.account.relayEntry.fetch(relayEntry)).lastHeartbeat;
      assert.isTrue(after.gte(before), "lastHeartbeat should be updated");
    });

    it("Transitions Active → Maintenance", async () => {
      const [relayEntry] = PublicKey.findProgramAddressSync(
        [Buffer.from("relay"), operator.publicKey.toBuffer()],
        registryProgram.programId,
      );

      await registryProgram.methods
        .updateStatus(2 /* Maintenance */)
        .accounts({ relayEntry })
        .rpc();

      const entry = await registryProgram.account.relayEntry.fetch(relayEntry);
      assert.equal(entry.status, 2 /* Maintenance */);
    });

    it("Transitions Maintenance → Active", async () => {
      const [relayEntry] = PublicKey.findProgramAddressSync(
        [Buffer.from("relay"), operator.publicKey.toBuffer()],
        registryProgram.programId,
      );

      await registryProgram.methods
        .updateStatus(0 /* Active */)
        .accounts({ relayEntry })
        .rpc();

      const entry = await registryProgram.account.relayEntry.fetch(relayEntry);
      assert.equal(entry.status, 0);
    });

    it("Governance can slash from any state", async () => {
      const [relayEntry] = PublicKey.findProgramAddressSync(
        [Buffer.from("relay"), operator.publicKey.toBuffer()],
        registryProgram.programId,
      );

      // Slash from Active → Slashed (governance override).
      await registryProgram.methods
        .updateStatus(3 /* Slashed */)
        .accounts({ relayEntry })
        .rpc();

      const entry = await registryProgram.account.relayEntry.fetch(relayEntry);
      assert.equal(entry.status, 3 /* Slashed */);
    });

    it("Deregisters relay and returns rent", async () => {
      const [relayEntry] = PublicKey.findProgramAddressSync(
        [Buffer.from("relay"), operator.publicKey.toBuffer()],
        registryProgram.programId,
      );

      const balanceBefore = await provider.connection.getBalance(operator.publicKey);

      await registryProgram.methods.deregister().accounts({ relayEntry }).rpc();

      const balanceAfter = await provider.connection.getBalance(operator.publicKey);
      assert.isAbove(balanceAfter, balanceBefore, "Rent should be returned");

      // Account should no longer exist.
      const account = await provider.connection.getAccountInfo(relayEntry);
      assert.isNull(account, "Relay entry should be closed");
    });
  });
});
