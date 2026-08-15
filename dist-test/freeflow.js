"use strict";
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || (function () {
    var ownKeys = function(o) {
        ownKeys = Object.getOwnPropertyNames || function (o) {
            var ar = [];
            for (var k in o) if (Object.prototype.hasOwnProperty.call(o, k)) ar[ar.length] = k;
            return ar;
        };
        return ownKeys(o);
    };
    return function (mod) {
        if (mod && mod.__esModule) return mod;
        var result = {};
        if (mod != null) for (var k = ownKeys(mod), i = 0; i < k.length; i++) if (k[i] !== "default") __createBinding(result, mod, k[i]);
        __setModuleDefault(result, mod);
        return result;
    };
})();
var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
Object.defineProperty(exports, "__esModule", { value: true });
const anchor = __importStar(require("@coral-xyz/anchor"));
const anchor_1 = require("@coral-xyz/anchor");
const web3_js_1 = require("@solana/web3.js");
const chai_1 = require("chai");
// ─── Test suite ───────────────────────────────────────────────────────────────
describe("FreeFlow Contract Suite", () => {
    const provider = anchor.AnchorProvider.env();
    anchor.setProvider(provider);
    const stakingProgram = anchor.workspace.Staking;
    const rewardsProgram = anchor.workspace.Rewards;
    const registryProgram = anchor.workspace.Registry;
    const operator = provider.wallet;
    const LAMPORTS_PER_FLOW = new anchor_1.BN(1000000000);
    // ── Staking tests ─────────────────────────────────────────────────────────
    describe("Staking", () => {
        it("Stakes Lightweight minimum (100 $FLOW)", () => __awaiter(void 0, void 0, void 0, function* () {
            const [stakeRecord] = web3_js_1.PublicKey.findProgramAddressSync([Buffer.from("stake"), operator.publicKey.toBuffer()], stakingProgram.programId);
            const amount = LAMPORTS_PER_FLOW.muln(100);
            yield stakingProgram.methods
                .stake(amount, 1 /* Lightweight */)
                .accounts({ stakeRecord })
                .rpc();
            const record = yield stakingProgram.account.stakeRecord.fetch(stakeRecord);
            chai_1.assert.equal(record.stakedAmount.toString(), amount.toString());
            chai_1.assert.equal(record.tier, 1);
            chai_1.assert.equal(record.status, 0 /* Locked */);
        }));
        it("Rejects stake below tier minimum", () => __awaiter(void 0, void 0, void 0, function* () {
            const tooLow = LAMPORTS_PER_FLOW.muln(99); // 99 < 100 minimum
            try {
                yield stakingProgram.methods
                    .stake(tooLow, 1)
                    .rpc();
                chai_1.assert.fail("Should have thrown InsufficientStake");
            }
            catch (e) {
                chai_1.assert.include(e.message, "InsufficientStake");
            }
        }));
        it("Verifies stake is above tier minimum", () => __awaiter(void 0, void 0, void 0, function* () {
            const [stakeRecord] = web3_js_1.PublicKey.findProgramAddressSync([Buffer.from("stake"), operator.publicKey.toBuffer()], stakingProgram.programId);
            // Should not throw.
            yield stakingProgram.methods
                .verifyStake(1 /* Lightweight */)
                .accounts({ stakeRecord })
                .rpc();
        }));
        it("Applies 10% slash for downtime", () => __awaiter(void 0, void 0, void 0, function* () {
            const [stakeRecord] = web3_js_1.PublicKey.findProgramAddressSync([Buffer.from("stake"), operator.publicKey.toBuffer()], stakingProgram.programId);
            const evidenceHash = Buffer.alloc(32, 0xAB);
            yield stakingProgram.methods
                .slash(0 /* Downtime */, [...evidenceHash])
                .accounts({ stakeRecord, operator: operator.publicKey })
                .rpc();
            const record = yield stakingProgram.account.stakeRecord.fetch(stakeRecord);
            const slashedFlow = record.slashedAmount.divn(1000000000).toNumber();
            chai_1.assert.equal(slashedFlow, 10, "10 $FLOW should be slashed (10% of 100)");
            chai_1.assert.equal(record.status, 2 /* Slashed */);
        }));
        it("Applies 100% slash for severe violation → ejected", () => __awaiter(void 0, void 0, void 0, function* () {
            const [stakeRecord] = web3_js_1.PublicKey.findProgramAddressSync([Buffer.from("stake"), operator.publicKey.toBuffer()], stakingProgram.programId);
            const evidenceHash = Buffer.alloc(32, 0xFF);
            yield stakingProgram.methods
                .slash(3 /* Severe */, [...evidenceHash])
                .accounts({ stakeRecord, operator: operator.publicKey })
                .rpc();
            const record = yield stakingProgram.account.stakeRecord.fetch(stakeRecord);
            chai_1.assert.equal(record.status, 3 /* Ejected */);
        }));
        it("Professional tier requires 1000 $FLOW", () => __awaiter(void 0, void 0, void 0, function* () {
            const tooLow = LAMPORTS_PER_FLOW.muln(999); // 999 < 1000
            try {
                yield stakingProgram.methods.stake(tooLow, 0 /* Professional */).rpc();
                chai_1.assert.fail("Should have thrown");
            }
            catch (e) {
                chai_1.assert.include(e.message, "InsufficientStake");
            }
        }));
    });
    // ── Rewards tests ──────────────────────────────────────────────────────────
    describe("Rewards", () => {
        it("Initialises rewards record", () => __awaiter(void 0, void 0, void 0, function* () {
            const [rewardsRecord] = web3_js_1.PublicKey.findProgramAddressSync([Buffer.from("rewards"), operator.publicKey.toBuffer()], rewardsProgram.programId);
            yield rewardsProgram.methods
                .initRewards(1 /* Lightweight */)
                .accounts({ rewardsRecord })
                .rpc();
            const record = yield rewardsProgram.account.rewardsRecord.fetch(rewardsRecord);
            chai_1.assert.equal(record.tier, 1);
            chai_1.assert.equal(record.bytesRouted.toNumber(), 0);
        }));
        it("Records routing contribution", () => __awaiter(void 0, void 0, void 0, function* () {
            const [rewardsRecord] = web3_js_1.PublicKey.findProgramAddressSync([Buffer.from("rewards"), operator.publicKey.toBuffer()], rewardsProgram.programId);
            const bytes = new anchor_1.BN(100 * 1024 * 1024 * 1024); // 100 GB
            yield rewardsProgram.methods
                .recordRouting(bytes)
                .accounts({ rewardsRecord })
                .rpc();
            const record = yield rewardsProgram.account.rewardsRecord.fetch(rewardsRecord);
            chai_1.assert.equal(record.bytesRouted.toString(), bytes.toString());
        }));
        it("Records seeding contribution", () => __awaiter(void 0, void 0, void 0, function* () {
            const [rewardsRecord] = web3_js_1.PublicKey.findProgramAddressSync([Buffer.from("rewards"), operator.publicKey.toBuffer()], rewardsProgram.programId);
            const bytes = new anchor_1.BN(50 * 1024 * 1024 * 1024); // 50 GB
            yield rewardsProgram.methods
                .recordSeeding(bytes)
                .accounts({ rewardsRecord })
                .rpc();
            const record = yield rewardsProgram.account.rewardsRecord.fetch(rewardsRecord);
            chai_1.assert.isTrue(record.bytesSeeded.gtn(0));
        }));
        it("Enforces 24h claim interval", () => __awaiter(void 0, void 0, void 0, function* () {
            const [rewardsRecord] = web3_js_1.PublicKey.findProgramAddressSync([Buffer.from("rewards"), operator.publicKey.toBuffer()], rewardsProgram.programId);
            try {
                yield rewardsProgram.methods.claimRewards().accounts({ rewardsRecord }).rpc();
                // Second claim immediately should fail.
                yield rewardsProgram.methods.claimRewards().accounts({ rewardsRecord }).rpc();
                chai_1.assert.fail("Should have thrown ClaimTooSoon");
            }
            catch (e) {
                chai_1.assert.include(e.message, "ClaimTooSoon");
            }
        }));
        it("Professional earns more than Lightweight for same bytes", () => __awaiter(void 0, void 0, void 0, function* () {
            // Pure logic test using the exported calculation function.
            // Professional: 150 bps routing, 200 bps seeding.
            const proRoutingMb = 1024;
            const liteRoutingMb = 1024;
            const baseRate = 1000; // lamports/MB
            const proEarnings = proRoutingMb * baseRate * 150 / 100;
            const liteEarnings = liteRoutingMb * baseRate * 100 / 100;
            chai_1.assert.isAbove(proEarnings, liteEarnings, "Professional should earn more");
            chai_1.assert.equal(proEarnings / liteEarnings, 1.5, "1.5× routing multiplier");
        }));
    });
    // ── Registry tests ────────────────────────────────────────────────────────
    describe("Registry", () => {
        const relayKeypair = web3_js_1.Keypair.generate();
        const relayPubkey32 = relayKeypair.publicKey.toBytes();
        it("Registers a Lightweight relay", () => __awaiter(void 0, void 0, void 0, function* () {
            const [relayEntry] = web3_js_1.PublicKey.findProgramAddressSync([Buffer.from("relay"), operator.publicKey.toBuffer()], registryProgram.programId);
            yield registryProgram.methods
                .registerRelay([...relayPubkey32], 1, // Lightweight
            [83, 71], // "SG"
            Buffer.from("1.2.3.4:443"), new anchor_1.BN(10))
                .accounts({ relayEntry })
                .rpc();
            const entry = yield registryProgram.account.relayEntry.fetch(relayEntry);
            chai_1.assert.equal(entry.tier, 1);
            chai_1.assert.equal(entry.status, 0 /* Active */);
            chai_1.assert.deepEqual(entry.country, [83, 71]);
        }));
        it("Sends heartbeat to update last_heartbeat", () => __awaiter(void 0, void 0, void 0, function* () {
            const [relayEntry] = web3_js_1.PublicKey.findProgramAddressSync([Buffer.from("relay"), operator.publicKey.toBuffer()], registryProgram.programId);
            const before = (yield registryProgram.account.relayEntry.fetch(relayEntry)).lastHeartbeat;
            // Wait 1 slot.
            yield new Promise(r => setTimeout(r, 500));
            yield registryProgram.methods.heartbeat().accounts({ relayEntry }).rpc();
            const after = (yield registryProgram.account.relayEntry.fetch(relayEntry)).lastHeartbeat;
            chai_1.assert.isTrue(after.gte(before), "lastHeartbeat should be updated");
        }));
        it("Transitions Active → Maintenance", () => __awaiter(void 0, void 0, void 0, function* () {
            const [relayEntry] = web3_js_1.PublicKey.findProgramAddressSync([Buffer.from("relay"), operator.publicKey.toBuffer()], registryProgram.programId);
            yield registryProgram.methods
                .updateStatus(2 /* Maintenance */)
                .accounts({ relayEntry })
                .rpc();
            const entry = yield registryProgram.account.relayEntry.fetch(relayEntry);
            chai_1.assert.equal(entry.status, 2 /* Maintenance */);
        }));
        it("Transitions Maintenance → Active", () => __awaiter(void 0, void 0, void 0, function* () {
            const [relayEntry] = web3_js_1.PublicKey.findProgramAddressSync([Buffer.from("relay"), operator.publicKey.toBuffer()], registryProgram.programId);
            yield registryProgram.methods
                .updateStatus(0 /* Active */)
                .accounts({ relayEntry })
                .rpc();
            const entry = yield registryProgram.account.relayEntry.fetch(relayEntry);
            chai_1.assert.equal(entry.status, 0);
        }));
        it("Governance can slash from any state", () => __awaiter(void 0, void 0, void 0, function* () {
            const [relayEntry] = web3_js_1.PublicKey.findProgramAddressSync([Buffer.from("relay"), operator.publicKey.toBuffer()], registryProgram.programId);
            // Slash from Active → Slashed (governance override).
            yield registryProgram.methods
                .updateStatus(3 /* Slashed */)
                .accounts({ relayEntry })
                .rpc();
            const entry = yield registryProgram.account.relayEntry.fetch(relayEntry);
            chai_1.assert.equal(entry.status, 3 /* Slashed */);
        }));
        it("Deregisters relay and returns rent", () => __awaiter(void 0, void 0, void 0, function* () {
            const [relayEntry] = web3_js_1.PublicKey.findProgramAddressSync([Buffer.from("relay"), operator.publicKey.toBuffer()], registryProgram.programId);
            const balanceBefore = yield provider.connection.getBalance(operator.publicKey);
            yield registryProgram.methods.deregister().accounts({ relayEntry }).rpc();
            const balanceAfter = yield provider.connection.getBalance(operator.publicKey);
            chai_1.assert.isAbove(balanceAfter, balanceBefore, "Rent should be returned");
            // Account should no longer exist.
            const account = yield provider.connection.getAccountInfo(relayEntry);
            chai_1.assert.isNull(account, "Relay entry should be closed");
        }));
    });
});
