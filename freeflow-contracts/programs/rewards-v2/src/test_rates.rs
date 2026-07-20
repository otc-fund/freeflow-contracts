//! Tests for foundation reward-rate authority + CommitClaim rate ceiling.
//!
//! | Handler                  | What's tested |
//! |--------------------------|---------------|
//! | `InitializeRewardRates`  | Creates the 81-byte reward_rates PDA with defaults + authority |
//! | `UpdateRewardRates`      | Bumps change_count, persists new values; non-foundation signer rejected |
//! | `CommitClaim` (derivation) | bandwidth/uptime amounts derived on-chain from pinned rates; mandatory reward_rates account enforced |

#[cfg(test)]
mod integration {
    use borsh::BorshDeserialize;
    use solana_program::pubkey::Pubkey;
    use solana_program_test::*;
    use solana_sdk::{
        clock::Clock,
        instruction::{AccountMeta, Instruction},
        signature::{Keypair, Signer},
        system_instruction, system_program,
        transaction::Transaction,
    };

    use crate::{
        constants::*,
        handlers::derive_reward_amount,
        id,
        process_instruction,
        types::{ClaimCommitment, RewardRatesAccount, CLAIM_COMMITMENT_SIZE, REWARD_RATES_SIZE},
        RewardsInstruction,
    };

    fn program_test() -> ProgramTest {
        ProgramTest::new("freeflow_rewards_v2", id(), processor!(process_instruction))
    }

    fn encode_ix(ix: &RewardsInstruction) -> Vec<u8> {
        borsh::to_vec(ix).expect("borsh encode")
    }

    fn foundation_config_pda() -> Pubkey {
        Pubkey::find_program_address(&[b"foundation_config"], &id()).0
    }
    fn reward_rates_pda() -> Pubkey {
        Pubkey::find_program_address(&[b"reward_rates"], &id()).0
    }
    fn claim_commitment_pda(relay: &Pubkey, epoch: u64) -> Pubkey {
        Pubkey::find_program_address(
            &[b"claim_commitment", relay.as_ref(), &epoch.to_le_bytes()],
            &id(),
        ).0
    }
    fn relay_meta_pda(relay: &Pubkey) -> Pubkey {
        Pubkey::find_program_address(&[b"relay_meta", relay.as_ref()], &id()).0
    }

    /// Create the FoundationConfig PDA with `payer` as the foundation wallet
    /// (via SetTrialEnabled, which create-or-initialises the config).
    async fn create_foundation_config(banks: &mut BanksClient, payer: &Keypair, bh: solana_sdk::hash::Hash) {
        let ix = Instruction {
            program_id: id(),
            accounts: vec![
                AccountMeta::new(payer.pubkey(), true),
                AccountMeta::new(foundation_config_pda(), false),
                AccountMeta::new_readonly(system_program::ID, false),
            ],
            data: encode_ix(&RewardsInstruction::SetTrialEnabled { enabled: true }),
        };
        banks.process_transaction(Transaction::new_signed_with_payer(
            &[ix], Some(&payer.pubkey()), &[payer], bh,
        )).await.expect("create foundation_config");
    }

    fn init_rates_ix(foundation: &Pubkey, routing: u64, seeding: u64, uptime: u64, price: u64) -> Instruction {
        Instruction {
            program_id: id(),
            accounts: vec![
                AccountMeta::new(*foundation, true),
                AccountMeta::new(reward_rates_pda(), false),
                AccountMeta::new_readonly(system_program::ID, false),
                AccountMeta::new_readonly(foundation_config_pda(), false),
            ],
            data: encode_ix(&RewardsInstruction::InitializeRewardRates {
                routing_per_mb: routing, seeding_per_mb: seeding,
                uptime_per_hour: uptime, flow_price_cents: price,
            }),
        }
    }

    fn update_rates_ix(foundation: &Pubkey, routing: u64, seeding: u64, uptime: u64, price: u64) -> Instruction {
        Instruction {
            program_id: id(),
            accounts: vec![
                AccountMeta::new(*foundation, true),
                AccountMeta::new(reward_rates_pda(), false),
                AccountMeta::new_readonly(foundation_config_pda(), false),
            ],
            data: encode_ix(&RewardsInstruction::UpdateRewardRates {
                routing_per_mb: routing, seeding_per_mb: seeding,
                uptime_per_hour: uptime, flow_price_cents: price,
            }),
        }
    }

    async fn current_epoch(banks: &mut BanksClient) -> u64 {
        let clock: Clock = banks.get_sysvar().await.expect("clock sysvar");
        clock.unix_timestamp as u64 / EPOCH_SECS
    }

    async fn read_rates(banks: &mut BanksClient) -> RewardRatesAccount {
        let acct = banks.get_account(reward_rates_pda()).await
            .expect("rpc").expect("reward_rates must exist");
        RewardRatesAccount::try_from_slice(&acct.data[..REWARD_RATES_SIZE]).expect("deserialize rates")
    }

    // ── InitializeRewardRates ─────────────────────────────────────────────────

    #[tokio::test]
    async fn initialize_reward_rates_creates_pda_with_defaults() {
        let (mut banks, payer, bh) = program_test().start().await;
        create_foundation_config(&mut banks, &payer, bh).await;
        let bh = banks.get_latest_blockhash().await.unwrap();

        // routing=0 → falls back to DEFAULT_ROUTING_PER_MB; uptime explicit.
        let ix = init_rates_ix(&payer.pubkey(), 0, 0, 10_000_000_000, 250);
        banks.process_transaction(Transaction::new_signed_with_payer(
            &[ix], Some(&payer.pubkey()), &[&payer], bh,
        )).await.expect("InitializeRewardRates must succeed");

        let rr = read_rates(&mut banks).await;
        assert_eq!(rr.authority, payer.pubkey().to_bytes(), "authority = foundation wallet");
        assert_eq!(rr.routing_per_mb, DEFAULT_ROUTING_PER_MB, "0 routing falls back to default");
        assert_eq!(rr.seeding_per_mb, DEFAULT_SEEDING_PER_MB, "0 seeding falls back to default");
        assert_eq!(rr.uptime_per_hour, 10_000_000_000);
        assert_eq!(rr.flow_price_cents, 250);
        assert_eq!(rr.change_count, 0, "fresh PDA starts at change_count 0");
    }

    #[tokio::test]
    async fn initialize_reward_rates_twice_rejected() {
        let (mut banks, payer, bh) = program_test().start().await;
        create_foundation_config(&mut banks, &payer, bh).await;
        let bh = banks.get_latest_blockhash().await.unwrap();
        banks.process_transaction(Transaction::new_signed_with_payer(
            &[init_rates_ix(&payer.pubkey(), 1_000_000, 2_000_000, 10_000_000_000, 0)],
            Some(&payer.pubkey()), &[&payer], bh,
        )).await.expect("first init ok");

        // Must be a genuinely NEW blockhash, not just a re-fetch: the second
        // InitializeRewardRates instruction is byte-identical to the first, so
        // reusing the same blockhash produces the same transaction signature.
        // The bank then treats it as an already-processed duplicate and
        // returns success WITHOUT re-invoking the program at all — which used
        // to make this assertion pass for the wrong reason (no execution, not
        // a real `RewardRatesAlreadyInitialized` rejection).
        let bh = banks.get_new_latest_blockhash(&bh).await.expect("advance blockhash");
        let result = banks.process_transaction(Transaction::new_signed_with_payer(
            &[init_rates_ix(&payer.pubkey(), 1_000_000, 2_000_000, 10_000_000_000, 0)],
            Some(&payer.pubkey()), &[&payer], bh,
        )).await;
        assert!(result.is_err(), "second InitializeRewardRates must be rejected");
    }

    // ── UpdateRewardRates ─────────────────────────────────────────────────────

    #[tokio::test]
    async fn update_reward_rates_bumps_change_count() {
        let (mut banks, payer, bh) = program_test().start().await;
        create_foundation_config(&mut banks, &payer, bh).await;
        let bh = banks.get_latest_blockhash().await.unwrap();
        banks.process_transaction(Transaction::new_signed_with_payer(
            &[init_rates_ix(&payer.pubkey(), 1_000_000, 2_000_000, 10_000_000_000, 0)],
            Some(&payer.pubkey()), &[&payer], bh,
        )).await.expect("init ok");

        let bh = banks.get_latest_blockhash().await.unwrap();
        banks.process_transaction(Transaction::new_signed_with_payer(
            &[update_rates_ix(&payer.pubkey(), 2_000_000, 0, 5_000_000_000, 300)],
            Some(&payer.pubkey()), &[&payer], bh,
        )).await.expect("update ok");

        let rr = read_rates(&mut banks).await;
        assert_eq!(rr.routing_per_mb, 2_000_000, "routing updated");
        assert_eq!(rr.seeding_per_mb, 2_000_000, "0 seeding keeps previous value");
        assert_eq!(rr.uptime_per_hour, 5_000_000_000, "uptime updated");
        assert_eq!(rr.flow_price_cents, 300, "price updated");
        assert_eq!(rr.change_count, 1, "change_count bumped to 1");
    }

    #[tokio::test]
    async fn update_reward_rates_rejects_non_foundation_signer() {
        let (mut banks, payer, bh) = program_test().start().await;
        create_foundation_config(&mut banks, &payer, bh).await;
        let bh = banks.get_latest_blockhash().await.unwrap();
        banks.process_transaction(Transaction::new_signed_with_payer(
            &[init_rates_ix(&payer.pubkey(), 1_000_000, 2_000_000, 10_000_000_000, 0)],
            Some(&payer.pubkey()), &[&payer], bh,
        )).await.expect("init ok");

        // Fund an intruder and have it attempt an update.
        let intruder = Keypair::new();
        let bh = banks.get_latest_blockhash().await.unwrap();
        banks.process_transaction(Transaction::new_signed_with_payer(
            &[system_instruction::transfer(&payer.pubkey(), &intruder.pubkey(), 1_000_000_000)],
            Some(&payer.pubkey()), &[&payer], bh,
        )).await.unwrap();

        let bh = banks.get_latest_blockhash().await.unwrap();
        let result = banks.process_transaction(Transaction::new_signed_with_payer(
            &[update_rates_ix(&intruder.pubkey(), 9_000_000, 0, 0, 0)],
            Some(&intruder.pubkey()), &[&intruder], bh,
        )).await;
        assert!(result.is_err(), "non-foundation signer must not update rates");
    }

    // ── CommitClaim value derivation ──────────────────────────────────────────
    //
    // CommitClaim no longer takes a relay-declared `total_amount` — the
    // contract derives `bandwidth_amount` from `total_bytes` and the pinned
    // `routing_per_mb`, so there is nothing left for a relay to over-declare
    // against a "ceiling". The `RateCeilingExceeded` error this section used
    // to exercise is now dead: see report for the removed
    // `commit_claim_above_ceiling_rejected` test.

    /// total_bytes=2 GB × routing_per_mb=1e6 / 1e6 = 2e9 $FLOW-base-units.
    const ROUTING: u64 = 1_000_000;
    const UPTIME: u64 = 10_000_000_000;
    const BYTES: u64 = 2_000_000_000;
    const UPTIME_HOURS: u64 = 3;

    /// `with_rates=true` supplies the three accounts CommitClaim now requires
    /// on top of [relay, commitment, system_program]: the mandatory
    /// reward_rates PDA, the per-relay relay_meta PDA (monotonic clamp basis),
    /// and the foundation_config PDA (uptime kill switch).
    fn commit_ix(relay: &Pubkey, epoch: u64, with_rates: bool) -> Instruction {
        let mut accounts = vec![
            AccountMeta::new(*relay, true),
            AccountMeta::new(claim_commitment_pda(relay, epoch), false),
            AccountMeta::new_readonly(system_program::ID, false),
        ];
        if with_rates {
            accounts.push(AccountMeta::new_readonly(reward_rates_pda(), false));
            accounts.push(AccountMeta::new(relay_meta_pda(relay), false));
            accounts.push(AccountMeta::new_readonly(foundation_config_pda(), false));
        }
        Instruction {
            program_id: id(),
            accounts,
            data: encode_ix(&RewardsInstruction::CommitClaim {
                merkle_root: [7u8; 32],
                client_count: 1,
                total_bytes: BYTES,
                uptime_hours: UPTIME_HOURS,
                claim_epoch: epoch,
            }),
        }
    }

    async fn setup_rates(banks: &mut BanksClient, payer: &Keypair, bh: solana_sdk::hash::Hash) {
        create_foundation_config(banks, payer, bh).await;
        let bh = banks.get_latest_blockhash().await.unwrap();
        banks.process_transaction(Transaction::new_signed_with_payer(
            &[init_rates_ix(&payer.pubkey(), ROUTING, 2_000_000, UPTIME, 0)],
            Some(&payer.pubkey()), &[payer], bh,
        )).await.expect("init rates");
    }

    #[tokio::test]
    async fn commit_claim_derives_bandwidth_and_uptime_amounts() {
        let (mut banks, payer, bh) = program_test().start().await;
        setup_rates(&mut banks, &payer, bh).await;
        let epoch = current_epoch(&mut banks).await;
        let bh = banks.get_latest_blockhash().await.unwrap();

        banks.process_transaction(Transaction::new_signed_with_payer(
            &[commit_ix(&payer.pubkey(), epoch, true)],
            Some(&payer.pubkey()), &[&payer], bh,
        )).await.expect("CommitClaim must succeed with the mandatory rate accounts");

        let acct = banks.get_account(claim_commitment_pda(&payer.pubkey(), epoch)).await
            .expect("rpc").expect("commitment exists");
        let c = ClaimCommitment::try_from_slice(&acct.data[..CLAIM_COMMITMENT_SIZE]).expect("deser");

        // bandwidth_amount is derived on-chain from bytes x the pinned rate —
        // never a relay-supplied figure. Assert against the same derivation
        // the contract itself uses, not a hand-computed literal.
        assert_eq!(
            c.bandwidth_amount,
            derive_reward_amount(BYTES, ROUTING),
            "bandwidth_amount must equal the contract-derived value from total_bytes and routing_per_mb",
        );
        assert_eq!(c.routing_per_mb, ROUTING, "pinned rate must match reward_rates at commit time");
        assert_eq!(c.uptime_per_hour, UPTIME, "pinned uptime rate must match reward_rates at commit time");

        // First-ever CommitClaim for this relay: relay_meta doesn't exist yet,
        // so clamp_uptime_hours has no elapsed-time basis and must clamp to
        // zero (see handlers::clamp_tests::first_epoch_earns_zero).
        assert_eq!(c.uptime_hours, 0, "first epoch for a relay must earn zero uptime");
        assert_eq!(c.uptime_amount, 0);
    }

    #[tokio::test]
    async fn commit_claim_without_rates_account_rejected() {
        // reward_rates is now mandatory (REWARD_RATES_REQUIRED = true): the
        // fallback-allow path that let a relay skip rate enforcement during
        // rollout — and previously left `total_amount` unbounded — is gone.
        let (mut banks, payer, _bh) = program_test().start().await;
        let epoch = current_epoch(&mut banks).await;
        let bh = banks.get_latest_blockhash().await.unwrap();

        let result = banks.process_transaction(Transaction::new_signed_with_payer(
            &[commit_ix(&payer.pubkey(), epoch, false)],
            Some(&payer.pubkey()), &[&payer], bh,
        )).await;
        assert!(result.is_err(), "CommitClaim without the mandatory reward_rates account must fail");
    }
}
