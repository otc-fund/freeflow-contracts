//! Tests for foundation reward-rate authority + CommitClaim rate ceiling.
//!
//! | Handler                  | What's tested |
//! |--------------------------|---------------|
//! | `InitializeRewardRates`  | Creates the 81-byte reward_rates PDA with defaults + authority |
//! | `UpdateRewardRates`      | Bumps change_count, persists new values; non-foundation signer rejected |
//! | `CommitClaim` (ceiling)  | At-ceiling succeeds, over-ceiling rejected, absent-PDA fallback-allow |

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

        let bh = banks.get_latest_blockhash().await.unwrap();
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

    // ── CommitClaim rate ceiling ──────────────────────────────────────────────

    /// total_bytes=2 GB × routing_per_mb=1e6 / 1e6 = 2e9 ; uptime 3h × 10 $FLOW = 3e10.
    const ROUTING: u64 = 1_000_000;
    const UPTIME: u64 = 10_000_000_000;
    const BYTES: u64 = 2_000_000_000;
    const UPTIME_HOURS: u64 = 3;
    const CEILING: u64 = 2_000_000_000 + 30_000_000_000; // 32e9

    fn commit_ix(relay: &Pubkey, epoch: u64, total_amount: u64, with_rates: bool) -> Instruction {
        let mut accounts = vec![
            AccountMeta::new(*relay, true),
            AccountMeta::new(claim_commitment_pda(relay, epoch), false),
            AccountMeta::new_readonly(system_program::ID, false),
        ];
        if with_rates {
            accounts.push(AccountMeta::new_readonly(reward_rates_pda(), false));
        }
        Instruction {
            program_id: id(),
            accounts,
            data: encode_ix(&RewardsInstruction::CommitClaim {
                merkle_root: [7u8; 32],
                client_count: 1,
                total_amount,
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
    async fn commit_claim_at_ceiling_succeeds() {
        let (mut banks, payer, bh) = program_test().start().await;
        setup_rates(&mut banks, &payer, bh).await;
        let epoch = current_epoch(&mut banks).await;
        let bh = banks.get_latest_blockhash().await.unwrap();

        banks.process_transaction(Transaction::new_signed_with_payer(
            &[commit_ix(&payer.pubkey(), epoch, CEILING, true)],
            Some(&payer.pubkey()), &[&payer], bh,
        )).await.expect("at-ceiling CommitClaim must succeed");

        let acct = banks.get_account(claim_commitment_pda(&payer.pubkey(), epoch)).await
            .expect("rpc").expect("commitment exists");
        let c = ClaimCommitment::try_from_slice(&acct.data[..CLAIM_COMMITMENT_SIZE]).expect("deser");
        assert_eq!(c.uptime_hours, UPTIME_HOURS, "uptime_hours persisted on commitment");
        assert_eq!(c.total_amount, CEILING);
    }

    #[tokio::test]
    async fn commit_claim_above_ceiling_rejected() {
        let (mut banks, payer, bh) = program_test().start().await;
        setup_rates(&mut banks, &payer, bh).await;
        let epoch = current_epoch(&mut banks).await;
        let bh = banks.get_latest_blockhash().await.unwrap();

        let result = banks.process_transaction(Transaction::new_signed_with_payer(
            &[commit_ix(&payer.pubkey(), epoch, CEILING + 1, true)],
            Some(&payer.pubkey()), &[&payer], bh,
        )).await;
        assert!(result.is_err(), "over-ceiling CommitClaim must be rejected (RateCeilingExceeded)");
    }

    #[tokio::test]
    async fn commit_claim_without_rates_account_succeeds() {
        // Fallback-allow during rollout: no reward_rates account supplied.
        let (mut banks, payer, bh) = program_test().start().await;
        let _ = bh;
        let epoch = current_epoch(&mut banks).await;
        let bh = banks.get_latest_blockhash().await.unwrap();

        banks.process_transaction(Transaction::new_signed_with_payer(
            &[commit_ix(&payer.pubkey(), epoch, u64::MAX / 2, false)],
            Some(&payer.pubkey()), &[&payer], bh,
        )).await.expect("CommitClaim without rates account must succeed (fallback-allow)");
    }
}
