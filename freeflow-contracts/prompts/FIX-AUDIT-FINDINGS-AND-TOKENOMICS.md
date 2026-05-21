# Claude Execution Prompt: Fix All Contract Audit Findings + Implement 80:20 Tokenomics

## Role
You are a senior Solana smart contract engineer fixing all Critical, High, and Medium findings from a security audit, plus implementing the finalized 80:20 tokenomics with hard cap and pre-mint.

## Context
- **Contracts repo:** `D:\Solana\freeflow-contracts` (Anchor/Solana programs)
- **5 Programs:** repflow-token, staking, rewards, registry, user-escrow
- **Deployed on devnet** (April 28, 2026) — all programs upgradeable
- **Authority wallet:** `8SL4dhnXU9tjvsbwfkVzQbfV99wGnVZBECoiuwrdbaJk`
- **Build toolchain:** Anchor v0.30.1, Solana CLI v1.18.26, cargo 1.75

---

## Finalized Tokenomics

| Allocation | Tokens | Mechanism |
|-----------|--------|-----------|
| **80% — Relay Rewards** | 800,000,000 | Minted gradually via rewards program (uptime + routing + seeding) |
| **20% — Foundation** | 200,000,000 | Pre-minted to foundation wallet, sold to users who burn on service use |
| **Hard Cap** | 1,000,000,000 total | No more tokens can be minted after 1B |
| **Burn Model** | Deflationary | User escrow burns $FLOW on service payment → supply decreases |

---

## Rules
1. **DO NOT touch relay code** (`freeflow-triton`) — this is contracts-only
2. **DO NOT touch `freeflow-client`** — completely separate project
3. **Preserve existing instruction opcodes** — maintain backward compatibility where possible
4. **Build after each program fix** — verify it compiles before moving to the next
5. **Document everything** — create/update `D:\Solana\docs\AUDIT-FIXES-2026-05-04.md`

---

## Phase 1: Critical Fixes (Do These First)

### Fix C-01: Add Foundation Verification to Rewards Config

**Contract:** `rewards/src/lib.rs`  
**Issue:** `process_initialize_rewards_config` and `process_set_migration_mode` only check `foundation.is_signer` — any key can initialize and lock migration mode.

**Fix:** Add a hardcoded foundation pubkey constant and verify it in both functions.

```rust
// At the top of rewards/src/lib.rs, with other constants:
/// Foundation multisig pubkey — required for InitializeRewardsConfig and SetMigrationMode.
/// Replace with actual foundation pubkey before mainnet deploy.
pub const FOUNDATION_PUBKEY: &str = "GoVxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"; // UPDATE THIS

// In process_initialize_rewards_config():
if foundation.key().to_string() != FOUNDATION_PUBKEY {
    msg!("InitializeRewardsConfig: unauthorized foundation key");
    return Err(ProgramError::InvalidArgument);
}

// In process_set_migration_mode():
if foundation.key().to_string() != FOUNDATION_PUBKEY {
    msg!("SetMigrationMode: unauthorized foundation key");
    return Err(ProgramError::InvalidArgument);
}
```

---

### Fix C-02: Add Stake Account Owner Validation

**Contract:** `staking/src/lib.rs`  
**Issue:** `process_unstake` and `process_slash` deserialize stake account data without verifying `stake_account.owner == program_id`.

**Fix:** Add owner check before deserialization in both functions.

```rust
// In process_unstake(), before try_from_slice:
if stake_account.owner != program_id {
    msg!("Unstake: stake account not owned by this program");
    return Err(ProgramError::InvalidAccountOwner);
}

// In process_slash(), before try_from_slice:
if stake_account.owner != program_id {
    msg!("Slash: stake account not owned by this program");
    return Err(ProgramError::InvalidAccountOwner);
}
```

---

## Phase 2: High Severity Fixes

### Fix H-01: Use Checked Math in calculate_reward

**Contract:** `rewards/src/lib.rs`  
**Issue:** `calculate_reward()` uses unchecked `routing_base * multiplier_bps` — can overflow u64.

**Fix:** Replace all multiplications with `checked_mul` or `saturating_mul`:

```rust
// In RewardAccount::calculate_reward():
let routing_base = (bytes_routed / 1_000_000) * 1_000;
let seeding_base = (bytes_seeded / 1_000_000) * 2_000;
let uptime_base = (uptime_seconds / 3600) * 10_000_000;

let routing = routing_base.checked_mul(multiplier_bps as u64)
    .unwrap_or(u64::MAX)
    .checked_div(100)
    .unwrap_or(u64::MAX);

let seeding = seeding_base.checked_mul(multiplier_bps as u64)
    .unwrap_or(u64::MAX)
    .checked_div(100)
    .unwrap_or(u64::MAX);

let cashback = routing.checked_add(seeding)
    .unwrap_or(u64::MAX)
    .checked_mul(cashback_pct as u64)
    .unwrap_or(u64::MAX)
    .checked_div(100)
    .unwrap_or(u64::MAX);

routing.saturating_add(seeding).saturating_add(uptime_base).saturating_add(cashback)
```

---

### Fix H-02: Use Saturating Subtraction in process_slash

**Contract:** `staking/src/lib.rs`  
**Issue:** `state.staked_lamports - state.slashed_lamports` panics if corrupted state has `slashed > staked`.

**Fix:**

```rust
// Replace:
let remaining = state.staked_lamports - state.slashed_lamports;
// With:
let remaining = state.staked_lamports.saturating_sub(state.slashed_lamports);
```

---

### Fix H-03: Validate Claim State PDA

**Contract:** `rewards/src/lib.rs`  
**Issue:** `process_claim_usage` receives `claim_state_ai` without validating PDA derivation — relay could pass fake account to replay old records.

**Fix:** Derive expected PDA and verify before processing:

```rust
// In process_claim_usage(), after loading records:
let expected_pda = Pubkey::find_program_address(
    &[b"claim_state", &records[0].user, relay_wallet.key.as_ref()],
    program_id,
).0;

if *claim_state_ai.key != expected_pda {
    msg!("ClaimUsage: invalid claim state PDA");
    return Err(ProgramError::InvalidArgument);
}
```

---

### Fix H-04: Add Foundation Check to user-escrow initialize_registry

**Contract:** `user-escrow/src/lib.rs`  
**Issue:** `initialize_registry` only checks `foundation: Signer` — anyone can become registry authority.

**Fix:** Add foundation pubkey constant and verify:

```rust
// At the top of user-escrow/src/lib.rs:
pub const FOUNDATION_PUBKEY: &str = "GoVxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"; // UPDATE THIS

// In initialize_registry():
if ctx.accounts.foundation.key().to_string() != FOUNDATION_PUBKEY {
    return Err(ProgramError::InvalidArgument.into());
}
```

---

## Phase 3: Medium Severity Fixes

### Fix M-01: Add Dispute Claim Evidence Requirement

**Contract:** `rewards/src/lib.rs`  
**Issue:** `process_dispute_claim` accepts disputes without any cryptographic proof.

**Fix:** Require the disputer to provide evidence hash and document the expected format:

```rust
// In process_dispute_claim(), add evidence parameter:
let evidence_hash = data[1..33].to_vec(); // 32 bytes SHA-256 hash of dispute evidence

// Log it for off-chain verification:
msg!("DisputeClaim: evidence hash submitted: {}", hex::encode(&evidence_hash));
// The evidence is verified off-chain during dispute resolution.
// The bond (50 $FLOW) deters frivolous disputes.
```

---

### Fix M-02: Fix Mint Constraint Dead Code

**Contract:** `repflow-token/src/mint.rs`  
**Issue:** `constraint = mint.key() == config.key()` compares mint to config PDA — always fails.

**Fix:** Store mint pubkey in config during initialization and validate:

```rust
// In RepFlowConfig, add:
pub mint_pubkey: Pubkey,

// In initialize_config(), set it:
config.mint_pubkey = *ctx.accounts.mint.key;

// In MintRepFlow constraint:
// Remove: constraint = mint.key() == config.key()
// Replace with runtime check in the handler:
if *ctx.accounts.mint.key != config.mint_pubkey {
    return Err(ProgramError::InvalidArgument.into());
}
```

---

### Fix M-03: Validate user_ata Ownership in ExecuteSlash

**Contract:** `repflow-token/src/burn.rs`  
**Issue:** `user_ata` is `UncheckedAccount` — burner could pass any token account.

**Fix:** Add validation that the ATA belongs to the target user:

```rust
// In execute_slash handler:
let expected_ata = spl_associated_token_account::get_associated_token_address(
    &repflow_user.wallet,
    &config.mint_pubkey,
);

if *ctx.accounts.user_ata.key != expected_ata {
    return Err(ProgramError::InvalidArgument.into());
}
```

---

## Phase 4: Tokenomics — Hard Cap + Pre-Mint

### Task 4.1: Add Supply Cap to repflow-token

**Contract:** `repflow-token/src/mint.rs`

```rust
// Constants:
pub const MAX_SUPPLY: u64 = 1_000_000_000 * 100_000_000; // 1B tokens with 8 decimals
pub const FOUNDATION_ALLOCATION: u64 = 200_000_000 * 100_000_000; // 200M to foundation
pub const REWARD_RESERVE: u64 = 800_000_000 * 100_000_000; // 800M for relay rewards
pub const DECIMALS: u8 = 8;

// In RepFlowConfig:
pub total_minted: u64,  // Track cumulative minting
pub max_supply: u64,     // Hard cap (1B)

// In initialize_config():
config.max_supply = MAX_SUPPLY;
config.total_minted = 0;

// In mint_repflow handler — add cap check:
let new_total = config.total_minted.checked_add(amount)
    .ok_or(ProgramError::InvalidArgument)?;

if new_total > config.max_supply {
    msg!("MintRepFlow: would exceed max supply. Remaining: {}", 
         config.max_supply.saturating_sub(config.total_minted));
    return Err(ProgramError::InvalidArgument.into());
}

config.total_minted = new_total;
```

### Task 4.2: Add Pre-Mint Foundation Allocation

Add a new instruction `0x05` — `PreMintFoundation`:

```rust
0x05 => {
    msg!("Instruction: PreMintFoundation");
    process_pre_mint_foundation(program_id, accounts, instruction_data)
}
```

```rust
fn process_pre_mint_foundation(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    _data: &[u8],
) -> ProgramResult {
    let accounts_iter = &mut accounts.iter();
    let config_ai = next_account_info(accounts_iter)?;
    let mint_ai = next_account_info(accounts_iter)?;
    let foundation_ata_ai = next_account_info(accounts_iter)?;
    let authority_ai = next_account_info(accounts_iter)?;
    let token_program_ai = next_account_info(accounts_iter)?;

    if !authority_ai.is_signer {
        return Err(ProgramError::MissingRequiredSignature);
    }

    let mut config = RepFlowConfig::try_from_slice(&config_ai.data.borrow())?;
    
    if config.authority != *authority_ai.key {
        return Err(ProgramError::InvalidArgument);
    }

    if config.foundation_pre_minted {
        msg!("PreMintFoundation: already minted");
        return Err(ProgramError::InvalidArgument);
    }

    // Mint 200M to foundation
    let amount = FOUNDATION_ALLOCATION;
    
    // Invoke SPL Token-2022 mint_to CPI
    solana_program::program::invoke_signed(
        &spl_token_2022::instruction::mint_to(
            &spl_token_2022::id(),
            mint_ai.key,
            foundation_ata_ai.key,
            config_ai.key,
            &[],
            amount,
        )?,
        &[config_ai.clone(), mint_ai.clone(), foundation_ata_ai.clone(), token_program_ai.clone()],
        &[&[b"repflow_config"]],
    )?;

    config.total_minted = config.total_minted.checked_add(amount)
        .ok_or(ProgramError::InvalidArgument)?;
    config.foundation_pre_minted = true;

    config.serialize(&mut *config_ai.data.borrow_mut())?;

    msg!("PreMintFoundation: 200M tokens minted to foundation. Total minted: {}", config.total_minted);

    Ok(())
}
```

### Task 4.3: Add Foundation Pre-Minted Flag to RepFlowConfig

```rust
// In RepFlowConfig struct:
pub foundation_pre_minted: bool,  // Can only be called once
```

---

## Phase 5: Build, Test, Verify

### Build all programs
```bash
cd D:\Solana\freeflow-contracts
# Build in WSL (Windows filesystem has issues)
cp -r /mnt/d/Solana/freeflow-contracts /root/freeflow-contracts
cd /root/freeflow-contracts
anchor build
```

### Verify all 5 .so files compile
```bash
ls -la target/deploy/*.so
# Should show: registry.so, repflow_token.so, rewards.so, staking.so, user_escrow.so
```

### Run tests (if you have them)
```bash
anchor test
```

---

## Deliverables

### Critical fixes:
1. `rewards/src/lib.rs` — Foundation pubkey check on InitializeRewardsConfig + SetMigrationMode
2. `staking/src/lib.rs` — Owner validation in process_unstake + process_slash

### High fixes:
3. `rewards/src/lib.rs` — Checked math in calculate_reward()
4. `staking/src/lib.rs` — Saturating subtraction in process_slash
5. `rewards/src/lib.rs` — Claim state PDA validation
6. `user-escrow/src/lib.rs` — Foundation check on initialize_registry

### Medium fixes:
7. `rewards/src/lib.rs` — Evidence hash in dispute claim
8. `repflow-token/src/mint.rs` — Fix mint constraint dead code
9. `repflow-token/src/burn.rs` — Validate user_ata ownership

### Tokenomics:
10. `repflow-token/src/mint.rs` — Hard cap (1B), pre-mint (200M), reward reserve (800M)
11. `repflow-token/src/mint.rs` — PreMintFoundation instruction (0x05)
12. `RepFlowConfig` — new fields: total_minted, max_supply, foundation_pre_minted

### Build:
13. All 5 programs compile cleanly with `anchor build`
14. Documentation in `D:\Solana\docs\AUDIT-FIXES-2026-05-04.md`

---

## Execution Order

1. **C-01** (rewards foundation check) → build rewards → verify
2. **C-02** (staking owner validation) → build staking → verify
3. **H-01** (checked math in rewards) → build rewards → verify
4. **H-02** (saturating sub in staking) → build staking → verify
5. **H-03** (claim state PDA validation) → build rewards → verify
6. **H-04** (user-escrow foundation check) → build user-escrow → verify
7. **M-01, M-02, M-03** → build all affected → verify
8. **Tokenomics** (hard cap + pre-mint) → build repflow-token → verify
9. **Final build** of all 5 programs together

Work through each fix sequentially. Build after each program is modified. Don't batch changes — verify each one compiles before moving on.
