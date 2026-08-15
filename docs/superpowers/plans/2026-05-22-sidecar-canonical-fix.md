# Sidecar → D:/Solana Canonical Contract Fix Implementation Plan

> **For agentic workers:** Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Fix every misalignment between the freeflow-sidecar and D:/Solana canonical contracts so the sidecar works correctly after the devnet program upgrade, and establish the correct signer model for Professional (self-hosted) and Mobile/Lightweight (detached) relays.

**Architecture:**
- The sidecar currently uses wrong discriminants, wrong account layouts, and wrong programs for every instruction. The one exception is `ReleaseRewards` (disc=7), which has correct data but a broken signer model.
- **Self-hosted sidecar** (Professional relays): relay runs the sidecar on their own server with their keypair loaded; sidecar signs all Solana transactions directly. The sidecar's hot key IS the relay wallet.
- **Detached sidecar** (Mobile/Lightweight relays): relay does NOT share its keypair with the shared DreamHost server. Instead, the relay's client software builds and signs the Solana transaction, then POST's the serialized signed bytes to the sidecar's `/v1/relay/broadcast` endpoint. The sidecar verifies the HTTP auth signature (already in place) and broadcasts to Solana RPC without re-signing.
- On-chain initialization (8 steps) must be run against the canonical program IDs before any transaction can succeed.

**Tech Stack:** Rust/Axum (freeflow-sidecar), Solana bare wire format (no solana-sdk), TypeScript (on-chain init scripts), Borsh encoding.

**Sidecar repo:** `C:\Users\Administrator\.openclaw\workspace\freeflow-triton\freeflow-sidecar\`
**Contracts repo:** `D:\Solana\freeflow-contracts\`

---

## File map

**Create:**
- `freeflow-sidecar/src/tx_builder.rs` — relay-side transaction serialization helpers for the broadcast path
- `freeflow-contracts/scripts/init-devnet.ts` — on-chain initialization script (8 steps, foundation key)
- `freeflow-contracts/scripts/init-relay-account.ts` — per-relay reward_account pre-allocation script

**Modify:**
- `freeflow-sidecar/config.toml` — add `registry_program_id`, fill `flow_mint`
- `freeflow-sidecar/src/config.rs` — add `registry_program_id` field; add `signing_mode` to WalletConfig
- `freeflow-sidecar/src/solana.rs` — fix all 6 instruction encoders + account layouts; add registry PDA helper; fix claim_pda seeds
- `freeflow-sidecar/src/handlers.rs` — fix `handle_register`, fix `handle_claim`, add `handle_broadcast`
- `freeflow-sidecar/src/routes.rs` — add `POST /v1/relay/broadcast`
- `freeflow-sidecar/src/main.rs` — add `signing_mode` to AppState

---

## Task 1: Fix config.toml — add missing program IDs

**Files:**
- Modify: `freeflow-sidecar/config.toml`
- Modify: `freeflow-sidecar/src/config.rs`

- [ ] **Step 1: Add `registry_program_id` and `flow_mint` to config.toml**

  Open `C:\Users\Administrator\.openclaw\workspace\freeflow-triton\freeflow-sidecar\config.toml`.

  In the `[relay]` section, change:
  ```toml
  [relay]
  rewards_program_id       = "2yeVew5qq5jf5zuoqiE2svVLRE9HTN6J2GfB9LopdM1C"
  repflow_token_program_id = "8K4GhPEQ1yy9vdTaMPTL83G5qr5ZHZiBm2VBQ58jJs5w"
  staking_program_id       = "7N1JRX3LY3goVAZCyaJyH7kpZ3kboZvh3jteDmCq6Dz4"
  flow_mint                = ""
  user_escrow_program_id   = ""
  ```
  To:
  ```toml
  [relay]
  rewards_program_id       = "2yeVew5qq5jf5zuoqiE2svVLRE9HTN6J2GfB9LopdM1C"
  registry_program_id      = "HkMhMoEv7U8VowyVsCCk9pZDkWwp18ei1BZ3Fif94DCE"
  repflow_token_program_id = "8K4GhPEQ1yy9vdTaMPTL83G5qr5ZHZiBm2VBQ58jJs5w"
  staking_program_id       = "7N1JRX3LY3goVAZCyaJyH7kpZ3kboZvh3jteDmCq6Dz4"
  flow_mint                = "8K4GhPEQ1yy9vdTaMPTL83G5qr5ZHZiBm2VBQ58jJs5w"
  user_escrow_program_id   = "7PzcA2sNDzrvhTNLFScWZuNKS4g7jCCghsowZA9RsZ26"
  ```

  > Note: `flow_mint` and `repflow_token_program_id` share the same address — the repflow SPL mint IS the $FLOW token.

- [ ] **Step 2: Add `signing_mode` to WalletConfig in config.toml**

  In the `[wallet]` section, add:
  ```toml
  [wallet]
  keypair_path = "/opt/freeflow/keypair.json"
  # "self_hosted"  — sidecar signs transactions with its own keypair (relay key must be same)
  # "detached"     — sidecar broadcasts pre-signed transactions from relays
  signing_mode = "self_hosted"
  ```

- [ ] **Step 3: Add fields to `RelayProgramConfig` in src/config.rs**

  Open `freeflow-sidecar/src/config.rs`. In `RelayProgramConfig`, add:
  ```rust
  pub struct RelayProgramConfig {
      pub rewards_program_id:       String,
      pub registry_program_id:      String,   // ← ADD THIS
      pub repflow_token_program_id: String,
      pub staking_program_id:       String,
      #[serde(default)]
      pub flow_mint:                String,
      #[serde(default)]
      pub user_escrow_program_id:   String,
  }
  ```

- [ ] **Step 4: Add `signing_mode` field to WalletConfig**

  In `WalletConfig`:
  ```rust
  #[derive(Debug, Clone, Deserialize)]
  pub struct WalletConfig {
      pub keypair_path: PathBuf,
      #[serde(default = "default_signing_mode")]
      pub signing_mode: SigningMode,
  }

  #[derive(Debug, Clone, Deserialize, PartialEq)]
  #[serde(rename_all = "snake_case")]
  pub enum SigningMode {
      SelfHosted,
      Detached,
  }

  fn default_signing_mode() -> SigningMode { SigningMode::SelfHosted }
  ```

- [ ] **Step 5: Add `signing_mode` to AppState in main.rs**

  In `main.rs`, `AppState` struct:
  ```rust
  pub struct AppState {
      pub config:        Arc<config::Config>,
      pub store:         Arc<RwLock<relay_store::RelayStore>>,
      pub solana:        Arc<solana::SolanaClient>,
      pub wallet_pubkey: String,
      pub signing_mode:  config::SigningMode,   // ← ADD THIS
  }
  ```

  In the `state` construction block in `main()`:
  ```rust
  let state = AppState {
      config:        cfg.clone(),
      store:         store.clone(),
      solana:        solana_client,
      wallet_pubkey,
      signing_mode:  cfg.wallet.signing_mode.clone(),   // ← ADD THIS
  };
  ```

- [ ] **Step 6: Build to confirm no compile errors**

  ```bat
  cd C:\Users\Administrator\.openclaw\workspace\freeflow-triton\freeflow-sidecar
  cargo build 2>&1
  ```
  Expected: compilation errors only for missing fields in handlers (because `registry_program_id` is now required). Fix those by adding `.registry_program_id` where needed — for now just add `todo!()` placeholders to confirm the config compiles.

- [ ] **Step 7: Commit**

  ```bat
  git add config.toml src/config.rs src/main.rs
  git commit -m "feat: add registry_program_id, flow_mint, signing_mode to config"
  ```

---

## Task 2: Fix register_relay — correct program, disc, data, accounts

**Files:**
- Modify: `freeflow-sidecar/src/solana.rs`
- Modify: `freeflow-sidecar/src/handlers.rs`

Current broken state:
- Sends to `rewards_program_id` instead of `registry_program_id`
- Disc = 1 (RecordBytes) instead of 0 (Register)
- Data = `[1u8] || country[2]` instead of `[0u8] || tier:u8 || country:[u8;2] || storage_bytes:u64le || addr_bytes:[u8;18]`
- Accounts: `[sidecar, claim_pda, relay_pk, system_pk]` instead of `[relay_wallet(signer), registry_pda, system_program]`
- PDA seeds in register: `["registry", relay_wallet]` (registry program owns it)

- [ ] **Step 1: Replace `encode_register_relay` in solana.rs**

  Find the existing:
  ```rust
  pub fn encode_register_relay(country: [u8; 2]) -> Vec<u8> {
      let mut d = vec![1u8]; // discriminant = RecordBytes (old: RegisterRelay)
      d.extend_from_slice(&country);
      d
  }
  ```

  Replace with:
  ```rust
  /// Encode `Register` (disc=0) for the **Registry** program.
  ///
  /// Data: `[0u8][tier:u8][country:[u8;2]][storage_bytes:u64le][addr_bytes:[u8;18]]`
  ///   tier: 0=Mobile, 1=Lightweight, 2=Professional
  ///   addr_bytes: 16-byte IPv6 (or v4-mapped) + 2-byte port, big-endian
  ///
  /// Accounts:
  ///   [0] relay_wallet   — signer (must be the relay's own key)
  ///   [1] registry_pda   — PDA: find_program_address(["registry", relay_wallet], registry_program)
  ///   [2] system_program — 111…11
  pub fn encode_register_relay(
      tier:          u8,
      country:       [u8; 2],
      storage_bytes: u64,
      addr_bytes:    [u8; 18],
  ) -> Vec<u8> {
      let mut d = vec![0u8]; // variant 0 = Register
      d.push(tier);
      d.extend_from_slice(&country);
      d.extend_from_slice(&storage_bytes.to_le_bytes());
      d.extend_from_slice(&addr_bytes);
      d
  }
  ```

- [ ] **Step 2: Add `find_registry_pda` helper in solana.rs**

  After `find_mint_authority_pda` or any other PDA helper, add:
  ```rust
  /// Derive the registry entry PDA for a relay.
  /// Seeds: `[b"registry", relay_wallet_pubkey]`
  /// Program: registry program (NOT rewards program).
  pub fn find_registry_pda(relay_pk: &[u8; 32], registry_program: &[u8; 32]) -> ([u8; 32], u8) {
      find_program_address(&[b"registry", relay_pk], registry_program)
  }
  ```

- [ ] **Step 3: Rewrite `register_relay` async fn in solana.rs**

  Find the existing `pub async fn register_relay(` block (lines ~474–508) and replace entirely:
  ```rust
  /// Submit `Register` (disc=0) to the **Registry** program.
  ///
  /// Accounts: [relay_wallet(signer), registry_pda, system_program]
  ///
  /// Self-hosted mode: `relay_keypair` must be provided and signs as relay_wallet.
  /// Detached mode: not called here — relay builds and signs the tx client-side.
  pub async fn register_relay(
      &self,
      relay_pubkey_b58:    &str,
      registry_program_b58: &str,
      tier:                 u8,
      country:              [u8; 2],
      storage_bytes:        u64,
      addr_bytes:           [u8; 18],
  ) -> Result<String> {
      // The sidecar's loaded keypair IS the relay wallet in self-hosted mode.
      // In detached mode this function should not be called.
      let relay_pk     = decode_pubkey(relay_pubkey_b58)?;
      let program_pk   = decode_pubkey(registry_program_b58)?;
      let system_pk    = [0u8; 32];

      let (registry_pda, _) = find_registry_pda(&relay_pk, &program_pk);

      // account_keys order: relay_wallet(0), registry_pda(1), system(2), program(3)
      let account_keys = [relay_pk, registry_pda, system_pk, program_pk];
      let blockhash    = self.get_latest_blockhash().await?;

      let ix = Instruction {
          program_id_index: 3,
          account_indices:  vec![0, 1, 2], // relay, registry_pda, system
          data:             encode_register_relay(tier, country, storage_bytes, addr_bytes),
      };

      // 1 signer (relay_wallet), 0 readonly signed, 1 readonly unsigned (system_pk)
      let tx = build_and_sign(
          &self.keypair, &account_keys, &blockhash,
          &[ix], 1, 0, 1,
      );
      self.send_transaction(&tx).await
  }
  ```

- [ ] **Step 4: Update `handle_register` in handlers.rs**

  The handler currently calls:
  ```rust
  state.solana.register_relay(
      &pubkey,
      &state.config.relay.rewards_program_id,   // ← wrong program
      country_bytes,
  ).await;
  ```

  First, parse tier and addr_bytes from the request body. Update `RegisterBody`:
  ```rust
  #[derive(Deserialize)]
  pub struct RegisterBody {
      #[serde(default = "default_country")]
      pub country:             String,
      pub addr:                Option<String>,
      pub tier:                Option<String>,   // "mobile"|"lightweight"|"professional"
      pub storage_bytes:       Option<u64>,
      pub reality_sni:         Option<String>,
      pub reality_fingerprint: Option<String>,
  }
  ```

  Add a helper to convert tier string → u8 and addr string → [u8; 18]:
  ```rust
  fn tier_to_u8(tier: Option<&str>) -> u8 {
      match tier {
          Some("professional") => 2,
          Some("lightweight")  => 1,
          _                    => 0,  // mobile / default
      }
  }

  /// Parse "ip:port" → 16-byte IPv6 (v4-mapped) + 2-byte port (big-endian).
  fn addr_to_bytes(addr: Option<&str>) -> [u8; 18] {
      let mut out = [0u8; 18];
      if let Some(a) = addr {
          if let Ok(sa) = a.parse::<std::net::SocketAddr>() {
              let ip6 = match sa.ip() {
                  std::net::IpAddr::V4(v4) => v4.to_ipv6_mapped(),
                  std::net::IpAddr::V6(v6) => v6,
              };
              out[..16].copy_from_slice(&ip6.octets());
              let port = sa.port().to_be_bytes();
              out[16] = port[0];
              out[17] = port[1];
          }
      }
      out
  }
  ```

  Update the on-chain call in `handle_register`:
  ```rust
  // Detached mode: skip on-chain tx; relay must register via /v1/relay/broadcast
  if state.signing_mode == crate::config::SigningMode::Detached {
      return ok(json!({
          "pubkey":       pubkey,
          "is_new":       is_new,
          "tx_signature": null,
          "note":         "detached mode — relay must self-sign Register tx via /v1/relay/broadcast",
      }));
  }

  let tx_result = state.solana.register_relay(
      &pubkey,
      &state.config.relay.registry_program_id,   // ← registry program
      tier_to_u8(body_parsed.tier.as_deref()),
      country_bytes,
      body_parsed.storage_bytes.unwrap_or(0),
      addr_to_bytes(body_parsed.addr.as_deref()),
  ).await;
  ```

- [ ] **Step 5: Build and confirm no compile errors**

  ```bat
  cargo build 2>&1
  ```
  Expected: compiles cleanly. The old `encode_register_relay` test at line ~844 references `encode_register_relay(*b"US")` — update it to use the new signature: `encode_register_relay(1, *b"US", 0, [0u8;18])`.

- [ ] **Step 6: Verify encoding manually**

  Add a quick inline check (or update existing test at line ~843):
  ```rust
  #[test]
  fn register_relay_encoding() {
      let data = encode_register_relay(2, *b"US", 1_000_000_000u64, [0u8; 18]);
      // disc=0, tier=2, country="US", 8 bytes storage, 18 bytes addr
      assert_eq!(data.len(), 1 + 1 + 2 + 8 + 18);
      assert_eq!(data[0], 0); // disc=Register
      assert_eq!(data[1], 2); // tier=Professional
      assert_eq!(&data[2..4], b"US");
  }
  ```

  Run: `cargo test register_relay_encoding`
  Expected: PASS

- [ ] **Step 7: Commit**

  ```bat
  git add src/solana.rs src/handlers.rs src/config.rs config.toml
  git commit -m "fix: register_relay — target registry program with correct disc=0 and accounts"
  ```

---

## Task 3: Fix handle_claim — use ClaimRewards (disc=0) with correct signer model

**Files:**
- Modify: `freeflow-sidecar/src/solana.rs`
- Modify: `freeflow-sidecar/src/handlers.rs`

Current broken state:
- Handler calls `claim_usage()` which sends disc=2 with 3 u64s — D:/Solana disc=2 expects `Vec<UsageRecordOnChain>` borsh blob, fails immediately on deserialize
- `encode_claim_rewards` (disc=0) exists and is correct, but is never called
- `reward_account` at account[1] must be pre-allocated before ClaimRewards can write to it
- Signer: sidecar hot key must equal relay wallet in self-hosted mode

The fix uses the **legacy `ClaimRewards` (disc=0) path** — D:/Solana still supports it, updates `RewardAccount` state (total bytes/uptime/tier), and does NOT mint immediately (minting happens at `ReleaseRewards`). This is the correct bridge for the current sidecar design.

- [ ] **Step 1: Rewrite the `claim_usage` async fn → `claim_rewards` in solana.rs**

  Find the existing `pub async fn claim_usage(` block (lines ~513–543) and replace:
  ```rust
  /// Submit `ClaimRewards` (disc=0) to the rewards program.
  ///
  /// This is the legacy/bridge path — accumulates bytes/uptime in `RewardAccount`
  /// without minting immediately. Rewards are released via `ReleaseRewards` after
  /// the 7-day dispute window.
  ///
  /// Accounts:
  ///   [0] relay_wallet   — signer (must match the relay's pubkey)
  ///   [1] reward_account — relay's reward aggregate account (writable, must be pre-allocated)
  ///
  /// `period_start` / `period_end`: Unix timestamps bounding this claim period.
  /// `repflow_balance`: relay's repFlow balance (0 if unknown → Newcomer tier).
  pub async fn claim_rewards(
      &self,
      relay_pubkey_b58:   &str,
      rewards_program_b58: &str,
      period_start:        i64,
      period_end:          i64,
      bytes_routed:        u64,
      bytes_seeded:        u64,
      uptime_seconds:      u64,
      repflow_balance:     u64,
  ) -> Result<String> {
      let relay_pk   = decode_pubkey(relay_pubkey_b58)?;
      let program_pk = decode_pubkey(rewards_program_b58)?;

      // reward_account: create_with_seed(relay_wallet, "freeflow-reward-v1", program_id)
      let reward_account = derive_reward_account(&relay_pk, &program_pk);

      // account_keys: relay(0), reward_account(1), program(2)
      let account_keys = [relay_pk, reward_account, program_pk];
      let blockhash    = self.get_latest_blockhash().await?;

      let ix = Instruction {
          program_id_index: 2,
          account_indices:  vec![0, 1], // relay_wallet(writable+signer), reward_account(writable)
          data:             encode_claim_rewards(
              period_start, period_end,
              bytes_routed, bytes_seeded, uptime_seconds, repflow_balance,
          ),
      };

      // relay_wallet is signer; reward_account is writable unsigned
      let tx = build_and_sign(
          &self.keypair, &account_keys, &blockhash,
          &[ix], 1, 0, 0,
      );
      self.send_transaction(&tx).await
  }
  ```

- [ ] **Step 2: Add `derive_reward_account` helper in solana.rs**

  Immediately above `claim_rewards`, add:
  ```rust
  /// Derive the relay's `reward_account` using Solana's `create_with_seed` method.
  ///
  /// Formula: SHA-256(base_pubkey || seed || program_id)
  /// base_pubkey = relay_wallet, seed = "freeflow-reward-v1", program_id = rewards program
  ///
  /// This matches the triton sidecar derivation and is accepted by D:/Solana process_claim
  /// (which does not verify the key derivation, only reads/writes the account data).
  pub fn derive_reward_account(relay_pk: &[u8; 32], program_pk: &[u8; 32]) -> [u8; 32] {
      let mut hasher = Sha256::new();
      hasher.update(relay_pk);
      hasher.update(b"freeflow-reward-v1");
      hasher.update(program_pk);
      hasher.finalize().into()
  }
  ```

- [ ] **Step 3: Update `handle_claim` in handlers.rs**

  Find the call to `state.solana.claim_usage(...)` in `handle_claim` and replace:
  ```rust
  // Reject in detached mode — relay must self-sign ClaimRewards tx
  if state.signing_mode == crate::config::SigningMode::Detached {
      return err(
          StatusCode::BAD_REQUEST,
          "detached_mode",
          "detached sidecar cannot sign ClaimRewards — use POST /v1/relay/broadcast with a pre-signed transaction",
      );
  }

  // Self-hosted: sidecar keypair IS the relay wallet; sign directly.
  let now      = crate::auth::now_unix() as i64;
  let period   = 3600i64; // claim window: 1 hour
  let period_start = now - period;
  let period_end   = now;

  match state.solana.claim_rewards(
      &pubkey,
      &state.config.relay.rewards_program_id,
      period_start,
      period_end,
      claim.bytes_routed,
      claim.bytes_seeded,
      claim.uptime_secs,
      0, // repflow_balance: 0 for now (Newcomer tier) — extend later via /v1/relay/state
  ).await {
      Ok(sig) => { /* same response as before */ }
      Err(e)  => { /* same error as before */ }
  }
  ```

  Update the `ClaimBody` to add an optional `repflow_balance`:
  ```rust
  #[derive(Deserialize)]
  pub struct ClaimBody {
      pub bytes_routed:    u64,
      pub bytes_seeded:    u64,
      pub uptime_secs:     u64,
      #[serde(default)]
      pub repflow_balance: u64,
  }
  ```

  And pass it: `repflow_balance: claim.repflow_balance`.

- [ ] **Step 4: Remove the now-dead `encode_claim_usage` / `encode_claim_usage_legacy` aliases in solana.rs**

  Delete or mark `#[cfg(test)]` the following dead functions:
  - `encode_claim_usage_legacy` (lines ~216–222)
  - The `encode_claim_usage` inline alias (lines ~226–229)

  Also delete the `encode_register_relay` test that used the old 1-argument signature and add the updated one from Task 2 Step 6.

- [ ] **Step 5: Build**

  ```bat
  cargo build 2>&1
  ```
  Expected: clean build.

- [ ] **Step 6: Test claim encoding**

  ```rust
  #[test]
  fn claim_rewards_encoding() {
      let data = encode_claim_rewards(
          1_748_000_000i64, 1_748_003_600i64,  // 1hr period
          1_073_741_824u64,                     // 1 GB routed
          536_870_912u64,                       // 512 MB seeded
          3600u64,                              // 1hr uptime
          0u64,                                 // newcomer
      );
      assert_eq!(data[0], 0);    // disc = ClaimRewards
      assert_eq!(data.len(), 1 + 8 + 8 + 8 + 8 + 8 + 8); // 49 bytes total
  }
  ```

  Run: `cargo test claim_rewards_encoding`
  Expected: PASS

- [ ] **Step 7: Commit**

  ```bat
  git add src/solana.rs src/handlers.rs
  git commit -m "fix: handle_claim uses ClaimRewards (disc=0); detached mode returns 400"
  ```

---

## Task 4: Fix release_rewards signer model

**Files:**
- Modify: `freeflow-sidecar/src/solana.rs`
- Modify: `freeflow-sidecar/src/handlers.rs`

The ReleaseRewards discriminant and data are already correct (disc=7, 32-byte claim_hash). The issue is:
1. `pending_claims` PDA is correct (`["pending_claims", relay_pk]`) ✅
2. `reward_account` derivation uses SHA256 (create_with_seed) — D:/Solana doesn't verify this ✅
3. `release_rewards` in solana.rs passes `relay_pk` as account[0] and uses `sidecar_pk` as the transaction signer — these must be the same key in self-hosted mode

- [ ] **Step 1: Read release_rewards in solana.rs (lines 564–620)**

  Verify the current account layout and signer. The existing code (from prior analysis):
  - account_keys: `[sidecar_pk, relay_pk, reward_acct, pending_claims, program_pk]`
  - ix accounts[0..2]: relay (read as signer), reward_acct, pending_claims

  The problem: `sidecar_pk` is the tx signer, but `relay_pk` at `account_indices[0]` is what the program sees as `relay_wallet`. If `sidecar_pk != relay_pk`, the program rejects with `MissingRequiredSignature`.

- [ ] **Step 2: Assert relay_pk == sidecar_pk in self-hosted mode**

  In `release_rewards`, add an early check:
  ```rust
  pub async fn release_rewards(
      &self,
      relay_pubkey_b58:   &str,
      rewards_program_b58: &str,
      claim_hash:          [u8; 32],
  ) -> Result<String> {
      let sidecar_pk = decode_pubkey(&self.wallet_pubkey)?;
      let relay_pk   = decode_pubkey(relay_pubkey_b58)?;
      let program_pk = decode_pubkey(rewards_program_b58)?;

      if sidecar_pk != relay_pk {
          anyhow::bail!(
              "release_rewards: sidecar wallet ({}) != relay wallet ({}) — \
               detached relays must use /v1/relay/broadcast",
              self.wallet_pubkey, relay_pubkey_b58
          );
      }

      let reward_account  = derive_reward_account(&relay_pk, &program_pk);
      let (pending_claims, _) = find_program_address(
          &[b"pending_claims", &relay_pk],
          &program_pk,
      );

      // account_keys: relay(0), reward_account(1), pending_claims(2), program(3)
      let account_keys = [relay_pk, reward_account, pending_claims, program_pk];
      let blockhash    = self.get_latest_blockhash().await?;

      let ix = Instruction {
          program_id_index: 3,
          account_indices:  vec![0, 1, 2], // relay(signer+writable), reward_acct(writable), pending_claims(writable)
          data:             encode_release_rewards(claim_hash),
      };

      let tx = build_and_sign(
          &self.keypair, &account_keys, &blockhash,
          &[ix], 1, 0, 0,
      );
      self.send_transaction(&tx).await
  }
  ```

- [ ] **Step 3: Update handle_release to handle detached mode**

  In `handle_release`, after parsing `claim_hash`, add:
  ```rust
  // Detached mode: cannot sign release on behalf of relay
  if state.signing_mode == crate::config::SigningMode::Detached {
      return err(
          StatusCode::BAD_REQUEST,
          "detached_mode",
          "detached sidecar cannot sign ReleaseRewards — use POST /v1/relay/broadcast",
      );
  }
  ```

- [ ] **Step 4: Fix the cron's release_rewards call in main.rs**

  The cron uses `cron_wallet` as the relay key when calling `release_rewards`. In self-hosted mode this is correct. In detached mode the cron should not run at all (since it can't sign for arbitrary relays). Add a guard in main.rs:
  ```rust
  if cfg.cron.release_rewards_enabled
      && cfg.wallet.signing_mode == config::SigningMode::SelfHosted
  {
      // ... existing cron spawn code ...
  } else if cfg.cron.release_rewards_enabled
      && cfg.wallet.signing_mode == config::SigningMode::Detached
  {
      info!("ReleaseRewards cron disabled in detached mode (relays self-sign)");
  } else {
      info!("ReleaseRewards cron disabled (cron.release_rewards_enabled = false)");
  }
  ```

- [ ] **Step 5: Build**

  ```bat
  cargo build 2>&1
  ```
  Expected: clean.

- [ ] **Step 6: Commit**

  ```bat
  git add src/solana.rs src/handlers.rs src/main.rs
  git commit -m "fix: release_rewards enforces relay==sidecar key; detached mode returns 400"
  ```

---

## Task 5: Add POST /v1/relay/broadcast — detached relay self-signed path

**Files:**
- Modify: `freeflow-sidecar/src/handlers.rs`
- Modify: `freeflow-sidecar/src/routes.rs`
- Modify: `freeflow-sidecar/src/solana.rs`

Detached relays (Mobile/Lightweight) build and sign their own Solana transactions and POST the raw base64-encoded wire bytes to this endpoint. The sidecar authenticates the HTTP request (verifies the relay's Ed25519 HTTP signature), optionally checks that the transaction was signed by the relay's key, then broadcasts to Solana RPC.

- [ ] **Step 1: Add `broadcast_transaction` to SolanaClient in solana.rs**

  ```rust
  /// Broadcast a pre-signed, base64-encoded Solana transaction.
  /// The transaction must already be signed by all required signers.
  /// The sidecar does NOT re-sign or modify the transaction.
  pub async fn broadcast_transaction(&self, signed_tx_base64: &str) -> Result<String> {
      // Decode to verify it's valid base64 (content not validated further)
      let _raw = base64::engine::general_purpose::STANDARD
          .decode(signed_tx_base64)
          .context("invalid base64 in transaction")?;

      // Send using the same sendTransaction RPC call
      let resp: serde_json::Value = self.rpc_call("sendTransaction", serde_json::json!([
          signed_tx_base64,
          { "encoding": "base64", "preflightCommitment": "confirmed" }
      ])).await?;

      if let Some(sig) = resp["result"].as_str() {
          return Ok(sig.to_string());
      }
      let err_msg = resp["error"]["message"].as_str().unwrap_or("unknown RPC error");
      anyhow::bail!("sendTransaction failed: {}", err_msg)
  }
  ```

- [ ] **Step 2: Add `handle_broadcast` in handlers.rs**

  ```rust
  // ── POST /v1/relay/broadcast ─────────────────────────────────────────────────
  //
  // Detached relay self-signed path.
  // Relay builds the Solana transaction client-side, signs with their keypair,
  // and POST's the base64-encoded wire bytes here for broadcast.
  //
  // Body: { "transaction": "<base64-encoded signed tx>" }

  #[derive(Deserialize)]
  pub struct BroadcastBody {
      /// Base64-encoded signed Solana transaction (wire format).
      pub transaction: String,
  }

  pub async fn handle_broadcast(
      State(state): State<AppState>,
      headers: HeaderMap,
      body: axum::body::Bytes,
  ) -> Response {
      // Authenticate — relay must sign the HTTP request with their Ed25519 key
      let pubkey = match authenticate(&state, &headers, "POST", "/v1/relay/broadcast", &body).await {
          Ok(pk) => pk,
          Err(r) => return r,
      };

      let req: BroadcastBody = match serde_json::from_slice(&body) {
          Ok(b)  => b,
          Err(_) => return err(
              StatusCode::BAD_REQUEST,
              "invalid_body",
              r#"expected { "transaction": "<base64 tx>" }"#,
          ),
      };

      info!("broadcast request from relay {}", &pubkey[..8]);

      match state.solana.broadcast_transaction(&req.transaction).await {
          Ok(sig) => {
              info!("broadcast ok for {}: sig={}", &pubkey[..8], &sig[..8.min(sig.len())]);
              ok(json!({ "tx_signature": sig }))
          }
          Err(e) => {
              error!("broadcast failed for {}: {e}", &pubkey[..8]);
              err(StatusCode::INTERNAL_SERVER_ERROR, "broadcast_failed", &e.to_string())
          }
      }
  }
  ```

- [ ] **Step 3: Wire the route in routes.rs**

  ```rust
  pub fn build_router(state: AppState) -> Router {
      Router::new()
          .route("/health",                get(handlers::handle_health))
          .route("/v1/tracker",            get(handlers::handle_tracker))
          .route("/v1/relay/rates",        get(handlers::handle_rates))
          .route("/v1/relay/peers",        get(handlers::handle_peers))
          .route("/v1/relay/register",     post(handlers::handle_register))
          .route("/v1/relay/state",        get(handlers::handle_state))
          .route("/v1/relay/claim",        post(handlers::handle_claim))
          .route("/v1/relay/release",      post(handlers::handle_release))
          .route("/v1/relay/broadcast",    post(handlers::handle_broadcast))  // ← ADD
          .with_state(state)
  }
  ```

- [ ] **Step 4: Add `GET /v1/relay/blockhash` — detached relays need current blockhash**

  Detached relays need the recent blockhash to build their transaction. Add:

  In `solana.rs`:
  ```rust
  /// Return the latest blockhash as a base58 string for client-side tx building.
  pub async fn get_blockhash_b58(&self) -> Result<String> {
      self.get_latest_blockhash().await.map(|h| bs58::encode(h).into_string())
  }
  ```

  In `handlers.rs`:
  ```rust
  pub async fn handle_blockhash(State(state): State<AppState>) -> Response {
      match state.solana.get_blockhash_b58().await {
          Ok(bh) => ok(json!({ "blockhash": bh })),
          Err(e) => err(StatusCode::INTERNAL_SERVER_ERROR, "rpc_error", &e.to_string()),
      }
  }
  ```

  > Note: `bs58` crate — check `Cargo.toml`. If not present, return hex instead: `hex::encode(h)`.

  In `routes.rs`:
  ```rust
  .route("/v1/relay/blockhash",  get(handlers::handle_blockhash))
  ```

- [ ] **Step 5: Document the detached relay client flow in main.rs header comment**

  At the top of `main.rs`, update the endpoint list:
  ```
  /// GET  /v1/relay/blockhash   — current blockhash for client-side tx building (no auth)
  /// POST /v1/relay/broadcast   — broadcast a relay-signed transaction (authenticated)
  ```

- [ ] **Step 6: Build**

  ```bat
  cargo build 2>&1
  ```
  Expected: clean.

- [ ] **Step 7: Test broadcast endpoint locally**

  With a running sidecar in detached mode:
  ```bat
  curl -X POST http://localhost:9210/v1/relay/broadcast \
    -H "Content-Type: application/json" \
    -H "X-Relay-PubKey: <hex_pubkey>" \
    -H "X-Timestamp: <unix>" \
    -H "X-Nonce: <16hex>" \
    -H "X-Signature: <64hex>" \
    -d '{"transaction":"<base64_tx>"}'
  ```
  Expected: `{ "ok": true, "data": { "tx_signature": "..." } }` or a descriptive RPC error.

- [ ] **Step 8: Commit**

  ```bat
  git add src/solana.rs src/handlers.rs src/routes.rs src/main.rs
  git commit -m "feat: add /v1/relay/broadcast endpoint for detached relay self-signed transactions"
  ```

---

## Task 6: Fix dead-code governance encoders (disc=16, 17)

**Files:**
- Modify: `freeflow-sidecar/src/solana.rs`

These are `#[allow(dead_code)]` but will be needed when governance functions are called. Fix them now while the discriminant mapping is fresh.

- [ ] **Step 1: Fix `encode_initialize_reward_rates` — change disc from 7 → 16**

  Find:
  ```rust
  pub fn encode_initialize_reward_rates(...) -> Vec<u8> {
      let mut d = vec![7u8]; // ← WRONG: 7 = ReleaseRewards in D:/Solana
  ```
  Change to:
  ```rust
  pub fn encode_initialize_reward_rates(...) -> Vec<u8> {
      let mut d = vec![16u8]; // disc=16 = InitializeRewardRates in D:/Solana canonical
  ```

  Add doc comment:
  ```rust
  /// Encode `InitializeRewardRates` (disc=16) for the rewards program.
  /// Requires foundation key as signer. Creates the `["reward_rates"]` PDA.
  ```

- [ ] **Step 2: Fix `encode_update_reward_rates` — change disc from 8 → 17**

  Find:
  ```rust
  pub fn encode_update_reward_rates(...) -> Vec<u8> {
      let mut d = vec![8u8]; // ← WRONG: 8 = InitializeRewardsConfig in D:/Solana
  ```
  Change to:
  ```rust
  pub fn encode_update_reward_rates(...) -> Vec<u8> {
      let mut d = vec![17u8]; // disc=17 = UpdateRewardRates in D:/Solana canonical
  ```

- [ ] **Step 3: Verify data fields match D:/Solana**

  D:/Solana `InitializeRewardRates` and `UpdateRewardRates` both have:
  ```rust
  { routing_per_mb:u64, seeding_per_mb:u64, uptime_per_hour:u64, flow_price_cents:u64 }
  ```
  Confirm the sidecar encoders write these four u64le fields in that order.

- [ ] **Step 4: Build + test**

  ```bat
  cargo build 2>&1
  cargo test 2>&1
  ```

- [ ] **Step 5: Commit**

  ```bat
  git add src/solana.rs
  git commit -m "fix: governance encoders — InitializeRewardRates disc=16, UpdateRewardRates disc=17"
  ```

---

## Task 7: Fix handle_state — correct claim_state PDA seeds

**Files:**
- Modify: `freeflow-sidecar/src/handlers.rs`

`handle_state` reads the `["claim_state", relay_pk]` PDA to show pending rewards. But D:/Solana's `claim_state` PDA is per `(user_pk, relay_pk)` — two seeds, not one. The single-seed form doesn't correspond to any on-chain account.

For now, the state endpoint can return the `reward_account` data instead (which is per-relay, not per-user). This shows the relay's aggregate totals (bytes, uptime, total lamports earned).

- [ ] **Step 1: Replace claim_state PDA read with reward_account read in handle_state**

  Find in `handle_state` (~line 222–239):
  ```rust
  let (claim_pda, _) = crate::solana::find_program_address(
      &[b"claim_state", &relay_pk],
      &program_id,
  );
  ```

  Replace with:
  ```rust
  let reward_account = crate::solana::derive_reward_account(&relay_pk, &program_id);
  let reward_acct_b58 = crate::solana::encode_pubkey(&reward_account);
  ```

  Then read `reward_acct_b58` instead of `claim_pda_b58`. Update the field names in the response:
  ```rust
  let (total_lamports, claim_count, last_claim_ts) =
      match state.solana.get_account_data(&reward_acct_b58).await {
          Ok(Some(data)) if data.len() >= RewardAccount::MIN_SIZE => {
              // RewardAccount layout (Borsh):
              // relay_wallet: [u8;32]        — bytes 0..32
              // total_lamports_claimed: u64  — bytes 32..40
              // total_bytes_routed: u64      — bytes 40..48
              // total_bytes_seeded: u64      — bytes 48..56
              // total_uptime_seconds: u64    — bytes 56..64
              // last_claim_ts: i64           — bytes 64..72
              // claim_count: u64             — bytes 72..80
              let lamports   = u64::from_le_bytes(data[32..40].try_into().unwrap_or_default());
              let count      = u64::from_le_bytes(data[72..80].try_into().unwrap_or_default());
              let last_ts    = i64::from_le_bytes(data[64..72].try_into().unwrap_or_default());
              (lamports, count, last_ts)
          }
          _ => (0, 0, 0i64),
      };
  ```

  Update the JSON response:
  ```rust
  ok(json!({
      "pubkey":                 pubkey,
      "balance_lamports":       balance_lamports,
      "total_lamports_claimed": total_lamports,
      "claim_count":            claim_count,
      "last_claim_ts":          last_claim_ts,
      "reward_account":         reward_acct_b58,
      "relay_store":            relay_record,
  }))
  ```

  Add a const for the minimum readable size:
  ```rust
  const REWARD_ACCOUNT_MIN_SIZE: usize = 80; // through claim_count field
  ```

- [ ] **Step 2: Build**

  ```bat
  cargo build 2>&1
  ```

- [ ] **Step 3: Commit**

  ```bat
  git add src/handlers.rs
  git commit -m "fix: handle_state reads reward_account instead of stale claim_state PDA"
  ```

---

## Task 8: On-chain initialization script

**Files:**
- Create: `D:\Solana\freeflow-contracts\scripts\init-devnet.ts`

Eight transactions must be sent (in order) with the foundation key `8SL4dhnXU9tjvsbwfkVzQbfV99wGnVZBECoiuwrdbaJk` before the D:/Solana canonical rewards program can process any instruction. Run this AFTER deploying the upgraded programs.

- [ ] **Step 1: Create scripts/init-devnet.ts**

  ```typescript
  /**
   * init-devnet.ts
   *
   * One-time initialization for D:/Solana canonical rewards program on devnet.
   * Must run AFTER program deploy and BEFORE any relay can submit claims.
   *
   * Prerequisites:
   *   - ANCHOR_WALLET set to foundation key (8SL4dhn...)
   *   - Programs upgraded on devnet
   *   - npx ts-node or node --no-experimental-strip-types
   *
   * Run:
   *   set ANCHOR_WALLET=D:\Solana\Wallet\id.json
   *   set TS_NODE_TRANSPILE_ONLY=true
   *   node --no-experimental-strip-types node_modules\.bin\ts-node scripts\init-devnet.ts
   */

  import {
    Connection, Keypair, PublicKey, Transaction, SystemProgram,
    sendAndConfirmTransaction, LAMPORTS_PER_SOL,
  } from "@solana/web3.js";
  import * as spl from "@solana/spl-token";
  import * as fs from "fs";
  import * as borsh from "borsh";

  const RPC_URL       = process.env.ANCHOR_PROVIDER_URL ?? "https://api.devnet.solana.com";
  const WALLET_PATH   = process.env.ANCHOR_WALLET       ?? `${process.env.USERPROFILE}\\.config\\solana\\id.json`;
  const REWARDS_PROG  = new PublicKey(process.env.REWARDS_PROG_ID  ?? "2yeVew5qq5jf5zuoqiE2svVLRE9HTN6J2GfB9LopdM1C");
  const FLOW_MINT     = new PublicKey("8K4GhPEQ1yy9vdTaMPTL83G5qr5ZHZiBm2VBQ58jJs5w");

  const conn = new Connection(RPC_URL, "confirmed");

  const FOUNDATION = Keypair.fromSecretKey(
    Uint8Array.from(JSON.parse(fs.readFileSync(WALLET_PATH, "utf-8")))
  );

  function log(step: string, msg: string) {
    console.log(`[${step}] ${msg}`);
  }

  // ── Step 1: InitializeRewardsConfig (disc=8) ─────────────────────────────────
  // Creates the RewardsConfig PDA. No fields — just the discriminant.
  async function step1_initializeRewardsConfig() {
    log("1/8", "InitializeRewardsConfig (disc=8)...");
    const [rewardsConfigPda] = PublicKey.findProgramAddressSync(
      [Buffer.from("rewards_config")], REWARDS_PROG
    );
    const data = Buffer.from([8]); // disc=8
    const tx = new Transaction().add({
      keys: [
        { pubkey: FOUNDATION.publicKey, isSigner: true,  isWritable: true  },
        { pubkey: rewardsConfigPda,     isSigner: false, isWritable: true  },
        { pubkey: SystemProgram.programId, isSigner: false, isWritable: false },
      ],
      programId: REWARDS_PROG,
      data,
    });
    const sig = await sendAndConfirmTransaction(conn, tx, [FOUNDATION]);
    log("1/8", `OK — sig: ${sig}`);
    return sig;
  }

  // ── Step 2: InitializeRewardRates (disc=16) ───────────────────────────────────
  // routing_per_mb, seeding_per_mb, uptime_per_hour, flow_price_cents — all u64le
  // Initial values: 100 lamports/MB routing, 50/MB seeding, 10/hr uptime, $0.005/FLOW (500 hundredths-of-cent)
  async function step2_initializeRewardRates() {
    log("2/8", "InitializeRewardRates (disc=16)...");
    const [rewardRatesPda] = PublicKey.findProgramAddressSync(
      [Buffer.from("reward_rates")], REWARDS_PROG
    );
    const buf = Buffer.alloc(1 + 8 + 8 + 8 + 8);
    buf.writeUInt8(16, 0);                          // disc=16
    buf.writeBigUInt64LE(100n, 1);                  // routing_per_mb
    buf.writeBigUInt64LE(50n, 9);                   // seeding_per_mb
    buf.writeBigUInt64LE(10n, 17);                  // uptime_per_hour
    buf.writeBigUInt64LE(500n, 25);                 // flow_price_cents (0.005 USD * 100_000)
    const tx = new Transaction().add({
      keys: [
        { pubkey: FOUNDATION.publicKey, isSigner: true,  isWritable: true  },
        { pubkey: rewardRatesPda,       isSigner: false, isWritable: true  },
        { pubkey: SystemProgram.programId, isSigner: false, isWritable: false },
      ],
      programId: REWARDS_PROG,
      data: buf,
    });
    const sig = await sendAndConfirmTransaction(conn, tx, [FOUNDATION]);
    log("2/8", `OK — sig: ${sig}`);
  }

  // ── Step 3: InitializeTreasuryConfig (disc=18) ─────────────────────────────────
  // initial_treasury_keys: Vec<[u8;32]> — foundation key is initial treasury member
  async function step3_initializeTreasuryConfig() {
    log("3/8", "InitializeTreasuryConfig (disc=18)...");
    const [treasuryConfigPda] = PublicKey.findProgramAddressSync(
      [Buffer.from("treasury_config")], REWARDS_PROG
    );
    const foundationBytes = FOUNDATION.publicKey.toBytes();
    // Borsh Vec<[u8;32]>: u32le length prefix + 32 bytes per element
    const buf = Buffer.alloc(1 + 4 + 32);
    buf.writeUInt8(18, 0);                          // disc=18
    buf.writeUInt32LE(1, 1);                        // 1 treasury key
    buf.set(foundationBytes, 5);
    const tx = new Transaction().add({
      keys: [
        { pubkey: FOUNDATION.publicKey, isSigner: true,  isWritable: true  },
        { pubkey: treasuryConfigPda,    isSigner: false, isWritable: true  },
        { pubkey: SystemProgram.programId, isSigner: false, isWritable: false },
      ],
      programId: REWARDS_PROG,
      data: buf,
    });
    const sig = await sendAndConfirmTransaction(conn, tx, [FOUNDATION]);
    log("3/8", `OK — sig: ${sig}`);
  }

  // ── Step 4: Derive mint_authority PDA ─────────────────────────────────────────
  // This PDA must be set as the $FLOW mint authority before ReleaseRewards can mint.
  function deriveMintAuthorityPda(): [PublicKey, number] {
    return PublicKey.findProgramAddressSync(
      [Buffer.from("mint_authority")], REWARDS_PROG
    );
  }

  // ── Step 5: Transfer $FLOW mint authority → mint_authority PDA ───────────────
  // The current mint authority must sign. Foundation key IS the current mint authority.
  async function step5_transferMintAuthority() {
    log("5/8", "Transfer $FLOW mint authority to rewards PDA...");
    const [mintAuthorityPda] = deriveMintAuthorityPda();
    log("5/8", `  mint_authority PDA = ${mintAuthorityPda.toBase58()}`);

    const sig = await spl.setAuthority(
      conn,
      FOUNDATION,                    // payer + signer
      FLOW_MINT,                     // mint account
      FOUNDATION.publicKey,          // current authority
      spl.AuthorityType.MintTokens,  // authority type
      mintAuthorityPda,              // new authority
    );
    log("5/8", `OK — sig: ${sig}`);
  }

  // ── Step 6: Register mint_authority PDA in user-escrow spender registry ───────
  // disc for UpdateSpenderRegistry in user_escrow program — must be verified
  // from the user_escrow source before running.
  async function step6_registerSpenderInEscrow() {
    log("6/8", "Register mint_authority PDA in user-escrow spender registry...");
    log("6/8", "⚠️  MANUAL STEP — verify UpdateSpenderRegistry disc from user_escrow/src/lib.rs first.");
    log("6/8", "   Then run: scripts/register-spender.ts");
    // This step requires knowing the user-escrow program's instruction encoding.
    // Defer to a separate script (scripts/register-spender.ts) after verifying disc.
  }

  // ── Step 7: SetMigrationMode(false) (disc=10) — IRREVERSIBLE ─────────────────
  // Blocks ClaimUsage until set to false. Call ONLY when ready to go live.
  // ⚠️  DO NOT run during initial setup unless you intend to open ClaimUsage immediately.
  async function step7_setMigrationModeFalse() {
    log("7/8", "SetMigrationMode(false) (disc=10) — IRREVERSIBLE");
    log("7/8", "⚠️  Skipping — run manually when ready to open ClaimUsage path.");
    // When ready:
    //   data = Buffer.from([10, 0])  // disc=10, enabled=false (bool as u8)
    //   accounts: [foundation(signer), rewards_config_pda]
  }

  // ── Step 8: PreMintFoundation (disc=15) — optional initial treasury mint ──────
  async function step8_preMintFoundation() {
    log("8/8", "PreMintFoundation — skip for now, run separately if needed.");
  }

  // ── Main ──────────────────────────────────────────────────────────────────────
  async function main() {
    console.log("=== FreeFlow D:/Solana Canonical On-chain Initialization ===");
    console.log(`RPC:         ${RPC_URL}`);
    console.log(`Foundation:  ${FOUNDATION.publicKey.toBase58()}`);
    console.log(`Rewards:     ${REWARDS_PROG.toBase58()}`);
    console.log(`FLOW mint:   ${FLOW_MINT.toBase58()}`);
    console.log("");

    const balance = await conn.getBalance(FOUNDATION.publicKey);
    if (balance < 0.5 * LAMPORTS_PER_SOL) {
      throw new Error(`Foundation key has only ${balance} lamports — needs at least 0.5 SOL`);
    }

    await step1_initializeRewardsConfig();
    await step2_initializeRewardRates();
    await step3_initializeTreasuryConfig();
    await step5_transferMintAuthority();
    step6_registerSpenderInEscrow();
    step7_setMigrationModeFalse();
    step8_preMintFoundation();

    console.log("\n=== Initialization complete ===");
    const [mintAuthorityPda] = deriveMintAuthorityPda();
    console.log(`mint_authority PDA: ${mintAuthorityPda.toBase58()}`);
    console.log("Remaining manual steps:");
    console.log("  6. Run scripts/register-spender.ts (after verifying user-escrow disc)");
    console.log("  7. Run SetMigrationMode(false) when ready to open ClaimUsage");
  }

  main().catch(e => { console.error(e); process.exit(1); });
  ```

- [ ] **Step 2: Run steps 1–3 against devnet (dry-run first)**

  ```bat
  set ANCHOR_WALLET=D:\Solana\Wallet\id.json
  set ANCHOR_PROVIDER_URL=https://api.devnet.solana.com
  set TS_NODE_TRANSPILE_ONLY=true
  node --no-experimental-strip-types node_modules\.bin\ts-node scripts\init-devnet.ts
  ```

  Expected: steps 1–3 succeed with tx signatures; steps 6–8 print manual notes.

  > **DO NOT run step 5 (mint authority transfer) until programs are deployed and verified** — it cannot be reversed without the new mint_authority PDA signing.

- [ ] **Step 3: Commit**

  ```bat
  git add scripts/init-devnet.ts
  git commit -m "feat: add on-chain initialization script for D:/Solana canonical rewards program"
  ```

---

## Task 9: Per-relay reward_account pre-allocation script

**Files:**
- Create: `D:\Solana\freeflow-contracts\scripts\init-relay-account.ts`

D:/Solana's `process_claim` writes to `reward_account` at account[1] but never allocates it. The account must be pre-created with `create_account_with_seed` before the first `ClaimRewards` call.

`RewardAccount::SIZE = 32+8+8+8+8+8+8+1+1+8+8+8 = 106 bytes` (from D:/Solana struct definition).

- [ ] **Step 1: Verify RewardAccount::SIZE in rewards lib.rs**

  ```bat
  grep -n "const SIZE" D:/Solana/freeflow-contracts/programs/rewards/src/lib.rs
  ```

  Take the value for use in the script.

- [ ] **Step 2: Create scripts/init-relay-account.ts**

  ```typescript
  /**
   * init-relay-account.ts
   *
   * Pre-allocates a relay's reward_account using create_account_with_seed.
   * Must run once per relay BEFORE that relay submits their first ClaimRewards.
   *
   * Usage:
   *   set ANCHOR_WALLET=D:\Solana\Wallet\id.json   (payer — covers rent)
   *   set RELAY_PUBKEY=<relay base58 pubkey>
   *   node --no-experimental-strip-types node_modules\.bin\ts-node scripts\init-relay-account.ts
   */

  import {
    Connection, Keypair, PublicKey, Transaction,
    sendAndConfirmTransaction, SystemProgram, LAMPORTS_PER_SOL,
  } from "@solana/web3.js";
  import { createHash } from "crypto";
  import * as fs from "fs";

  const RPC_URL      = process.env.ANCHOR_PROVIDER_URL ?? "https://api.devnet.solana.com";
  const WALLET_PATH  = process.env.ANCHOR_WALLET ?? `${process.env.USERPROFILE}\\.config\\solana\\id.json`;
  const REWARDS_PROG = new PublicKey(process.env.REWARDS_PROG_ID ?? "2yeVew5qq5jf5zuoqiE2svVLRE9HTN6J2GfB9LopdM1C");
  const RELAY_PUBKEY = process.env.RELAY_PUBKEY;

  if (!RELAY_PUBKEY) throw new Error("Set RELAY_PUBKEY env var to the relay's base58 public key");

  const conn    = new Connection(RPC_URL, "confirmed");
  const PAYER   = Keypair.fromSecretKey(
    Uint8Array.from(JSON.parse(fs.readFileSync(WALLET_PATH, "utf-8")))
  );
  const relayPk = new PublicKey(RELAY_PUBKEY);

  const REWARD_ACCOUNT_SIZE = 106; // RewardAccount::SIZE — verify against lib.rs
  const SEED                = "freeflow-reward-v1";

  function deriveRewardAccount(relayPk: PublicKey, programId: PublicKey): PublicKey {
    const h = createHash("sha256");
    h.update(relayPk.toBytes());
    h.update(Buffer.from(SEED));
    h.update(programId.toBytes());
    return new PublicKey(h.digest());
  }

  async function main() {
    const rewardAccount = deriveRewardAccount(relayPk, REWARDS_PROG);
    console.log(`Relay:          ${relayPk.toBase58()}`);
    console.log(`Rewards prog:   ${REWARDS_PROG.toBase58()}`);
    console.log(`Reward account: ${rewardAccount.toBase58()}`);

    const existing = await conn.getAccountInfo(rewardAccount);
    if (existing) {
      console.log(`Account already exists (${existing.data.length} bytes) — nothing to do.`);
      return;
    }

    const rent = await conn.getMinimumBalanceForRentExemption(REWARD_ACCOUNT_SIZE);
    console.log(`Allocating ${REWARD_ACCOUNT_SIZE} bytes (rent: ${rent} lamports)...`);

    const tx = new Transaction().add(
      SystemProgram.createAccountWithSeed({
        fromPubkey:   PAYER.publicKey,
        newAccountPubkey: rewardAccount,
        basePubkey:   relayPk,
        seed:         SEED,
        lamports:     rent,
        space:        REWARD_ACCOUNT_SIZE,
        programId:    REWARDS_PROG,
      })
    );

    // relay must also sign because basePubkey = relayPk
    // If running from sidecar (self-hosted), relay keypair is available.
    // For external init (payer pays, relay signs), both must be signers.
    // ⚠️  If the payer IS the relay, pass only [PAYER].
    // If payer ≠ relay, load relay keypair separately and pass [PAYER, RELAY_KEYPAIR].
    const sig = await sendAndConfirmTransaction(conn, tx, [PAYER]);
    console.log(`OK — reward_account created. Sig: ${sig}`);
  }

  main().catch(e => { console.error(e); process.exit(1); });
  ```

- [ ] **Step 3: Verify RewardAccount::SIZE**

  ```bat
  grep -n "SIZE\|const SIZE\|pub const" D:/Solana/freeflow-contracts/programs/rewards/src/lib.rs | head -20
  ```

  Find the `RewardAccount` struct and count the fields to confirm 106 bytes:
  - relay_wallet: 32
  - total_lamports_claimed: 8
  - total_bytes_routed: 8
  - total_bytes_seeded: 8
  - total_uptime_seconds: 8
  - last_claim_ts: 8
  - claim_count: 8
  - tier: 1
  - bump: 1
  - repflow_balance: 8
  - repflow_tier: 1
  - total_cashback_earned: 8

  Total = 32+8+8+8+8+8+8+1+1+8+1+8 = **99 bytes** (confirm vs `RewardAccount::SIZE` constant in lib.rs and update script if different).

- [ ] **Step 4: Run for the RackNerd relay**

  The only registered relay is `AyKhSpMgE4XWJncJawR79pbH2DtedKx95ViTrkLCvD8X`:
  ```bat
  set ANCHOR_WALLET=D:\Solana\Wallet\id.json
  set RELAY_PUBKEY=AyKhSpMgE4XWJncJawR79pbH2DtedKx95ViTrkLCvD8X
  set ANCHOR_PROVIDER_URL=https://api.devnet.solana.com
  set TS_NODE_TRANSPILE_ONLY=true
  node --no-experimental-strip-types node_modules\.bin\ts-node scripts\init-relay-account.ts
  ```

  Expected: prints derived `reward_account` address and tx signature.

  > **Run this AFTER Task 8 on-chain init, AFTER program deploy.**

- [ ] **Step 5: Commit**

  ```bat
  git add scripts/init-relay-account.ts
  git commit -m "feat: add per-relay reward_account pre-allocation script"
  ```

---

## Task 10: Integration smoke test — self-hosted path

This task verifies the full self-hosted flow against the local test-validator (not devnet — avoids real money).

- [ ] **Step 1: Start local validator**

  ```bat
  start-validator.bat
  ```
  Wait for `Processed Slot: 1` in output.

- [ ] **Step 2: Deploy programs**

  ```bat
  solana program deploy target\deploy\rewards.so   --program-id target\deploy\rewards-keypair.json
  solana program deploy target\deploy\registry.so  --program-id target\deploy\registry-keypair.json
  ```

- [ ] **Step 3: Run init-devnet.ts against local validator**

  ```bat
  set ANCHOR_PROVIDER_URL=http://127.0.0.1:8899
  set REWARDS_PROG_ID=<local validator rewards program id>
  node --no-experimental-strip-types node_modules\.bin\ts-node scripts\init-devnet.ts
  ```

- [ ] **Step 4: Run init-relay-account.ts for the test relay**

  ```bat
  set RELAY_PUBKEY=<test relay pubkey from sidecar wallet>
  node --no-experimental-strip-types node_modules\.bin\ts-node scripts\init-relay-account.ts
  ```

- [ ] **Step 5: Start sidecar in self-hosted mode pointing at local validator**

  Update `config.toml`:
  ```toml
  [rpc]
  url = "http://127.0.0.1:8899"

  [wallet]
  signing_mode = "self_hosted"
  ```

  ```bat
  cargo run -p freeflow-sidecar -- --config config.toml
  ```

- [ ] **Step 6: Register relay**

  ```bat
  curl -X POST http://localhost:9210/v1/relay/register \
    -H "Content-Type: application/json" \
    -H "X-Relay-PubKey: <hex>" \
    -H "X-Timestamp: <unix>" \
    -H "X-Nonce: <16hex>" \
    -H "X-Signature: <64hex>" \
    -d '{"country":"US","tier":"professional","addr":"1.2.3.4:443","storage_bytes":1073741824}'
  ```
  Expected: `{ "ok": true, "data": { "tx_signature": "..." } }`

- [ ] **Step 7: Submit claim**

  ```bat
  curl -X POST http://localhost:9210/v1/relay/claim \
    -H "Content-Type: application/json" \
    -H "X-Relay-PubKey: <hex>" \
    ... \
    -d '{"bytes_routed":1073741824,"bytes_seeded":536870912,"uptime_secs":3600}'
  ```
  Expected: `{ "ok": true, "data": { "tx_signature": "..." } }`

- [ ] **Step 8: Verify reward_account updated on-chain**

  ```bat
  solana account <reward_account_address>
  ```
  Expected: account owned by rewards program, data 99+ bytes.

- [ ] **Step 9: Commit final integration notes**

  ```bat
  git add docs/windows-validator-setup.md
  git commit -m "docs: update setup notes with canonical contract sidecar flow"
  ```

---

## Summary table — all fixes

| Gap | Root cause | Fix in | Task |
|---|---|---|---|
| register → wrong program | `rewards_program_id` used instead of `registry_program_id` | handlers.rs + config.toml | Task 1+2 |
| register → disc=1 (RecordBytes) | Stale discriminant, should be 0 | solana.rs | Task 2 |
| register → wrong data format | Missing tier, storage_bytes, addr_bytes | solana.rs | Task 2 |
| register → wrong accounts | claim_pda instead of registry_pda | solana.rs | Task 2 |
| handle_claim calls disc=2 | Claims `claim_usage` but D:/Solana disc=2 needs full Vec<UsageRecordOnChain> | handlers.rs | Task 3 |
| encode_claim_rewards never wired | Dead function; handler uses wrong path | handlers.rs | Task 3 |
| Signer mismatch — self-hosted | Sidecar key must equal relay key; assertion added | solana.rs | Task 4 |
| Signer mismatch — detached | No relay keypair on shared server | handlers.rs + new /broadcast | Task 4+5 |
| No broadcast endpoint | Mobile/lightweight relay can't self-sign without it | routes.rs + handlers.rs | Task 5 |
| InitializeRewardRates disc=7 (ReleaseRewards!) | Off-by-9 error | solana.rs | Task 6 |
| UpdateRewardRates disc=8 (InitRewardsConfig!) | Off-by-9 error | solana.rs | Task 6 |
| handle_state reads wrong PDA | ["claim_state", relay_pk] is per-user+relay in D:/Solana | handlers.rs | Task 7 |
| No on-chain init done | RewardsConfig/rates/treasury PDAs don't exist | scripts/init-devnet.ts | Task 8 |
| reward_account not allocated | D:/Solana process_claim doesn't self-create the account | scripts/init-relay-account.ts | Task 9 |
| flow_mint blank | CPI minting path disabled | config.toml | Task 1 |
| registry_program_id missing | No path to call registry | config.toml + config.rs | Task 1 |
