# FreeFlow — Client Login Gate Implementation

> **Date:** 2026-05-24
> **Scope:** Relay-side enforcement + per-client platform requirements
> **Goal:** Gate all relay access behind valid escrowed $FLOW or active free trial
> **Constraint:** DOCUMENT ONLY — DO NOT TOUCH CODE

---

## Executive Summary

The relay already has the building blocks for gated access — invite codes, free trial module, balance checker, session auth — but they are **not enforced consistently** and have **critical gaps** that allow bypass. The transition from "open for testing" to "production gated" requires changes on the relay (enforcement logic), the foundation (admin auth + operational tooling), Solana programs (escrow completeness), and each client platform (escrow proof + trial UI).

**Current state:** A client with a valid invite code and any wallet can connect. Free trial grants 10 GB but quota resets on relay restart. Balance is checked once at connection, never refreshed. No transition from trial to paid. Foundation beta defaults to `enabled=true`.

**Target state:** Every connection must prove either (a) an active UserEscrow PDA with sufficient $FLOW balance, or (b) a valid, non-expired free trial record. Invites are wallet-bound. Trials are Sybil-resistant. Balance is checked periodically mid-session. Trial-to-paid transition is seamless.

---

## Architecture Overview

```
Client ──► [VLESS auth + invite code] ──► Relay
                                      │
                                      ├─► ClientInviteChecker (beta flag + invite validate)
                                      ├─► FreeTrialVerifier (device + wallet check, 10 GB)
                                      ├─► BalanceChecker (UserEscrow PDA read)
                                      ├─► SessionAuthManager (24h ed25519 session key)
                                      └─► StreamDispatcher (route to gateway/content/tunnel)

Foundation ──► Invite engine (generate/consume/revoke)
             ► Beta flags (clients_enabled)
             ► Blocklist/ban management

Solana ──► UserEscrow PDA (balance + held)
         ► FundHold PDA (dispute window)
         ► Rewards program (ClaimUsage with escrow CPI)
```

---

## Part 1: Relay-Side Enforcement

### RG1: Enforce Balance Check Before Every Connection

**Current:** `BalanceChecker` reads `UserEscrow` + `UserEscrowReservation` PDAs at connection start. But `ClientInviteChecker` only validates the invite code — it does **not** check balance. A client with a valid invite and zero balance still connects.

**What needs to change:**

The gate at `dispatcher.rs:handle_gateway_stream` must enforce:

```
if is_beta_enabled("clients"):
    invite_code = extract_from_vless_addon(stream)
    if not validate_invite(invite_code):
        reject("invalid invite")

    # NEW: must also pass one of:
    if has_active_trial(device_uuid, wallet):
        if trial_quota_exhausted(device_uuid, wallet):
            reject("trial exhausted")
        grant_trial_session()
    elif has_sufficient_escrow(wallet):
        balance = read_escrow_balance(wallet)
        reserved = read_escrow_reserved(wallet)
        if (balance - reserved) < MIN_ESCROW_THRESHOLD:
            reject("insufficient escrow")
        grant_paid_session()
    else:
        reject("no active trial or escrow")
```

**Files to modify:**
- `freeflow-relay-runtime/src/dispatcher.rs` — add dual-gate (trial OR escrow) to `handle_gateway_stream`
- `freeflow-relay-runtime/src/payments/mod.rs` — expose `has_sufficient_escrow()` as public function
- `freeflow-relay-runtime/src/free_trial/mod.rs` — expose `has_active_trial()` and `trial_quota_exhausted()`

### RG2: Periodic Mid-Session Balance Refresh

**Current:** Balance checked once at connection. Client can drain escrow mid-session and keep routing traffic until the next claim fails.

**What needs to change:**

Add a background ticker that re-checks escrow balance every N minutes (suggested: 5 min) per active session. If effective balance drops below a cutoff (e.g., enough for 1 GB of routing), terminate the session gracefully.

```
SessionMonitor {
    check_interval: Duration::from_secs(300),  // 5 min
    min_balance_threshold: 1_000_000,  // enough for ~1 GB at current rates
}

// On each tick:
for session in active_sessions {
    if session.is_trial:
        if trial_quota_exhausted(session.device, session.wallet):
            disconnect(session, "trial exhausted")
    else:
        balance = read_escrow_balance(session.wallet)
        reserved = read_escrow_reserved(session.wallet)
        if (balance - reserved) < min_balance_threshold:
            disconnect(session, "insufficient escrow")
}
```

**Files to modify:**
- `freeflow-relay-runtime/src/payments/mod.rs` — add `SessionBalanceMonitor` background task
- `freeflow-relay-runtime/src/dispatcher.rs` — register session with monitor on connect, deregister on disconnect

### RG3: Free Trial Quota Persistence

**Current:** `QuotaTracker` is an in-memory `HashMap`. Relay restart = all quotas reset = free trial can be re-claimed indefinitely by reconnecting.

**What needs to change:**

Persist quota state to disk alongside the existing `SequenceCounter` persistence. On startup, restore the `QuotaTracker` from disk.

```
// New file or addition to existing persistence:
// ~/.freeflow/relay/trial_quota.json
{
    "device_uuid_hash": "...",
    "wallet_pubkey": "...",
    "bytes_consumed": 10485760,  // 10 MB used of 10 GB
    "created_at": "2026-05-24T00:00:00Z",
    "expires_at": "2026-06-23T00:00:00Z"  // 30-day expiry (NEW)
}
```

**Files to modify:**
- `freeflow-relay-runtime/src/free_trial/mod.rs` — add disk persistence for `QuotaTracker`
- `freeflow-relay-runtime/src/node.rs` — load trial quotas on startup, save on shutdown (alongside DHT state)

### RG4: 30-Day Trial Expiry Enforcement

**Current:** `FreeTrialClaim` has an `expiry` field but it's never checked. Expired trials are still accepted.

**What needs to change:**

In `FreeTrialVerifier::validate()`, add:

```rust
if claim.expiry < current_timestamp() {
    return Err(TrialExpired);
}
```

Also add a background cleanup job that prunes expired trial records from DHT and disk every 24 hours.

**Files to modify:**
- `freeflow-relay-runtime/src/free_trial/mod.rs` — add expiry check to validation, add cleanup job

### RG5: Trial-to-Paid Transition

**Current:** No mechanism. Trial client must disconnect, generate a new session, and reconnect with escrow.

**What needs to change:**

When a trial client's quota is near exhaustion (e.g., 80% used), send a VLESS addon message notifying the client to fund escrow. If the client funds escrow mid-session, transition the session from trial mode to paid mode without disconnecting.

```
// In QuotaTracker:
fn check_transition_trigger(&self, device, wallet) -> bool {
    let used_pct = self.bytes_used(device, wallet) as f64 / TRIAL_QUOTA as f64;
    used_pct >= 0.8  // 80% threshold
}

// In dispatcher, on gateway stream:
if session.is_trial && quota.check_transition_trigger():
    send_addon_notification(stream, "TRIAL_NEAR_EXPIRE", { remaining_bytes, escrow_address })

// Client funds escrow → relay detects balance on next tick:
if session.is_trial && has_sufficient_escrow(wallet):
    session.transition_to_paid()
```

**Files to modify:**
- `freeflow-relay-runtime/src/free_trial/mod.rs` — add transition trigger check
- `freeflow-relay-runtime/src/dispatcher.rs` — send notification, handle transition
- `freeflow-relay-runtime/src/payments/mod.rs` — detect new escrow balance mid-session

### RG6: Invite Code Wallet Binding

**Current:** Invite codes are not tied to specific wallets. A generated code can be used by any client with any wallet.

**What needs to change:**

Foundation should bind invite codes to a specific Solana wallet pubkey at generation time. Relay should verify that the wallet used in the connection matches the wallet bound to the invite code.

```
// Foundation (generate):
SealedInvite {
    ...
    bound_wallet: Option<Pubkey>,  // NEW: optional wallet binding
}

// Relay (validate):
if invite.bound_wallet.is_some() && invite.bound_wallet != session.wallet {
    return Err(WalletMismatch);
}
```

**Files to modify:**
- `freeflow-foundation/src/services/invite.rs` — add `bound_wallet` param to generate endpoint
- `freeflow-relay-runtime/src/invite.rs` — verify wallet match during `validate_and_consume_client()`
- `freeflow-relay-runtime/src/dispatcher.rs` — pass session wallet pubkey to invite validator

### RG7: Beta Default Should Be Disabled

**Current:** `BetaFlag` defaults to `enabled=true`. All features are open by default.

**What needs to change:**

Change the default to `enabled=false`. Client gating is only active when the foundation operator explicitly enables it.

**Files to modify:**
- `freeflow-foundation/src/services/invite.rs` — change `BetaFlag` default from `true` to `false`

### RG8: Foundation Unreachable Fallback

**Current:** If Foundation is down, `is_beta_enabled()` fails closed — all connections rejected.

**What needs to change:**

Add a fallback mode: if Foundation is unreachable for >5 minutes, switch to "cached last known state" with a warning log. If the cached state is "beta enabled", continue accepting valid invites (which are cached locally after first validation). If cached state is "beta disabled", allow all connections (open mode) until Foundation recovers.

This is a **safety valve**, not a security bypass — in production you'd want to fail closed, but during testing you don't want a Foundation outage to kill all relay traffic.

**Files to modify:**
- `freeflow-relay-runtime/src/dispatcher.rs` — add fallback logic to `ClientInviteChecker`
- `freeflow-relay-runtime/src/invite.rs` — cache last known beta state with timestamp

---

## Part 2: Foundation Server

### FG1: Admin Authentication on Invite Endpoints

**Current:** Anyone who can reach the Foundation API can generate/consume/revoke invites. No admin auth on `/v1/invite/*` routes.

**What needs to change:**

Wire up the existing `check_admin_token()` pattern (used by `/v1/beta/*`, `/v1/ban/*`) to all invite generation/revocation endpoints. Read-only endpoints (stats, consume) can remain public.

**Files to modify:**
- `freeflow-foundation/src/main.rs` — add `check_admin_token()` middleware to invite generate/revoke routes

### FG2: Invite Code Expiry

**Current:** Invite codes have no TTL. They remain valid until consumed or revoked.

**What needs to change:**

Add `expires_at` field to `SealedInvite`. Reject codes past expiry during validation.

```
SealedInvite {
    ...
    expires_at: u64,  // Unix timestamp, default 7 days from creation
}
```

**Files to modify:**
- `freeflow-foundation/src/services/invite.rs` — add expiry to generation, check during consume
- `freeflow-relay-runtime/src/invite.rs` — reject expired codes

### FG3: Rate Adjustment Endpoint

**Current:** No way to call `UpdateRewardRates` on-chain (see FOUNDATION-GAPS.md F1, EMISSIONS-GAP.md E5).

**What needs to change:**

Add `POST /v1/admin/rates` endpoint that:
1. Requires admin token
2. Builds `UpdateRewardRates` instruction via sidecar encoder
3. Signs with foundation delegate key
4. Submits to Solana RPC

This is needed because even if relays gate by escrow correctly, the reward amounts are 1000x below target.

**Files to modify:**
- `freeflow-foundation/src/main.rs` — add rates endpoint
- `freeflow-foundation/src/config.rs` — add reward rate defaults to config

### FG4: Audit Trail for Admin Actions

**Current:** No logging of invite generation, revocation, beta flag changes, or ban management.

**What needs to change:**

Append every admin action to a tamper-evident log file:

```
// ~/.freeflow/foundation/admin_audit.jsonl
{"timestamp": "2026-05-24T00:00:00Z", "action": "invite_generate", "admin_ip": "x.x.x.x", "detail": {...}}
{"timestamp": "2026-05-24T00:01:00Z", "action": "beta_toggle", "admin_ip": "x.x.x.x", "flag": "clients", "enabled": true}
```

**Files to modify:**
- `freeflow-foundation/src/main.rs` — add audit logging wrapper around admin routes

---

## Part 3: Solana Programs

### SG1: User Escrow Withdrawal

**Current:** Users can fund escrow, but there's no instruction to withdraw funds back. Funds are locked until consumed by claims or burned.

**What needs to change:**

Add `WithdrawFromEscrow` instruction:
- Requires user signature
- Transfers specified amount from UserEscrow token account back to user wallet
- Fails if withdrawal would bring balance below a minimum reserve (e.g., enough for 1 claim)

**Files to modify:**
- `freeflow-contracts/programs/user_escrow/src/lib.rs` — add `withdraw_from_escrow` instruction

### SG2: Escrow Balance Cap Per User

**Current:** No limit on how much a single user can hold in escrow.

**What needs to change:**

Add `MAX_ESCROW_BALANCE` constant (or PDA-configurable) to `purchase_and_escrow`. Reject purchases that would push user's escrow balance above the cap.

This prevents a single user from locking up a disproportionate share of the $FLOW supply.

**Files to modify:**
- `freeflow-contracts/programs/user_escrow/src/lib.rs` — add balance cap check to `purchase_and_escrow`

### SG3: Reward Rate Fix

**Current:** `process_claim()` uses hardcoded constants 1000x below target (EMISSIONS-GAP.md E1). `process_claim_usage()` reads PDA for `flow_price_cents` but not for reward amounts.

**What needs to change:**

Either:
- **Option A:** Bump the hardcoded constants in `rewards/lib.rs` to match the on-chain PDA values (routing=1,000,000/MB, uptime=10,000,000,000/hr)
- **Option B:** Wire `process_claim()` to read from `RewardRatesAccount` PDA and use those values

Option A is simpler and doesn't change the PDA interface. Option B is more flexible long-term (rates adjustable without redeploy). Recommend **Option A first, Option B later**.

Also fix the integer division bug: `uptime_seconds / 3600` → use floating point or accumulate uptime across claims.

**Files to modify:**
- `freeflow-contracts/programs/rewards/src/lib.rs:2422-2427` — bump constants, fix division

---

## Part 4: Per-Client Platform Requirements

All clients share the same core requirements but differ in how they're implemented per platform.

### Common Requirements (All Platforms)

| Requirement | Description |
|-------------|-------------|
| **CR1: Wallet Integration** | Client must have a Solana wallet (keypair) to prove identity and fund escrow |
| **CR2: Escrow Proof** | Client must present proof of active UserEscrow PDA with sufficient balance to relay at connection time |
| **CR3: Invite Code Entry** | UI for entering/pasting invite code (`XX-XXXXXX` format) |
| **CR4: Free Trial Enrollment** | UI to enroll in free trial (generates device UUID + wallet pair, submits to relay) |
| **CR5: Trial Status Display** | Show remaining trial quota (e.g., "8.2 GB of 10 GB remaining") |
| **CR6: Escrow Balance Display** | Show current escrow balance, reserved amount, effective balance |
| **CR7: Transition Prompt** | When trial nears exhaustion, prompt user to fund escrow |
| **CR8: Session Key Management** | Generate ed25519 session key, sign with wallet, send to relay for auth |
| **CR9: Connection Error Handling** | Clear error messages: "invite invalid", "escrow insufficient", "trial expired" |

---

### Android Client

**Status:** Source not checked out locally. Code complete (29 source files). 9 diagnosed runtime bugs. APK never produced.

| Requirement | Implementation Notes |
|-------------|---------------------|
| **CR1 Wallet** | Use Android Keystore for keypair storage. Wallet JSON in app private storage. |
| **CR2 Escrow Proof** | Sidecar bridge (`freeflow-solana/src/main.rs`) can query UserEscrow PDA. Relay side reads the same PDA — client just needs the wallet pubkey in VLESS addon. |
| **CR3 Invite** | Add `EditText` dialog on first launch. Store consumed invite in `SharedPreferences`. |
| **CR4 Trial** | Generate UUID v4 on first launch. Store in `SharedPreferences`. Send with VLESS addon tag 0x03. |
| **CR5 Trial Status** | Relay sends remaining quota in session auth response. Display in `TextView` on status screen. |
| **CR6 Escrow Balance** | Sidecar RPC call to `/v1/relay/state` returns escrow info. Display in settings. |
| **CR7 Transition** | When relay sends `TRIAL_NEAR_EXPIRE` addon notification, show `AlertDialog` with "Fund Escrow" button. |
| **CR8 Session Key** | Generate ed25519 keypair on first session. Sign challenge from relay. Send pubkey + sig in VLESS addon. |
| **CR9 Errors** | Map relay rejection reasons to Android `Toast` or `Snackbar` messages. |

**Additional Android-specific:**
- Fix the 9 diagnosed runtime bugs before adding gating (see ALL-KNOWN-GAPS.md G11)
- `protect()` socket before relay connect (VpnService requirement)
- Handle network switch (WiFi ↔ cellular) without killing session keys
- Foreground service for VPN mode (survives app close)

**Files to create/modify (expected):**
- `app/src/main/java/io/freeflow/android/ui/InviteCodeDialog.kt` — invite entry
- `app/src/main/java/io/freeflow/android/ui/TrialStatusView.kt` — trial quota display
- `app/src/main/java/io/freeflow/android/ui/EscrowBalanceView.kt` — escrow display
- `app/src/main/java/io/freeflow/android/auth/WalletManager.kt` — keypair storage, signing
- `app/src/main/java/io/freeflow/android/auth/SessionKeyManager.kt` — ed25519 session keys
- `app/src/main/java/io/freeflow/android/vless/VlessAddonBuilder.kt` — attach invite code, device UUID, wallet pubkey to VLESS handshake
- Modify existing connection setup to include escrow proof in VLESS auth

---

### Windows Client

**Status:** Source not checked out locally. 3 modes (SOCKS5, TUN, WinDivert). SOCKS5 works. TUN blocked by WFP. WinDivert untested.

| Requirement | Implementation Notes |
|-------------|---------------------|
| **CR1 Wallet** | Store wallet JSON in `%APPDATA%\FreeFlow\wallet.json`. Optionally encrypt with Windows DPAPI. |
| **CR2 Escrow Proof** | Same as Android — wallet pubkey in VLESS addon. Sidecar or direct RPC for balance query. |
| **CR3 Invite** | Settings dialog or first-run wizard for invite code entry. Store in config TOML. |
| **CR4 Trial** | Generate UUID on first run. Store in config TOML. Send in VLESS addon. |
| **CR5 Trial Status** | System tray tooltip or settings panel. |
| **CR6 Escrow Balance** | Settings panel. Poll sidecar RPC every 60s. |
| **CR7 Transition** | Windows notification (toast) when trial nears exhaustion. |
| **CR8 Session Key** | Generate on first session. Store in memory (not disk). Re-generate on app restart. |
| **CR9 Errors** | System tray notification + log file entry. |

**Additional Windows-specific:**
- WFP discard issue (G10) must be resolved for TUN mode to work with gating
- WinDivert mode needs integration testing
- DPAPI encryption for wallet storage (optional but recommended)
- Windows service mode for auto-start with system

**Files to create/modify (expected):**
- `src/config/wallet.rs` — wallet loading from `%APPDATA%`
- `src/auth/invite.rs` — invite code storage and transmission
- `src/auth/session.rs` — ed25519 session key generation
- `src/ui/settings.rs` — invite entry, escrow balance display
- `src/ui/trial_status.rs` — trial quota display
- Modify existing VLESS connection code to attach wallet pubkey + invite code

---

### Mac Client

**Status:** Not assessed. Assumed to share architecture with Windows/Linux client (Rust-based relay runtime).

| Requirement | Implementation Notes |
|-------------|---------------------|
| **CR1 Wallet** | Store in `~/Library/Application Support/FreeFlow/wallet.json`. Optionally encrypt with Keychain. |
| **CR2-CR9** | Same as Windows, with macOS-native UI (system menu bar, NotificationCenter). |

**Additional Mac-specific:**
- Keychain integration for wallet encryption
- Launch daemon for auto-start
- Network extension for TUN mode (NetworkExtension framework, not smoltcp)
- Sandboxing considerations for file access

---

### Linux Client

**Status:** Not assessed. Likely the same Rust codebase as relay-runtime.

| Requirement | Implementation Notes |
|-------------|---------------------|
| **CR1 Wallet** | Store in `~/.config/freeflow/wallet.json`. Optional: encrypt with libsecret (GNOME Keyring / KWallet). |
| **CR2-CR9** | Same as Windows/Mac, with systemd service for auto-start. |

**Additional Linux-specific:**
- systemd service file for relay daemon
- TUN mode via `ip tuntap` (no WFP issues)
- CLI-first interface (no GUI expected) — all status via `freeflow-relay status` command
- Invite code via config file or CLI flag: `freeflow-relay --invite-code XX-XXXXXX`

---

### iPhone Client (iOS)

**Status:** Not assessed. No iOS client code found in any workspace.

| Requirement | Implementation Notes |
|-------------|---------------------|
| **CR1 Wallet** | Store in Keychain. No file system storage for wallet material. |
| **CR2 Escrow Proof** | Same as other clients — wallet pubkey in VLESS addon. |
| **CR3 Invite** | SwiftUI text input on first launch. Store in UserDefaults (encrypted). |
| **CR4 Trial** | UUID via `NSUUID`. Store in Keychain alongside wallet. |
| **CR5 Trial Status** | SwiftUI view in settings tab. |
| **CR6 Escrow Balance** | Settings view. Poll sidecar RPC. |
| **CR7 Transition** | iOS local notification. |
| **CR8 Session Key** | ed25519 via `CryptoKit` or third-party (Sodium). |
| **CR9 Errors** | SwiftUI alert / Toast. |

**Additional iOS-specific:**
- Network Extension (PacketTunnelProvider) for TUN mode
- App backgrounding limitations — relay must handle app suspend/resume gracefully
- TLS certificate pinning for relay connections
- App Store review considerations for proxy apps

**Files to create (expected):**
- `FreeFlowiOS/Sources/Keychain/WalletStore.swift` — Keychain wallet management
- `FreeFlowiOS/Sources/Auth/SessionKeyManager.swift` — ed25519 session keys
- `FreeFlowiOS/Sources/Network/PacketTunnelProvider.swift` — Network Extension TUN
- `FreeFlowiOS/Sources/UI/InviteCodeView.swift` — invite entry
- `FreeFlowiOS/Sources/UI/TrialStatusView.swift` — trial quota
- `FreeFlowiOS/Sources/UI/EscrowBalanceView.swift` — escrow display
- `FreeFlowiOS/Sources/VLESS/VlessAddonBuilder.swift` — attach auth data to VLESS

---

## Part 5: End-to-End Test Scenarios

| # | Scenario | Expected Result |
|---|----------|-----------------|
| T1 | New client with valid invite + no trial + no escrow | **REJECT** — "no active trial or escrow" |
| T2 | New client with valid invite + active trial | **ACCEPT** — trial session, 10 GB quota |
| T3 | New client with valid invite + funded escrow | **ACCEPT** — paid session, balance verified |
| T4 | Client with expired trial | **REJECT** — "trial expired" |
| T5 | Client with exhausted trial (10 GB used) | **REJECT** — "trial quota exhausted" |
| T6 | Client with insufficient escrow (balance < threshold) | **REJECT** — "insufficient escrow" |
| T7 | Client with invalid invite code | **REJECT** — "invalid invite" |
| T8 | Client with revoked invite | **REJECT** — "invite revoked" |
| T9 | Client with wallet mismatch (invite bound to different wallet) | **REJECT** — "wallet mismatch" |
| T10 | Paid client drains escrow mid-session | **DISCONNECT** after next balance check (5 min) |
| T11 | Trial client uses 80% quota | **NOTIFY** — relay sends transition prompt |
| T12 | Trial client funds escrow mid-session | **TRANSITION** — session switches from trial to paid |
| T13 | Foundation unreachable at connection | **FALLBACK** — use cached beta state (configurable) |
| T14 | Client reuses consumed invite code | **REJECT** — "invite already consumed" |
| T15 | Client with banned wallet | **REJECT** — "wallet banned" |
| T16 | Client with banned relay | **REJECT** — "relay banned" |
| T17 | Relay restart — trial client reconnects | **QUOTA PRESERVED** — disk persistence prevents reset |
| T18 | Two devices same wallet (trial) | **REJECT** on second device — "wallet already in use" |
| T19 | Two wallets same device (trial) | **REJECT** on second wallet — "device already in trial" |

---

## Part 6: Implementation Priority

| Phase | Tasks | Dependencies |
|-------|-------|-------------|
| **P0** | RG1 (enforce dual-gate), RG3 (trial persistence), RG4 (trial expiry), FG1 (admin auth on invites) | None |
| **P1** | RG2 (mid-session balance), RG5 (trial-to-paid), RG6 (wallet binding), FG2 (invite expiry) | P0 |
| **P2** | RG7 (beta default), RG8 (fallback), FG3 (rate endpoint), SG1 (escrow withdrawal) | P1 |
| **P3** | SG2 (escrow cap), SG3 (reward rate fix), FG4 (audit trail) | P2 |
| **Clients** | CR1-CR9 for each platform | P0 (relay must enforce before clients can prove) |

**Recommended order:** Fix relay enforcement first (P0), then add operational polish (P1-P2), then fix Solana program gaps (P3), then roll out client UI per platform.

---

## Part 7: Risk Assessment

| Risk | Impact | Mitigation |
|------|--------|------------|
| DHT data loss | Trial records lost → free trial re-claimable | RG3 (disk persistence) reduces reliance on DHT |
| Foundation outage | No invite validation → all connections fail | RG8 (cached fallback) |
| Balance checker reads wrong offset | Silent balance corruption | Add PDA layout version check |
| Sybil attack on trial | Infinite free trials via UUID spoofing | Bind trial to wallet (on-chain verifiable) not just device UUID |
| Client drains escrow, relay doesn't notice | Free routing until next claim | RG2 (5-min balance check) limits exposure |
| Invite code leak | Stolen code grants unauthorized access | FG2 (7-day expiry), RG6 (wallet binding) |
| Reward rates still 1000x low | Clients pay for escrow, relays earn pennies → relays quit | SG3 (fix rates) must be done before production launch |

---

## Summary of What Exists vs What's Missing

| Component | Exists | Missing |
|-----------|--------|---------|
| Invite codes | Encrypted, signed, DHT-anchored, single-use | Wallet binding, expiry, admin auth on generation |
| Free trial | 10 GB per device+wallet, DHT tracked, QuotaTracker | Disk persistence, expiry enforcement, Sybil resistance, trial-to-paid |
| Balance check | Reads UserEscrow + Reservation PDAs | Mid-session refresh, fallback, offset validation |
| Session auth | 24h ed25519 keys, relay-to-sidecar auth | Client-side session key generation, revocation |
| Escrow (Solana) | FundHold, HoldStatus, CPI burn/release | Withdrawal, balance cap, UpdateRewardRates |
| Beta gating | `is_beta_enabled()` with 5-min cache | Default should be disabled, unreachable fallback |
| Client UI | None (all platforms) | All CR1-CR9 requirements |
