# FreeFlow Network — All Known Gaps

> **Date:** 2026-05-23
> **Scope:** All repos (triton, contracts, android, windows)
> **Status:** Android + Windows clients built and tested. Contracts compile. Foundation server compiles. No code deployed. No live integration tested.
> **Updated:** 2026-05-24 — re-audit found G1 pubkey, G5 enum+UDP, G6 tracker+invites, G7 latency trigger, G12 metrics all resolved since doc was written.
> **Updated:** 2026-05-26 — FOUNDATION-GAPS F1-F9 fixed; EMISSIONS-GAP E1/E2/E5 fixed; G17 fixed.

## Related Documents

- **`FOUNDATION-GAPS.md`** — Foundation server gaps: F1-F9 **FIXED** (2026-05-26), F10-F12 P2 deferred
- **`EMISSIONS-GAP.md`** — Emissions gaps: E1/E2/E5 **FIXED** (2026-05-25), E3/E4/E6/E7 P2 deferred

## Changelog (resolved since original audit)

| Date | Gap | What resolved | Evidence |
|------|-----|---------------|----------|
| 2026-05-24 | G1 | `NETWORK_AUTHORITY_PUBKEY` — real hex key replaces placeholder | `pool.rs:274` |
| 2026-05-24 | G5 | `VlessCommand` enum (0x01–0x04) defined; `udp_proxy.rs` fully coded | `vless.rs:58-66`, `udp_proxy.rs` |
| 2026-05-24 | G6 | `/v1/tracker` endpoint live; beta invite engine (6 routes) coded | `main.rs:254`, `main.rs:682-686` |
| 2026-05-24 | G7 | `LatencyMonitor` with 60s baseline, 5x spike, dual-trigger policy | `hopper.rs:79-162` |
| 2026-05-24 | G12 | `MetricsSnapshot` + tamper-evident periodic persistence | `metrics.rs`, `persistence.rs`, `node.rs:1001` |
| 2026-05-24 | G17 | `UpdateRewardRates` disc=17 exists on-chain, no foundation endpoint | (open) |
| 2026-05-25 | G17 | E1/E2 fixed in rewards program: PDA rates read by process_claim, integer division fixed | triton a3e1885, contracts 270b174 |
| 2026-05-25 | G17 | E5 fixed: `scripts/update-reward-rates.ts` CLI tool created | contracts 270b174 |
| 2026-05-26 | F1  | `GET /v1/admin/rates` proxies to sidecar `/v1/relay/rates` | triton e2cc421 |
| 2026-05-26 | F3  | `compute_flush_eta()` replaces hardcoded 3600/86400 stubs | triton e2cc421 |
| 2026-05-26 | F4  | URL `/v1/relay/claim`, key `tx_signature`, lamports parsed | triton e2cc421 |
| 2026-05-26 | F5  | `relay_addr` field in ClaimRequest; real addresses in tracker | triton e2cc421 |
| 2026-05-26 | F6  | `/pool`, `/pool/v1/tracker`, `/pool/latest` live; delta 501 | triton e2cc421 |
| 2026-05-26 | F8  | `GET /v1/admin/status` — pending claims, config, ETA, services | triton e2cc421 |
| 2026-05-26 | F9  | threshold_gb 300→1, flush_interval_secs=86400, background flush task | triton e2cc421 |

---

## G1: Pool Authority Infrastructure

**Impact:** Blocks gateway hopping, referral, P2P mesh bootstrap.
**Priority:** P0

| Item | Details |
|------|---------|
| Network authority keypair | **RESOLVED** (2026-05-24). Real hex key at `freeflow-hopping/src/pool.rs:274` (`6e7ee205cf04716c9f85d7c2addc4d1b1690acb02960411f6e5896e9ab632559`). Also used in `freeflow-foundation/src/services/tracker.rs`. |
| Pool delta server (`pool.freeflow.my`) | **SKELETON ADDED** (2026-05-26). `/pool`, `/pool/v1/tracker`, `/pool/latest` routes live. `/pool/v1/delta/:tier` returns 501. Full signed delta protocol deferred to Phase 4. nginx proxy rule still needed on DreamHost (`location /pool { proxy_pass http://127.0.0.1:8442; }`). See F6 in `FOUNDATION-GAPS.md`. |
| Domain registration | **VERIFIED** (2026-05-26). `freeflow.my` resolves to 173.236.223.85, TLS valid until 2026-07-29. `/pool` currently 404 — nginx proxy not yet configured. See F7 in `FOUNDATION-GAPS.md`. |
| Pool authority key in HSM | No HSM setup, no key rotation procedure. |

**What's coded:** `freeflow-hopping/src/pool_updater.rs` can fetch signed deltas and verify Ed25519 signatures. `merkle.rs` computes and verifies tier hashes. Both work with a live server.
**What's missing:** The delta server, DNS.

---

## G2: Ed25519 On-Chain Signature Verification

**Impact:** Client signatures on `UsageRecordOnChain` are stored blobs, not cryptographically verified until a dispute fires.
**Priority:** P0 (SHIELD Finding 8.2)

| Item | Details |
|------|---------|
| `user_sig` not verified on claim | `validate_client_signature()` checks `client_signature != [0; 64]` (presence only). No Ed25519 precompile call during `ClaimUsage`. |
| `relay_sig` not verified on claim | Same — stored as evidence, verified only during disputes. |
| `client_signature` (countersig) not verified on claim | Same. The comment at `lib.rs:1333` says "In production: the Ed25519Program precompile verifies". It doesn't. |

**What's coded:** The signature fields exist on `UsageRecordOnChain`. The Ed25519 precompile is used during `DisputeClaim` for dispute resolution.
**What's missing:** A transaction-level precompile call in `ClaimUsage` that verifies signatures upfront.

---

## G3: Contract Deployment

**Impact:** Nothing on-chain is real. All claims, staking, rewards, escrow are theoretical.
**Priority:** P0

| Item | Details |
|------|---------|
| Programs not deployed | All 5 programs (repflow_token, staking, rewards, registry, user_escrow) exist as `.so` files but never deployed to devnet or mainnet. |
| $FLOW SPL token not created | Token-2022 mint address doesn't exist. Mint authority not transferred to mint_authority PDA. |
| Program IDs are placeholders | `Anchor.toml`, `freeflow-relay-runtime/src/config.rs`, `freeflow-solana/src/wallet.rs` all contain placeholder addresses. |
| Solana CLI not installed | Current machine cannot deploy or test live against devnet. |
| Sidecar wallet missing | `sidecar_wallet.json` not provisioned. Sidecar will crash on startup. |

**What's coded:** All 5 programs compile. 2000+ lines of Rust tests pass. Sidecar bridge code exists (+270 lines in `freeflow-solana/src/main.rs`).
**What's missing:** Deployment, token creation, real program IDs, live integration test.

---

## G4: Governance & Multisig

**Impact:** Slashing requires governance authorization. Currently a hardcoded placeholder.
**Priority:** P1

| Item | Details |
|------|---------|
| `GOVERNANCE_PUBKEY` | `"GoVxxx..."` placeholder in `staking/src/lib.rs`. Not a real Squads multisig. |
| Appeal process undocumented | What happens after a slash? How does a relay appeal? |
| Slash flow never tested end-to-end | Governance key is fake, so slash path through real multisig never validated. |

---

## G5: VLESS Protocol Commands

**Impact:** Relay can only proxy TCP. No UDP, no hopping, no content fetching.
**Priority:** P1

| Command | Byte | Status | Gap |
|---------|------|--------|-----|
| TCP | `0x01` | Working | — |
| UDP | `0x02` | **PARTIAL** (2026-05-24) | `VlessCommand::Udp` enum exists. Full `UdpProxy` impl at `freeflow-obfuscation/src/udp_proxy.rs` (QUIC datagram-based, 30s idle timeout). But handler in `proxy.rs:121` returns `UnsupportedCommand` — not wired into dispatch. |
| Relay Hop | `0x03` | Not implemented | Enum defined, but handler returns `UnsupportedCommand`. TCP connection migration at hop time not coded. |
| Content | `0x04` | Not implemented | Enum defined, but handler returns `UnsupportedCommand`. |

**What's coded:** Protocol stack (Reality TLS + yamux + VLESS auth) works for TCP. `VlessCommand` enum has all 4 values. UDP proxy module fully coded. Both Android and Windows clients connect via TCP and serve traffic.
**What's missing:** Wiring 0x02/0x03/0x04 into `proxy.rs` dispatch match, implementing 0x03 and 0x04 handlers.

---

## G6: DHT Discovery & Bootstrap

**Impact:** Relays can't find each other. Pool is empty. Hopping can't work.
**Priority:** P1

| Item | Details |
|------|---------|
| Bootstrap tracker (`tracker.json`) | **RESOLVED** (2026-05-24). `GET /v1/tracker` endpoint live in foundation server (`main.rs:254`). Returns signed seed nodes from `TrackerEngine`. Static peers configured in `freeflow.toml`. |
| DHT persistence bug | **PARTIAL**. DHT state saved on shutdown (`node.rs:1778`). Tamper-evident persistence for metrics (`persistence.rs`) works with periodic saves. But DHT periodic persistence during runtime — **STILL MISSING** (no interval-based save, crash between shutdowns still loses peers). |
| Per-tier encrypted DHT | Tier-specific AES-256-GCP key distribution via ECDH documented but not coded. Relay IPs stored in plaintext in DHT. |
| Beta invite system | **RESOLVED** (2026-05-24). Invite engine fully coded with 6 routes: `/v1/invite/stats`, `/v1/invite/generate`, `/v1/invite/revoke`, `/v1/invite/{sha256_hex}`, `/v1/invite/consume/{sha256_hex}`, plus beta flags. |

---

## G7: Gateway Hopping

**Impact:** No anti-censorship. Single relay = single point of failure.
**Priority:** P1

| Item | Details |
|------|---------|
| Algorithm implemented | `HMAC-SHA256(shared_secret, "{snapped_ts}:{hop_counter}")` exists in `freeflow-hopping/src/hmac.rs`. |
| Pool management coded | `pool.rs` + `pool_updater.rs` manage tier partitioning. |
| Dual-trigger hop policy | **RESOLVED** (2026-05-24). `LatencyMonitor` in `freeflow-hopping/src/hopper.rs` — 60s baseline window, 30-sample ring buffer, 5x spike multiplier, `HopReason::{TimeInterval, LatencySpike}` enum, fully unit tested. Hop fires on **either** 600s interval OR rolling avg > 5x baseline (with >= 5 post-baseline samples). |
| Hopping blocked by empty pool | **RESOLVED** (2026-05-24). Tracker endpoint returns seed nodes; pool updater wired. |
| TCP connection migration not implemented | Hop requires QUIC migration or TCP reconnect with state preservation. Neither coded. Tied to missing VLESS 0x03 handler (G5). |
| VLESS 0x03 relay hop command | Missing (see G5). |

---

## G8: Merkle Routing Proofs

**Impact:** Relay can claim rewards for traffic it never routed. No cryptographic proof of routing.
**Priority:** P2 (SHIELD Finding 8.2 prerequisite)

| Item | Details |
|------|---------|
| Documented (Phase 2) | `DHT-CHALLENGE-RESPONSE.md` — user creates Merkle tree of routed chunks, random relay audits, target produces inclusion proof. |
| No code exists | No Merkle tree builder for routed chunks. No inclusion proof generator. No audit protocol. |
| Reputation → on-chain Merkle proof | Documented: relay submits Merkle proof of reputation score to contract. Not coded. |
| Automated slashing from challenge failure | Documented (Phase 3). Not coded. |
| Storage proofs partially coded | `freeflow-contentchain/src/storage_proof.rs` exists (challenge → SHA256(chunk || nonce) → verify). But oracle integration not connected. |

---

## G9: DNS-over-TCP (Windows Client)

**Impact:** DNS cache-miss queries are dropped.
**Priority:** P2

| Item | Details |
|------|---------|
| DNS cache works | Hit → returns cached response. |
| DNS DoH-through-relay | TODO. Cache miss → query dropped. No fallback resolver. |
| AAAA queries return empty | Working as designed (blocks IPv6). |

---

## G10: Windows TUN Mode — WFP Discard

**Impact:** Full VPN mode broken. Only SOCKS5 works.
**Priority:** P1 (for Windows VPN)

| Item | Status |
|------|--------|
| smoltcp SYN-ACK stuck in `SynReceived` | WFP discard layer blocks packets. 6 attempted fixes, all failed. |
| 5 unexplored approaches | Firewall block rule, proper `windows-sys` usage, full NAT, portproxy, kernel injection. |
| WinDivert mode untested | Coded but never integration-tested. Requires signed kernel driver. |
| TUN mode WFP fix untested | Code exists (`wfp_filter.rs`) but fails with `FWP_E_INVALID_LAYER`. |

---

## G11: Android Client — Runtime Bugs

**Impact:** APK never produced. 9 diagnosed bugs not confirmed fixed.
**Priority:** P1 (for Android launch)

| Item | Details |
|------|---------|
| TCP preconnect timeout | `prompts/tcp-preconnect-timeout-kills-service` — service dies on preconnect. |
| Proxy data stalls after auth | `prompts/proxy-data-stalls-after-auth` / `auth2` — data stops flowing after VLESS auth succeeds. |
| TLS handshake failure | `prompts/rust-thread-panic-tls-handshake-failure` — panic on TLS setup. |
| Sequential connect delay | `prompts/connect-delay-sequential-warmup` — connections warm up too slowly. |
| WiFi recovery pool sockets die | `prompts/wifi-recovery-pool-sockets-die` — network switch kills all relay sockets. |
| VPN survives app close | `prompts/vpn-survives-app-close` — foreground service lifecycle. |
| JNI class loading on background thread | `prompts/jni-findclass-background-thread` — `FindClass` crashes on non-JNI threads. |
| Protect socket before connect | `prompts/protect-before-connect` — Android VpnService requires `protect()` before relay connect. |
| Errno location in NDK | `prompts/errno-location-android-ndk` — Rust errno resolution on Android. |
| APK never produced | `build-rust.sh` + `./gradlew assembleDebug` never ran successfully. |
| Never tested on device | No integration test on actual Android hardware. |

---

## G12: Monitoring & Observability

**Impact:** No visibility into relay health, rewards, slashing events.
**Priority:** P2

| Item | Details |
|------|---------|
| Prometheus + Grafana | **RESOLVED** (2026-05-24). `freeflow-relay-runtime/src/metrics.rs` — `MetricsSnapshot` with atomic counters (bytes routed, connections, challenges, rewards, uptime). Dashboard at `freeflow-config/src/dashboard.html`. |
| Periodic persistence | **RESOLVED** (2026-05-24). Tamper-evident `metrics.json` saved periodically via `node.rs:1001` with Ed25519 signing. Load-on-startup restores state after crash. |
| Log rotation | Not configured. systemd journalctl limits or logrotate not set up. |
| Centralized logging | Fleet log aggregation not implemented. |
| Privacy audit | Not confirmed — no PII or traffic content in logs not yet verified. |

---

## G13: Update Mechanism & Key Management

**Impact:** No auto-update. No key rotation. Lost relay key = lost identity + unstake.
**Priority:** P2

| Item | Details |
|------|---------|
| Auto-update | `freeflow-relay update` subcommand not implemented. No GitHub release check. |
| Signed releases | No GPG-signed `.deb`, `.dmg`, `.exe` artifacts. |
| Key rotation | `freeflow-relay rotate-key` not implemented. |
| Key backup | Documented but not tested — recovery procedure not validated. |
| Passphrase encryption | Optional encryption on `relay.key` not implemented. |

---

## G14: ContentChain

**Impact:** No content seeding. Content discovery dead.
**Priority:** P3

| Item | Details |
|------|---------|
| Chunk store | Coded but empty. No content to seed. |
| DHT publishing | Coded but never exercised — no content metadata published. |
| Mutable/immutable items | Code exists for BEP 44 DHT items, never used. |

---

## G15: External Audit

**Impact:** Cannot go to mainnet without audit.
**Priority:** P0 (for mainnet)

| Item | Details |
|------|---------|
| Smart contract audit | No engagement with OtterSec, Neodyme, Halborn, etc. |
| Cryptography review | TOTP hop algorithm, X25519 Reality ECDH, certificate pinning — reviewed but not audited by cryptographer. |
| GFW evasion validation | Suricata/Zeek zero-alert requirement not validated. No test from restrictive jurisdiction. |

---

## G16: Performance Validation

**Impact:** Unknown throughput. May not meet tier targets.
**Priority:** P2

| Item | Target | Status |
|------|--------|--------|
| Linux throughput | 800+ MB/s | Not measured on reference hardware. |
| Windows throughput | 650-700 MB/s | Not measured. |
| macOS throughput | 400-600 MB/s | Not measured. |
| QUIC handshake latency | <10ms 0-RTT | Not measured. |
| Hop overhead | <10ms per hop | Not measured. |

---

## G17: Reward Rates — Hardcoded Constants 1000x Below Target ✅ FIXED

**Fixed:** 2026-05-25 in commits a3e1885 (freeflow-triton) and 270b174 (freeflow-contracts)
**Deep dive:** `EMISSIONS-GAP.md`

| Item | Fix |
|------|-----|
| E1: `process_claim()` used hardcoded constants | ✅ Now reads optional `RewardRatesAccount` PDA as account[2]; sidecar passes PDA in tx |
| E2: Integer division `seconds/3600*rate` zeroed sub-hour rewards | ✅ Fixed to `seconds*rate/3600` |
| E5: No rate adjustment mechanism | ✅ `scripts/update-reward-rates.ts` CLI tool; `GET /v1/admin/rates` endpoint in foundation |

**Deployed:** Rewards program redeployed to devnet slot 464861055.
**Sidecar:** Updated to include `reward_rates_pda` as account[2] in ClaimRewards transactions.
**Foundation:** `GET /v1/admin/rates` proxies to sidecar `/v1/relay/rates` to surface live PDA values.

Remaining items E3/E4/E6/E7 are P2 — see `EMISSIONS-GAP.md`.

---

---

## Summary by Priority

| Priority | Gaps | Count |
|----------|------|-------|
| **P0** | G1 Pool authority (delta server/domain), G2 On-chain sig verification, G3 Contract deployment, G15 Audit, G17 Reward rates 1000x below target | 5 |
| **P1** | G4 Governance, G5 VLESS commands (0x03/0x04), G6 DHT persistence, G7 Connection migration, G10 Windows TUN, G11 Android bugs | 6 |
| **P2** | G8 Merkle routing proofs, G9 DNS-over-relay, G12 Log rotation/privacy, G13 Updates/keys, G16 Performance | 5 |
| **P3** | G14 ContentChain | 1 |

---

## What Works Today (Built + Tested)

| Component | Status |
|-----------|--------|
| **5 Solana programs** | Compile, ~2000+ lines tests pass. Not deployed. |
| **Foundation server** | Compiles. Challenge engine, tracker publisher, invite engine (6 routes), beta flags, rendezvous, blocklist — all coded and routed. Not deployed. |
| **Freeflow-solana sidecar** | Compiles. CPI-bridge, live release coded. Not deployed. |
| **Freeflow-sidecar** | Compiles. Config.toml-based. Wallet not provisioned. |
| **Android client** | Code complete (29 source files). 9 diagnosed runtime bugs. APK never produced. |
| **Windows client** | Code complete (3 modes). SOCKS5 works. TUN blocked by WFP. WinDivert untested. |
| **Freeflow-hopping** | Merkle pool, pool updater, HMAC hop algorithm, `LatencyMonitor` (60s baseline, 5x spike, dual-trigger), fully unit tested. |
| **Freeflow-contentchain** | Chunk store, storage proofs — coded but empty. |
| **Freeflow-relay-runtime** | TCP transport, Reality TLS, yamux, VLESS TCP (0x01), challenge response, metrics with tamper-evident persistence, dashboard — working. |
| **Freeflow-obfuscation** | `VlessCommand` enum (Tcp/Udp/Relay/Content), UDP proxy module coded (not wired into dispatch). |
| **Network authority** | Real Ed25519 pubkey at `pool.rs:274`. Delta signing infrastructure ready (no delta server routes yet). |
