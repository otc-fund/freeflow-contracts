# FreeFlow Foundation Server — All Gaps

> **Date:** 2026-05-24
> **Scope:** `freeflow-foundation` binary only (1256 lines Rust)
> **Method:** Line-by-line audit of `main.rs`, `config.rs`, `services/claim_push.rs`, `services/tracker.rs`, `services/invite.rs`, `services/challenge.rs`, `services/validator.rs`, `services/key_authority.rs`, `services/rendezvous.rs`
> **Status:** Server compiles. 5 services run. ~20 HTTP routes live. No rate management. No pool delta server. Claims route through sidecar, not Solana directly.

---

## F1: No Reward Rate Management Endpoints

**Impact:** On-chain reward rates are frozen at initialization values. Foundation cannot adjust `routing_per_mb`, `seeding_per_mb`, `uptime_per_hour`, or `flow_price_cents` after deploy.

| Item | Details |
|------|---------|
| On-chain support | `InitializeRewardRates` (disc=16) and `UpdateRewardRates` (disc=17) exist in rewards program (`rewards/lib.rs:4286`, `rewards/lib.rs:4390`) |
| Sidecar support | `encode_initialize_reward_rates()` and `encode_update_reward_rates()` exist in `sidecar/src/solana.rs:300-331` |
| Foundation routes | **NONE**. No route in `build_router()` calls either encoder |
| Admin auth pattern | `check_admin_token()` exists at `main.rs:385` — used by invite/beta/ban routes. Same pattern could protect rate endpoints |

**Current state:** Rates set once at init, never changeable. If rates are wrong (they are — uptime is 10x target), no operational path to fix without redeploy.

---

## F2: Claim Push Goes Through Sidecar, Not Direct Solana

**Impact:** Foundation server doesn't talk to Solana RPC. It POSTs claim batches to a sidecar RPC URL, which then builds and signs the Solana transaction.

**Code path:** `claim_push.rs:326-367` — `submit_to_solana()`:
```
Foundation → POST {rpc_url}/v1/claim → sidecar → Solana RPC
```

| Issue | Details |
|-------|---------|
| Dev mode stub | If `rpc_url` is empty or starts with `http://127`, returns `DEVTX_{timestamp}` stub — no Solana interaction at all (`claim_push.rs:327-331`) |
| Sidecar dependency | Foundation cannot submit claims without a running sidecar. Sidecar must have wallet loaded, Solana RPC configured |
| No fallback | If sidecar is down, claims pile up in `pending_claims.json` indefinitely |
| No tx confirmation | `lamports_distributed` always hardcoded to `0` in `FlushedResponse` (`claim_push.rs:259`, `main.rs:342`) |

**What's missing:** Direct Solana submission path from foundation, or at minimum a sidecar health check before accepting claims.

---

## F3: Hardcoded ETA Stubs in Claim Status

**Impact:** Relays receive meaningless ETA estimates for when their claims will flush.

**Code:** `main.rs:317-322`:
```rust
let eta = if pending.cumulative_gb() > 0.0 {
    3600u64      // always 1 hour
} else {
    86_400       // always 24 hours
};
```

No accumulation rate tracking. No historical flush data. Just two hardcoded constants.

---

## F4: `lamports_distributed` Always Zero

**Impact:** Flush responses cannot tell relays how much $FLOW was actually minted/distributed.

**Code:** `claim_push.rs:259`:
```rust
lamports_distributed: 0, // populated from Solana tx response in production
```

Comment says "in production" — but the sidecar response at `submit_to_solana()` only extracts `tx_sig` from the JSON body (`claim_push.rs:364`). Even if sidecar returned `lamports_distributed`, foundation doesn't parse it.

---

## F5: Tracker Seed Addresses Are Placeholders

**Impact:** New relays joining via tracker file get invalid connection addresses.

**Code:** `main.rs:853-858` (CLI `TrackerPublish`):
```rust
let seed_nodes: Vec<SeedNode> = relay_keys.into_iter().map(|pubkey| SeedNode {
    node_id: pubkey.clone(),
    addr:    format!("{}:443", pubkey),  // DHT will have real addrs in Phase 4
    tier:    1,
    pubkey,
}).collect();
```

And `main.rs:981-986` (auto-publish background loop):
```rust
.map(|pubkey| SeedNode {
    node_id: pubkey.clone(),
    addr:    format!("{}:8443", pubkey),
    tier:    1,
    pubkey,
}).collect();
```

Two different hardcoded ports (443 vs 8443). Neither resolves to real IP addresses. The comment says "DHT will have real addrs in Phase 4" — but DHT persistence is still incomplete (see G6 in ALL-KNOWN-GAPS.md).

Static seed relays from `foundation.toml` (`relay_dht.seed_relays`) DO have real addresses — those work. Only the dynamically discovered relays from reputation store get placeholder addresses.

---

## F6: No Pool Delta Server

**Impact:** Relay pool updates (tier changes, new relays, revocations) cannot be distributed as signed deltas. Relays must re-fetch full tracker files.

| Item | Details |
|------|---------|
| Pool authority URL | `https://freeflow.my/pool` — not registered, not proxied |
| Delta endpoints | `/delta/{tier}?since=<seq>` — not coded |
| Pool snapshot | `/pool/latest` — not coded |
| Ed25519 signing infra | Exists (`delegate.signing_key` in `main.rs`) — could sign deltas today |
| `pool_updater.rs` | Relay-side client expects delta endpoints — coded but has nothing to talk to |

This is a subset of G1 in ALL-KNOWN-GAPS.md. The foundation server is where the delta server would live.

---

## F7: No Domain Registration for `freeflow.my`

**Impact:** Pool authority URL, tracker push endpoint, and all HTTPS endpoints are unreachable.

| Item | Status |
|------|--------|
| Domain | Not registered |
| DNS | No A/AAAA records |
| TLS | No certificates |
| nginx proxy | Not configured on DreamHost |
| Pool endpoint | `https://freeflow.my/pool` — dead URL |

The tracker publisher pushes to `POOL_AUTHORITY_URL = "https://freeflow.my/pool/v1/tracker"` (`tracker.rs:20`). This POST goes nowhere.

---

## F8: No Reward Rate Monitoring or Alerting

**Impact:** Foundation operators cannot detect when on-chain rates diverge from targets, or when claims produce anomalous rewards.

| Item | Status |
|------|--------|
| Rate dashboard | None. Foundation has no metrics endpoint |
| Rate alerts | None. No monitoring of `RewardRatesAccount` PDA |
| Claim anomaly detection | None. `pre_flush_validate()` only checks period bounds and byte plausibility, not reward amounts |
| Prometheus metrics | Not wired up. Foundation exposes no `/metrics` endpoint |

The relay runtime has `MetricsSnapshot` with Prometheus counters (`metrics.rs`), but foundation server has no equivalent observability.

---

## F9: Claim Accumulation Threshold Is 300 GB

**Impact:** Relays with small throughput may wait days or weeks for a flush. During this time, their rewards are not on-chain and not dispute-protected.

**Config:** `ClaimPushConfig::threshold_gb = 300` (`config.rs:236`). At DreamHost's current rate of ~19 GB over 16.8 days (~1.1 GB/day), a single relay would take ~273 days to trigger a flush alone.

| Scenario | Time to 300 GB |
|----------|---------------|
| DreamHost alone (~1.1 GB/day) | ~273 days |
| DreamHost + RackNerd combined (~1.2 GB/day) | ~250 days |
| 10 relays at same rate | ~25 days |

The emergency safety (`max_pending_gb = 1000`) is even further away. No periodic time-based flush exists — only byte threshold.

---

## F10: Foundation Key Authority — Key Rotation Never Tested

**Impact:** Tier key rotation is coded but the procedure has never been exercised with real keys. Lost or compromised tier keys break relay registration.

**Code:** `key_authority.rs` — `KeyAuthorityEngine` runs on a schedule (`rotation_day`, `overlap_days` from config). But:
- No HSM for master key storage
- No key rotation procedure documented or tested
- `delegate_cert.json` and `delegate_key.bin` are flat files on disk
- No key revocation mechanism if delegate key is compromised

---

## F11: Validator Quorum Uses File-Based Vote Storage

**Impact:** 3-of-5 quorum votes stored in `votes_epoch_N.json` files. No tamper protection, no replay detection, no cryptographic binding between epoch and votes.

**Code:** `main.rs:882-899` — gossip messages written to `FileState`:
```rust
let mut votes: Vec<ProposalVote> =
    val_state.read_or_default(&key).unwrap_or_default();
if !votes.iter().any(|v| v.node_id == vote.node_id) {
    votes.push(vote);
    let _ = val_state.write(&key, &votes);
}
```

| Issue | Details |
|-------|---------|
| No dedup beyond node_id | Same node can vote twice if node_id changes slightly |
| No signature verification on vote | `sig` field stored but never verified against delegate cert |
| No epoch finalization | Votes accumulate but no code triggers quorum completion → on-chain submission |
| Gossip not encrypted | Peer messages sent in plaintext over UDP |

---

## F12: Challenge Issuer — No Slashing Integration

**Impact:** Challenges are issued and recorded, but failure has no consequences beyond a reputation score change.

**Code:** `challenge.rs` — challenges recorded to reputation file-state. But:
- No automatic slashing on challenge failure
- No link between reputation score and on-chain actions
- Challenge types (DNS 80%, HTTP 15%, Echo 5%) never validated against real relay capabilities
- No challenge difficulty scaling — same challenges for all tiers

---

## Summary by Priority

| Priority | Gaps | Count |
|----------|------|-------|
| **P0** | F1 No rate management, F3 Hardcoded ETAs, F4 Zero lamports tracking | 3 |
| **P1** | F2 Sidecar-only Solana path, F5 Placeholder seed addresses, F6 No delta server, F7 No domain, F9 300 GB threshold too high | 5 |
| **P2** | F8 No monitoring/alerting, F10 Key rotation untested, F11 Validator file-based votes, F12 No slashing from challenges | 4 |

---

## What Works Today

| Component | Status |
|-----------|--------|
| **HTTP API** | ~20 routes on single port (8442). Health, tierkeys, tracker, reputation, claim, claim/status, delegate-cert, invite (6 routes), beta flags (4 routes), blocklists (2 routes), ban management (4 routes), rendezvous (2 routes) |
| **Claim Push** | Accumulates relay batches, validates Ed25519 signatures, filters invalid pre-flush, persists to disk, submits to sidecar |
| **Tracker Publisher** | Builds signed tracker files, pushes to pool authority URL + CDN endpoints, auto-renews daily |
| **Challenge Issuer** | Periodic challenges (30min default), 3 types, reputation scoring |
| **Key Authority** | Tier key generation with rotation schedule |
| **Validator** | Gossip-based quorum voting, epoch snapshots |
| **Invite Engine** | Full beta invite system with generate/consume/revoke/stats |
| **Admin Auth** | Bearer token via `FOUNDATION_ADMIN_TOKEN` env var |
| **Background Services** | All 5 spawn as tokio tasks with graceful shutdown on Ctrl-C |
