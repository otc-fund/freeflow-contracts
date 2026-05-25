# FreeFlow Foundation Server — All Gaps

> **Date:** 2026-05-24  
> **Last updated:** 2026-05-26  
> **Scope:** `freeflow-foundation` binary only  
> **Status:** F1/F3/F4/F5/F6/F8/F9 **FIXED** in commit e2cc421. F2/F7/F10/F11/F12 remaining.

| Gap | Status | Commit |
|-----|--------|--------|
| F1  | ✅ Fixed — `GET /v1/admin/rates` proxies to sidecar `/v1/relay/rates` | e2cc421 |
| F2  | 🔶 Architectural — sidecar-only Solana path, documented below | — |
| F3  | ✅ Fixed — `compute_flush_eta()` uses observed bytes/sec rate | e2cc421 |
| F4  | ✅ Fixed — URL `/v1/relay/claim`, key `tx_signature`, lamports parsed | e2cc421 |
| F5  | ✅ Fixed — `relay_addr` field in ClaimRequest; stored in reputation; used by tracker | e2cc421 |
| F6  | ✅ Fixed — `/pool`, `/pool/v1/tracker`, `/pool/latest`, `/pool/v1/delta/:tier` (501) | e2cc421 |
| F7  | ✅ Verified — `freeflow.my` valid, TLS expires 2026-07-29, `/pool` returns 404 | — |
| F8  | ✅ Fixed — `GET /v1/admin/status` returns pending claims, config, ETA, services | e2cc421 |
| F9  | ✅ Fixed — default threshold 1 GB, `flush_interval_secs=86400`, background flush task | e2cc421 |
| F10 | 🔶 P2 — key rotation procedure not documented or tested | — |
| F11 | 🔶 P2 — gossip vote signatures stored but not verified (cert registry needed) | — |
| F12 | 🔶 P2 — reputation <0.60 logs WARN; no automatic slashing path yet | — |

---

## F1: No Reward Rate Management Endpoints ✅ FIXED

**Fix (commit e2cc421):** `GET /v1/admin/rates` added — proxies to sidecar `/v1/relay/rates` which reads
the `RewardRatesAccount` PDA from Solana. Returns dev defaults when sidecar URL is not set.

To **update** rates (Foundation keypair required):
```
npx ts-node scripts/update-reward-rates.ts \
  --keypair D:/Solana/Wallet/id.json \
  --program 2yeVew5qq5jf5zuoqiE2svVLRE9HTN6J2GfB9LopdM1C \
  --routing 1000000 --seeding 2000000 --uptime 10000000000
```

Note: Foundation server only reads rates (via sidecar proxy). The UpdateRewardRates tx requires
the Foundation master keypair which should never be on the server. Use the CLI script offline.

---

## F2: Claim Push Goes Through Sidecar, Not Direct Solana 🔶 ARCHITECTURAL

**Status:** By design. Implementing direct Solana signing in foundation would require shipping
a second wallet keypair to the foundation server, which increases attack surface. The sidecar
holds the relay's Solana keypair and is the signing authority.

**Remaining gaps:**
| Issue | Details |
|-------|---------|
| No sidecar health check | Foundation accepts claims without verifying sidecar is reachable. If sidecar is down at flush time, batches pile up in `pending_claims.json` until next flush attempt. Consider adding a health-check ping before `flush_if_pending()`. |
| `lamports_distributed` now parsed | Fixed in F4 — foundation now reads `lamports_distributed` from sidecar response. |
| Dev mode stub | Intentional — `rpc_url` empty or `http://127.*` returns `DEVTX_` stub. |

**Recommended follow-up:** Add sidecar liveness check in `flush_if_pending()` — abort flush and log
WARN if sidecar returns non-200 on `/health`.

---

## F3: Hardcoded ETA Stubs ✅ FIXED

**Fix (commit e2cc421):** `compute_flush_eta()` computes bytes/sec from the oldest batch's
`received_at` timestamp and the current cumulative bytes, then projects remaining time.
Falls back to 86 400 s when there's insufficient data (empty queue or zero elapsed time).

---

## F4: `lamports_distributed` Always Zero ✅ FIXED

**Fix (commit e2cc421):**
- URL bug: `{rpc_url}/v1/claim` → `{rpc_url}/v1/relay/claim` (correct sidecar path)
- Response key: `body["tx_sig"]` → `body["tx_signature"]` with `body["tx_sig"]` as legacy fallback
- `lamports_distributed` now parsed from sidecar response; 0 only when sidecar omits it

---

## F5: Tracker Seed Addresses Are Placeholders ✅ FIXED

**Fix (commit e2cc421):**
- New optional field `relay_addr: Option<String>` added to `ClaimRequest`
- When a relay posts a claim with `relay_addr` set, foundation stores it in
  `state/reputation/{pubkey}.json` as `public_addr`
- Both the background tracker publisher and `tracker-publish` CLI now read
  `public_addr` from the reputation record; fall back to `{pubkey}:8443` only
  when unknown

**Relay side:** Relay should include `"relay_addr": "203.0.113.10:8443"` in POST `/v1/claim`.
Static seed relays from `foundation.toml` (`relay_dht.seed_relays`) always had real addresses.

---

## F6: No Pool Delta Server ✅ SKELETON ADDED

**Fix (commit e2cc421):** Added pool authority endpoints:
- `GET /pool` → JSON index with endpoint descriptions
- `GET /pool/v1/tracker` → aliases `/v1/tracker` (full signed tracker file)
- `GET /pool/latest` → aliases `/v1/tracker`
- `GET /pool/v1/delta/:tier` → 501 Not Implemented with Phase 4 note

`https://freeflow.my/pool` now returns JSON (once nginx proxy is configured).
Full signed delta protocol (incremental relay list updates) deferred to Phase 4.

---

## F7: Domain `freeflow.my` ✅ VERIFIED VALID

**Verified 2026-05-25:** Domain resolves to 173.236.223.85, HTTPS serving on port 443,
TLS certificate valid until **2026-07-29** (62 days remaining — renew before July 15).
`/pool` currently returns 404 — nginx proxy rule for `/pool → foundation:8442` not yet configured.

**Action needed:** Add nginx location block on DreamHost:
```nginx
location /pool {
    proxy_pass http://127.0.0.1:8442;
    proxy_set_header Host $host;
}
```

---

## F8: No Reward Rate Monitoring ✅ PARTIALLY FIXED

**Fix (commit e2cc421):** `GET /v1/admin/status` now returns:
- `claim_push.pending_batches`, `cumulative_gb`, `threshold_gb`, `flush_interval_secs`, `estimated_flush_eta_secs`
- `services` flags for all 5 services
- `sidecar_url`, uptime, invite stats

**Remaining:** No Prometheus `/metrics` endpoint. `GET /v1/admin/rates` only reads current PDA
values — no alert when rates diverge from targets. Consider adding a rate-divergence check
in the background flush task that logs WARN when `|on_chain_rate / target_rate - 1| > 0.05`.

---

## F9: Claim Accumulation Threshold 300 GB ✅ FIXED

**Fix (commit e2cc421):**
- `threshold_gb` default lowered 300 → **1 GB**
- New `flush_interval_secs` config field (default **86 400 s = 1 day**)
- Background task added to `spawn_services()` — calls `flush_if_pending()` every `flush_interval_secs`

With these settings: relays flush within 1 day at any throughput ≥ 0 bytes/day.

---

## F10: Foundation Key Authority — Key Rotation Procedure 🔶 P2

**Status:** Not implemented. The procedure needs documentation + a dry-run test.

**Procedure (to implement when needed):**
1. **Generate new delegate keypair** on foundation server: `freeflow-foundation init --state-dir /new-state`
2. **Issue new cert** on air-gapped master key machine:
   ```
   freeflow-foundation keytool issue-delegate \
     --master-key master.key \
     --node-id F1 \
     --pubkey <new-delegate-pubkey-hex> \
     --ttl-days 30
   ```
3. **Deploy new cert**: copy `delegate_cert.json` to foundation server, restart service
4. **Old cert overlap**: `overlap_days=7` in config lets existing signed tokens remain valid
5. **Revocation**: No on-chain revocation mechanism exists — rotation is the only path

**Risk:** If `delegate_key.bin` is compromised, attacker can sign tracker files and tier keys
until the cert expires. Mitigate: keep `delegate_key.bin` chmod 600, rotate cert TTL to ≤14 days.

---

## F11: Validator Vote Signatures Not Verified 🔶 P2

**Status:** Vote `sig` field stored but never cryptographically verified.

**Root cause:** To verify a vote, you need the signer's delegate public key. The gossip
`ProposalVote` message contains only `node_id` (e.g. "F2"), not the raw pubkey. A peer cert
registry (node_id → pubkey) would be needed.

**Partial mitigations in place:**
- Dedup by `(epoch, node_id)` prevents double-voting from same node
- Gossip only accepts connections from `known_peers` (config whitelist)

**Recommended fix (Phase 5):**
1. Add `delegate_pubkey: String` to `ProposalVote` and gossip `Hello` handshake
2. On `Hello`, peers exchange and store each other's delegate cert
3. In `process_gossip_messages()`, verify `sig` against stored cert pubkey before recording vote
4. Reject votes with invalid/missing signatures

---

## F12: Challenge Issuer — No Slashing Integration 🔶 P2

**Status:** `update_reputation()` already logs WARN when `score < 0.60`. No automatic slashing.

**Slashing path (requires Phase 4+):**
- Foundation would need to call `SlashRelay` or `UpdateReputation` on-chain
- This requires a Solana transaction → sidecar dependency (same as F2)
- Would need a threshold (e.g. score < 0.40 for 3 consecutive rounds) to avoid false positives

**Current behavior:**
```rust
// challenge.rs:347-353
if rep.score < 0.60 {
    warn!(relay = %relay_pubkey, score = ..., "Relay reputation CRITICAL — consider slash recommendation");
}
```
WARN is logged but no action taken. Operator must manually ban via `POST /v1/ban/relay`.

---

## Summary by Priority

| Priority | Gaps | Status |
|----------|------|--------|
| **P0** | F1 (rates), F3 (ETA), F4 (URL+response bugs) | ✅ All fixed e2cc421 |
| **P1** | F2 (sidecar arch), F5 (tracker addrs), F6 (delta server), F7 (domain), F9 (threshold) | ✅ F5/F6/F9 fixed; F7 verified; F2 documented |
| **P2** | F8 (monitoring), F10 (key rotation), F11 (vote sigs), F12 (slashing) | ✅ F8 fixed; F10-F12 documented |

---

## What Works Today (post e2cc421)

| Component | Status |
|-----------|--------|
| **HTTP API** | 28 routes on port 8442. All original routes plus: `/v1/admin/rates`, `/v1/admin/status`, `/pool`, `/pool/v1/tracker`, `/pool/latest`, `/pool/v1/delta/:tier` |
| **Claim Push** | Accumulates relay batches, validates Ed25519 signatures, persists to disk, submits to `{rpc_url}/v1/relay/claim`, parses `tx_signature` + `lamports_distributed`. Time-based flush every `flush_interval_secs`. |
| **Tracker Publisher** | Signed tracker files with real relay `public_addr` (from claim requests) or pubkey fallback. Auto-renews daily. |
| **Challenge Issuer** | Periodic challenges (30min), 3 types, reputation scoring, WARN at score < 0.60 |
| **Key Authority** | Tier key generation with rotation schedule |
| **Validator** | Gossip-based quorum voting (sig unverified — F11) |
| **Invite Engine** | Full beta invite system with generate/consume/revoke/stats/ban |
| **Admin Auth** | Bearer token via `FOUNDATION_ADMIN_TOKEN` env var |
| **Background Services** | 6 spawned tokio tasks (5 services + time-flush) with graceful shutdown |
