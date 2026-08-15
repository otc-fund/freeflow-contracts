<#
.SYNOPSIS
    Monitor repFlow and $FLOW token minting/rewards on DreamHost and RackNerd relays.
.DESCRIPTION
    Polls both relay /status endpoints and Solana devnet RPC for token mint data.
    Appends one JSONL record per poll to relay-monitor.jsonl.
.USAGE
    .\monitor-relay-tokens.ps1              # Single poll
    .\monitor-relay-tokens.ps1 -Interval 300 # Poll every 5 minutes (Ctrl+C to stop)
#>

param(
    [int]$Interval = 0  # 0 = single poll, >0 = poll every N seconds
)

$OutputFile = "$PSScriptRoot\relay-monitor.jsonl"

# ─── Relay endpoints ────────────────────────────────────────────────────────
$Relays = @{
    DreamHost = @{
        StatusUrl   = "https://freeflow.my/status"
        SidecarUrl  = "https://freeflow.my/sidecar"
        Pubkey      = "f90aaacc0f9cbe22ed460648c3671d7ad1a9f7b150f8a4217f216809590d382c"
        SolanaWallet = "AyKhSpMgE4XWJncJawR79pbH2DtedKx95ViTrkLCvD8X"
        Name        = "freeflow-relay-dreamhost"
    }
    RackNerd = @{
        StatusUrl   = "http://192.3.41.221:8080/status"
        SidecarUrl  = $null  # not publicly proxied
        Pubkey      = "4e026f82bda3194a4f4967a269091c05e58bf8ea3e4b92e44521740b62a85560"
        SolanaWallet = $null  # unknown
        Name        = "freeflow-relay-racknerd"
    }
}

# ─── Solana devnet RPC ──────────────────────────────────────────────────────
$SolanaRpc = "https://api.devnet.solana.com"
$RepFlowMint  = "BFaMqKEjS57NZdP6naPoEHavzUQc1KHL27WqY5CZMkmN"
$FlowMint     = "7w6YxBZmXMZfuS4PJCwDmY5hX98RrpnR7xNEV9Ugwzxc"
$RewardsPrg   = "2yeVew5qq5jf5zuoqiE2svVLRE9HTN6J2GfB9LopdM1C"
$StakingPrg   = "7N1JRX3LY3goVAZCyaJyH7kpZ3kboZvh3jteDmCq6Dz4"
$GovernancePkg = "8SL4dhnXU9tjvsbwfkVzQbfV99wGnVZBECoiuwrdbaJk"

function Invoke-SafeJson {
    param([string]$Url)
    try {
        $r = Invoke-RestMethod -Uri $Url -TimeoutSec 10 -ErrorAction Stop
        return $r
    } catch {
        return $null
    }
}

function Invoke-SolanaRpc {
    param([string]$Method, [array]$Params)
    $body = @{ jsonrpc = "2.0"; id = 1; method = $Method; params = $Params } | ConvertTo-Json -Depth 5
    try {
        $r = Invoke-RestMethod -Uri $SolanaRpc -Method Post -ContentType "application/json" -Body $body -TimeoutSec 15 -ErrorAction Stop
        return $r.result.value
    } catch {
        return $null
    }
}

function Get-RelayData {
    param([string]$Name, [hashtable]$Config)

    $status  = Invoke-SafeJson $Config.StatusUrl
    $sidecar = if ($Config.SidecarUrl) { Invoke-SafeJson $Config.SidecarUrl } else { $null }

    # sidecar data may be embedded in status or separate
    $sc = if ($sidecar) { $sidecar } elseif ($status -and $status.sidecar) { $status.sidecar } else { $null }

    if (-not $status) {
        return @{
            relay      = $Name
            reachable  = $false
            error      = "Status endpoint unreachable"
        }
    }

    return @{
        relay                = $Name
        solana_wallet        = $Config.SolanaWallet
        pubkey               = $status.relay.pubkey
        tier                 = $status.relay.tier
        uptime_days          = [math]::Round($status.uptime_secs / 86400, 1)
        active_connections   = $status.active_connections
        total_connections    = $status.total_connections
        bytes_routed_gb      = [math]::Round($status.bytes_routed_gb, 3)
        bytes_seeded_gb      = [math]::Round($status.bytes_seeded_gb, 3)
        throughput_mbps      = [math]::Round($status.throughput_mbps, 4)
        dht_items            = $status.dht_items
        dht_registrations    = $status.dht_registrations
        heartbeats_sent      = $status.heartbeats_sent
        total_hops           = $status.total_hops
        hop_success_rate_pct = $status.hop_success_rate_pct

        # Sidecar / rewards
        staked_lamports      = $sc.staked_lamports
        stake_tier           = $sc.stake_tier
        stake_locked         = $sc.stake_locked
        pending_lamports     = $sc.pending_lamports
        pending_flow         = [math]::Round(($sc.pending_lamports / 1e9), 6)
        repflow_balance      = $sc.repflow_balance
        repflow_tier         = $sc.repflow_tier
        sidecar_reachable    = $sc.sidecar_reachable
        claim_account_exists = $sc.claim_account_exists
        total_claimed_flow   = [math]::Round(($sc.total_claimed_lamports / 1e9), 6)
        claim_count          = $sc.claim_count
        last_claim_utc       = if ($sc.last_claim_ts) { (Get-Date -UnixTimeSeconds $sc.last_claim_ts).ToString("o") } else { $null }
        cooldown_remaining_hrs = [math]::Round(($sc.cooldown_remaining_secs / 3600), 1)
        can_claim_now        = $sc.can_claim_now
        repflow_tier_progress_pct = $sc.repflow_tier_progress_pct
        repflow_to_next_tier = $sc.repflow_to_next_tier
        repflow_next_tier    = $sc.repflow_next_tier

        # Reward rates
        routing_per_mb       = $sc.reward_rates.routing_per_mb
        seeding_per_mb       = $sc.reward_rates.seeding_per_mb
        uptime_per_hour      = $sc.reward_rates.uptime_per_hour
        flow_price_cents     = $sc.reward_rates.flow_price_cents
    }
}

function Get-TokenSupply {
    param([string]$Mint)
    $info = Invoke-SolanaRpc "getAccountInfo" @(
        $Mint, @{ encoding = "jsonParsed" }
    )
    if ($info -and $info.data.parsed.info) {
        $raw = [decimal]$info.data.parsed.info.supply
        $dec = [int]$info.data.parsed.info.decimals
        $human = $raw / [math]::Pow(10, $dec)
        return @{
            mint       = $Mint
            raw_supply = $raw
            human_supply = [math]::Round($human, 4)
            decimals   = $dec
            mint_auth  = $info.data.parsed.info.mintAuthority
            is_init    = $info.data.parsed.info.isInitialized
        }
    }
    return @{ mint = $Mint; error = "RPC failed" }
}

function Get-RecentClaims {
    param([int]$Limit = 5)
    $info = Invoke-SolanaRpc "getSignaturesForAddress" @(
        $RewardsPrg, @{ limit = $Limit }
    )
    if ($info) {
        return $info | ForEach-Object {
            @{
                slot       = $_.slot
                signature  = $_.signature
                block_time = if ($_.blockTime) { (Get-Date -UnixTimeSeconds $_.blockTime).ToString("o") } else { $null }
                err        = if ($_.err) { "failed" } else { "success" }
            }
        }
    }
    return @()
}

# ─── Main ───────────────────────────────────────────────────────────────────

$poll = 0
do {
    $poll++
    $ts = (Get-Date).ToUniversalTime().ToString("o")
    Write-Host "`n=== Poll #$poll @ $ts ===" -ForegroundColor Cyan

    $record = @{
        ts            = $ts
        poll_number   = $poll
        governance    = $GovernancePkg
        relays        = @()
        token_mints   = @{}
        recent_claims = @()
    }

    # Relay data
    foreach ($name in @("DreamHost", "RackNerd")) {
        Write-Host "  Polling $name..." -NoNewline
        $data = Get-RelayData -Name $name -Config $Relays[$name]
        $record.relays += $data
        if ($data.reachable -eq $false) {
            Write-Host " UNREACHABLE" -ForegroundColor Red
        } else {
            Write-Host " OK (routed $($data.bytes_routed_gb) GB, claimed $($data.total_claimed_flow) FLOW, repFlow $($data.repflow_balance))" -ForegroundColor Green
        }
    }

    # Token mints
    Write-Host "  Querying repFlow mint..." -NoNewline
    $repFlowData = Get-TokenSupply -Mint $RepFlowMint
    $record.token_mints.repflow = $repFlowData
    Write-Host "supply: $($repFlowData.human_supply)" -ForegroundColor Green

    Write-Host "  Querying $FLOW mint..." -NoNewline
    $flowData = Get-TokenSupply -Mint $FlowMint
    $record.token_mints.flow = $flowData
    Write-Host "supply: $($flowData.human_supply)" -ForegroundColor Green

    # Recent claims
    Write-Host "  Recent reward claims..." -NoNewline
    $claims = Get-RecentClaims -Limit 5
    $record.recent_claims = $claims
    Write-Host "$($claims.Count) found" -ForegroundColor Green

    # Write JSONL
    $json = $record | ConvertTo-Json -Depth 5 -Compress
    Add-Content -Path $OutputFile -Value $json
    Write-Host "  Written to $OutputFile" -ForegroundColor Yellow

    if ($Interval -gt 0) {
        Write-Host "  Sleeping ${Interval}s..." -ForegroundColor DarkGray
        Start-Sleep -Seconds $Interval
    }
} while ($Interval -gt 0)
