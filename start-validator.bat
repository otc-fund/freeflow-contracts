@echo off
REM ============================================================
REM  FreeFlow local test validator launcher (Windows)
REM
REM  Fixes applied:
REM   1. SOLANA_METRICS_CONFIG → fail-fast (prevents 2.5min hang)
REM   2. tar.exe in validator bin dir → Python-based bzip2 shim
REM      (bsdtar 3.5.2 on Windows can't pipe to external bzip2)
REM   3. --bind-address 127.0.0.1 → faucet_addr uses loopback
REM      (Windows rejects connections to 0.0.0.0)
REM
REM  To rebuild .so files:
REM    cargo build-sbf --manifest-path programs/registry/Cargo.toml
REM    cargo build-sbf --manifest-path programs/staking/Cargo.toml
REM    cargo build-sbf --manifest-path programs/rewards/Cargo.toml
REM
REM  After validator starts, deploy programs:
REM    solana program deploy target/deploy/registry.so --program-id target/deploy/registry-keypair.json
REM    solana program deploy target/deploy/staking.so  --program-id target/deploy/staking-keypair.json
REM    solana program deploy target/deploy/rewards.so  --program-id target/deploy/rewards-keypair.json
REM
REM  Run tests:
REM    set ANCHOR_WALLET=%USERPROFILE%\.config\solana\id.json
REM    npx mocha
REM ============================================================

set SOLANA_METRICS_CONFIG=host=http://127.0.0.1:1,db=solana,u=admin,p=password

"%USERPROFILE%\.local\share\solana\install\active_release\bin\solana-test-validator.exe" ^
  --ledger test-ledger ^
  --reset ^
  --faucet-port 9920 ^
  --bind-address 127.0.0.1 ^
  --rpc-port 8899
