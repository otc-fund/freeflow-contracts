module.exports = {
  require: ['ts-node/register'],
  extension: ['ts'],
  // No `spec` here on purpose: mocha MERGES an rc-file `spec` with any path
  // passed on the command line rather than letting the CLI override it, so a
  // fixed spec here would run on every invocation regardless of what's asked
  // for. Concretely, `npx mocha tests/freeflow.ts` would also load
  // tests/user-escrow.ts, which throws "ANCHOR_PROVIDER_URL is not defined"
  // outside `anchor test` and aborts the whole run before either suite's tests
  // execute. Each entry point names its own file explicitly instead: `anchor
  // test` via Anchor.toml's [scripts] test command for tests/user-escrow.ts,
  // and tests/freeflow.ts run directly per its own header.
  timeout: 60000,
};
