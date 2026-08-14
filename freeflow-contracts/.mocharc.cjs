module.exports = {
  require: ['ts-node/register'],
  extension: ['ts'],
  // The Anchor suite, which `anchor test` runs against solana-test-validator.
  //
  // NOTE: mocha MERGES this with any spec passed on the command line rather than
  // letting the CLI override it — so anything listed here runs on every
  // invocation. tests/freeflow.ts is deliberately absent: it is the native-Borsh
  // suite, it needs TS_NODE_TRANSPILE_ONLY=true plus program IDs that
  // `anchor test` does not deploy, and listing it here dragged 33 unrelated
  // failures into every Anchor run. Run it explicitly per its own header.
  spec: 'tests/user-escrow.ts',
  timeout: 60000,
};
