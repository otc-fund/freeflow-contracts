module.exports = {
  require: ['ts-node/register'],
  extension: ['ts'],
  // Only run native-Borsh test suite (user-escrow.ts requires Anchor)
  spec: 'tests/freeflow.ts',
  timeout: 60000,
};
