#!/usr/bin/env node
// ARPK relayer — submits a kernel-signed receipt to the vault.
//
// The relayer authenticates with a FUNCTION-CALL key restricted to `execute_value` on
// the vault, never a full-access key. That restriction is the security property: a
// leaked relayer key can only submit receipts the kernel already signed, and it cannot
// reach owner methods — those require 1 yocto, which a function-call key cannot attach.
//
// Usage:
//   arpkd sign ... > receipt.json
//   node tools/relayer/relayer.mjs --vault vault.test.near \
//        --account relayer.test.near --key .local/relayer-key.json \
//        --receipt receipt.json [--rpc https://rpc.testnet.near.org] \
//        [--network testnet] [--dry-run]
//
// `--dry-run` validates the receipt shape and prints the transaction it would send,
// without touching the chain. Requires `npm i near-api-js` only for a live submit.

import { readFileSync } from 'node:fs';

function arg(name) {
  const i = process.argv.indexOf(name);
  return i >= 0 ? process.argv[i + 1] : undefined;
}

const vault = arg('--vault');
const account = arg('--account');
const keyFile = arg('--key');
const receiptFile = arg('--receipt');
const rpc = arg('--rpc') ?? 'https://rpc.testnet.near.org';
const network = arg('--network') ?? 'testnet';
const dryRun = process.argv.includes('--dry-run');

for (const [name, value] of [
  ['--vault', vault],
  ['--account', account],
  ['--key', keyFile],
  ['--receipt', receiptFile],
]) {
  if (!value) {
    console.error(`relayer: missing ${name}`);
    process.exit(2);
  }
}

let args;
try {
  args = JSON.parse(readFileSync(receiptFile, 'utf8'));
} catch (e) {
  console.error(`relayer: cannot read receipt ${receiptFile}: ${e.message}`);
  process.exit(2);
}

// Shape check: exactly the execute_value argument list, with byte fields as arrays.
const required = ['agent_id', 'action', 'receipt', 'signature', 'v'];
for (const k of required) {
  if (!(k in args)) {
    console.error(`relayer: receipt is missing '${k}'`);
    process.exit(2);
  }
}
for (const k of ['agent_id', 'session_id', 'action_hash', 'manifest_hash', 'context_hash', 'nonce']) {
  if (!Array.isArray(args.receipt[k])) {
    console.error(`relayer: receipt.${k} must be a byte array`);
    process.exit(2);
  }
}
if (!Array.isArray(args.signature) || args.signature.length !== 64) {
  console.error('relayer: signature must be a 64-byte array');
  process.exit(2);
}

if (dryRun) {
  console.log(
    JSON.stringify(
      { contract: vault, method: 'execute_value', account, network, rpc, args },
      null,
      2,
    ),
  );
  process.exit(0);
}

const keyJson = JSON.parse(readFileSync(keyFile, 'utf8'));
const { connect, keyStores, KeyPair } = await import('near-api-js');
const privateKey = keyJson.private_key ?? keyJson.secret_key;
if (!privateKey) {
  console.error("relayer: key file has no 'private_key'");
  process.exit(2);
}
const keyStore = new keyStores.InMemoryKeyStore();
await keyStore.setKey(network, account, KeyPair.fromString(privateKey));

const near = await connect({ networkId: network, nodeUrl: rpc, keyStore });
const relayer = await near.account(account);
const outcome = await relayer.functionCall({
  contractId: vault,
  methodName: 'execute_value',
  args,
  gas: 300000000000000n, // 300 Tgas
});
console.log(JSON.stringify(outcome, null, 2));
