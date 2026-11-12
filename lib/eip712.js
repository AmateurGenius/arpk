// EIP-712 hashing — an independent JavaScript implementation of the format the Rust
// kernel and the NEAR contract both use.
//
// This exists so a judge can verify a receipt in a language other than the one that issued
// it. The two implementations must agree byte for byte; `npm test` checks that against the
// committed golden vectors, and CI does the same.

import { keccak_256 } from '@noble/hashes/sha3';

export const EIP712_DOMAIN_TYPE =
  'EIP712Domain(string name,string version,bytes32 salt)';
export const VALUE_ACTION_TYPE =
  'ValueAction(string chain,string venue,string to,string asset,uint128 amount,bytes32 memoHash)';
export const RECEIPT_TYPE =
  'Receipt(bytes32 agentId,bytes16 sessionId,uint8 class,bytes32 actionHash,bytes32 manifestHash,bytes32 contextHash,uint8 verdict,bytes16 nonce,uint64 issuedMs,uint64 expiryMs)';

const enc = new TextEncoder();

/** keccak256(typeHash ‖ field₀ ‖ field₁ ‖ …) — the EIP-712 hashStruct. */
function hashStruct(ty, fields) {
  const buf = new Uint8Array(32 + fields.length * 32);
  buf.set(keccak_256(enc.encode(ty)), 0);
  fields.forEach((f, i) => buf.set(f, 32 + i * 32));
  return keccak_256(buf);
}

/** A 16-byte value left-aligned in 32 bytes (bytes16 in the type string). */
function pad16(v16) {
  const b = new Uint8Array(32);
  b.set(v16, 0);
  return b;
}

/** A uint8/uint64/uint128 right-aligned in 32 bytes, big-endian. */
function uintTo32(v) {
  let x = BigInt(v);
  const b = new Uint8Array(32);
  for (let i = 31; i >= 0 && x > 0n; i -= 1) {
    b[i] = Number(x & 0xffn);
    x >>= 8n;
  }
  return b;
}

export function domainSeparator(domain) {
  return hashStruct(EIP712_DOMAIN_TYPE, [
    keccak_256(enc.encode(domain.name)),
    keccak_256(enc.encode(domain.version)),
    domain.salt,
  ]);
}

/**
 * The action hash, over the resolved value action.
 * `amount` may be a decimal string or a BigInt; `memoHash` is 32 bytes.
 */
export function hashValueAction(action) {
  return hashStruct(VALUE_ACTION_TYPE, [
    keccak_256(enc.encode(action.chain)),
    keccak_256(enc.encode(action.venue)),
    keccak_256(enc.encode(action.to)),
    keccak_256(enc.encode(action.asset)),
    uintTo32(action.amount),
    action.memoHash,
  ]);
}

/** The receipt hash. Byte fields are Uint8Array; numeric fields are numbers/strings. */
export function hashReceipt(receipt) {
  return hashStruct(RECEIPT_TYPE, [
    receipt.agentId,
    pad16(receipt.sessionId),
    uintTo32(receipt.class),
    receipt.actionHash,
    receipt.manifestHash,
    receipt.contextHash,
    uintTo32(receipt.verdict),
    pad16(receipt.nonce),
    uintTo32(receipt.issuedMs),
    uintTo32(receipt.expiryMs),
  ]);
}

/** keccak256(0x19 ‖ 0x01 ‖ domainSeparator ‖ hashStruct(Receipt)) */
export function digest(domain, receipt) {
  // 2 bytes of marker + a 32-byte domain separator, then the 32-byte receipt hash: 66 total.
  const full = new Uint8Array(66);
  full[0] = 0x19;
  full[1] = 0x01;
  full.set(domainSeparator(domain), 2);
  full.set(hashReceipt(receipt), 34);
  return keccak_256(full);
}

/** The salt: keccak256(chain_id ‖ contract_id), the same binding the kernel uses. */
export function saltFor(chainId, contractId) {
  return keccak_256(new Uint8Array([...enc.encode(chainId), ...enc.encode(contractId)]));
}
