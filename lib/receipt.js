// Receipt verification — the same check order the vault runs, in JavaScript.
//
// This is the C6 evidence: an independent implementation verifies our receipts. It runs
// entirely in the process (or the browser); there is no ARPK server involved.

import * as curves from '@noble/curves/secp256k1';
import { digest, hashValueAction } from './eip712.js';

export const CLASS_VALUE = 1;
export const VERDICT_ALLOW = 1;
export const MAX_RECEIPT_TTL_MS = 120_000;
export const SKEW_MS = 30_000;

/** A denial carries the exact ARPK:* code the contract would use. */
export function deny(code, detail) {
  return { ok: false, code, detail };
}

export function allow(detail) {
  return { ok: true, code: null, detail };
}

/**
 * Verify a receipt against a manifest, a set of registered kernel keys and a nonce set.
 *
 * `input`:
 *   domain      {name, version, salt}
 *   action      {chain, venue, to, asset, amount, memoHash}
 *   receipt     {agentId, sessionId, class, actionHash, manifestHash, contextHash,
 *                verdict, nonce, issuedMs, expiryMs}
 *   signature   64 bytes (r ‖ s)
 *   v           0 | 1
 *   nowMs       the clock to check against
 *   kernelKeys  array of 64-byte public keys (or hex strings)
 *   usedNonces  array of hex nonces already consumed
 *   expectedManifestHash  the manifest hash on record (optional)
 */
export function verifyReceipt(input) {
  const { domain, action, receipt, signature, v, nowMs } = input;
  const kernelKeys = (input.kernelKeys || []).map(normaliseKey);
  const usedNonces = new Set((input.usedNonces || []).map(hex));

  // 2. class and verdict
  if (receipt.class !== CLASS_VALUE) {
    return deny('ARPK:receipt.class_mismatch', `class ${receipt.class}`);
  }
  if (receipt.verdict !== VERDICT_ALLOW) {
    return deny('ARPK:receipt.verdict_not_allow', `verdict ${receipt.verdict}`);
  }

  // 3. recover the signer and compare against the registered kernel keys
  let pubkey;
  try {
    const sig = curves.secp256k1.Signature.fromCompact(bytes(signature));
    const point = sig.recoverPublicKey(digest(domain, receipt));
    pubkey = point.toRawBytes(false).slice(1); // 64-byte X‖Y, what ecrecover returns
  } catch (e) {
    return deny('ARPK:receipt.bad_signature', e.message);
  }
  if (!kernelKeys.some((k) => hex(k) === hex(pubkey))) {
    return deny('ARPK:receipt.key_invalid', `recovered ${hex(pubkey).slice(0, 18)}…`);
  }

  // 4. manifest hash matches the record
  if (
    input.expectedManifestHash &&
    hex(receipt.manifestHash) !== hex(input.expectedManifestHash)
  ) {
    return deny('ARPK:manifest.hash_mismatch', hex(receipt.manifestHash));
  }

  // 5. action hash recomputed from the action
  const recomputed = hashValueAction(action);
  if (hex(recomputed) !== hex(receipt.actionHash)) {
    return deny('ARPK:receipt.action_hash_mismatch', hex(recomputed));
  }

  // 6. time window, TTL and nonce
  if (receipt.issuedMs > nowMs + SKEW_MS) {
    return deny('ARPK:receipt.not_yet_valid', `issued ${receipt.issuedMs} > now + skew`);
  }
  if (receipt.expiryMs <= nowMs) {
    return deny('ARPK:receipt.expired', `expiry ${receipt.expiryMs} <= now ${nowMs}`);
  }
  if (receipt.expiryMs - receipt.issuedMs > MAX_RECEIPT_TTL_MS) {
    return deny(
      'ARPK:receipt.ttl_too_long',
      `ttl ${receipt.expiryMs - receipt.issuedMs}ms > ${MAX_RECEIPT_TTL_MS}ms`,
    );
  }
  if (usedNonces.has(hex(receipt.nonce))) {
    return deny('ARPK:receipt.replayed', hex(receipt.nonce));
  }

  return allow(`signer ${hex(pubkey).slice(0, 18)}… matches a registered kernel key`);
}

function normaliseKey(k) {
  if (typeof k === 'string') return bytesFromHex(k);
  return bytes(k);
}

function bytes(v) {
  return v instanceof Uint8Array ? v : new Uint8Array(v);
}

function hex(v) {
  if (typeof v === 'string') return v.replace(/^0x/, '');
  return [...bytes(v)].map((b) => b.toString(16).padStart(2, '0')).join('');
}

function bytesFromHex(s) {
  const clean = s.replace(/^0x/, '');
  const out = new Uint8Array(clean.length / 2);
  for (let i = 0; i < out.length; i += 1) {
    out[i] = parseInt(clean.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}
