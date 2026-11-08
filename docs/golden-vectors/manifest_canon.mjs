// Independent manifest-hash reference for ARPK.
//
// Canonicalizes the manifest with plain JS (RFC 8785 subset: keys sorted, no
// whitespace, minimal string escapes, exact integers) and hashes it with
// @noble/hashes keccak_256. Shares no Rust code with the kernel, so agreement is
// real evidence rather than a tautology.
//
// Usage:  npm i @noble/hashes   # from the repo root
//         node docs/golden-vectors/manifest_canon.mjs
//
// Expected output (pinned by kernel/src/manifest.rs):
//   hash: 42823b03c5367ee2e57c3c29bd894de223b21f23cbf72cc1740dd7870d31e620

import { keccak_256 } from '@noble/hashes/sha3';

// Keep this in sync with `sample()` in kernel/src/manifest.rs.
const manifest = {
  agent_id: "aa".repeat(32),
  owner: "owner.test.near",
  expiry_ms: 1762400000000,
  lease_ttl_s: 3600,
  permitted_actions: [{ tool: "transfer", tier: "value" }],
  value: {
    assets: [{
      asset: "near",
      per_call_cap: 1000,
      bucket: { capacity: 1000, refill_per_s: 10 },
      pct_of_balance_cap_bps: 10000,
      approval_threshold: 5000,
      degraded_cap: 0,
    }],
    destinations: ["dest.test.near"],
    venues: [{ id: "venue-a", exposure_cap: 10000 }],
  },
};

function canon(v) {
  if (v === null) return "null";
  if (typeof v === "boolean") return String(v);
  if (typeof v === "number") return Number.isInteger(v) ? String(v) : v.toString();
  if (typeof v === "bigint") return v.toString();
  if (typeof v === "string") return JSON.stringify(v);
  if (Array.isArray(v)) return "[" + v.map(canon).join(",") + "]";
  const keys = Object.keys(v).sort();
  return "{" + keys.map((k) => JSON.stringify(k) + ":" + canon(v[k])).join(",") + "}";
}

const canonical = canon(manifest);
console.log("canonical:", canonical);
const hash = Buffer.from(
  keccak_256(Buffer.concat([Buffer.from("ARPK-MANIFEST-v3"), Buffer.from(canonical)]))
).toString("hex");
console.log("hash:", hash);
