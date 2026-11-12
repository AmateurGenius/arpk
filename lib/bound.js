// The bound (claim C0): value out over an interval Δ is at most capacity + refill·Δ.
//
// This is the same arithmetic the kernel and the contract both run — the kernel to decide,
// the contract to enforce. It is exported so a judge can compute it themselves.

/**
 * @param {bigint|number|string} capacity  the bucket capacity K
 * @param {bigint|number|string} refillPerS the refill rate r, per second
 * @param {bigint|number|string} seconds   the interval Δ
 * @returns {bigint} K + r·Δ
 */
export function bound(capacity, refillPerS, seconds) {
  return BigInt(capacity) + BigInt(refillPerS) * BigInt(seconds);
}

/**
 * Whether a sequence of takes stays within the bound.
 *
 * @param {Array<{amount: bigint|number|string, atSeconds: number}>} takes
 * @returns {{holds: boolean, totalOut: bigint, bound: bigint, reason: string|null}}
 */
export function checkSequence(takes, capacity, refillPerS, seconds) {
  const limit = bound(capacity, refillPerS, seconds);
  const totalOut = takes.reduce((acc, t) => acc + BigInt(t.amount), 0n);
  const holds = totalOut <= limit;
  return {
    holds,
    totalOut,
    bound: limit,
    reason: holds ? null : `total out ${totalOut} exceeds the bound ${limit}`,
  };
}
