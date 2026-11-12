// ARPK base policy set — the six policies from build plan §5.6.
//
// Kernel caps are only ever more restrictive than the contract's; the contract's caps
// remain the bound. A policy that errors is skipped by Cedar, so the kernel treats any
// diagnostics error as a deny (ARPK:policy.eval_error, B14).

// permit-transfer-full: full authority permits value transfers that are neither stale
// nor on a paused venue.
permit(principal is Agent, action == Action::"execute_value", resource is Venue)
when { context.authority == "full" && !context.stale && !resource.paused };

// permit-degraded: a degraded session is bounded by the manifest's degraded_cap, which the
// owner chose. The default is zero, so a manifest that does not raise it permits only
// zero-value transfers.
permit(principal is Agent, action == Action::"execute_value", resource is Venue)
when { context.authority == "degraded" && !context.stale && !resource.paused && context.amount <= context.degraded_cap };

// forbid-stale
forbid(principal is Agent, action == Action::"execute_value", resource is Venue)
when { context.stale };

// forbid-venue-paused
forbid(principal is Agent, action == Action::"execute_value", resource is Venue)
when { resource.paused };

// forbid-admin-autonomous
forbid(principal is Agent, action == Action::"execute_value", resource is Venue)
when { principal.tier == "administrative" };

// forbid-askonly
forbid(principal is Agent, action == Action::"execute_value", resource is Venue)
when { context.authority == "askonly" };
