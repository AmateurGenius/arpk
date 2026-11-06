# Non-claims (publish verbatim)

These are the things ARPK does **not** do. They belong in the README and in every
presentation of the project.

- TEE hardware compromise is mitigated by revocation, not prevented.
- The Shade attestation registry is deprecated and flagged by NEAR as having known
  critical vulnerabilities.
- The default kernel key is owner-registered; artifacts say **owner-attested**, not
  hardware-attested.
- A malicious owner's permissive manifest is enforced, not judged.
- Harmful-but-in-scope actions are permitted. ARPK bounds loss; it does not decide wisdom.
- Scanners and classifiers carry no guarantee.
- Taint is a coarse session watermark, not a proof of provenance.
- The model-provider channel is outside the verified path. This build uses a scripted
  adversary and no model; live-LLM mode is unverified.
- The bound assumes block timestamps are monotonic within ε.
- Cross-chain valuation, the Aurora/EVM port, and formal policy analysis are not built.
- Social engineering of humans is out of scope.
- Not formally verified end to end.

## Incident verdicts are counterfactual

The incident table in the README lists historical agent failures and states which ARPK
control would have applied. Those are **counterfactual verdicts**, not eliminations:
"would not have occurred if deployed behind ARPK", "would have been bounded", or
"not addressed". They are reconstructions, not reproductions.
