# Standalone operator workflow

1. Run `./human/cptc-tools preflight` and review availability separately from
   admission. A present executable is not an authorization to use it.
2. Create an owner-only workspace with `init`, an operator policy, and an
   approved age recipient. Keep engagement storage outside Git.
3. Review `modules` and the policy's exact target/module assignments.
4. Use `run` only for an explicitly selected admitted profile. Use `import`
   for offline files from a local operator-controlled collector or review.
5. Inspect `coverage`, run `audit-verify`, and use `report` only after the
   audit is verified and ready. Use `stop` to latch the engagement closed.

The terminal does not turn scanner availability into an admission. Manual-only
modules, unsupported containment, missing isolation, scope/exclusion failures,
rate limits, and uncertain outcomes remain blocked and visible.
