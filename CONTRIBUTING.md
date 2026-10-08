# Contributing

Thank you for your interest in the Verdifax verifier. Because this
tool adjudicates evidence, correctness and reviewability outrank
features; small, well-tested changes are the norm here.

## Reporting bugs

Open a GitHub issue with the verifier version (`verdifax-verify
--version`), the command you ran, what you expected, and what
happened. If the report involves a bundle that verifies when it
should not, or fails when it should verify, please follow
[SECURITY.md](./SECURITY.md) instead of opening a public issue.

## Proposing changes

1. Open an issue describing the change before writing significant
   code, so the approach can be agreed first.
2. Fork, branch, and keep the change focused: one concern per pull
   request.
3. Every change to hashing, canonicalization, or verification logic
   must come with tests, including a known-answer test where
   applicable. Run the full suite locally before pushing:

   ```bash
   go vet ./...
   go build ./...
   go test ./...
   ```

4. CI (vet, build, test) must pass on the pull request.

## Ground rules

- Backwards compatibility of verification verdicts is sacrosanct: a
  bundle that verified under an earlier release must not silently
  change verdict. Verdict-affecting changes require an explicit
  version bump and release-note disclosure.
- No new dependencies without discussion in the issue first. The
  verifier deliberately stays close to the Go standard library so
  auditors can read everything it does.
- Code is licensed under the repository's Clear BSD license; by
  submitting a contribution you agree it is provided under the same
  license.

## Questions

Open an issue, or email robert@verdifax.com.
