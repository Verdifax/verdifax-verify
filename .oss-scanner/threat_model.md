# Threat model: verdifax-verify

## What this program is

`verdifax-verify` is a standalone, offline verifier for Verdifax
audit bundles: sealed, tamper-evident records of AI decisions. It
reads a bundle (JSON, via file path, stdin, or an HTTPS URL),
recomputes every canonical hash from the bundle's own content,
re-verifies embedded signatures, certificate chains, AMD SEV-SNP
attestation reports, and Sigstore Rekor inclusion proofs, and
renders a verdict through its exit code: 0 verified, 1 verification
failed, 2 unparseable input.

The verdict is the product. Auditors, regulators, and counterparties
run this binary over records produced by a party they deliberately
do not trust, and act on the exit code. The binary is the trust
anchor for the whole system.

## Where untrusted input enters

Everything the program reads is attacker-controlled by assumption:

- The bundle JSON itself (file, stdin, or fetched over HTTPS), in
  its entirety: hashes, field values, embedded X.509 certificate
  chains, SEV-SNP report bytes, Merkle inclusion proofs, checkpoint
  signatures, and all metadata.
- Command-line flags are operator-supplied and trusted.

Key code: `main.go` (parsing, orchestration, verdict, report
output), `internal/artifacts` (canonical hash recomputation),
`internal/rekorverify` (Merkle proofs, checkpoint signatures),
`internal/sevsnp` (AMD report parsing and certificate chain
verification against the pinned ARK root).

## Severity guidance

- **Critical: any input that makes a record verify when it should
  not.** A crafted bundle that yields exit code 0, or a VERIFIED
  verdict in text or `--json` output, despite content that was
  mutated, forged, or signed by the wrong identity. This includes
  hash-confusion or canonicalization ambiguity (two different
  contents reaching the same recomputed hash path), acceptance of
  an invalid SEV-SNP certificate chain or report signature,
  acceptance of an invalid Merkle inclusion proof or checkpoint
  signature, and any parser differential that lets verified and
  displayed content diverge.
- **High: verdict integrity failures short of forgery.** `--strict`
  failing to reject a scaffold-flagged bundle, exit code 0 with a
  failure printed in the report, or `--json` output disagreeing
  with the exit code.
- **Medium: resource exhaustion** (memory or CPU) from small
  malformed bundles, since verifiers run in batch pipelines.
- **Low: crashes and panics on malformed input** that produce a
  nonzero exit code. A crash fails closed (exit 2), so it is a
  robustness bug, not a verdict bug.

## Out of scope

- Collision attacks against SHA-256 itself.
- The Verdifax orchestrator, API service, and SDKs (separate
  codebases; this repository is only the verifier).
- Scenarios requiring a tampered verifier binary; binary integrity
  is handled by Cosign signatures and SLSA provenance on releases.
- The TLS stack used for `https://` bundle fetching (Go standard
  library); a reviewer who cannot fetch simply passes a local file.

## How to exercise it

Build output is at `/usr/local/bin/verdifax-verify`. The test suite
(`go test ./...`) includes known-answer hash tests and a production
golden bundle at `internal/artifacts/testdata/`, which is the
easiest seed corpus for mutation: flip any byte of a golden bundle
and the verdict must be nonzero. Reports are most useful as a
reproducer bundle plus expected-versus-actual exit code; patches
are welcome in the style of CONTRIBUTING.md (tests required for
verification-logic changes).
