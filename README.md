# verdifax-verify

[![OpenSSF Best Practices](https://www.bestpractices.dev/projects/15320/badge)](https://www.bestpractices.dev/projects/15320)

`verdifax-verify` is the standalone, independent verifier for Verdifax
audit bundles. It reads a bundle JSON file (or stdin), recomputes every
section hash, the bundle hash, the pre-anchor table digest and the
anchored ledger leaf from the bundle's own content, and compares each
against the recorded value to detect tampering. It also confirms that
every section is bound to the same manifest hash. The manifest hash
itself is not recomputed here: its preimage includes fields held only
in the orchestrator's stored manifest, which the orchestrator re-derives
server-side for authenticated callers at `GET /runs/{id}/verify`.

It is the offline-verification path for Verdifax bundles: given just a
bundle file, this binary decides whether the evidence is internally
consistent. Verification itself makes no network calls, needs no
Verdifax credentials, and places no trust in the Verdifax API server:
the Sigstore Rekor inclusion proof is checked offline against a Rekor
public key embedded in the binary. The one network operation is
optional input retrieval: passing an `http://` or `https://` URL instead
of a file path makes the binary fetch the bundle with a single GET
request (30 second timeout, 32 MiB cap) before verifying it exactly as
it would a local file. Pass a file path or stdin to keep the whole run
offline.

## License

The Clear BSD License (SPDX `BSD-3-Clause-Clear`), see
[`LICENSE`](./LICENSE), from v0.5.0. Releases through v0.4.0 were
published under MIT and remain available under it. The Clear BSD
License is as permissive as MIT for using, copying and modifying the
code, and states explicitly that it grants no patent rights. The
verifier is intentionally open-source so auditors can read the code
that adjudicates evidence.
The verifier produces no attestations of its own; it only checks that
a received bundle is internally consistent.

## Install

### From source

```bash
go install github.com/Verdifax/verdifax-verify@latest
```

Requires Go 1.27 or later. The binary lands at `$(go env GOPATH)/bin/verdifax-verify`.

### Pre-built binaries

Pre-built binaries for Linux / macOS / Windows are attached to each
[GitHub release](https://github.com/Verdifax/verdifax-verify/releases).

## Usage

```bash
verdifax-verify bundle.json           # verify a file, print human report
cat bundle.json | verdifax-verify     # verify from stdin
verdifax-verify --json bundle.json    # machine-readable JSON output
verdifax-verify --strict bundle.json  # also fail on any scaffold-flagged value
verdifax-verify --version
```

### Exit codes

| Code | Meaning |
|---|---|
| 0 | All hashes verified, no failures. |
| 1 | One or more verification checks failed (or `--strict` + scaffold). |
| 2 | Could not parse the bundle. |

### `--strict` mode

By default, the verifier reports scaffold-flagged values (L6 ZK proof,
L8 hardware attestation, L10 formal verifier, see
[Verdifax scaffold-gaps documentation](https://docs.verdifax.com/concepts/scaffold-gaps/))
without failing the run. Pass `--strict` to fail verification when any
scaffold flag is set. High-trust environments should always use
`--strict`.

## What this verifier proves and doesn't prove

**Proves:** the bundle is internally consistent, every recorded hash
matches its canonical preimage, and any post-hoc modification to a
field invalidates the hash.

**Also proves, since 2026-09-08:** that the Sigstore Rekor entry the
bundle names is *this run's* entry and not someone else's. The verifier
rebuilds the leaf preimage from the bundle's own `envelope_id`,
`aer_hash` and `zksp_binding_hash` (plus `input_nonce` where present)
and confirms it hashes to the anchored leaf.

That check did not exist before. Until then this tool proved two things
separately and never joined them: that the manifest was internally
consistent, and that some leaf was genuinely inside Rekor's tree. A
bundle citing a real Rekor entry belonging to a different run satisfied
both and verified cleanly. It now fails, and the failure is a failure,
not an advisory line.

**Also checks, since v0.7.0, with the honest wording tightened in
v0.7.1:** the Ed25519 actor signature in the bundle's `nrep` section,
rebuilt from this run's `envelope_id`, `aer_hash` and `signed_at` and
validated against the public key the bundle itself supplies. Read that
last clause carefully: because the key comes from the bundle and the
nrep section is not yet covered by the bundle hash or the public-log
leaf, an attacker can replace the whole section with a self-consistent
one of their own, and this check cannot tell. A second external review
(2026-10-15) demonstrated exactly that against v0.7.0, which printed
"verified" for a forged identity; v0.7.1 therefore reports a passing
check as CONSISTENT, never verified, and states on every line that the
key is not pinned and the section is not sealed. An invalid signature
still fails the whole verdict, which catches tampering by anyone who
does not bother to re-sign. Pinning keys against a registry remains queued;
until it lands, even a sealed actor line is consistency, not identity.
Bundles sealed before `signed_at` shipped are reported as not
offline-checkable at all.

**Also proves, since v0.8.0:** that the actor section and the scaffold
flags of a version-3 anchored bundle are the ones that were anchored.
The v3 ledger leaf embeds digests of both, and this verifier recomputes
those digests from the bundle's own contents when rebuilding the leaf,
so replacing the actor section or clearing a placeholder flag breaks
the anchored leaf no matter how many unanchored hashes the editor
rewrites; both forgeries demonstrated against v0.7.0 are encoded as
tests and now fail. A sealed actor line reads "consistent and SEALED to
the anchor"; identity still waits on key pinning. Runtime stage timings
(real measurements, new in the same release) are digest-sealed at the
bundle level and reported with their honest boundary: the timing digest
is deliberately NOT in the anchored leaf, because per-run timings there
would break the replay-determinism promise, so an editor who rewrites
timings and digest together is outside what a bundle-level seal can
catch. Pre-v3 bundles report every one of these states explicitly
instead of pretending.

**Does not prove:** that the underlying execution actually happened on
Verdifax-operated hardware. Anchoring establishes that a bundle existed
and was publicly committed at a point in time; it does not establish
that the computation behind it was honest. An orchestrator that
controlled the whole pipeline could still anchor a fabricated but
internally consistent run. Closing that gap needs hardware-rooted
attestation, which is currently a scaffold value; see
[scaffold-gaps](https://docs.verdifax.com/concepts/scaffold-gaps/).

The `log_entry_id` field remains searchable on `search.sigstore.dev` if
you would rather confirm the entry by hand than trust this binary.

## Release verification (Cosign and SLSA provenance)

Every release binary ships with a Sigstore bundle and, from
v0.6.3, SLSA Build Level 3 provenance generated by the SLSA
project's trusted builder workflow rather than this repository's
own CI. Verify a download before trusting it:

```bash
# Signature (Cosign keyless, bound to this repository's CI identity)
cosign verify-blob \
  --bundle verdifax-verify-linux-amd64.bundle \
  --certificate-identity-regexp '^https://github.com/Verdifax/verdifax-verify/' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  verdifax-verify-linux-amd64

# Build provenance (SLSA Level 3)
slsa-verifier verify-artifact verdifax-verify-linux-amd64 \
  --provenance-path verdifax-verify-v0.6.3.intoto.jsonl \
  --source-uri github.com/Verdifax/verdifax-verify \
  --source-tag v0.6.3
```

A passing provenance check proves the binary was built by this
repository's release workflow from the stated tag, with an
attestation signed outside the repository's own control.

The verifier's untrusted-input path is also fuzzed continuously:
a coverage-guided harness (`fuzz_test.go`) drives arbitrary bytes
through bundle parsing and verification weekly in CI, with the
runs public in the Actions history. The first baseline (October
2026) executed 5.38 million inputs with zero failures.

## Source provenance

This repository contains the verifier source code only. The full
Verdifax orchestrator (which produces the bundles this tool verifies)
is maintained separately and not currently open source. The verifier
was extracted from the orchestrator's `cmd/verdifax-verify/` directory
to provide an auditable, independent verification tool that any third
party can build from source.

## Reporting issues

Open an issue on GitHub or email `access@verdifax.com`.
