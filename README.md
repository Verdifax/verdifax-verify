# verdifax-verify

`verdifax-verify` is the standalone, independent verifier for Verdifax
audit bundles. It reads a bundle JSON file (or stdin) and recomputes
every canonical hash from the bundle's content, comparing against the
recorded values to detect tampering.

It is the offline-verification path for Verdifax bundles: given just a
bundle file, this binary decides whether the evidence is internally
consistent. No network access, no Verdifax credentials, no trust in the
Verdifax API server.

## License

MIT, see [`LICENSE`](./LICENSE). The verifier is intentionally
open-source so auditors can read the code that adjudicates evidence.
The verifier produces no attestations of its own; it only checks that
a received bundle is internally consistent.

## Install

### From source

```bash
go install github.com/Verdifax/verdifax-verify@latest
```

Requires Go 1.21 or later. The binary lands at `$(go env GOPATH)/bin/verdifax-verify`.

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

## Source provenance

This repository contains the verifier source code only. The full
Verdifax orchestrator (which produces the bundles this tool verifies)
is maintained separately and not currently open source. The verifier
was extracted from the orchestrator's `cmd/verdifax-verify/` directory
to provide an auditable, independent verification tool that any third
party can build from source.

## Reporting issues

Open an issue on GitHub or email `access@verdifax.com`.
