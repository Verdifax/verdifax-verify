# Test fixtures

## golden-bundle-run-208.json

A real sealed audit bundle from production run 208, used by
`golden_bundle_test.go` to prove the open-source verifier recomputes and
matches a genuine production bundle offline.

**This file is safe to be public.** Verdifax audit bundles seal
cryptographic *hashes and metadata*, never plaintext. This bundle
contains, for example, a payload record with `content_hash`,
`content_length`, and `payload_id` — but not the payload content itself.
No prompt text, model output, PII, credentials, or secrets are
recoverable from a bundle. Publishing it exposes only what the verifier
is designed to let any third party verify: that a set of canonical
hashes chains consistently to a sealed manifest.

If this fixture is ever regenerated, regenerate it from a run whose
payload is non-sensitive by construction, and re-confirm the above
before committing.
