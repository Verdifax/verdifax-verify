package rekorverify

// RekorPublicKeyPEM is the production Sigstore Rekor public key used
// to verify signed log checkpoints. This value MUST be populated
// before the verifier can perform any offline Rekor proof
// verification, leaving it empty causes loadRekorPublicKey to return
// a clear "populate this file" error rather than silently accepting
// any key.
//
// HOW TO POPULATE
// ────────────────
//
// Sigstore's Rekor instance publishes its public key at:
//
//	https://rekor.sigstore.dev/api/v1/log/publicKey
//
// Fetch it once during deployment provisioning:
//
//	curl -sS https://rekor.sigstore.dev/api/v1/log/publicKey
//
// The response is a PEM block of the form:
//
//	-----BEGIN PUBLIC KEY-----
//	MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE...
//	...
//	-----END PUBLIC KEY-----
//
// Copy it verbatim (including the BEGIN/END lines and trailing
// newline) into the constant below. Commit. Rebuild the verifier.
//
// HOW TO ROTATE
// ─────────────
//
// Sigstore rotates its keys infrequently (the current key has been
// stable for years). Rotation is announced via:
//
//   - the Sigstore TUF root: https://tuf-repo-cdn.sigstore.dev/
//   - the public sigstore-keyring: https://github.com/sigstore/root-signing
//   - the Sigstore Slack and mailing list
//
// When rotation happens, rebuild the verifier with the new key. Old
// audit bundles signed under the old key will no longer verify
// against the new key, operators may want to keep both keys
// available during a transition window. The simplest extension is to
// turn this constant into a slice and have loadRekorPublicKey try
// each key in turn until one verifies.
//
// HOW TO VERIFY YOU HAVE THE RIGHT KEY
// ────────────────────────────────────
//
// The Rekor LogID is the hex SHA-256 of the DER-encoded public key.
// Compute it locally:
//
//	echo -n "$(cat rekor_public_key.pem)" | \
//	  openssl pkey -pubin -outform DER | \
//	  sha256sum
//
// Compare against the LogID embedded in any recent Rekor entry
// (visible at https://search.sigstore.dev/?logIndex=<any-recent-index>).
// They must match. If they don't, the key is wrong, do not commit it.
//
// SECURITY NOTE
// ─────────────
//
// This is a TRUSTED ROOT. Any compromise of this constant means an
// attacker can forge anchored entries. Treat changes to this file
// with the same scrutiny as changes to /etc/ssl/certs.
const RekorPublicKeyPEM = ``

// Above intentionally empty. Operators MUST populate before building.
// See loadRekorPublicKey in verify.go for the runtime-error message
// that surfaces when this is missed.
