# WASM in-browser verifier, implementation plan

Status: NOT SHIPPED. Tracked as task #226.

## Why this exists

The current CLI verifier requires `curl | chmod` or `go install` plus a
terminal session. That excludes non-technical reviewers who land at
`verdifax.com/verify/{run-id}` from the audit PDF's QR code and would
prefer a one-click "verify this for me" experience.

A WASM verifier compiled from the same Go source as the CLI lets a
browser tab recompute every hash, walk the Rekor inclusion proof, and
return PASS / FAIL without installing anything. The cryptographic
guarantees are identical to the CLI path; only the runtime changes.

## Scope estimate

4 to 8 hours of focused work, broken down:

1. Refactor `main.go` to extract the verify pipeline behind a function
   that takes bundle bytes and returns a Result struct, so both the CLI
   and the WASM wrapper can call it. About 1 hour.

2. Add `cmd/wasm/main.go` with `syscall/js` bindings exposing the
   verifier as a JS-callable function. About 1 hour.

3. Add a `make wasm` target (or shell script) that compiles with
   `GOOS=js GOARCH=wasm go build` and copies the resulting `.wasm` file
   plus the Go runtime's `wasm_exec.js` into the website's public
   directory. About 30 minutes.

4. Build a React/TS component in `verdifax-website/app/verify/[id]/`
   that loads the WASM module, fetches the bundle from
   `/runs/{id}/bundle.json`, hands it to the WASM function, and renders
   the result with the same verdict format as the CLI. About 2 hours.

5. Test in Chrome, Firefox, Safari, mobile Safari. Handle the bundle
   size (likely 3-5 MB initial download). Add a loading spinner. About
   1 hour.

6. Handle edge cases: bundle fetch failure, WASM load failure on older
   browsers, network errors during proof verification, runs that do not
   have public bundles (404). About 1-2 hours.

## Dependencies and risks

The verifier uses `crypto/ecdsa`, `crypto/sha256`, `encoding/json`, and
the embedded Rekor public key. All four work cleanly under
`GOOS=js GOARCH=wasm`. Confidence high.

The verifier currently shells out to the CLI for URL fetches via
`http.Get`. Under WASM, that becomes a `fetch()` call which the JS
wrapper handles. Refactor cost is bounded.

The bundle size for the verifier WASM module is the main user-facing
risk. Typical Go-to-WASM output is 3-5 MB. For a one-off verification
flow that is acceptable but should be measured before shipping; if it
ends up over 8 MB consider TinyGo as a compiler swap.

## What blocks shipping in the current session

A working Go toolchain to compile and test, plus browser-side
validation. Neither is available in the sandbox the session is
running in. Estimated 4-8 hours of focused work on the user's machine
to ship correctly. Better to do that in a dedicated session than
attempt a partial ship now.

## What the page should fall back to in the meantime

The existing `/verify` page already covers this case: it renders the
CLI install commands per platform, the verify command with the run ID
substituted from the URL, and an explanation of what each command
does. That is sufficient for technical reviewers (including Kayvan).
The WASM path is purely a UX improvement for non-technical reviewers.

## Next session checklist

- [ ] Refactor verifier pipeline into a callable function.
- [ ] Add `cmd/wasm/main.go` with `syscall/js` bindings.
- [ ] Add Make target / build script for WASM compilation.
- [ ] Wire React component on verdifax-website to load and call the WASM.
- [ ] Cross-browser test (Chrome, Firefox, Safari, mobile Safari).
- [ ] Measure WASM bundle size, decide on TinyGo if over 8 MB.
- [ ] Update the audit-PDF QR target to point at the per-run verify
      page once shipped (currently points at the public bundle URL).
