package artifacts

import "errors"

// ErrDenyReceiptHashMismatch is returned by VerifyDenyReceiptHash when
// the recomputed canonical hash does not match the stored Hash field.
// This indicates either tampering or implementation divergence.
var ErrDenyReceiptHashMismatch = errors.New("artifacts: deny receipt hash mismatch")

// ErrMCDFindingHashMismatch is returned by VerifyMCDFindingHash when
// the recomputed canonical hash does not match the stored Hash field.
var ErrMCDFindingHashMismatch = errors.New("artifacts: mcd finding hash mismatch")

// ErrAllowTokenHashMismatch is returned by VerifyAllowTokenHash when the
// recomputed canonical hash does not match the stored Hash field.
var ErrAllowTokenHashMismatch = errors.New("artifacts: allow token hash mismatch")

// ErrCCVHaltReceiptHashMismatch is returned by VerifyCCVHaltReceiptHash
// when the recomputed canonical hash does not match the stored Hash field.
var ErrCCVHaltReceiptHashMismatch = errors.New("artifacts: ccv halt receipt hash mismatch")

// ErrMACCHaltReceiptHashMismatch is returned by VerifyMACCHaltReceiptHash
// when the recomputed canonical hash does not match the stored Hash field.
var ErrMACCHaltReceiptHashMismatch = errors.New("artifacts: macc halt receipt hash mismatch")

// ErrAivpT4HaltReceiptHashMismatch is returned by VerifyAivpT4HaltReceiptHash
// when the recomputed canonical hash does not match the stored Hash field.
var ErrAivpT4HaltReceiptHashMismatch = errors.New("artifacts: aivp-t4 halt receipt hash mismatch")
