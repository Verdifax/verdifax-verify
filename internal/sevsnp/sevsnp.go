// Package sevsnp independently re-verifies the AMD SEV-SNP hardware
// attestation embedded in a Verdifax audit bundle. It is a standalone
// port of the orchestrator's internal/attestation verifier, so this
// tool never has to trust the orchestrator's claim that a quote was
// verified: everything is re-checked here from the raw bytes in the
// bundle.
//
// What is verified:
//
//  1. The VLEK certificate chain: leaf (SEV-VLEK) → intermediate
//     (SEV-VLEK-Milan) → root (ARK-Milan). BOTH the root and the
//     intermediate are pinned by SHA-256 fingerprint of their DER
//     encoding. A chain not terminating at AMD's Milan root fails.
//  2. The report signature: ECDSA P-384 over SHA-384 of the 672-byte
//     report body (r/s little-endian in the signature block).
//  3. The run binding: report_data must equal
//     sha512("verdifax.sevsnp.report_data.v1:" + envelope_hash + ":"
//     + aer_hash) for THIS bundle, so the quote cannot have been
//     produced for any other run.
package sevsnp

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/asn1"
	"encoding/binary"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
)

const (
	// ARKMilanRootSHA256 pins AMD's self-signed Milan root (ARK-Milan),
	// fetched from https://kdsintf.amd.com/vlek/v1/Milan/cert_chain and
	// cross-checked against a live snpguest verification on 2026-07-17.
	ARKMilanRootSHA256 = "69d063b45344d26a2e94e1f4210de49ef555308287d4c174445c95639a540bcd"

	// SEVVLEKMilanIntermediateSHA256 pins the SEV-VLEK-Milan signing cert.
	SEVVLEKMilanIntermediateSHA256 = "c5e081f59b7efab1fe2f8b505e159704e72f29cab7ef7cf628a05a42439082f5"

	reportBodyLen  = 0x2A0
	reportLen      = 1184
	bindingDomain  = "verdifax.sevsnp.report_data.v1"
)

// Result reports what was checked.
type Result struct {
	ChainVerified     bool
	SignatureVerified bool
	ReportDataBound   bool
	MeasurementHex    string
	ReportIDHex       string
	ReportVersion     uint32
}

// BindingReportData recomputes the 64-byte run-binding value from the
// bundle's own envelope and AER hashes.
func BindingReportData(envelopeHash, aerHash string) [64]byte {
	return sha512.Sum512([]byte(bindingDomain + ":" + envelopeHash + ":" + aerHash))
}

// Verify re-runs the full verification against raw bundle evidence.
// expectedReportData must be the recomputed binding for this bundle.
func Verify(rawReport, vlekPEM, chainPEM, expectedReportData []byte) (*Result, error) {
	if len(rawReport) != reportLen {
		return nil, fmt.Errorf("sevsnp: report length %d, want %d", len(rawReport), reportLen)
	}
	sigAlgo := binary.LittleEndian.Uint32(rawReport[0x34:])
	if sigAlgo != 1 {
		return nil, fmt.Errorf("sevsnp: unsupported signature algorithm %d", sigAlgo)
	}
	res := &Result{
		ReportVersion:  binary.LittleEndian.Uint32(rawReport[0x00:]),
		MeasurementHex: hex.EncodeToString(rawReport[0x90:0xC0]),
		ReportIDHex:    hex.EncodeToString(rawReport[0x140:0x160]),
	}

	// 1. Pinned chain.
	leaf, err := parseSingleCert(vlekPEM)
	if err != nil {
		return nil, fmt.Errorf("sevsnp: leaf cert: %w", err)
	}
	chain, err := parseCerts(chainPEM)
	if err != nil {
		return nil, fmt.Errorf("sevsnp: chain: %w", err)
	}
	if len(chain) != 2 {
		return nil, fmt.Errorf("sevsnp: chain has %d certs, want 2", len(chain))
	}
	intermediate, root := chain[0], chain[1]
	if got := fingerprint(root); got != ARKMilanRootSHA256 {
		return nil, fmt.Errorf("sevsnp: root fingerprint %s is not pinned ARK-Milan", got)
	}
	if got := fingerprint(intermediate); got != SEVVLEKMilanIntermediateSHA256 {
		return nil, fmt.Errorf("sevsnp: intermediate fingerprint %s is not pinned SEV-VLEK-Milan", got)
	}
	if err := root.CheckSignatureFrom(root); err != nil {
		return nil, fmt.Errorf("sevsnp: root self-signature: %w", err)
	}
	if err := intermediate.CheckSignatureFrom(root); err != nil {
		return nil, fmt.Errorf("sevsnp: intermediate not signed by pinned root: %w", err)
	}
	if err := leaf.CheckSignatureFrom(intermediate); err != nil {
		return nil, fmt.Errorf("sevsnp: leaf not signed by intermediate: %w", err)
	}
	res.ChainVerified = true

	// 2. Report signature.
	pub, ok := leaf.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return nil, errors.New("sevsnp: leaf public key is not ECDSA")
	}
	sig := rawReport[reportBodyLen:]
	r := new(big.Int).SetBytes(reverse(sig[0:72]))
	s := new(big.Int).SetBytes(reverse(sig[72:144]))
	digest := sha512.Sum384(rawReport[:reportBodyLen])
	if !ecdsa.Verify(pub, digest[:], r, s) {
		return nil, errors.New("sevsnp: report signature verification FAILED")
	}
	res.SignatureVerified = true

	// 3. Run binding.
	if !bytes.Equal(rawReport[0x50:0x90], expectedReportData) {
		return nil, fmt.Errorf("sevsnp: report_data not bound to this bundle: got %x want %x",
			rawReport[0x50:0x90], expectedReportData)
	}
	res.ReportDataBound = true
	return res, nil
}

func parseSingleCert(pemBytes []byte) (*x509.Certificate, error) {
	certs, err := parseCerts(pemBytes)
	if err != nil {
		return nil, err
	}
	if len(certs) != 1 {
		return nil, fmt.Errorf("want exactly 1 certificate, got %d", len(certs))
	}
	return certs[0], nil
}

func parseCerts(pemBytes []byte) ([]*x509.Certificate, error) {
	var out []*x509.Certificate
	rest := pemBytes
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		c, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			c, err = parseCertLenientSerial(block.Bytes)
			if err != nil {
				return nil, err
			}
		}
		out = append(out, c)
	}
	if len(out) == 0 {
		return nil, errors.New("no certificates found in PEM input")
	}
	return out, nil
}

// parseCertLenientSerial handles AMD's serial-number-zero VLEK
// certificates under strict parsers: parse a serial-patched copy for
// structure, then restore the ORIGINAL Raw (for fingerprinting) and
// ORIGINAL RawTBSCertificate (so signature checks verify what the
// issuer actually signed).
func parseCertLenientSerial(der []byte) (*x509.Certificate, error) {
	patched, err := patchZeroSerial(der)
	if err != nil {
		return nil, err
	}
	c, err := x509.ParseCertificate(patched)
	if err != nil {
		return nil, err
	}
	var outer struct {
		TBSCertificate     asn1.RawValue
		SignatureAlgorithm asn1.RawValue
		SignatureValue     asn1.BitString
	}
	if _, err := asn1.Unmarshal(der, &outer); err != nil {
		return nil, fmt.Errorf("restore tbs: %w", err)
	}
	c.Raw = der
	c.RawTBSCertificate = outer.TBSCertificate.FullBytes
	return c, nil
}

func patchZeroSerial(der []byte) ([]byte, error) {
	var cert struct {
		TBSCertificate     asn1.RawValue
		SignatureAlgorithm asn1.RawValue
		SignatureValue     asn1.BitString
	}
	if _, err := asn1.Unmarshal(der, &cert); err != nil {
		return nil, fmt.Errorf("outer asn1: %w", err)
	}
	tbs := cert.TBSCertificate.FullBytes
	limit := 24
	if len(tbs) < limit {
		limit = len(tbs)
	}
	idx := bytes.Index(tbs[:limit], []byte{0x02, 0x01, 0x00})
	if idx < 0 {
		return nil, errors.New("zero serial not found where expected")
	}
	base := bytes.Index(der, tbs)
	if base < 0 {
		return nil, errors.New("tbs offset not found")
	}
	out := append([]byte(nil), der...)
	out[base+idx+2] = 0x01
	return out, nil
}

func fingerprint(c *x509.Certificate) string {
	sum := sha256.Sum256(c.Raw)
	return hex.EncodeToString(sum[:])
}

func reverse(b []byte) []byte {
	out := make([]byte, len(b))
	for i, v := range b {
		out[len(b)-1-i] = v
	}
	return out
}
