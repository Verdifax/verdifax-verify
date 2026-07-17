package sevsnp

import (
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
)

// Golden set: a REAL Milan attestation report captured 2026-07-17 on
// the verdifax-sevsnp-dev instance, verified on-box by snpguest.

const goldenReportDataHex = "911a3b0bbfdc934c198c219df2b707c3e62e44a7dd9d7bb75f53c276993fedaa" +
	"8ccd1e8848aa12413b479ec31e54a138b44d7ef74e766bc31df00df3a47f4bc5"

func loadGolden(t *testing.T) (report, vlek, chain []byte) {
	t.Helper()
	var err error
	report, err = os.ReadFile(filepath.Join("testdata", "report.bin"))
	if err != nil {
		t.Fatalf("report.bin: %v", err)
	}
	vlek, err = os.ReadFile(filepath.Join("testdata", "vlek.pem"))
	if err != nil {
		t.Fatalf("vlek.pem: %v", err)
	}
	chain, err = os.ReadFile(filepath.Join("testdata", "cert_chain.pem"))
	if err != nil {
		t.Fatalf("cert_chain.pem: %v", err)
	}
	return
}

func TestVerify_Golden(t *testing.T) {
	report, vlek, chain := loadGolden(t)
	expected, _ := hex.DecodeString(goldenReportDataHex)
	res, err := Verify(report, vlek, chain, expected)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if !res.ChainVerified || !res.SignatureVerified || !res.ReportDataBound {
		t.Fatalf("incomplete verification: %+v", res)
	}
}

func TestVerify_Tampered_Fails(t *testing.T) {
	report, vlek, chain := loadGolden(t)
	expected, _ := hex.DecodeString(goldenReportDataHex)
	tampered := append([]byte(nil), report...)
	tampered[0x90] ^= 0x01
	if _, err := Verify(tampered, vlek, chain, expected); err == nil {
		t.Fatal("tampered report verified")
	}
}

func TestVerify_WrongBinding_Fails(t *testing.T) {
	report, vlek, chain := loadGolden(t)
	wrong := make([]byte, 64)
	if _, err := Verify(report, vlek, chain, wrong); err == nil {
		t.Fatal("wrong binding accepted")
	}
}

func TestBindingReportData(t *testing.T) {
	a := BindingReportData("e1", "a1")
	b := BindingReportData("e1", "a2")
	if a == b {
		t.Fatal("binding ignores aer hash")
	}
}
