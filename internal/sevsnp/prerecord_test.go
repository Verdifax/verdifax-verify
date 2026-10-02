package sevsnp

import (
	"crypto/sha256"
	"encoding/hex"
	"testing"
)

func hx(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

// Same known answer the orchestrator pins, computed in Python from the
// published recipe, so the two implementations cannot drift apart.
func TestPreRecordReportDataKnownAnswer(t *testing.T) {
	ids := make([]string, 6)
	for i := range ids {
		ids[i] = hx("kernel-" + string(rune('1'+i)))
	}
	got := PreRecordReportData(hx("input"), hx("transport"), hx("control"), hx("program"), ids)
	want := "be2449128e2218f921c46fd139677a398ce2976b4d7594d8be1e6e60e8e7d0fe" +
		"0a9adbc0fb52ce879214a84dc89126a894965ac3fd6249799da6daee93ebfcb3"
	if hex.EncodeToString(got[:]) != want {
		t.Errorf("report_data = %x, want %s", got, want)
	}
}
