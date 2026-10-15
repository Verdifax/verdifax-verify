package artifacts

// The nonce is a nanosecond timestamp, which exceeds JavaScript's
// exact-integer range; FlexInt64 therefore marshals as a string and
// accepts both forms on the way in. These tests pin that contract.

import (
	"encoding/json"
	"testing"
)

func TestFlexInt64UnmarshalJSON(t *testing.T) {
	cases := []struct {
		in   string
		want int64
		ok   bool
	}{
		{`1760556239000000001`, 1760556239000000001, true},
		{`"1760556239000000001"`, 1760556239000000001, true},
		{`""`, 0, true},
		{`null`, 0, true},
		{`"not-a-number"`, 0, false},
	}
	for _, c := range cases {
		var f FlexInt64
		err := json.Unmarshal([]byte(c.in), &f)
		if c.ok && (err != nil || int64(f) != c.want) {
			t.Errorf("Unmarshal(%s) = %d, %v; want %d", c.in, int64(f), err, c.want)
		}
		if !c.ok && err == nil {
			t.Errorf("Unmarshal(%s) succeeded, want parse error", c.in)
		}
	}
}

func TestFlexInt64MarshalJSON(t *testing.T) {
	out, err := json.Marshal(FlexInt64(1760556239000000001))
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if string(out) != `"1760556239000000001"` {
		t.Errorf("Marshal = %s, want the string form", out)
	}
	var back FlexInt64
	if err := json.Unmarshal(out, &back); err != nil || back != 1760556239000000001 {
		t.Errorf("round trip = %d, %v", int64(back), err)
	}
}
