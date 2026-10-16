package artifacts

// Strict bundle decoding (v0.12.1), the answer to round eight of the
// external review.
//
// encoding/json matches object keys to struct fields case-insensitively
// (with Unicode simple folding, so "reſult" and "RESULT" both match
// Result) and lets the last match win. jq, Python, JavaScript and most
// other readers are case-sensitive. A bundle could therefore carry a
// forged value under the exact key and the original under a case
// variant placed after it: this verifier read the original, every hash
// recomputed, and the record verified, while every other tool showed
// the forgery. No key, log entry or hash recomputation was needed.
//
// DecodeBundleStrict closes that before any hash is computed. It walks
// the raw JSON against the AuditBundle type and refuses:
//
//   - two keys in one object that are equal under Unicode case folding
//     (which includes exact duplicates), and
//   - any key that is not byte-for-byte the JSON name of a field this
//     verifier models at that position.
//
// So every value any reader can see is a value this verifier checked.
// Map-typed fields keep free-form keys but still refuse fold-equal
// duplicates; values decoded by a custom UnmarshalJSON (FlexInt64) are
// scalars and are walked for duplicates only.

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"reflect"
	"strings"
	"sync"
)

// ErrNotStrictJSON wraps every refusal, so callers can name it.
var ErrNotStrictJSON = errors.New("bundle JSON is ambiguous or carries fields this verifier does not model")

// DecodeBundleStrict decodes data into an AuditBundle only if every
// object key is unambiguous and modeled; see the package comment above.
func DecodeBundleStrict(data []byte) (*AuditBundle, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	if walkErr := walkStrict(dec, reflect.TypeOf(AuditBundle{}), "$"); walkErr != nil {
		return nil, fmt.Errorf("%w: %v", ErrNotStrictJSON, walkErr)
	}
	if _, trailingErr := dec.Token(); trailingErr != io.EOF {
		return nil, fmt.Errorf("%w: data after the bundle's closing brace", ErrNotStrictJSON)
	}
	var b AuditBundle
	if unmarshalErr := json.Unmarshal(data, &b); unmarshalErr != nil {
		return nil, unmarshalErr
	}
	return &b, nil
}

var unmarshalerType = reflect.TypeOf((*json.Unmarshaler)(nil)).Elem()

// opaque reports whether values of t are decoded by something other
// than the struct/map/slice rules, so only duplicates are checked.
func opaque(t reflect.Type) bool {
	if t == nil || t.Kind() == reflect.Interface {
		return true
	}
	return t.Implements(unmarshalerType) || reflect.PointerTo(t).Implements(unmarshalerType)
}

func walkStrict(dec *json.Decoder, t reflect.Type, path string) error {
	for t != nil && t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	tok, tokErr := dec.Token()
	if tokErr != nil {
		return fmt.Errorf("%s: %v", path, tokErr)
	}
	delim, isDelim := tok.(json.Delim)
	if !isDelim {
		return nil // scalar: nothing to disambiguate
	}
	switch delim {
	case '[':
		var elem reflect.Type
		if t != nil && !opaque(t) && (t.Kind() == reflect.Slice || t.Kind() == reflect.Array) {
			elem = t.Elem()
		}
		for i := 0; dec.More(); i++ {
			if elemErr := walkStrict(dec, elem, fmt.Sprintf("%s[%d]", path, i)); elemErr != nil {
				return elemErr
			}
		}
		_, closeErr := dec.Token()
		return closeErr
	case '{':
		var fields map[string]reflect.Type
		var mapElem reflect.Type
		modeled := t != nil && !opaque(t)
		if modeled {
			switch t.Kind() {
			case reflect.Struct:
				fields = jsonFields(t)
			case reflect.Map:
				mapElem = t.Elem()
			default:
				modeled = false
			}
		}
		var seen []string
		for dec.More() {
			keyTok, keyErr := dec.Token()
			if keyErr != nil {
				return fmt.Errorf("%s: %v", path, keyErr)
			}
			key, _ := keyTok.(string)
			for _, prior := range seen {
				if strings.EqualFold(prior, key) {
					return fmt.Errorf("%s has both %q and %q; readers disagree about which one is the value",
						path, prior, key)
				}
			}
			seen = append(seen, key)
			var next reflect.Type
			switch {
			case fields != nil:
				ft, known := fields[key]
				if !known {
					return fmt.Errorf("%s.%s is not a field this verifier models, so it would not be checked", path, key)
				}
				next = ft
			case mapElem != nil:
				next = mapElem
			}
			if valErr := walkStrict(dec, next, path+"."+key); valErr != nil {
				return valErr
			}
		}
		_, closeErr := dec.Token()
		return closeErr
	}
	return fmt.Errorf("%s: unexpected %v", path, delim)
}

var fieldCache sync.Map // reflect.Type -> map[string]reflect.Type

// jsonFields returns the exact JSON key of every field encoding/json
// would decode into t, with promoted fields of untagged embedded
// structs, mapped to the field's type.
func jsonFields(t reflect.Type) map[string]reflect.Type {
	if cached, ok := fieldCache.Load(t); ok {
		return cached.(map[string]reflect.Type)
	}
	out := map[string]reflect.Type{}
	for i := 0; i < t.NumField(); i++ {
		f := t.Field(i)
		tag := f.Tag.Get("json")
		if tag == "-" {
			continue
		}
		name, _, _ := strings.Cut(tag, ",")
		if f.Anonymous && name == "" {
			et := f.Type
			if et.Kind() == reflect.Pointer {
				et = et.Elem()
			}
			if et.Kind() == reflect.Struct {
				for k, v := range jsonFields(et) {
					if _, shadowed := out[k]; !shadowed {
						out[k] = v
					}
				}
				continue
			}
		}
		if !f.IsExported() {
			continue
		}
		if name == "" {
			name = f.Name
		}
		out[name] = f.Type
	}
	fieldCache.Store(t, out)
	return out
}
