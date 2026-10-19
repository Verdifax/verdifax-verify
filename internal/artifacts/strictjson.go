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
//     verifier models at that position, and
//   - any number not written in its canonical form (v0.13.0): the
//     spelling encoding/json produces for that value, which is also the
//     RFC 8785 spelling for every number Verdifax emits. "0.011" passes;
//     "0.0110000000000000001", "1.0", "1e3" and "011" do not, so the
//     exact bytes are pinned, not only the values, and
//   - invalid UTF-8, an unpaired UTF-16 surrogate escape, or the NUL
//     character in any string (v0.14.5). Go replaces the first two with
//     U+FFFD while other readers keep or reject them, so readers would
//     disagree; NUL is the separator several sealed digests join on.
//     Verdifax refuses NUL in requests and writes only valid UTF-8, so
//     no genuine record carries any of the three.
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
	"regexp"
	"strconv"
	"strings"
	"sync"
	"unicode/utf8"
)

// ErrNotStrictJSON wraps every refusal, so callers can name it.
var ErrNotStrictJSON = errors.New("JSON is ambiguous or carries fields this verifier does not model")

// DecodeBundleStrict decodes data into an AuditBundle only if every
// object key is unambiguous and modeled; see the package comment above.
func DecodeBundleStrict(data []byte) (*AuditBundle, error) {
	if textErr := checkStringText(data); textErr != nil {
		return nil, fmt.Errorf("%w: %v", ErrNotStrictJSON, textErr)
	}
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

// DecodeReceiptStrict decodes a receipt document under the same rules
// as DecodeBundleStrict.
func DecodeReceiptStrict(data []byte) (*ReceiptDocument, error) {
	if textErr := checkStringText(data); textErr != nil {
		return nil, fmt.Errorf("%w: %v", ErrNotStrictJSON, textErr)
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	if walkErr := walkStrict(dec, reflect.TypeOf(ReceiptDocument{}), "$"); walkErr != nil {
		return nil, fmt.Errorf("%w: %v", ErrNotStrictJSON, walkErr)
	}
	if _, trailingErr := dec.Token(); trailingErr != io.EOF {
		return nil, fmt.Errorf("%w: data after the document's closing brace", ErrNotStrictJSON)
	}
	var d ReceiptDocument
	if unmarshalErr := json.Unmarshal(data, &d); unmarshalErr != nil {
		return nil, unmarshalErr
	}
	return &d, nil
}

// CheckStrict applies the rules above to a whole document that will be
// decoded into type t, without decoding it: checkStringText, then
// walkStrict from the root, then no data after the closing token. Every
// refusal wraps ErrNotStrictJSON. internal/policyhash uses it for
// --policy documents, so a policy is read under the same rules as a
// bundle.
func CheckStrict(data []byte, t reflect.Type) error {
	if textErr := checkStringText(data); textErr != nil {
		return fmt.Errorf("%w: %v", ErrNotStrictJSON, textErr)
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	if walkErr := walkStrict(dec, t, "$"); walkErr != nil {
		return fmt.Errorf("%w: %v", ErrNotStrictJSON, walkErr)
	}
	if _, trailingErr := dec.Token(); trailingErr != io.EOF {
		return fmt.Errorf("%w: data after the document's closing token", ErrNotStrictJSON)
	}
	return nil
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
		if num, isNum := tok.(json.Number); isNum {
			return checkCanonicalNumber(num, path)
		}
		return nil // string, bool or null: nothing to disambiguate
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

// checkCanonicalNumber refuses a number whose text is not the canonical
// spelling of its value. Error model: the reason is returned to the
// caller, which reports it; this package has no logger.
func checkCanonicalNumber(num json.Number, path string) error {
	text := num.String()
	// Whole numbers: the canonical spelling is the plain decimal digits,
	// read exactly (no float rounding), so large integers such as an
	// input_nonce stored as a number keep their exact value.
	if integerLiteral.MatchString(text) {
		if text == "-0" {
			return fmt.Errorf("%s is written %q; its canonical form is \"0\"", path, text)
		}
		if _, intErr := strconv.ParseInt(text, 10, 64); intErr != nil {
			if _, uintErr := strconv.ParseUint(text, 10, 64); uintErr != nil {
				return fmt.Errorf("%s: integer %q is out of the 64-bit range", path, text)
			}
		}
		return nil
	}
	// Fractions and exponents: the canonical spelling is the one
	// encoding/json produces for the float64 value.
	value, parseErr := strconv.ParseFloat(text, 64)
	if parseErr != nil {
		return fmt.Errorf("%s: number %q does not parse: %v", path, text, parseErr)
	}
	canonical, encodeErr := json.Marshal(value)
	if encodeErr != nil {
		return fmt.Errorf("%s: number %q cannot be encoded: %v", path, text, encodeErr)
	}
	if string(canonical) != text {
		return fmt.Errorf("%s is written %q; its canonical form is %q, so the bytes are not the ones sealed",
			path, text, canonical)
	}
	return nil
}

// integerLiteral matches a JSON integer with no leading zeros, sign
// only for negatives, and no fraction or exponent.
var integerLiteral = regexp.MustCompile(`^-?(0|[1-9][0-9]*)$`)

// checkStringText refuses invalid UTF-8 anywhere in the document, and,
// inside JSON strings, an unpaired surrogate escape or the NUL
// character. Error model: the reason is returned to the caller, which
// reports it; this package has no logger.
func checkStringText(data []byte) error {
	if !utf8.Valid(data) {
		return errors.New("the document is not valid UTF-8")
	}
	inString := false
	for i := 0; i < len(data); i++ {
		c := data[i]
		if !inString {
			if c == '"' {
				inString = true
			}
			continue
		}
		switch c {
		case '"':
			inString = false
		case '\\':
			if i+1 >= len(data) {
				return nil // truncated input is reported by the decoder
			}
			if data[i+1] != 'u' {
				i++
				continue
			}
			v, ok := hex4(data, i+2)
			if !ok {
				return nil // malformed escape is reported by the decoder
			}
			switch {
			case v == 0:
				return errors.New("a string contains the NUL character (\\u0000)")
			case v >= 0xDC00 && v <= 0xDFFF:
				return fmt.Errorf("a string contains an unpaired low surrogate (\\u%04x)", v)
			case v >= 0xD800 && v <= 0xDBFF:
				low, okLow := uint32(0), false
				if i+11 < len(data) && data[i+6] == '\\' && data[i+7] == 'u' {
					low, okLow = hex4(data, i+8)
				}
				if !okLow || low < 0xDC00 || low > 0xDFFF {
					return fmt.Errorf("a string contains an unpaired high surrogate (\\u%04x)", v)
				}
				i += 11
				continue
			}
			i += 5
		}
	}
	return nil
}

// hex4 parses four hex digits at data[at:at+4].
func hex4(data []byte, at int) (uint32, bool) {
	if at+4 > len(data) {
		return 0, false
	}
	v, parseErr := strconv.ParseUint(string(data[at:at+4]), 16, 32)
	if parseErr != nil {
		return 0, false
	}
	return uint32(v), true
}
