package psleval

// Match applies the matcher's operator to the given value.
func Match(m Matcher, value string) bool {
	switch m.Operator {
	case MatchAny:
		return true
	case MatchExact:
		return value == m.Value
	case MatchPrefix:
		return hasPrefix(value, m.Value)
	case MatchSuffix:
		return hasSuffix(value, m.Value)
	case MatchSubstring:
		return contains(value, m.Value)
	case MatchIn:
		return inSet(value, m.Values)
	case MatchNotIn:
		return !inSet(value, m.Values)
	default:
		return false
	}
}

func hasPrefix(s, prefix string) bool {
	if len(prefix) > len(s) {
		return false
	}
	return s[:len(prefix)] == prefix
}

func hasSuffix(s, suffix string) bool {
	if len(suffix) > len(s) {
		return false
	}
	return s[len(s)-len(suffix):] == suffix
}

func contains(s, substr string) bool {
	if substr == "" {
		return true
	}
	if len(substr) > len(s) {
		return false
	}
	for i := 0; i+len(substr) <= len(s); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

func inSet(value string, values []string) bool {
	for _, v := range values {
		if v == value {
			return true
		}
	}
	return false
}

// CompareClassification returns -1, 0, or 1 if a is less than, equal to,
// or greater than b in the classification ordering. The ordering is:
//
//	PUBLIC < INTERNAL < CONFIDENTIAL < RESTRICTED < TOP_SECRET < TS_SCI
//
// Returns 0 with ok=false if either value is unrecognized.
func CompareClassification(a, b ClassificationLevel) (int, bool) {
	rankA, okA := classificationRank(a)
	rankB, okB := classificationRank(b)
	if !okA || !okB {
		return 0, false
	}
	if rankA < rankB {
		return -1, true
	}
	if rankA > rankB {
		return 1, true
	}
	return 0, true
}

// KnownClassification reports whether c is one of the documented levels.
func KnownClassification(c ClassificationLevel) bool {
	_, ok := classificationRank(c)
	return ok
}

func knownOperator(o MatchOperator) bool {
	switch o {
	case MatchAny, MatchExact, MatchPrefix, MatchSuffix, MatchSubstring, MatchIn, MatchNotIn:
		return true
	default:
		return false
	}
}

func classificationRank(c ClassificationLevel) (int, bool) {
	switch c {
	case ClassificationPublic:
		return 0, true
	case ClassificationInternal:
		return 1, true
	case ClassificationConfidential:
		return 2, true
	case ClassificationRestricted:
		return 3, true
	case ClassificationTopSecret:
		return 4, true
	case ClassificationTSSCI:
		return 5, true
	default:
		return 0, false
	}
}
