package main

// Head statements' age (round 61, N24). A head statement says a history or a
// feed was complete as of the public log's time for its entry. The older the
// head, the longer a later entry has had to exist without the head showing
// it, so every report prints the head's age beside its time, and a head older
// than a limit fails: 24 hours by default, raised or lowered with
// --signoff-head-max-age for a sign-off history and --feed-head-max-age for a
// signal feed.

import (
	"errors"
	"fmt"
	"time"
)

// defaultHeadMaxAge is how old a head statement may be before it fails.
const defaultHeadMaxAge = 24 * time.Hour

var (
	// checkClock is this check's time; tests set it.
	checkClock = time.Now
	// signOffHeadMaxAge and feedHeadMaxAge are the limits in force, set from
	// --signoff-head-max-age and --feed-head-max-age.
	signOffHeadMaxAge = defaultHeadMaxAge
	feedHeadMaxAge    = defaultHeadMaxAge
)

// errHeadTooOld opens the failure of a head older than its limit.
var errHeadTooOld = errors.New("the head statement is older than the limit")

// headAsOf reads a head's public-log time and its age at this check. It
// returns the time, a phrase for the report ("3 days before this check"),
// and an error when the head is older than limit; flag names the flag that
// raises the limit and fetch what to fetch again.
func headAsOf(integratedTime int64, limit time.Duration, flag, fetch string) (string, string, error) {
	at := time.Unix(integratedTime, 0).UTC()
	age := checkClock().Sub(at)
	phrase := agePhrase(age)
	if age > limit {
		return at.Format(time.RFC3339), phrase, fmt.Errorf("%w; fetch the %s again: its time on the public log, %s, is %s, and the limit is %s (raise it with %s)",
			errHeadTooOld, fetch, at.Format(time.RFC3339), phrase, limit, flag)
	}
	return at.Format(time.RFC3339), phrase, nil
}

// agePhrase says how long before this check a time was, in the largest
// whole unit that fits.
func agePhrase(age time.Duration) string {
	if age < 0 {
		return "after this check's clock by " + unitPhrase(-age)
	}
	return unitPhrase(age) + " before this check"
}

func unitPhrase(d time.Duration) string {
	plural := func(n int64, unit string) string {
		if n == 1 {
			return fmt.Sprintf("1 %s", unit)
		}
		return fmt.Sprintf("%d %ss", n, unit)
	}
	switch {
	case d < time.Minute:
		return "less than a minute"
	case d < time.Hour:
		return plural(int64(d/time.Minute), "minute")
	case d < 48*time.Hour:
		return plural(int64(d/time.Hour), "hour")
	}
	return plural(int64(d/(24*time.Hour)), "day")
}

// parseHeadMaxAge reads a head age limit, a positive Go duration such as 72h.
func parseHeadMaxAge(name, value string) (time.Duration, error) {
	d, err := time.ParseDuration(value)
	if err != nil || d <= 0 {
		return 0, fmt.Errorf("--%s must be a positive duration such as 24h or 72h, not %q", name, value)
	}
	return d, nil
}
