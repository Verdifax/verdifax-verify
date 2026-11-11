package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strconv"

	"github.com/Verdifax/verdifax-verify/internal/artifacts"
)

// Round 56, E4. A restore from backup can lose the last entries of an
// account's chain that already sit on the public log. The server never
// reuses their places and never leaves a silent hole: a sealed restore-gap
// record, anchored as its own entry, names the places the chain skips, and
// the chain's history holds it in its place. A history may skip places only
// where such a record names exactly the places skipped; the report lists
// every gap.

// chainItem is one element of a chain's history: a restore gap, an
// interrupted record (round 57, N2), or the raw chain entry for its own
// reader.
type chainItem struct {
	gap         *artifacts.RestoreGap
	interrupted *artifacts.ChainInterrupted
	raw         json.RawMessage
}

var (
	reflectRestoreGap       = reflect.TypeOf(artifacts.RestoreGap{})
	reflectChainInterrupted = reflect.TypeOf(artifacts.ChainInterrupted{})
)

// isSkip reports an item that moves the chain past places instead of
// taking one: a restore gap or an interrupted record.
func (it chainItem) isSkip() bool { return it.gap != nil || it.interrupted != nil }

// skipAccount is the account whose feed holds the skip's event.
func (it chainItem) skipAccount() string {
	if it.gap != nil {
		return it.gap.Signal.Account
	}
	return it.interrupted.Signal.Account
}

// checkSkip checks a restore gap or an interrupted record in a chain's
// history and returns the chain's next place after it and a report line.
func (it chainItem) checkSkip(chain string, keyID, next int64) (int64, string, error) {
	if it.gap != nil {
		after, err := checkChainGap(it.gap, chain, keyID, next)
		return after, gapLine(it.gap), err
	}
	after, err := checkChainInterrupted(it.interrupted, chain, keyID, next)
	return after, interruptedLine(it.interrupted), err
}

// readChainItems reads a history list strictly: each element is checked as
// what its format field says it is, a restore gap or the chain's own entry
// type (entryType).
func readChainItems(data []byte, entryType reflect.Type) ([]chainItem, error) {
	var raws []json.RawMessage
	if err := json.Unmarshal(data, &raws); err != nil {
		return nil, fmt.Errorf("it is not a list: %w", err)
	}
	if len(raws) == 0 {
		return nil, errors.New("it holds no entries")
	}
	items := make([]chainItem, 0, len(raws))
	for i, raw := range raws {
		var head struct {
			Format string `json:"format"`
		}
		_ = json.Unmarshal(raw, &head)
		if head.Format == artifacts.ChainInterruptedFormat {
			if strictErr := artifacts.CheckStrict(raw, reflectChainInterrupted); strictErr != nil {
				return nil, fmt.Errorf("entry %d, an interrupted record, is not plain JSON: %w", i+1, strictErr)
			}
			var c artifacts.ChainInterrupted
			if err := json.Unmarshal(raw, &c); err != nil {
				return nil, fmt.Errorf("entry %d, an interrupted record: %w", i+1, err)
			}
			items = append(items, chainItem{interrupted: &c})
			continue
		}
		if head.Format != artifacts.RestoreGapFormat {
			if strictErr := artifacts.CheckStrict(raw, entryType); strictErr != nil {
				return nil, fmt.Errorf("entry %d is not plain JSON: %w", i+1, strictErr)
			}
			items = append(items, chainItem{raw: raw})
			continue
		}
		if strictErr := artifacts.CheckStrict(raw, reflectRestoreGap); strictErr != nil {
			return nil, fmt.Errorf("entry %d, a restore gap, is not plain JSON: %w", i+1, strictErr)
		}
		var g artifacts.RestoreGap
		if err := json.Unmarshal(raw, &g); err != nil {
			return nil, fmt.Errorf("entry %d, a restore gap: %w", i+1, err)
		}
		items = append(items, chainItem{gap: &g})
	}
	return items, nil
}

// checkChainGap checks a restore gap in a chain's history: it is sealed and
// on the public log, names this chain, and starts at the chain's next place.
// It returns the chain's next place after the gap.
func checkChainGap(g *artifacts.RestoreGap, chain string, keyID, next int64) (int64, error) {
	if g.Chain != chain || g.KeyID != keyID {
		return 0, fmt.Errorf("it is a restore gap of the %s chain, not of this one", g.Chain)
	}
	if g.LostFrom != next {
		return 0, fmt.Errorf("its restore gap names places %d to %d, and the chain's next place is %d", g.LostFrom, g.LostTo, next)
	}
	if err := checkSealedEntry(g.Validate(), g.ComputeHash(), g.RestoreGapHash, g.RecordedAt, "recorded_at",
		g.Anchor, artifacts.RestoreGapKind, g.LeafHash()); err != nil {
		return 0, fmt.Errorf("its restore gap: %w", err)
	}
	return g.LostTo + 1, nil
}

// gapLine says what a restore gap records, for the report.
func gapLine(g *artifacts.RestoreGap) string {
	return "places " + strconv.FormatInt(g.LostFrom, 10) + " to " + strconv.FormatInt(g.LostTo, 10) +
		" skipped after a restore from backup; they may hold entries the restore lost (gap recorded " + g.RecordedAt + ")"
}

// checkChainInterrupted checks an interrupted record in a chain's history
// (round 57, N2): it is sealed and on the public log, names this chain, and
// closes exactly the chain's next place. It returns the place after it.
func checkChainInterrupted(c *artifacts.ChainInterrupted, chain string, keyID, next int64) (int64, error) {
	if c.Chain != chain || c.KeyID != keyID {
		return 0, fmt.Errorf("it is an interrupted record of the %s chain, not of this one", c.Chain)
	}
	if c.Place != next {
		return 0, fmt.Errorf("its interrupted record closes place %d, and the chain's next place is %d", c.Place, next)
	}
	if err := checkSealedEntry(c.Validate(), c.ComputeHash(), c.InterruptedHash, c.RecordedAt, "recorded_at",
		c.Anchor, artifacts.ChainInterruptedKind, c.LeafHash()); err != nil {
		return 0, fmt.Errorf("its interrupted record: %w", err)
	}
	return c.Place + 1, nil
}

// interruptedLine says what an interrupted record records, for the report.
func interruptedLine(c *artifacts.ChainInterrupted) string {
	return "place " + strconv.FormatInt(c.Place, 10) + " skipped: a " + c.RecordKind +
		" the public log never confirmed, whose planned entry carries leaf " + c.PlannedLeaf + " (recorded " + c.RecordedAt + ")"
}
