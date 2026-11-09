// Package aivpcheck re-runs the AI review's contradiction check on a trace,
// in Go, exactly as the review engine (the Rust AIVP workspace) runs it.
//
// THIS DIRECTORY IS IDENTICAL IN THE ORCHESTRATOR AND THE PUBLIC VERIFIER
// (internal/aivpcheck in both repositories). The server's mock review uses
// it; the verifier uses it to confirm a sealed finding from the trace text a
// record's owner keeps. testdata/keyword-v1-vectors.json holds the engine's
// own results on every trace Verdifax recorded while measuring the review,
// so the Go and Rust checks cannot drift apart without a test failing.
//
// Nothing here imports another package of either project.
package aivpcheck

import (
	"fmt"
	"strings"
	"unicode"
)

// CheckerKeywordV1 is the checker this package implements.
const CheckerKeywordV1 = "keyword-v1"

// Node is one paragraph of a trace.
type Node struct {
	ID   string
	Text string
}

// Finding is the first contradiction the checker finds.
type Finding struct {
	NodeA    string
	NodeB    string
	Term     string
	Opposite string
}

// KeywordV1Pairs are the opposing terms keyword-v1 looks for, in its order.
var KeywordV1Pairs = [][2]string{
	{"always", "never"},
	{"true", "false"},
	{"valid", "invalid"},
	{"safe", "unsafe"},
	{"authorized", "unauthorized"},
	{"approved", "rejected"},
	{"confirmed", "denied"},
	{"possible", "impossible"},
	{"correct", "incorrect"},
	{"certain", "uncertain"},
}

// ParseTrace splits a trace into nodes as the engine's ChainOfThoughtAdapter
// does: paragraphs separated by a blank line ("\n\n"), each trimmed of white
// space, a leading "ASSUME:" or "INFER:" removed and the rest trimmed again,
// empty paragraphs skipped. A node's id is its paragraph's position counted
// from 1, empty paragraphs included, as node-0001, node-0002 and so on.
func ParseTrace(text string) []Node {
	var nodes []Node
	for i, para := range strings.Split(text, "\n\n") {
		p := strings.TrimFunc(para, unicode.IsSpace)
		if p == "" {
			continue
		}
		if rest, cut := strings.CutPrefix(p, "ASSUME:"); cut {
			p = strings.TrimFunc(rest, unicode.IsSpace)
		} else if rest, cut := strings.CutPrefix(p, "INFER:"); cut {
			p = strings.TrimFunc(rest, unicode.IsSpace)
		}
		if p == "" {
			continue
		}
		nodes = append(nodes, Node{ID: fmt.Sprintf("node-%04d", i+1), Text: p})
	}
	return nodes
}

// alphanumeric is Rust's char::is_alphanumeric: the Unicode Alphabetic
// property or a numeric character.
func alphanumeric(r rune) bool {
	return unicode.IsLetter(r) || unicode.IsNumber(r) || unicode.Is(unicode.Other_Alphabetic, r)
}

func containsTerm(text, term string) bool {
	for _, word := range strings.FieldsFunc(strings.ToLower(text), func(r rune) bool { return !alphanumeric(r) }) {
		if word == term {
			return true
		}
	}
	return false
}

// KeywordV1 returns keyword-v1's finding on the nodes, or nil: for each pair
// of nodes in order, the first term pair one holds and the other opposes.
func KeywordV1(nodes []Node) *Finding {
	for i, a := range nodes {
		for _, b := range nodes[i+1:] {
			for _, pair := range KeywordV1Pairs {
				term, opposite := pair[0], pair[1]
				if (containsTerm(a.Text, term) && containsTerm(b.Text, opposite)) ||
					(containsTerm(a.Text, opposite) && containsTerm(b.Text, term)) {
					return &Finding{NodeA: a.ID, NodeB: b.ID, Term: term, Opposite: opposite}
				}
			}
		}
	}
	return nil
}
