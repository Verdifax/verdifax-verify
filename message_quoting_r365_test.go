package main

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// r365Verb matches one fmt verb (a percent sign followed by optional flags,
// width and precision, then a verb letter). A doubled percent sign is a
// literal percent and is removed before matching.
var r365Verb = regexp.MustCompile(`%[-+# 0]*(\[[0-9]+\])?([0-9]+|\*)?(\.([0-9]+|\*))?[a-zA-Z]`)

// r365Literal returns the value of a string literal, or of a concatenation
// of string literals, and false for anything else.
func r365Literal(e ast.Expr) (string, bool) {
	switch v := e.(type) {
	case *ast.BasicLit:
		if v.Kind != token.STRING {
			return "", false
		}
		s, unquoteErr := strconv.Unquote(v.Value)
		if unquoteErr != nil {
			return "", false
		}
		return s, true
	case *ast.ParenExpr:
		return r365Literal(v.X)
	case *ast.BinaryExpr:
		if v.Op != token.ADD {
			return "", false
		}
		left, leftOK := r365Literal(v.X)
		right, rightOK := r365Literal(v.Y)
		if !leftOK || !rightOK {
			return "", false
		}
		return left + right, true
	}
	return "", false
}

// r365Offenders lists every call in the non-test Go files under root with a
// string argument (a literal, or literals joined with +) that holds both a
// single quote and a verb. That covers fmt.Sprintf, fmt.Errorf, fmt.Printf,
// fmt.Fprintf and every local wrapper that hands its format to them.
func r365Offenders(t *testing.T, root string) []string {
	t.Helper()
	var found []string
	fset := token.NewFileSet()
	walkErr := filepath.WalkDir(root, func(path string, d fs.DirEntry, walkPathErr error) error {
		if walkPathErr != nil {
			return walkPathErr
		}
		if d.IsDir() {
			name := d.Name()
			if path != root && (name == "testdata" || name == "vendor" || strings.HasPrefix(name, ".")) {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		file, parseErr := parser.ParseFile(fset, path, nil, 0)
		if parseErr != nil {
			return parseErr
		}
		ast.Inspect(file, func(n ast.Node) bool {
			call, isCall := n.(*ast.CallExpr)
			if !isCall {
				return true
			}
			// Every argument is read, not only the format argument of the
			// fmt functions: the local wrappers (fail, failEntry, add, line)
			// pass their first string on to fmt.Sprintf.
			for _, arg := range call.Args {
				format, isLiteral := r365Literal(arg)
				if !isLiteral {
					continue
				}
				bare := strings.ReplaceAll(format, "%%", "")
				if strings.Contains(format, "'") && r365Verb.MatchString(bare) {
					at := fset.Position(arg.Pos())
					rel, relErr := filepath.Rel(root, at.Filename)
					if relErr != nil {
						rel = at.Filename
					}
					found = append(found, rel+":"+strconv.Itoa(at.Line))
				}
			}
			return true
		})
		return nil
	})
	if walkErr != nil {
		t.Fatalf("R365: reading the Go files failed: %v", walkErr)
	}
	sort.Strings(found)
	return found
}

// R365: no message places a formatted value in a format string that holds a
// single quote, so code scanning (go/unsafe-quoting) has nothing to flag.
// Every non-test Go file of the repository is parsed, internal packages
// included.
func TestR365NoQuoteInFormatStrings(t *testing.T) {
	root, wdErr := os.Getwd()
	if wdErr != nil {
		t.Fatalf("R365: working directory unknown: %v", wdErr)
	}
	for _, at := range r365Offenders(t, root) {
		t.Errorf("R365: %s: a format string holds a single quote and a verb; reword it without the quote (for example, \"the clock of the refusal\")", at)
	}
}

// R365: the scan itself finds a quote beside a verb, so a passing run means
// the files are clean, not that the scan is blind.
func TestR365ScanFindsAPlantedMessage(t *testing.T) {
	dir := t.TempDir()
	src := "package x\n\nimport \"fmt\"\n\nfunc f(a string) error {\n\treturn fmt.Errorf(\"the refusal\" + \"'s clock %s\", a)\n}\n\nfunc g(a string) string {\n\treturn fmt.Sprintf(\"the clock of the refusal %s\", a)\n}\n\nfunc h(fail func(string, ...any) error, a string) error {\n\treturn fail(\"the receipt's clock %q\", a)\n}\n"
	if writeErr := os.WriteFile(filepath.Join(dir, "x.go"), []byte(src), 0o600); writeErr != nil {
		t.Fatalf("R365: writing the planted file failed: %v", writeErr)
	}
	got := r365Offenders(t, dir)
	if len(got) != 2 || got[0] != "x.go:14" || got[1] != "x.go:6" {
		t.Fatalf("R365: the scan found %v, want exactly [x.go:14 x.go:6]", got)
	}
}
