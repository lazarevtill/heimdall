// Repo-policy tests live at the module root — they guard go.mod, not any
// one package.
package heimdall

import (
	"os"
	"strings"
	"testing"
)

// The recorded dependency budget (ADR-G02). Adding a direct dependency
// requires amending the ADR first, then this list. This test doubles as the
// CI guard against mattn/go-sqlite3 (cgo) ever reappearing.
var allowedDirect = map[string]bool{
	"golang.org/x/sync":        true,
	"modernc.org/sqlite":       true,
	"github.com/google/go-cmp": true, // tests only
}

func TestDependencyBudget(t *testing.T) {
	data, err := os.ReadFile("go.mod")
	if err != nil {
		t.Fatalf("read go.mod: %v", err)
	}
	for _, dep := range directDependencies(string(data)) {
		if !allowedDirect[dep] {
			t.Errorf("direct dependency %q is outside the recorded budget; amend ADR-G02 before go.mod", dep)
		}
	}
}

// The parser is what the budget rests on, so it is pinned against the go.mod
// shapes that could otherwise slip a direct dependency past it: the
// single-line form, a block, and an "// indirect" marker (which alone makes
// an entry not direct).
func TestDirectDependenciesParser(t *testing.T) {
	gomod := `module example.invalid/x

go 1.25.0

require github.com/google/go-cmp v0.7.0

require (
	golang.org/x/sync v0.22.0
	github.com/stretchr/testify v1.9.0
)

require (
	github.com/dustin/go-humanize v1.0.1 // indirect
)
`
	got := directDependencies(gomod)
	want := []string{"github.com/google/go-cmp", "golang.org/x/sync", "github.com/stretchr/testify"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("directDependencies = %v, want %v", got, want)
	}
}

// directDependencies returns the module paths go.mod requires directly, in
// file order: every require entry, single-line or in a block, not marked
// "// indirect".
func directDependencies(gomod string) []string {
	var out []string
	inBlock := false
	for _, raw := range strings.Split(gomod, "\n") {
		line := strings.TrimSpace(raw)
		switch {
		case line == "require (":
			inBlock = true
			continue
		case inBlock && line == ")":
			inBlock = false
			continue
		}
		var entry string
		switch {
		case inBlock:
			entry = line
		case strings.HasPrefix(line, "require "):
			entry = strings.TrimPrefix(line, "require ")
		default:
			continue
		}
		if strings.Contains(entry, "// indirect") {
			continue
		}
		if fields := strings.Fields(entry); len(fields) >= 2 {
			out = append(out, fields[0])
		}
	}
	return out
}
