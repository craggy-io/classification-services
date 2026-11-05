package classificationservices_test

import (
	"slices"
	"testing"

	"github.com/craggy-io/foundation-kit/archtest"
)

// layers are the packages AGENTS.md places in the dependency order. Other
// packages (defs, internal/..., integration) aren't placed there, so no rule
// here restricts them or what imports them.
var layers = []string{
	"./evidence", "./catalog", "./signatures", "./views", "./probes",
	"./definitions", "./classify", "./cmd/...",
}

// below returns a rule that lets the from packages import only the listed
// layers, forbidding every other layer (AGENTS.md, "Dependencies run one
// way"). Allowing a package also allows what it depends on, since the order
// is transitive.
func below(from string, allowed ...string) archtest.Rule {
	var forbid []string
	for _, l := range layers {
		if l != from && !slices.Contains(allowed, l) {
			forbid = append(forbid, l)
		}
	}
	return archtest.Rule{
		Name:   "dependency order for " + from,
		Why:    "dependencies run one way (AGENTS.md): move the code to a lower package rather than importing upward",
		From:   []string{from},
		Forbid: forbid,
	}
}

// TestArchitecture enforces the import rules in AGENTS.md ("Choose the owning
// package"). archtest skips _test.go files and sees only direct imports, so
// an indirect import through an unplaced package (such as internal/paged) is
// not caught. It also checks only this module: adapters/artifactsvc is a
// nested module and is exempt from the core-module rules, and the module
// graph (go.mod requires) isn't inspected. Test-only requires such as
// foundation-kit are therefore outside the core-module rule.
func TestArchitecture(t *testing.T) {
	archtest.Check(t, archtest.Config{
		Rules: []archtest.Rule{
			// evidence <- catalog, signatures, views; views <- probes;
			// views, catalog, signatures <- definitions; all <- classify <- cmd.
			below("./evidence"),
			below("./catalog", "./evidence"),
			below("./signatures", "./evidence"),
			below("./views", "./evidence"),
			below("./probes", "./views", "./evidence"),
			below("./definitions", "./views", "./catalog", "./signatures", "./evidence"),
			below("./classify", "./evidence", "./catalog", "./signatures", "./views", "./probes", "./definitions"),
			{
				Name:   "probes never imports classify",
				Why:    "AGENTS.md: probes never imports classify; classify depends on probes, not the reverse",
				From:   []string{"./probes"},
				Forbid: []string{"./classify"},
			},
			{
				Name:   "definitions never imports probes",
				Why:    "AGENTS.md: definitions never imports probes; definitions build on views, catalog and signatures",
				From:   []string{"./definitions"},
				Forbid: []string{"./probes"},
			},
			{
				Name:   "core module is stdlib and go.starlark.net only",
				Why:    "AGENTS.md: the core module imports only the standard library and go.starlark.net; put integrations in a nested module under adapters/",
				From:   []string{"./..."},
				Forbid: []string{archtest.External},
				Allow:  []string{"go.starlark.net/..."},
			},
			{
				Name:   "no artifact-services",
				Why:    "AGENTS.md: the core module must never import artifact-services; integration belongs in adapters/",
				From:   []string{"./..."},
				Forbid: []string{"github.com/craggy-io/artifact-services/..."},
			},
		},
	})
}
