// Package rules holds the individual security checks ocisec runs against an
// OCI runtime spec. Each rule is small, self-contained, and explains the
// container-escape or isolation risk it detects.
package rules

import (
	"github.com/jayekwere/ocisec/internal/analyzer"
	specs "github.com/opencontainers/runtime-spec/specs-go"
)

// Rule is a single check over a parsed OCI runtime spec. Returning a slice
// (rather than one finding) lets a rule report several distinct issues, e.g.
// multiple dangerous capabilities in one set.
type Rule interface {
	ID() string
	Check(spec *specs.Spec) []analyzer.Finding
}

// All returns every rule ocisec runs, in a stable order.
func All() []Rule {
	return []Rule{
		capabilitiesRule{},
		namespacesRule{},
		seccompRule{},
		apparmorRule{},
		mountsRule{},
		processRule{},
	}
}
