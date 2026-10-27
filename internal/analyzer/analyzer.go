// Package analyzer defines the core types shared across ocisec: severities,
// findings, and the rank ordering used to drive CI gating decisions.
package analyzer

import "fmt"

// Severity describes how dangerous a finding is. The ordering matters: it is
// what the CI gate compares against the configured --fail-on threshold.
type Severity int

const (
	Info Severity = iota
	Low
	Medium
	High
	Critical
)

// String returns the lowercase name used in CLI flags and text output.
func (s Severity) String() string {
	switch s {
	case Critical:
		return "critical"
	case High:
		return "high"
	case Medium:
		return "medium"
	case Low:
		return "low"
	default:
		return "info"
	}
}

// ParseSeverity converts a flag value (e.g. "high") into a Severity.
func ParseSeverity(v string) (Severity, error) {
	switch v {
	case "critical":
		return Critical, nil
	case "high":
		return High, nil
	case "medium":
		return Medium, nil
	case "low":
		return Low, nil
	case "info":
		return Info, nil
	default:
		return Info, fmt.Errorf("unknown severity %q (want one of: critical, high, medium, low, info)", v)
	}
}

// Finding is a single issue detected in an OCI runtime spec. Remediation and
// Reference exist so the output is defensible, not just a label - every finding
// explains why it matters and how to fix it.
type Finding struct {
	RuleID      string   `json:"rule_id"`
	Title       string   `json:"title"`
	Severity    Severity `json:"-"`
	SeverityStr string   `json:"severity"`
	Detail      string   `json:"detail"`
	Remediation string   `json:"remediation"`
	Reference   string   `json:"reference,omitempty"`
}

// New builds a Finding and fills the string severity used for JSON output.
func New(ruleID, title string, sev Severity, detail, remediation, ref string) Finding {
	return Finding{
		RuleID:      ruleID,
		Title:       title,
		Severity:    sev,
		SeverityStr: sev.String(),
		Detail:      detail,
		Remediation: remediation,
		Reference:   ref,
	}
}

// Highest returns the most severe finding level in the set, or Info if empty.
func Highest(findings []Finding) Severity {
	top := Info
	for _, f := range findings {
		if f.Severity > top {
			top = f.Severity
		}
	}
	return top
}
