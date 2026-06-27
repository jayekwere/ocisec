// Command ocisec is a static analyzer for OCI runtime specifications
// (config.json). It parses a spec against the upstream opencontainers
// runtime-spec Go types and reports container-escape and isolation
// misconfigurations, returning a non-zero exit code when findings meet or
// exceed a configurable severity threshold so it can act as a CI gate.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"sort"

	"github.com/jayekwere/ocisec/internal/analyzer"
	"github.com/jayekwere/ocisec/internal/rules"
	specs "github.com/opencontainers/runtime-spec/specs-go"
)

// version is overridable at build time via -ldflags "-X main.version=...".
var version = "dev"

// Exit codes are deliberate and documented so CI pipelines can branch on them:
//
//	0 = clean (no findings at or above --fail-on)
//	1 = gate tripped (findings at or above --fail-on)
//	2 = usage or runtime error (could not analyze)
const (
	exitClean = 0
	exitGate  = 1
	exitError = 2
)

func main() {
	os.Exit(run())
}

func run() int {
	input := flag.String("input", "config.json", "path to the OCI runtime spec (config.json)")
	format := flag.String("format", "text", "output format: text or json")
	failOn := flag.String("fail-on", "high", "minimum severity that fails the gate: critical|high|medium|low|info")
	showVersion := flag.Bool("version", false, "print version and exit")
	flag.Parse()

	if *showVersion {
		fmt.Println("ocisec", version)
		return exitClean
	}

	threshold, err := analyzer.ParseSeverity(*failOn)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return exitError
	}

	spec, err := loadSpec(*input)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return exitError
	}

	var findings []analyzer.Finding
	for _, r := range rules.All() {
		findings = append(findings, r.Check(spec)...)
	}

	// Sort most-severe first for a readable report.
	sort.SliceStable(findings, func(i, j int) bool {
		return findings[i].Severity > findings[j].Severity
	})

	switch *format {
	case "json":
		printJSON(findings)
	case "text":
		printText(*input, findings)
	default:
		fmt.Fprintf(os.Stderr, "error: unknown format %q\n", *format)
		return exitError
	}

	if analyzer.Highest(findings) >= threshold && len(findings) > 0 {
		return exitGate
	}
	return exitClean
}

func loadSpec(path string) (*specs.Spec, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading spec: %w", err)
	}
	var spec specs.Spec
	if err := json.Unmarshal(data, &spec); err != nil {
		return nil, fmt.Errorf("parsing spec as OCI runtime config: %w", err)
	}
	return &spec, nil
}

func printText(input string, findings []analyzer.Finding) {
	fmt.Printf("ocisec %s — analyzing %s\n\n", version, input)
	if len(findings) == 0 {
		fmt.Println("No findings. Spec passed all ocisec checks.")
		return
	}
	counts := map[analyzer.Severity]int{}
	for _, f := range findings {
		counts[f.Severity]++
		fmt.Printf("[%s] %s (%s)\n", upper(f.SeverityStr), f.Title, f.RuleID)
		fmt.Printf("    why:  %s\n", f.Detail)
		fmt.Printf("    fix:  %s\n", f.Remediation)
		if f.Reference != "" {
			fmt.Printf("    ref:  %s\n", f.Reference)
		}
		fmt.Println()
	}
	fmt.Printf("Summary: %d finding(s) — %d critical, %d high, %d medium, %d low\n",
		len(findings),
		counts[analyzer.Critical], counts[analyzer.High], counts[analyzer.Medium], counts[analyzer.Low])
}

func printJSON(findings []analyzer.Finding) {
	if findings == nil {
		findings = []analyzer.Finding{}
	}
	out := struct {
		Findings []analyzer.Finding `json:"findings"`
		Count    int                `json:"count"`
		Highest  string             `json:"highest_severity"`
	}{
		Findings: findings,
		Count:    len(findings),
		Highest:  analyzer.Highest(findings).String(),
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	_ = enc.Encode(out)
}

func upper(s string) string {
	if s == "" {
		return s
	}
	b := []byte(s)
	if b[0] >= 'a' && b[0] <= 'z' {
		b[0] -= 32
	}
	return string(b)
}
