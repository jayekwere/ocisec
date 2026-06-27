package rules

import (
	"encoding/json"
	"os"
	"testing"

	"github.com/jayekwere/ocisec/internal/analyzer"
	specs "github.com/opencontainers/runtime-spec/specs-go"
)

// loadFixture parses a testdata spec the same way the CLI does.
func loadFixture(t *testing.T, path string) *specs.Spec {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading fixture %s: %v", path, err)
	}
	var spec specs.Spec
	if err := json.Unmarshal(data, &spec); err != nil {
		t.Fatalf("parsing fixture %s: %v", path, err)
	}
	return &spec
}

// runAll executes every rule, mirroring main.run.
func runAll(spec *specs.Spec) []analyzer.Finding {
	var findings []analyzer.Finding
	for _, r := range All() {
		findings = append(findings, r.Check(spec)...)
	}
	return findings
}

func TestSecureSpecHasNoFindings(t *testing.T) {
	spec := loadFixture(t, "../../testdata/secure.json")
	if findings := runAll(spec); len(findings) != 0 {
		t.Fatalf("hardened spec produced %d finding(s), want 0:\n%+v", len(findings), findings)
	}
}

func TestInsecureSpecTripsExpectedRules(t *testing.T) {
	spec := loadFixture(t, "../../testdata/insecure.json")
	findings := runAll(spec)
	if len(findings) == 0 {
		t.Fatal("insecure spec produced no findings")
	}

	// The gate must see at least one Critical so a default --fail-on=high trips.
	if analyzer.Highest(findings) < analyzer.High {
		t.Fatalf("highest severity = %v, want >= High so the CI gate trips", analyzer.Highest(findings))
	}

	// Spot-check that the marquee escape paths are actually detected.
	wantTitles := []string{
		"Dangerous capability granted: CAP_SYS_ADMIN",
		"Sensitive host path mounted (writable): /var/run/docker.sock",
		"No seccomp profile applied",
		"Host PID namespace shared",
	}
	got := map[string]bool{}
	for _, f := range findings {
		got[f.Title] = true
	}
	for _, want := range wantTitles {
		if !got[want] {
			t.Errorf("expected a finding titled %q, but it was not produced", want)
		}
	}
}

func TestReadonlyDockerSockDowngradesFromCritical(t *testing.T) {
	// A read-only sensitive mount should be reported one band below the
	// writable case, proving the read-only handling is exercised.
	spec := &specs.Spec{
		Mounts: []specs.Mount{
			{Destination: "/host", Source: "/", Type: "bind", Options: []string{"rbind", "ro"}},
		},
	}
	findings := mountsRule{}.Check(spec)
	if len(findings) != 1 {
		t.Fatalf("want 1 mount finding, got %d", len(findings))
	}
	if findings[0].Severity != analyzer.High {
		t.Errorf("read-only host-root mount severity = %v, want High (downgraded from Critical)", findings[0].Severity)
	}
}

func TestEveryRuleHasRemediation(t *testing.T) {
	// A finding with no remediation is not defensible in a review, so enforce it.
	spec := loadFixture(t, "../../testdata/insecure.json")
	for _, f := range runAll(spec) {
		if f.Remediation == "" {
			t.Errorf("finding %q (%s) has no remediation", f.Title, f.RuleID)
		}
	}
}
