package analyzer

import "testing"

func TestParseSeverity(t *testing.T) {
	cases := map[string]struct {
		want    Severity
		wantErr bool
	}{
		"critical": {Critical, false},
		"high":     {High, false},
		"medium":   {Medium, false},
		"low":      {Low, false},
		"info":     {Info, false},
		"bogus":    {Info, true},
	}
	for in, c := range cases {
		got, err := ParseSeverity(in)
		if c.wantErr && err == nil {
			t.Errorf("ParseSeverity(%q): expected error, got nil", in)
			continue
		}
		if !c.wantErr && err != nil {
			t.Errorf("ParseSeverity(%q): unexpected error %v", in, err)
			continue
		}
		if !c.wantErr && got != c.want {
			t.Errorf("ParseSeverity(%q) = %v, want %v", in, got, c.want)
		}
	}
}

func TestSeverityOrdering(t *testing.T) {
	// The CI gate depends on this ordering, so assert it explicitly.
	if !(Critical > High && High > Medium && Medium > Low && Low > Info) {
		t.Fatal("severity ordering is broken; CI gating comparisons would be wrong")
	}
}

func TestHighest(t *testing.T) {
	if got := Highest(nil); got != Info {
		t.Errorf("Highest(nil) = %v, want Info", got)
	}
	findings := []Finding{
		New("A", "a", Low, "", "", ""),
		New("B", "b", Critical, "", "", ""),
		New("C", "c", Medium, "", "", ""),
	}
	if got := Highest(findings); got != Critical {
		t.Errorf("Highest = %v, want Critical", got)
	}
}

func TestNewFillsSeverityString(t *testing.T) {
	f := New("X", "title", High, "detail", "fix", "ref")
	if f.SeverityStr != "high" {
		t.Errorf("SeverityStr = %q, want %q", f.SeverityStr, "high")
	}
}
