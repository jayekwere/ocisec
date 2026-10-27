package rules

import (
	"fmt"

	"github.com/jayekwere/ocisec/internal/analyzer"
	specs "github.com/opencontainers/runtime-spec/specs-go"
)

// dangerousCaps maps a capability to its severity and the escape/abuse path it
// opens. The "why" is deliberately stored next to the rule so the output can be
// defended in a review, not just flagged.
var dangerousCaps = map[string]struct {
	sev    analyzer.Severity
	reason string
}{
	"CAP_SYS_ADMIN":       {analyzer.Critical, "the broadest capability; permits mount, pivot_root, BPF and namespace operations - effectively a kernel-level escape primitive"},
	"CAP_SYS_MODULE":      {analyzer.Critical, "load/unload kernel modules, giving direct, full control of the host kernel"},
	"CAP_SYS_RAWIO":       {analyzer.Critical, "raw I/O port and /dev/mem access; can read or overwrite kernel memory"},
	"CAP_SYS_PTRACE":      {analyzer.High, "attach to and modify other processes; combined with a shared host PID namespace this enables host process injection"},
	"CAP_DAC_READ_SEARCH": {analyzer.High, "bypass file read permission checks; enabled the Shocker-style host filesystem read escape"},
	"CAP_DAC_OVERRIDE":    {analyzer.High, "bypass all file permission checks inside the container, undermining least privilege"},
	"CAP_SYS_BOOT":        {analyzer.High, "reboot the host or load a new kernel"},
	"CAP_SYS_CHROOT":      {analyzer.Medium, "use chroot; a building block in some breakout chains"},
	"CAP_NET_ADMIN":       {analyzer.High, "reconfigure host networking, interfaces and firewall rules"},
	"CAP_NET_RAW":         {analyzer.Medium, "craft raw packets; enables spoofing and traffic sniffing"},
	"CAP_BPF":             {analyzer.High, "load BPF programs; a growing kernel attack surface"},
	"CAP_PERFMON":         {analyzer.Medium, "performance monitoring syscalls that expose kernel data"},
	"CAP_SYSLOG":          {analyzer.Medium, "read kernel logs, leaking addresses useful for exploitation"},
}

type capabilitiesRule struct{}

func (capabilitiesRule) ID() string { return "OCISEC-CAP" }

func (capabilitiesRule) Check(spec *specs.Spec) []analyzer.Finding {
	var findings []analyzer.Finding
	if spec.Process == nil || spec.Process.Capabilities == nil {
		return findings
	}

	// The effective + bounding sets are what actually constrain the process at
	// runtime, so we inspect both and de-duplicate.
	seen := map[string]bool{}
	for _, set := range [][]string{spec.Process.Capabilities.Effective, spec.Process.Capabilities.Bounding, spec.Process.Capabilities.Permitted} {
		for _, cap := range set {
			if seen[cap] {
				continue
			}
			if d, ok := dangerousCaps[cap]; ok {
				seen[cap] = true
				findings = append(findings, analyzer.New(
					"OCISEC-CAP",
					fmt.Sprintf("Dangerous capability granted: %s", cap),
					d.sev,
					fmt.Sprintf("%s %s.", cap, d.reason),
					fmt.Sprintf("Drop %s unless the workload provably requires it; prefer a minimal, explicit capability set over the default bounding set.", cap),
					"https://man7.org/linux/man-pages/man7/capabilities.7.html",
				))
			}
		}
	}
	return findings
}
