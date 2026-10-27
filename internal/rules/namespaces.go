package rules

import (
	"github.com/jayekwere/ocisec/internal/analyzer"
	specs "github.com/opencontainers/runtime-spec/specs-go"
)

// In an OCI spec, linux.namespaces lists the namespaces the container is placed
// into. If a namespace type is ABSENT from that list, the container shares the
// host's namespace of that type - which is the isolation boundary we care about.
type namespacesRule struct{}

func (namespacesRule) ID() string { return "OCISEC-NS" }

func (namespacesRule) Check(spec *specs.Spec) []analyzer.Finding {
	var findings []analyzer.Finding
	if spec.Linux == nil {
		return findings
	}

	present := map[specs.LinuxNamespaceType]bool{}
	for _, ns := range spec.Linux.Namespaces {
		present[ns.Type] = true
	}

	checks := []struct {
		nsType specs.LinuxNamespaceType
		name   string
		sev    analyzer.Severity
		reason string
	}{
		{specs.PIDNamespace, "PID", analyzer.High, "shares the host process tree: the container can see, signal and (with CAP_SYS_PTRACE) inspect or inject into host processes"},
		{specs.NetworkNamespace, "network", analyzer.High, "shares the host network stack: access to host-loopback services, traffic sniffing, and binding privileged host ports"},
		{specs.IPCNamespace, "IPC", analyzer.Medium, "shares host System V IPC and POSIX message queues, allowing cross-container/host data access"},
		{specs.UTSNamespace, "UTS", analyzer.Low, "shares the host hostname/domain namespace; the container can change the host's hostname"},
		{specs.MountNamespace, "mount", analyzer.High, "shares the host mount namespace, exposing host filesystems directly"},
	}

	for _, c := range checks {
		if !present[c.nsType] {
			findings = append(findings, analyzer.New(
				"OCISEC-NS",
				"Host "+c.name+" namespace shared",
				c.sev,
				"The "+c.name+" namespace is not declared in linux.namespaces, so the container "+c.reason+".",
				"Add a "+c.name+" namespace entry so the container is isolated from the host (equivalent to avoiding --"+nsFlag(c.name)+" in Docker/Kubernetes hostNetwork/hostPID settings).",
				"https://github.com/opencontainers/runtime-spec/blob/main/config-linux.md#namespaces",
			))
		}
	}
	return findings
}

func nsFlag(name string) string {
	switch name {
	case "network":
		return "net=host"
	case "PID":
		return "pid=host"
	case "IPC":
		return "ipc=host"
	default:
		return "host-namespace"
	}
}
