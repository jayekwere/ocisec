package rules

import (
	"github.com/jayekwere/ocisec/internal/analyzer"
	specs "github.com/opencontainers/runtime-spec/specs-go"
)

// processRule groups the process- and root-level hardening checks that don't
// warrant their own file individually but each remove a privilege-escalation
// or persistence path.
type processRule struct{}

func (processRule) ID() string { return "OCISEC-PROC" }

func (processRule) Check(spec *specs.Spec) []analyzer.Finding {
	var findings []analyzer.Finding

	if spec.Process != nil {
		// Running as UID 0 means a container breakout starts with host root-
		// equivalent privileges, especially without a user namespace remap.
		if spec.Process.User.UID == 0 {
			findings = append(findings, analyzer.New(
				"OCISEC-PROC-ROOT",
				"Container process runs as root (UID 0)",
				analyzer.Medium,
				"process.user.uid is 0, so the workload runs as root inside the container; any escape begins with root-level privileges on the host unless a user namespace remaps it.",
				"Run as a dedicated non-root UID, and where possible enable a user namespace so in-container root maps to an unprivileged host UID.",
				"https://github.com/opencontainers/runtime-spec/blob/main/config.md#user",
			))
		}

		// noNewPrivileges=false allows setuid binaries and file capabilities to
		// raise privileges after exec - a classic local escalation primitive.
		if !spec.Process.NoNewPrivileges {
			findings = append(findings, analyzer.New(
				"OCISEC-PROC-NNP",
				"noNewPrivileges is not set",
				analyzer.Medium,
				"process.noNewPrivileges is false, so a process can gain privileges via setuid binaries or file capabilities after exec.",
				"Set process.noNewPrivileges to true to block privilege escalation through setuid/setgid binaries.",
				"https://github.com/opencontainers/runtime-spec/blob/main/config.md#linux-process",
			))
		}
	}

	if spec.Root != nil && !spec.Root.Readonly {
		findings = append(findings, analyzer.New(
			"OCISEC-PROC-ROOTFS",
			"Root filesystem is writable",
			analyzer.Low,
			"root.readonly is false; an attacker who lands code execution can modify the container filesystem for persistence or tampering.",
			"Set root.readonly to true and mount explicit writable volumes only where the workload needs them.",
			"https://github.com/opencontainers/runtime-spec/blob/main/config.md#root",
		))
	}

	// The runtime masks paths like /proc/kcore and /sys/firmware to prevent
	// kernel-memory disclosure; an empty list usually means those defaults were
	// stripped out.
	if spec.Linux != nil && len(spec.Linux.MaskedPaths) == 0 {
		findings = append(findings, analyzer.New(
			"OCISEC-PROC-MASK",
			"No masked paths configured",
			analyzer.Medium,
			"linux.maskedPaths is empty, so sensitive kernel interfaces (e.g. /proc/kcore, /proc/sysrq-trigger) are not hidden from the container.",
			"Restore the default masked paths so kernel-memory and host-control interfaces are not readable inside the container.",
			"https://github.com/opencontainers/runtime-spec/blob/main/config-linux.md#masked-paths",
		))
	}

	return findings
}
