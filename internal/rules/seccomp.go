package rules

import (
	"github.com/jayekwere/ocisec/internal/analyzer"
	specs "github.com/opencontainers/runtime-spec/specs-go"
)

type seccompRule struct{}

func (seccompRule) ID() string { return "OCISEC-SECCOMP" }

func (seccompRule) Check(spec *specs.Spec) []analyzer.Finding {
	var findings []analyzer.Finding
	if spec.Linux == nil {
		return findings
	}

	// A nil Seccomp block means no syscall filtering: the full kernel syscall
	// surface (~350 syscalls) is reachable, widening the path to a kernel exploit.
	if spec.Linux.Seccomp == nil {
		findings = append(findings, analyzer.New(
			"OCISEC-SECCOMP",
			"No seccomp profile applied",
			analyzer.High,
			"linux.seccomp is absent, so syscall filtering is disabled and the container can issue any syscall the kernel exposes.",
			"Apply a seccomp profile (the runtime default blocks ~44 dangerous syscalls). Avoid the 'unconfined' profile in production.",
			"https://github.com/opencontainers/runtime-spec/blob/main/config-linux.md#seccomp",
		))
		return findings
	}

	// SCMP_ACT_ALLOW as the default action is effectively unconfined: every
	// syscall is permitted unless explicitly denied, which inverts allow-listing.
	if spec.Linux.Seccomp.DefaultAction == specs.ActAllow {
		findings = append(findings, analyzer.New(
			"OCISEC-SECCOMP",
			"Seccomp default action is ALLOW",
			analyzer.Medium,
			"The seccomp default action is SCMP_ACT_ALLOW, which permits all syscalls unless individually blocked - the opposite of a deny-by-default posture.",
			"Set the default action to SCMP_ACT_ERRNO or SCMP_ACT_KILL and allow-list only the syscalls the workload needs.",
			"https://github.com/opencontainers/runtime-spec/blob/main/config-linux.md#seccomp",
		))
	}
	return findings
}
