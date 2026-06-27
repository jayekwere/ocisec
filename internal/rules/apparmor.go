package rules

import (
	"strings"

	"github.com/jayekwere/ocisec/internal/analyzer"
	specs "github.com/opencontainers/runtime-spec/specs-go"
)

type apparmorRule struct{}

func (apparmorRule) ID() string { return "OCISEC-APPARMOR" }

func (apparmorRule) Check(spec *specs.Spec) []analyzer.Finding {
	var findings []analyzer.Finding
	if spec.Process == nil {
		return findings
	}

	profile := strings.TrimSpace(spec.Process.ApparmorProfile)

	// An empty profile means no mandatory access control is requested; an
	// explicit "unconfined" profile actively disables it. Both leave file and
	// capability access governed only by DAC, removing a defense-in-depth layer.
	if profile == "" {
		findings = append(findings, analyzer.New(
			"OCISEC-APPARMOR",
			"No AppArmor profile specified",
			analyzer.Medium,
			"process.apparmorProfile is empty, so no mandatory access control (MAC) profile constrains the container's file and capability access.",
			"Set process.apparmorProfile to a confined profile (e.g. the runtime default such as 'docker-default') on AppArmor-enabled hosts.",
			"https://github.com/opencontainers/runtime-spec/blob/main/config-linux.md#apparmor-profile",
		))
	} else if strings.EqualFold(profile, "unconfined") {
		findings = append(findings, analyzer.New(
			"OCISEC-APPARMOR",
			"AppArmor explicitly set to unconfined",
			analyzer.High,
			"process.apparmorProfile is 'unconfined', which deliberately disables AppArmor confinement for the container.",
			"Replace 'unconfined' with a real confined profile unless a specific, documented workload requirement justifies it.",
			"https://github.com/opencontainers/runtime-spec/blob/main/config-linux.md#apparmor-profile",
		))
	}
	return findings
}
