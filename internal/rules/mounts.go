package rules

import (
	"fmt"
	"path/filepath"
	"strings"

	"github.com/jayekwere/ocisec/internal/analyzer"
	specs "github.com/opencontainers/runtime-spec/specs-go"
)

type mountsRule struct{}

func (mountsRule) ID() string { return "OCISEC-MOUNT" }

// sensitiveSources are host paths that, when bind-mounted in, hand the container
// a direct route to host control. Matched on the mount Source (host side).
var sensitiveSources = map[string]struct {
	sev    analyzer.Severity
	reason string
}{
	"/var/run/docker.sock":                {analyzer.Critical, "the Docker daemon socket; write access lets the container start a new privileged container and take over the host"},
	"/run/docker.sock":                    {analyzer.Critical, "the Docker daemon socket; write access lets the container start a new privileged container and take over the host"},
	"/var/run/containerd/containerd.sock": {analyzer.Critical, "the containerd socket; equivalent to host control via the container runtime API"},
	"/":                                   {analyzer.Critical, "the entire host root filesystem"},
	"/etc":                                {analyzer.High, "host system configuration, including users and scheduled tasks"},
	"/proc":                               {analyzer.High, "the host proc filesystem, exposing kernel and process internals"},
	"/sys":                                {analyzer.High, "the host sysfs, which can expose writable kernel tunables and cgroup-release-agent escapes"},
	"/dev":                                {analyzer.High, "host devices, including block devices that bypass the container filesystem"},
	"/boot":                               {analyzer.Medium, "host kernel and bootloader files"},
	"/root":                               {analyzer.Medium, "the host root user's home directory and credentials"},
}

func (mountsRule) Check(spec *specs.Spec) []analyzer.Finding {
	var findings []analyzer.Finding
	for _, m := range spec.Mounts {
		src := filepath.Clean(m.Source)
		if d, ok := sensitiveSources[src]; ok {
			ro := mountIsReadonly(m.Options)
			sev := d.sev
			note := "writable"
			if ro {
				note = "read-only"
				// Read-only still leaks data, but removes the write-driven takeover
				// path, so we lower critical findings by one band.
				if sev == analyzer.Critical {
					sev = analyzer.High
				}
			}
			findings = append(findings, analyzer.New(
				"OCISEC-MOUNT",
				fmt.Sprintf("Sensitive host path mounted (%s): %s", note, src),
				sev,
				fmt.Sprintf("Mount of %s exposes %s.", src, d.reason),
				fmt.Sprintf("Remove the bind mount of %s, or scope it to the minimal required subpath and mark it read-only.", src),
				"https://github.com/opencontainers/runtime-spec/blob/main/config.md#mounts",
			))
		}
	}
	return findings
}

func mountIsReadonly(opts []string) bool {
	for _, o := range opts {
		if strings.EqualFold(o, "ro") {
			return true
		}
	}
	return false
}
