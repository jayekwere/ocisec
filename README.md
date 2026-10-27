# ocisec

`ocisec` is a static analyzer for **OCI runtime specifications** (`config.json`). It parses a spec against the upstream [`opencontainers/runtime-spec`](https://github.com/opencontainers/runtime-spec) Go types and reports container-escape and isolation misconfigurations, returning a severity-aware exit code so it can act as a **CI gate**.

It checks the configuration before the container runs. Findings include a severity, an explanation and a suggested fix.

## Why

OCI runtime configurations expose settings such as capabilities, namespaces, mounts and syscall filters. This tool checks those fields using the runtime-spec Go types and returns an exit code that CI can use to reject unsafe configurations.

## Install

```sh
go install github.com/jayekwere/ocisec@latest
```

Or build from source:

```sh
git clone https://github.com/jayekwere/ocisec.git
cd ocisec
go build -o ocisec .
```

## Usage

```sh
ocisec --input config.json
ocisec --input config.json --format json
ocisec --input config.json --fail-on critical
```

| Flag        | Default       | Description                                              |
|-------------|---------------|----------------------------------------------------------|
| `--input`   | `config.json` | Path to the OCI runtime spec.                            |
| `--format`  | `text`        | Output format: `text` or `json`.                         |
| `--fail-on` | `high`        | Minimum severity that fails the gate: `critical`/`high`/`medium`/`low`/`info`. |
| `--version` | -             | Print version and exit.                                  |

### Exit codes (the CI contract)

| Code | Meaning                                                |
|------|--------------------------------------------------------|
| `0`  | Clean - no findings at or above `--fail-on`.            |
| `1`  | Gate tripped - findings at or above `--fail-on`.        |
| `2`  | Usage or runtime error (spec could not be analyzed).   |

## What it checks

Each rule maps a misconfiguration to the concrete attack path it enables.

| Rule ID            | Checks for                                            | Why it matters                                                                 |
|--------------------|------------------------------------------------------|-------------------------------------------------------------------------------|
| `OCISEC-CAP`       | Dangerous Linux capabilities (e.g. `CAP_SYS_ADMIN`)  | Capabilities like `SYS_ADMIN`/`SYS_MODULE` are kernel-level escape primitives. |
| `OCISEC-NS`        | Host namespaces shared (pid/net/ipc/uts/mount)       | A namespace absent from `linux.namespaces` means the host's is shared.          |
| `OCISEC-SECCOMP`   | Missing seccomp / `SCMP_ACT_ALLOW` default           | No syscall filtering widens the path to a kernel exploit.                       |
| `OCISEC-APPARMOR`  | Missing or `unconfined` AppArmor profile             | Removes a mandatory-access-control defense-in-depth layer.                      |
| `OCISEC-MOUNT`     | Sensitive host bind mounts (docker.sock, `/`, `/proc`…) | A mounted runtime socket or host root is direct host takeover.               |
| `OCISEC-PROC-*`    | UID 0, `noNewPrivileges`, writable rootfs, masked paths | Each removes a privilege-escalation or persistence path.                     |

Read-only sensitive mounts are reported one severity band lower than writable ones, since the write-driven takeover path is removed.

## CI integration

Example GitHub Actions step:

```yaml
- name: Scan container runtime spec
  run: |
    go build -o ocisec .
    ./ocisec --input path/to/config.json --fail-on high
```

A non-zero exit fails the job. The [CI workflow](.github/workflows/ci.yml) builds, vets, tests, scans the hardened fixture (must pass), and asserts the gate trips on the insecure fixture.

## Design notes

- **Parsing.** The spec is unmarshaled into `specs.Spec` from `opencontainers/runtime-spec`, so checks reflect the actual schema and survive formatting changes.
- **Scope.** `ocisec` analyzes configuration only. It does not observe a running container, enforce policy at admission, or replace runtime detection.
- **Finding details.** Every finding carries a severity, the risk it represents, a remediation, and a spec/man-page reference.

## Limitations

- Analyzes a single OCI `config.json` at a time; it does not interpret higher-level Docker Compose / Kubernetes manifests directly (convert or generate the runtime spec first).
- Severity ratings are sensible defaults, not a substitute for environment-specific risk judgment.
- Not a runtime security tool (no eBPF, no admission control, no live monitoring).

## License

MIT - see [LICENSE](LICENSE).
