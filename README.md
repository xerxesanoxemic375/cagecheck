# cagecheck

Check if your sandbox can be escaped.

`cagecheck` is a single static binary that runs **inside** any sandbox and checks for concrete escape vectors. It detects the isolation boundary (hardware VM, syscall interception, or kernel namespaces) and runs the appropriate checks, outputting a pass/fail checklist.

Works with Docker, gVisor, Firecracker, Kata Containers, nsjail, bubblewrap, and anything else running Linux.

## Quick Start

```bash
# Download the binary
curl -fsSL https://github.com/declaw-ai/cagecheck/releases/latest/download/cagecheck-linux-amd64 \
  -o cagecheck && chmod +x cagecheck

# Run it
./cagecheck
```

Or via Docker:

```bash
docker run --rm ghcr.io/declaw-ai/cagecheck
```

## Output

```
cagecheck v0.1.0

  Environment:  docker container
  Boundary:     kernel

  ESCAPE CHECKLIST
  ──────────────────────────────────────────────────────────────────────
  [PASS]  Cloud metadata service (169.254.169.254) not reachable
  [FAIL]  Unrestricted outbound internet access (reached 1.1.1.1:443)
  [PASS]  Host gateway (172.17.0.1) has no exposed services
  [PASS]  No Kubernetes credentials exposed
  [PASS]  No container runtime sockets exposed
  [PASS]  Container is not in privileged mode
  [PASS]  No dangerous escape-enabling capabilities
  [PASS]  Seccomp filtering is active
  [FAIL]  Host PID namespace shared — host processes visible
  [PASS]  No writable /proc or /sys escape paths
  [PASS]  CAP_SYS_ADMIN not available — cgroup release_agent escape not possible
  [PASS]  No host filesystem exposure detected
  [PASS]  No dangerous device files accessible
  [PASS]  Kernel 6.8.0 has no known critical escape CVEs
  [PASS]  No critical information leakage detected

  2 failed, 13 passed
```

When running inside a Firecracker microVM, kernel-level checks are automatically skipped (the VM boundary replaces them):

```
cagecheck v0.1.0

  Environment:  microvm (kvm)
  Boundary:     hardware

  ESCAPE CHECKLIST
  ──────────────────────────────────────────────────────────────────────
  [PASS]  Cloud metadata service (169.254.169.254) not reachable
  [FAIL]  Unrestricted outbound internet access (reached 1.1.1.1:443)
  [PASS]  Host gateway (169.254.0.22) has no exposed services
  [PASS]  No Kubernetes credentials exposed
  [N/A ]  Runtime socket check — not applicable (hardware isolation)
  [N/A ]  Privileged mode check — not applicable (hardware isolation)
  ...
  [N/A ]  Info leakage checks — not applicable (hardware isolation)

  1 failed, 3 passed
```

## Flags

```
./cagecheck                  # terminal checklist
./cagecheck --json           # machine-readable JSON
./cagecheck --report         # full Markdown report
./cagecheck --findings       # include detailed probe findings
./cagecheck --quiet          # JSON only, no terminal output
./cagecheck --version        # print version
```

Exit code is 1 if any check fails, 0 if all pass. Use in CI:

```bash
./cagecheck --quiet || echo "Sandbox has escape vectors"
```

## What It Checks

**Universal checks (all sandbox types):**

| Check | Why it matters |
|-------|---------------|
| Metadata service | Cloud providers expose temporary credentials at 169.254.169.254. If reachable, an attacker can steal the instance's IAM credentials, access cloud APIs (S3, EC2, etc.), and pivot into the infrastructure. |
| Outbound internet | Unrestricted egress allows data exfiltration, command-and-control communication, and downloading attack tools from external servers. |
| Gateway services | If the host's gateway exposes services (SSH, Docker API, etc.), an attacker inside the sandbox can reach host infrastructure directly. |
| K8s credentials | Kubernetes service account tokens and API server env vars, if present inside the sandbox, allow cluster-level operations — listing pods, reading secrets, or deploying workloads. |

**Kernel-boundary checks (Docker, Podman, nsjail, etc.):**

| Check | Why it matters |
|-------|---------------|
| Runtime sockets | An exposed Docker or containerd socket allows spawning a privileged container and escaping to the host. |
| Privileged mode | A privileged container has all Linux capabilities, all devices, no seccomp — trivial escape via `nsenter` or device mount. |
| Dangerous capabilities | Capabilities like SYS_ADMIN (mount, cgroup escape), SYS_PTRACE (process injection), SYS_MODULE (kernel module loading) each enable specific escape paths. |
| Seccomp | Without syscall filtering, dangerous syscalls like `mount`, `ptrace`, and `unshare` are available for escape. |
| Namespace breakout | If the sandbox shares the host PID namespace, an attacker can see all host processes. Combined with CAP_SYS_PTRACE, they can inject code into them. |
| Writable /proc paths | Writing to `/proc/sys/kernel/core_pattern` enables remote code execution on the host when any process crashes. Writing to `/proc/sysrq-trigger` can reboot the host. |
| Cgroup escape | With CAP_SYS_ADMIN and cgroup v1, an attacker can write a payload to `release_agent` which executes as host root when the cgroup empties. |
| Host filesystem | Mounted host paths (/, /etc, /root) give direct read/write access to host files — credentials, crontabs, SSH keys. |
| Dangerous devices | Access to `/dev/mem` or `/dev/kmem` allows direct physical or kernel memory read/write — full host compromise. |
| Kernel CVEs | Containers share the host kernel. Known vulnerabilities (Dirty Pipe, cgroup escape, nf_tables) can be exploited from inside a container to gain host root. VMs are not affected since they run a separate kernel. |
| Info leakage | Readable `/proc/sched_debug` exposes all host process names and PIDs across namespace boundaries. `/proc/kallsyms` with real addresses defeats KASLR, making kernel exploitation easier. |

**Hardware-boundary sandboxes (Firecracker, Kata, Cloud Hypervisor):**
Kernel-level checks are marked N/A — the VM boundary replaces them. Only network checks apply.

**Syscall-interception sandboxes (gVisor):**
Kernel-level checks are marked N/A — the userspace kernel replaces host kernel controls. Only network checks apply.

## Isolation Boundary Detection

cagecheck automatically detects the isolation boundary:

| Boundary | Detected by | Examples |
|----------|-------------|---------|
| `hardware` | CPUID hypervisor flag + minimal PCI devices | Firecracker, Cloud Hypervisor, Kata |
| `hardware` | CPUID hypervisor flag + full PCI | QEMU, VirtualBox, VMware |
| `syscall-interception` | `/proc/version` contains "gvisor" | gVisor (runsc) |
| `kernel` | `/.dockerenv`, cgroup markers, env vars | Docker, Podman, K8s, LXC, nsjail, bubblewrap |
| `unknown` | Nothing matched (gets all checks) | Bare metal, unrecognized |

## Results Across Providers (May 2026)

We ran cagecheck against 7 sandbox providers using their default configurations:

| Check | A | B | C | D | E | F | G |
|-------|:---:|:---:|:---:|:---:|:---:|:---:|:---:|
| **Boundary** | hardware | hardware | hardware | hardware | hardware | kernel | kernel |
| Metadata service | PASS | PASS | PASS | FAIL | FAIL | FAIL | PASS |
| Outbound internet | FAIL | FAIL | FAIL | FAIL | FAIL | FAIL | FAIL |
| Gateway services | PASS | PASS | PASS | PASS | PASS | FAIL | PASS |
| K8s credentials | PASS | PASS | PASS | PASS | PASS | PASS | PASS |
| Runtime sockets | N/A | N/A | N/A | N/A | N/A | PASS | PASS |
| Privileged mode | N/A | N/A | N/A | N/A | N/A | PASS | PASS |
| Capabilities | N/A | N/A | N/A | N/A | N/A | PASS | PASS |
| Seccomp | N/A | N/A | N/A | N/A | N/A | PASS | PASS |
| Namespace breakout | N/A | N/A | N/A | N/A | N/A | FAIL | PASS |
| Writable /proc | N/A | N/A | N/A | N/A | N/A | PASS | PASS |
| Cgroup escape | N/A | N/A | N/A | N/A | N/A | PASS | PASS |
| Host filesystem | N/A | N/A | N/A | N/A | N/A | FAIL | FAIL |
| Dangerous devices | N/A | N/A | N/A | N/A | N/A | PASS | PASS |
| Kernel CVEs | N/A | N/A | N/A | N/A | N/A | PASS | PASS |
| Info leakage | N/A | N/A | N/A | N/A | N/A | PASS | PASS |
| **Failed** | **1** | **1** | **1** | **2** | **2** | **5** | **2** |
| **Passed** | **3** | **3** | **3** | **2** | **2** | **10** | **13** |

All providers were tested with default sandbox configurations. Some failures may be intentional design choices (e.g., outbound internet access is required for many use cases). Run cagecheck yourself to verify.

## Build from Source

```bash
make build          # native platform
make build-all      # linux/amd64 + linux/arm64
```

## Design Principles

- **Zero dependencies** -- single static binary, no runtime requirements
- **Safe by default** -- read-only probes, no active exploitation, no destructive actions
- **Vendor-neutral** -- no provider-specific code, tests universal Linux primitives
- **No telemetry** -- no phone-home, no analytics, no tracking
- **Boundary-aware** -- automatically adjusts checks based on detected isolation type

## License

MIT
