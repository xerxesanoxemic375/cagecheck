package detect

import (
	"fmt"
	"os"
	"runtime"
	"strings"

	"github.com/declaw-ai/cagecheck/internal/checks"
)

type Environment struct {
	Type       string              `json:"type"`
	Boundary   checks.BoundaryType `json:"boundary"`
	Hypervisor string              `json:"hypervisor,omitempty"`
	Runtime    string              `json:"runtime,omitempty"`
	Kernel     string              `json:"kernel"`
	Arch       string              `json:"arch"`
}

func DetectEnvironment() Environment {
	env := Environment{
		Kernel: readKernelVersion(),
		Arch:   runtime.GOARCH,
	}

	env.Hypervisor = detectHypervisor()
	env.Runtime = detectRuntime(env.Hypervisor)
	env.Type = classifyType(env)
	env.Boundary = classifyBoundary(env)

	return env
}

func FormatEnvironment(e Environment) string {
	parts := []string{}
	if e.Runtime != "" {
		parts = append(parts, e.Runtime)
	}
	if e.Type != "" && e.Type != e.Runtime {
		parts = append(parts, e.Type)
	}
	if e.Hypervisor != "" {
		parts = append(parts, fmt.Sprintf("(%s)", e.Hypervisor))
	}
	if len(parts) == 0 {
		return "unknown"
	}
	return strings.Join(parts, " ")
}

func classifyBoundary(env Environment) checks.BoundaryType {
	if env.Runtime == "gvisor" {
		return checks.BoundarySyscall
	}
	if env.Hypervisor != "" {
		return checks.BoundaryHardware
	}
	if isContainerRuntime(env.Runtime) {
		return checks.BoundaryKernel
	}
	if detectAnyContainerMarker() {
		return checks.BoundaryKernel
	}
	return checks.BoundaryUnknown
}

func isContainerRuntime(rt string) bool {
	switch rt {
	case "docker", "podman", "kubernetes", "lxc", "nsjail", "bubblewrap", "systemd-nspawn":
		return true
	}
	return false
}

// --- Kernel version ---

func readKernelVersion() string {
	data, err := os.ReadFile("/proc/version")
	if err != nil {
		return "unknown"
	}
	fields := strings.Fields(string(data))
	if len(fields) >= 3 {
		return fields[2]
	}
	return strings.TrimSpace(string(data))
}

// --- Hypervisor detection ---
// Uses multiple signals: CPUID hypervisor flag, DMI data, /sys/hypervisor.

func detectHypervisor() string {
	if !hasHypervisorFlag() {
		if _, err := os.Stat("/sys/hypervisor/type"); err == nil {
			data, _ := os.ReadFile("/sys/hypervisor/type")
			if strings.TrimSpace(string(data)) == "xen" {
				return "xen"
			}
		}
		return ""
	}

	vendor := readDMI("/sys/class/dmi/id/sys_vendor")
	product := readDMI("/sys/class/dmi/id/product_name")
	boardName := readDMI("/sys/class/dmi/id/board_name")
	vl := strings.ToLower(vendor)
	pl := strings.ToLower(product)
	bl := strings.ToLower(boardName)

	switch {
	case strings.Contains(pl, "virtualbox") || strings.Contains(bl, "virtualbox"):
		return "virtualbox"
	case strings.Contains(vl, "vmware") || strings.Contains(pl, "vmware"):
		return "vmware"
	case strings.Contains(vl, "microsoft") || strings.Contains(pl, "virtual machine"):
		return "hyperv"
	case strings.Contains(vl, "xen") || strings.Contains(pl, "xen"):
		return "xen"
	case strings.Contains(vl, "qemu") || strings.Contains(pl, "kvm") || strings.Contains(vl, "amazon"):
		return "kvm"
	default:
		return "kvm"
	}
}

func hasHypervisorFlag() bool {
	data, err := os.ReadFile("/proc/cpuinfo")
	if err != nil {
		return false
	}
	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, "flags") && strings.Contains(line, "hypervisor") {
			return true
		}
	}
	return false
}

// --- Runtime detection ---
// Order matters: check VM-level indicators first (gVisor, microVM),
// then container markers. A Docker container inside a Firecracker VM
// should be identified as microVM, not Docker.

func detectRuntime(hypervisor string) string {
	if isGVisor() {
		return "gvisor"
	}

	if hypervisor != "" && isMicroVM() {
		return "microvm"
	}

	if isNsjail() {
		return "nsjail"
	}
	if isBubblewrap() {
		return "bubblewrap"
	}
	if isSystemdNspawn() {
		return "systemd-nspawn"
	}
	if _, err := os.Stat("/.dockerenv"); err == nil {
		return "docker"
	}
	if _, err := os.Stat("/run/.containerenv"); err == nil {
		return "podman"
	}
	if isLXC() {
		return "lxc"
	}

	if data, err := os.ReadFile("/proc/1/cgroup"); err == nil {
		s := string(data)
		if strings.Contains(s, "kubepods") {
			return "kubernetes"
		}
		if strings.Contains(s, "docker") || strings.Contains(s, "containerd") {
			return "docker"
		}
		if strings.Contains(s, "lxc") {
			return "lxc"
		}
	}

	return ""
}

// gVisor: only trust explicit signals — /proc/version or /proc/sys/kernel/ostype
// containing "gvisor". No heuristics that could false-positive on minimal containers.
func isGVisor() bool {
	if data, err := os.ReadFile("/proc/version"); err == nil {
		if strings.Contains(strings.ToLower(string(data)), "gvisor") {
			return true
		}
	}
	if data, err := os.ReadFile("/proc/sys/kernel/ostype"); err == nil {
		if strings.Contains(strings.ToLower(string(data)), "gvisor") {
			return true
		}
	}
	return false
}

// MicroVM: hypervisor is present but minimal device model.
// Covers Firecracker, Cloud Hypervisor, and minimal QEMU configs.
func isMicroVM() bool {
	entries, err := os.ReadDir("/sys/bus/pci/devices")
	if err != nil || len(entries) == 0 {
		return true
	}
	// Firecracker and Cloud Hypervisor typically have very few PCI devices (0-3).
	// Full QEMU VMs have 10+. Threshold of 5 covers both minimal VMMs.
	if len(entries) <= 5 {
		return true
	}
	return false
}

func isNsjail() bool {
	// nsjail sets specific environment variable
	if os.Getenv("NSJAIL") != "" {
		return true
	}
	// nsjail's /proc/1/cmdline often contains "nsjail"
	if data, err := os.ReadFile("/proc/1/cmdline"); err == nil {
		if strings.Contains(strings.ToLower(string(data)), "nsjail") {
			return true
		}
	}
	return false
}

func isBubblewrap() bool {
	if data, err := os.ReadFile("/proc/1/cmdline"); err == nil {
		if strings.Contains(string(data), "bwrap") {
			return true
		}
	}
	// bubblewrap creates a minimal mount namespace with /.flatpak-info
	if _, err := os.Stat("/.flatpak-info"); err == nil {
		return true
	}
	return false
}

func isSystemdNspawn() bool {
	// systemd-nspawn sets $container=systemd-nspawn
	if os.Getenv("container") == "systemd-nspawn" {
		return true
	}
	if data, err := os.ReadFile("/run/host/container-manager"); err == nil {
		if strings.TrimSpace(string(data)) == "systemd-nspawn" {
			return true
		}
	}
	return false
}

func isLXC() bool {
	if os.Getenv("container") == "lxc" {
		return true
	}
	if _, err := os.Stat("/dev/lxd"); err == nil {
		return true
	}
	return false
}

// detectAnyContainerMarker checks generic signals that indicate we're
// in some kind of container, even if we can't identify which one.
func detectAnyContainerMarker() bool {
	// /proc/1/cgroup has any non-root path
	if data, err := os.ReadFile("/proc/1/cgroup"); err == nil {
		for _, line := range strings.Split(string(data), "\n") {
			parts := strings.SplitN(line, ":", 3)
			if len(parts) == 3 && parts[2] != "/" && parts[2] != "" {
				return true
			}
		}
	}
	return false
}

func classifyType(env Environment) string {
	switch env.Runtime {
	case "docker", "podman", "kubernetes", "lxc":
		return "container"
	case "nsjail", "bubblewrap", "systemd-nspawn":
		return "sandbox"
	case "gvisor":
		return "gvisor-sandbox"
	case "microvm":
		return "microvm"
	}
	if env.Hypervisor != "" {
		return "vm"
	}
	return "bare-metal"
}

func readDMI(path string) string {
	data, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(data))
}
