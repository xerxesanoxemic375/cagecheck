package checks

import (
	"fmt"
	"os"
	"strconv"
	"strings"
)

type EscapeVectorCheck struct{}

func (e *EscapeVectorCheck) Category() string { return "Escape Vectors" }

func (e *EscapeVectorCheck) Run() []Result {
	var results []Result

	results = append(results, checkPrivilegedEscape())
	results = append(results, checkDockerSocketEscape())
	results = append(results, checkCgroupReleaseAgent())
	results = append(results, checkPIDNSPtrace())
	results = append(results, checkDirtyPipe())
	results = append(results, checkCorePatternEscape())
	results = append(results, checkDeviceAccess())

	return results
}

func checkPrivilegedEscape() Result {
	status := readProcStatus()
	capEff := parseCapHex(status["CapEff"])
	if isFullCaps(capEff) {
		return Result{
			Name:     "privileged_escape",
			Status:   Fail,
			Severity: Critical,
			Detail:   "Privileged container — trivial host escape via nsenter or device mount",
		}
	}
	return Result{
		Name:     "privileged_escape",
		Status:   Pass,
		Severity: Critical,
		Detail:   "Container is not privileged",
	}
}

func checkDockerSocketEscape() Result {
	for _, path := range []string{"/var/run/docker.sock", "/run/containerd/containerd.sock"} {
		info, err := os.Stat(path)
		if err != nil {
			continue
		}
		if info.Mode()&os.ModeSocket != 0 {
			return Result{
				Name:     "socket_escape",
				Status:   Fail,
				Severity: Critical,
				Detail:   fmt.Sprintf("Container runtime socket at %s — escape via spawning privileged container", path),
			}
		}
	}
	return Result{
		Name:     "socket_escape",
		Status:   Pass,
		Severity: Critical,
		Detail:   "No container runtime sockets accessible",
	}
}

func checkCgroupReleaseAgent() Result {
	status := readProcStatus()
	capEff := parseCapHex(status["CapEff"])
	hasSysAdmin := (capEff & (1 << 21)) != 0

	if !hasSysAdmin {
		return Result{
			Name:     "cgroup_release_agent",
			Status:   Pass,
			Severity: High,
			Detail:   "CAP_SYS_ADMIN not available — cgroup release_agent escape not possible",
		}
	}

	_, err := os.ReadFile("/sys/fs/cgroup/release_agent")
	if err == nil {
		return Result{
			Name:     "cgroup_release_agent",
			Status:   Fail,
			Severity: High,
			Detail:   "CAP_SYS_ADMIN + cgroup release_agent accessible — Felix Wilhelm escape possible",
		}
	}

	return Result{
		Name:     "cgroup_release_agent",
		Status:   Warn,
		Severity: High,
		Detail:   "CAP_SYS_ADMIN present but release_agent not directly accessible — cgroup mount may still enable escape",
	}
}

func checkPIDNSPtrace() Result {
	selfNS := readNamespaceInodes("/proc/self/ns")
	initNS := readNamespaceInodes("/proc/1/ns")

	sharedPID := selfNS["pid"] != "" && initNS["pid"] != "" && selfNS["pid"] == initNS["pid"]

	status := readProcStatus()
	capEff := parseCapHex(status["CapEff"])
	hasPtrace := (capEff & (1 << 19)) != 0

	if sharedPID && hasPtrace {
		return Result{
			Name:     "pid_ns_ptrace",
			Status:   Fail,
			Severity: High,
			Detail:   "Host PID namespace + CAP_SYS_PTRACE — can inject code into host processes",
		}
	}
	return Result{
		Name:     "pid_ns_ptrace",
		Status:   Pass,
		Severity: High,
		Detail:   "PID namespace isolated or ptrace not available",
	}
}

func checkDirtyPipe() Result {
	data, err := os.ReadFile("/proc/version")
	if err != nil {
		return Result{
			Name:     "dirty_pipe",
			Status:   Skip,
			Severity: High,
			Detail:   "Could not determine kernel version",
		}
	}

	version := string(data)
	fields := strings.Fields(version)
	if len(fields) < 3 {
		return Result{
			Name:     "dirty_pipe",
			Status:   Skip,
			Severity: High,
			Detail:   "Could not parse kernel version",
		}
	}

	kernelVer := fields[2]
	parts := strings.SplitN(kernelVer, ".", 3)
	if len(parts) < 3 {
		return Result{
			Name:     "dirty_pipe",
			Status:   Skip,
			Severity: High,
			Detail:   fmt.Sprintf("Could not parse kernel version: %s", kernelVer),
		}
	}

	major, _ := strconv.Atoi(parts[0])
	minor, _ := strconv.Atoi(parts[1])
	patchStr := parts[2]
	patchParts := strings.SplitN(patchStr, "-", 2)
	patch, _ := strconv.Atoi(patchParts[0])

	vulnerable := false
	if major == 5 && minor >= 8 && minor <= 16 {
		vulnerable = true
		if minor == 10 && patch >= 102 {
			vulnerable = false
		}
		if minor == 15 && patch >= 25 {
			vulnerable = false
		}
		if minor == 16 && patch >= 11 {
			vulnerable = false
		}
		if minor > 16 {
			vulnerable = false
		}
	}

	if vulnerable {
		return Result{
			Name:     "dirty_pipe",
			Status:   Fail,
			Severity: High,
			Detail:   fmt.Sprintf("Kernel %s is vulnerable to CVE-2022-0847 (Dirty Pipe)", kernelVer),
		}
	}
	return Result{
		Name:     "dirty_pipe",
		Status:   Pass,
		Severity: High,
		Detail:   fmt.Sprintf("Kernel %s is not vulnerable to Dirty Pipe", kernelVer),
	}
}

func checkCorePatternEscape() Result {
	f, err := os.OpenFile("/proc/sys/kernel/core_pattern", os.O_WRONLY, 0)
	if err != nil {
		return Result{
			Name:     "core_pattern_escape",
			Status:   Pass,
			Severity: High,
			Detail:   "/proc/sys/kernel/core_pattern is not writable",
		}
	}
	f.Close()
	return Result{
		Name:     "core_pattern_escape",
		Status:   Fail,
		Severity: High,
		Detail:   "/proc/sys/kernel/core_pattern is writable — RCE via crafted core dump",
	}
}

func checkDeviceAccess() Result {
	dangerousDevs := []string{"/dev/mem", "/dev/kmem", "/dev/port"}
	var accessible []string
	for _, dev := range dangerousDevs {
		f, err := os.Open(dev)
		if err == nil {
			f.Close()
			accessible = append(accessible, dev)
		}
	}
	if len(accessible) > 0 {
		return Result{
			Name:     "device_access",
			Status:   Fail,
			Severity: Medium,
			Detail:   fmt.Sprintf("Dangerous devices accessible: %s", strings.Join(accessible, ", ")),
		}
	}
	return Result{
		Name:     "device_access",
		Status:   Pass,
		Severity: Medium,
		Detail:   "No dangerous device files accessible",
	}
}
