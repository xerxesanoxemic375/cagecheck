package checks

import (
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"time"
)

// BuildChecklist produces the escape checklist based on probed results and boundary type.
func BuildChecklist(boundary BoundaryType) []EscapeItem {
	var items []EscapeItem

	// --- Universal checks (apply to all sandbox types) ---
	items = append(items, checkMetadata()...)
	items = append(items, checkEgress()...)
	items = append(items, checkGatewayServices()...)
	items = append(items, checkK8sCredentials()...)

	// --- Checks that are N/A when isolation is non-kernel ---
	// Hardware boundary (Firecracker/Kata): VM boundary replaces all kernel controls.
	// Syscall-interception boundary (gVisor): Sentry replaces host kernel; /proc is
	//   emulated, so probing seccomp/caps/namespaces tests the sentry, not the host.
	//   Network checks still matter since traffic leaves the sandbox.
	if boundary == BoundaryHardware || boundary == BoundarySyscall {
		reason := "hardware isolation"
		if boundary == BoundarySyscall {
			reason = "syscall-interception isolation"
		}
		items = append(items,
			na("runtime_sockets", fmt.Sprintf("Runtime socket check — not applicable (%s)", reason)),
			na("privileged_mode", fmt.Sprintf("Privileged mode check — not applicable (%s)", reason)),
			na("dangerous_capabilities", fmt.Sprintf("Dangerous capabilities check — not applicable (%s)", reason)),
			na("seccomp_disabled", fmt.Sprintf("Seccomp check — not applicable (%s)", reason)),
			na("namespace_breakout", fmt.Sprintf("Namespace breakout check — not applicable (%s)", reason)),
			na("writable_proc_escape", fmt.Sprintf("Writable /proc escape paths — not applicable (%s)", reason)),
			na("cgroup_escape", fmt.Sprintf("Cgroup release_agent escape — not applicable (%s)", reason)),
			na("host_filesystem", fmt.Sprintf("Host filesystem check — not applicable (%s)", reason)),
			na("dangerous_devices", fmt.Sprintf("Device access check — not applicable (%s)", reason)),
			na("kernel_cves", fmt.Sprintf("Kernel CVE checks — not applicable (%s)", reason)),
			na("info_leakage", fmt.Sprintf("Info leakage checks — not applicable (%s)", reason)),
		)
	} else {
		items = append(items, checkRuntimeSockets()...)
		items = append(items, checkPrivileged())
		items = append(items, checkDangerousCaps())
		items = append(items, checkSeccomp())
		items = append(items, checkNamespaceBreakout())
		items = append(items, checkWritableProcEscape()...)
		items = append(items, checkCgroupEscape())
		items = append(items, checkHostFilesystem(boundary)...)
		items = append(items, checkDangerousDevices()...)
		items = append(items, checkKernelCVEs()...)
		items = append(items, checkInfoLeakage(boundary)...)
	}

	return items
}

// --- Runtime socket checks ---

func checkRuntimeSockets() []EscapeItem {
	var items []EscapeItem
	sockets := []struct {
		path, name string
	}{
		{"/var/run/docker.sock", "Docker socket"},
		{"/run/docker.sock", "Docker socket (alt path)"},
		{"/run/containerd/containerd.sock", "containerd socket"},
		{"/run/crio/crio.sock", "CRI-O socket"},
		{"/var/run/dockershim.sock", "dockershim socket"},
	}
	found := false
	for _, s := range sockets {
		conn, err := net.Dial("unix", s.path)
		if err == nil {
			conn.Close()
			items = append(items, fail("runtime_socket_"+sanitize(s.name),
				fmt.Sprintf("%s exposed at %s — container escape possible", s.name, s.path)))
			found = true
		}
	}
	if !found {
		items = append(items, pass("runtime_sockets", "No container runtime sockets exposed"))
	}
	return items
}

// --- Metadata service checks ---

func checkMetadata() []EscapeItem {
	conn, err := net.DialTimeout("tcp", "169.254.169.254:80", 2*time.Second)
	if err != nil {
		return []EscapeItem{pass("metadata_service", "Cloud metadata service (169.254.169.254) not reachable")}
	}
	conn.Close()
	return []EscapeItem{fail("metadata_service",
		"Cloud metadata service (169.254.169.254) reachable — credential theft possible")}
}

// --- Egress checks ---

func checkEgress() []EscapeItem {
	targets := []string{"1.1.1.1:443", "93.184.216.34:80"}
	for _, t := range targets {
		conn, err := net.DialTimeout("tcp", t, 2*time.Second)
		if err == nil {
			conn.Close()
			return []EscapeItem{fail("unrestricted_egress",
				fmt.Sprintf("Unrestricted outbound internet access (reached %s)", t))}
		}
	}
	return []EscapeItem{pass("unrestricted_egress", "Outbound internet access is restricted")}
}

// --- Host gateway services ---

func checkGatewayServices() []EscapeItem {
	gateway := detectGatewayIP()
	if gateway == "" {
		return []EscapeItem{pass("gateway_services", "No default gateway detected")}
	}

	ports := []struct {
		port, name string
	}{
		{"22", "SSH"},
		{"2375", "Docker API"},
		{"2376", "Docker API (TLS)"},
		{"6443", "K8s API"},
		{"10250", "Kubelet"},
		{"10255", "Kubelet (read-only)"},
		{"9090", "Internal API"},
		{"8080", "HTTP"},
	}

	var openPorts []string
	for _, p := range ports {
		conn, err := net.DialTimeout("tcp", gateway+":"+p.port, 1*time.Second)
		if err == nil {
			conn.Close()
			openPorts = append(openPorts, fmt.Sprintf("%s (%s)", p.port, p.name))
		}
	}

	if len(openPorts) > 0 {
		return []EscapeItem{fail("gateway_services",
			fmt.Sprintf("Host gateway (%s) exposes services: %s", gateway, strings.Join(openPorts, ", ")))}
	}
	return []EscapeItem{pass("gateway_services",
		fmt.Sprintf("Host gateway (%s) has no exposed services", gateway))}
}

func detectGatewayIP() string {
	data, err := os.ReadFile("/proc/net/route")
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) >= 3 && fields[1] == "00000000" {
			return hexToIPv4(fields[2])
		}
	}
	return ""
}

func hexToIPv4(hex string) string {
	if len(hex) != 8 {
		return ""
	}
	var octets [4]byte
	for i := 0; i < 4; i++ {
		v := hexDigit(hex[i*2])*16 + hexDigit(hex[i*2+1])
		octets[i] = byte(v)
	}
	return fmt.Sprintf("%d.%d.%d.%d", octets[3], octets[2], octets[1], octets[0])
}

func hexDigit(c byte) byte {
	switch {
	case c >= '0' && c <= '9':
		return c - '0'
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10
	case c >= 'A' && c <= 'F':
		return c - 'A' + 10
	}
	return 0
}

// --- Kubernetes credentials ---

func checkK8sCredentials() []EscapeItem {
	var findings []string

	if host := os.Getenv("KUBERNETES_SERVICE_HOST"); host != "" {
		findings = append(findings, fmt.Sprintf("KUBERNETES_SERVICE_HOST=%s", host))
	}

	tokenPaths := []string{
		"/var/run/secrets/kubernetes.io/serviceaccount/token",
		"/run/secrets/kubernetes.io/serviceaccount/token",
	}
	for _, p := range tokenPaths {
		if _, err := os.Stat(p); err == nil {
			findings = append(findings, fmt.Sprintf("service account token at %s", p))
		}
	}

	if len(findings) > 0 {
		return []EscapeItem{fail("k8s_credentials",
			fmt.Sprintf("Kubernetes credentials accessible: %s", strings.Join(findings, ", ")))}
	}
	return []EscapeItem{pass("k8s_credentials", "No Kubernetes credentials exposed")}
}

// --- Privileged mode ---

func checkPrivileged() EscapeItem {
	capEff := readCapEff()
	if isFullCaps(capEff) {
		return fail("privileged_mode", "Container is in privileged mode — trivial escape via nsenter or device mount")
	}
	return pass("privileged_mode", "Container is not in privileged mode")
}

// --- Dangerous capabilities ---

func checkDangerousCaps() EscapeItem {
	capEff := readCapEff()
	type dangerCap struct {
		bit  uint
		name string
	}
	dangerous := []dangerCap{
		{21, "CAP_SYS_ADMIN"},
		{19, "CAP_SYS_PTRACE"},
		{16, "CAP_SYS_MODULE"},
		{2, "CAP_DAC_READ_SEARCH"},
		{17, "CAP_SYS_RAWIO"},
	}
	var found []string
	for _, d := range dangerous {
		if capEff&(1<<d.bit) != 0 {
			found = append(found, d.name)
		}
	}
	if len(found) > 0 {
		return fail("dangerous_capabilities",
			fmt.Sprintf("Dangerous capabilities granted: %s", strings.Join(found, ", ")))
	}
	return pass("dangerous_capabilities", "No dangerous escape-enabling capabilities")
}

// --- Seccomp ---

func checkSeccomp() EscapeItem {
	status := readProcStatusMap()
	val := status["Seccomp"]
	if val == "0" {
		return fail("seccomp_disabled", "Seccomp is disabled — all syscalls available")
	}
	return pass("seccomp_disabled", "Seccomp filtering is active")
}

// --- Namespace breakout ---

func checkNamespaceBreakout() EscapeItem {
	selfPID, _ := os.Readlink("/proc/self/ns/pid")
	initPID, _ := os.Readlink("/proc/1/ns/pid")

	if selfPID != "" && initPID != "" && selfPID == initPID {
		capEff := readCapEff()
		hasPtrace := (capEff & (1 << 19)) != 0
		if hasPtrace {
			return fail("namespace_breakout",
				"Host PID namespace shared + CAP_SYS_PTRACE — can inject into host processes")
		}
		return fail("namespace_breakout", "Host PID namespace shared — host processes visible")
	}
	return pass("namespace_breakout", "PID namespace is isolated from host")
}

// --- Writable /proc escape paths ---

func checkWritableProcEscape() []EscapeItem {
	var items []EscapeItem
	paths := []struct {
		path, name, risk string
	}{
		{"/proc/sysrq-trigger", "sysrq_trigger", "can reboot/crash host"},
		{"/proc/sys/kernel/core_pattern", "core_pattern", "RCE via crafted core dump"},
		{"/proc/sys/kernel/modprobe", "modprobe_path", "RCE via module load trigger"},
		{"/sys/kernel/uevent_helper", "uevent_helper", "RCE via device events"},
	}
	anyFailed := false
	for _, p := range paths {
		f, err := os.OpenFile(p.path, os.O_WRONLY, 0)
		if err == nil {
			f.Close()
			items = append(items, fail("writable_"+p.name,
				fmt.Sprintf("%s is writable — %s", p.path, p.risk)))
			anyFailed = true
		}
	}
	if !anyFailed {
		items = append(items, pass("writable_proc_escape", "No writable /proc or /sys escape paths"))
	}
	return items
}

// --- Cgroup escape ---

func checkCgroupEscape() EscapeItem {
	capEff := readCapEff()
	hasSysAdmin := (capEff & (1 << 21)) != 0
	if !hasSysAdmin {
		return pass("cgroup_escape", "CAP_SYS_ADMIN not available — cgroup release_agent escape not possible")
	}
	_, err := os.ReadFile("/sys/fs/cgroup/release_agent")
	if err == nil {
		return fail("cgroup_escape", "CAP_SYS_ADMIN + cgroup v1 release_agent accessible — escape possible")
	}
	return EscapeItem{
		Name:   "cgroup_escape",
		Status: Warn,
		Detail: "CAP_SYS_ADMIN present — cgroup escape may be possible via mount",
	}
}

// --- Host filesystem ---

func checkHostFilesystem(boundary BoundaryType) []EscapeItem {
	var items []EscapeItem

	if boundary == BoundaryHardware {
		items = append(items, pass("host_filesystem", "Hardware isolation — filesystem is VM-local"))
		return items
	}

	// Check /proc/1/root
	entries, err := os.ReadDir("/proc/1/root")
	if err == nil && len(entries) > 5 {
		data, _ := os.Readlink("/proc/1/ns/pid")
		selfData, _ := os.Readlink("/proc/self/ns/pid")
		if data != "" && selfData != "" && data == selfData {
			items = append(items, fail("host_root_traversal",
				"/proc/1/root accessible with shared PID namespace — host filesystem exposed"))
		}
	}

	// Check for host mounts
	data, err := os.ReadFile("/proc/self/mountinfo")
	if err == nil {
		content := string(data)
		hostPaths := []string{"/etc/shadow", "/etc/crontab", "/root"}
		for _, hp := range hostPaths {
			if strings.Contains(content, hp) {
				items = append(items, fail("host_mount_"+sanitize(hp),
					fmt.Sprintf("Host path %s appears to be mounted", hp)))
			}
		}
	}

	if len(items) == 0 {
		items = append(items, pass("host_filesystem", "No host filesystem exposure detected"))
	}
	return items
}

// --- Dangerous devices ---

func checkDangerousDevices() []EscapeItem {
	devs := []string{"/dev/mem", "/dev/kmem", "/dev/port"}
	var accessible []string
	for _, dev := range devs {
		f, err := os.Open(dev)
		if err == nil {
			f.Close()
			accessible = append(accessible, dev)
		}
	}
	if len(accessible) > 0 {
		return []EscapeItem{fail("dangerous_devices",
			fmt.Sprintf("Dangerous devices accessible: %s", strings.Join(accessible, ", ")))}
	}
	return []EscapeItem{pass("dangerous_devices", "No dangerous device files accessible")}
}

// --- Kernel CVEs ---

func checkKernelCVEs() []EscapeItem {
	var items []EscapeItem
	major, minor, patch := parseKernelVersion()
	if major == 0 {
		return []EscapeItem{{Name: "kernel_cves", Status: Skip, Detail: "Could not parse kernel version"}}
	}

	ver := fmt.Sprintf("%d.%d.%d", major, minor, patch)

	// Dirty Pipe: 5.8 <= kernel < 5.16.11 / 5.15.25 / 5.10.102
	dirtyPipe := false
	if major == 5 && minor >= 8 && minor <= 16 {
		dirtyPipe = true
		if minor == 10 && patch >= 102 {
			dirtyPipe = false
		}
		if minor == 15 && patch >= 25 {
			dirtyPipe = false
		}
		if minor == 16 && patch >= 11 {
			dirtyPipe = false
		}
		if minor > 16 {
			dirtyPipe = false
		}
	}
	if dirtyPipe {
		items = append(items, fail("cve_dirty_pipe",
			fmt.Sprintf("Kernel %s vulnerable to CVE-2022-0847 (Dirty Pipe)", ver)))
	}

	// CVE-2022-0492: cgroup v1 unpriv user namespace, kernel < 5.16.2/5.15.17/5.10.93
	cgroupVuln := false
	if major == 5 {
		if minor < 10 {
			cgroupVuln = true
		}
		if minor == 10 && patch < 93 {
			cgroupVuln = true
		}
		// 5.11-5.14 were EOL with no fix backported
		if minor >= 11 && minor <= 14 {
			cgroupVuln = true
		}
		if minor == 15 && patch < 17 {
			cgroupVuln = true
		}
		if minor == 16 && patch < 2 {
			cgroupVuln = true
		}
	}
	if major < 5 {
		cgroupVuln = true
	}
	if cgroupVuln {
		items = append(items, EscapeItem{
			Name:   "cve_cgroup_escape",
			Status: Warn,
			Detail: fmt.Sprintf("Kernel %s may be vulnerable to CVE-2022-0492 (cgroup escape)", ver),
		})
	}

	// CVE-2024-1086: nf_tables, kernel < 5.15.149 / 6.1.76 / 6.6.15
	nftVuln := false
	if major == 5 && minor == 15 && patch < 149 {
		nftVuln = true
	}
	if major == 6 && minor == 1 && patch < 76 {
		nftVuln = true
	}
	if major == 6 && minor == 6 && patch < 15 {
		nftVuln = true
	}
	if nftVuln {
		items = append(items, fail("cve_nftables",
			fmt.Sprintf("Kernel %s vulnerable to CVE-2024-1086 (nf_tables privilege escalation)", ver)))
	}

	if len(items) == 0 {
		items = append(items, pass("kernel_cves",
			fmt.Sprintf("Kernel %s has no known critical escape CVEs", ver)))
	}
	return items
}

// --- Info leakage ---

func checkInfoLeakage(boundary BoundaryType) []EscapeItem {
	var items []EscapeItem

	// /proc/sched_debug — leaks all host PIDs
	if boundary != BoundaryHardware {
		_, err := os.ReadFile("/proc/sched_debug")
		if err == nil {
			items = append(items, fail("sched_debug_leak",
				"/proc/sched_debug readable — all host PIDs and process names exposed"))
		}
	}

	// /proc/kallsyms with real addresses
	data, err := os.ReadFile("/proc/kallsyms")
	if err == nil && len(data) > 20 {
		firstLine := string(data[:min(len(data), 40)])
		if !strings.HasPrefix(firstLine, "0000000000000000") {
			items = append(items, fail("kallsyms_leak",
				"/proc/kallsyms exposes kernel addresses — KASLR bypass possible"))
		}
	}

	if len(items) == 0 {
		items = append(items, pass("info_leakage", "No critical information leakage detected"))
	}
	return items
}

// --- Helpers ---

func readCapEff() uint64 {
	status := readProcStatusMap()
	val := strings.TrimSpace(status["CapEff"])
	v, _ := strconv.ParseUint(val, 16, 64)
	return v
}

func readProcStatusMap() map[string]string {
	return readProcFile("/proc/self/status")
}

func parseKernelVersion() (int, int, int) {
	data, err := os.ReadFile("/proc/version")
	if err != nil {
		return 0, 0, 0
	}
	fields := strings.Fields(string(data))
	if len(fields) < 3 {
		return 0, 0, 0
	}
	parts := strings.SplitN(fields[2], ".", 3)
	if len(parts) < 3 {
		return 0, 0, 0
	}
	major, _ := strconv.Atoi(parts[0])
	minor, _ := strconv.Atoi(parts[1])
	patchStr := strings.SplitN(parts[2], "-", 2)[0]
	patch, _ := strconv.Atoi(patchStr)
	return major, minor, patch
}

func sanitize(s string) string {
	return strings.ReplaceAll(strings.ReplaceAll(strings.ToLower(s), " ", "_"), "/", "_")
}

func pass(name, detail string) EscapeItem {
	return EscapeItem{Name: name, Status: Pass, Detail: detail}
}

func fail(name, detail string) EscapeItem {
	return EscapeItem{Name: name, Status: Fail, Detail: detail}
}

func na(name, detail string) EscapeItem {
	return EscapeItem{Name: name, Status: NA, Detail: detail}
}
