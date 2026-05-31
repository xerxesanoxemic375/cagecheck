package checks

import (
	"fmt"
	"net"
	"os"
	"strings"
)

type pathProbe struct {
	Path     string
	Name     string
	Severity Severity
	Writable bool // if true, check writability; otherwise check readability
}

var sensitiveReadPaths = []pathProbe{
	{"/proc/sched_debug", "proc_sched_debug", High, false},
	{"/proc/kallsyms", "proc_kallsyms", High, false},
	{"/proc/kcore", "proc_kcore", High, false},
	{"/proc/kmsg", "proc_kmsg", Medium, false},
	{"/proc/config.gz", "proc_config", Medium, false},
	{"/proc/modules", "proc_modules", Medium, false},
	{"/proc/1/root", "proc_1_root", High, false},
	{"/sys/kernel/debug", "sys_kernel_debug", Medium, false},
	{"/sys/firmware/efi/vars", "sys_efi_vars", Low, false},
}

var sensitiveWritePaths = []pathProbe{
	{"/proc/sysrq-trigger", "proc_sysrq_trigger", Critical, true},
	{"/proc/sys/kernel/core_pattern", "proc_core_pattern", Critical, true},
	{"/sys/kernel/uevent_helper", "sys_uevent_helper", High, true},
}

type FilesystemCheck struct{}

func (f *FilesystemCheck) Category() string { return "Filesystem Exposure" }

func (f *FilesystemCheck) Run() []Result {
	var results []Result

	results = append(results, checkSocket("/var/run/docker.sock", "docker_socket", "Docker"))
	results = append(results, checkSocket("/run/containerd/containerd.sock", "containerd_socket", "containerd"))

	for _, p := range sensitiveWritePaths {
		results = append(results, checkWritable(p))
	}
	for _, p := range sensitiveReadPaths {
		results = append(results, checkReadable(p))
	}

	results = append(results, checkHostMounts())

	return results
}

func checkSocket(path, name, label string) Result {
	conn, err := net.Dial("unix", path)
	if err != nil {
		return Result{
			Name:     name,
			Status:   Pass,
			Severity: Critical,
			Detail:   fmt.Sprintf("%s socket not accessible", label),
		}
	}
	conn.Close()
	return Result{
		Name:     name,
		Status:   Fail,
		Severity: Critical,
		Detail:   fmt.Sprintf("%s socket is accessible at %s — container escape possible", label, path),
	}
}

func checkWritable(p pathProbe) Result {
	f, err := os.OpenFile(p.Path, os.O_WRONLY, 0)
	if err != nil {
		return Result{
			Name:     p.Name,
			Status:   Pass,
			Severity: p.Severity,
			Detail:   fmt.Sprintf("%s is not writable", p.Path),
		}
	}
	f.Close()
	return Result{
		Name:     p.Name,
		Status:   Fail,
		Severity: p.Severity,
		Detail:   fmt.Sprintf("%s is writable — can be used for host compromise", p.Path),
	}
}

func checkReadable(p pathProbe) Result {
	f, err := os.Open(p.Path)
	if err != nil {
		return Result{
			Name:     p.Name,
			Status:   Pass,
			Severity: p.Severity,
			Detail:   fmt.Sprintf("%s is not accessible", p.Path),
		}
	}
	f.Close()

	if p.Name == "proc_kallsyms" {
		return checkKallsymsAddresses(p)
	}

	return Result{
		Name:     p.Name,
		Status:   Fail,
		Severity: p.Severity,
		Detail:   fmt.Sprintf("%s is readable — information exposure", p.Path),
	}
}

func checkKallsymsAddresses(p pathProbe) Result {
	data, err := os.ReadFile(p.Path)
	if err != nil || len(data) == 0 {
		return Result{
			Name:     p.Name,
			Status:   Pass,
			Severity: p.Severity,
			Detail:   fmt.Sprintf("%s is not accessible", p.Path),
		}
	}
	firstLine := string(data[:min(len(data), 80)])
	if strings.HasPrefix(firstLine, "0000000000000000") {
		return Result{
			Name:     p.Name,
			Status:   Pass,
			Severity: p.Severity,
			Detail:   fmt.Sprintf("%s is readable but addresses are zeroed (kptr_restrict active)", p.Path),
		}
	}
	return Result{
		Name:     p.Name,
		Status:   Fail,
		Severity: p.Severity,
		Detail:   fmt.Sprintf("%s is readable with kernel addresses exposed — KASLR bypass possible", p.Path),
	}
}

func checkHostMounts() Result {
	data, err := os.ReadFile("/proc/self/mountinfo")
	if err != nil {
		return Result{
			Name:     "host_mounts",
			Status:   Skip,
			Severity: Medium,
			Detail:   "Could not read /proc/self/mountinfo",
		}
	}
	content := string(data)
	hostIndicators := []string{"/var/lib/docker", "/var/lib/containerd", "upperdir=", "workdir="}
	var found []string
	for _, indicator := range hostIndicators {
		if strings.Contains(content, indicator) {
			found = append(found, indicator)
		}
	}
	if len(found) > 0 {
		return Result{
			Name:     "host_mounts",
			Status:   Warn,
			Severity: Medium,
			Detail:   fmt.Sprintf("Host filesystem paths visible in mountinfo: %s", strings.Join(found, ", ")),
			Data:     found,
		}
	}
	return Result{
		Name:     "host_mounts",
		Status:   Pass,
		Severity: Medium,
		Detail:   "No host filesystem paths detected in mountinfo",
	}
}

