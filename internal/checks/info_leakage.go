package checks

import (
	"fmt"
	"os"
	"strings"
)

type InfoLeakageCheck struct{}

func (i *InfoLeakageCheck) Category() string { return "Information Leakage" }

func (i *InfoLeakageCheck) Run() []Result {
	var results []Result

	results = append(results, checkSchedDebugLeak())
	results = append(results, checkMountInfoLeak())
	results = append(results, checkMemInfoLeak())
	results = append(results, checkPartitionsLeak())
	results = append(results, checkModulesLeak())
	results = append(results, checkKernelVersion())

	return results
}

func checkSchedDebugLeak() Result {
	data, err := os.ReadFile("/proc/sched_debug")
	if err != nil {
		return Result{
			Name:     "sched_debug_leak",
			Status:   Pass,
			Severity: High,
			Detail:   "/proc/sched_debug is not accessible",
		}
	}
	lineCount := strings.Count(string(data), "\n")
	return Result{
		Name:     "sched_debug_leak",
		Status:   Fail,
		Severity: High,
		Detail:   fmt.Sprintf("/proc/sched_debug is readable (%d lines) — exposes all host PIDs and process names", lineCount),
	}
}

func checkMountInfoLeak() Result {
	data, err := os.ReadFile("/proc/self/mountinfo")
	if err != nil {
		return Result{
			Name:     "mountinfo_leak",
			Status:   Pass,
			Severity: Medium,
			Detail:   "Could not read mountinfo",
		}
	}
	content := string(data)
	if strings.Contains(content, "upperdir=") || strings.Contains(content, "/var/lib/docker") {
		return Result{
			Name:     "mountinfo_leak",
			Status:   Fail,
			Severity: Medium,
			Detail:   "Host filesystem paths visible in /proc/self/mountinfo",
		}
	}
	return Result{
		Name:     "mountinfo_leak",
		Status:   Pass,
		Severity: Medium,
		Detail:   "No host filesystem paths detected in mountinfo",
	}
}

func checkMemInfoLeak() Result {
	data, err := os.ReadFile("/proc/meminfo")
	if err != nil {
		return Result{
			Name:     "meminfo_leak",
			Status:   Pass,
			Severity: Low,
			Detail:   "/proc/meminfo is not accessible",
		}
	}
	lines := strings.Split(string(data), "\n")
	for _, line := range lines {
		if strings.HasPrefix(line, "MemTotal:") {
			return Result{
				Name:     "meminfo_leak",
				Status:   Warn,
				Severity: Low,
				Detail:   fmt.Sprintf("/proc/meminfo shows host memory — %s", strings.TrimSpace(line)),
			}
		}
	}
	return Result{
		Name:     "meminfo_leak",
		Status:   Pass,
		Severity: Low,
		Detail:   "/proc/meminfo not readable",
	}
}

func checkPartitionsLeak() Result {
	_, err := os.ReadFile("/proc/partitions")
	if err != nil {
		return Result{
			Name:     "partitions_leak",
			Status:   Pass,
			Severity: Low,
			Detail:   "/proc/partitions is not accessible",
		}
	}
	return Result{
		Name:     "partitions_leak",
		Status:   Fail,
		Severity: Low,
		Detail:   "/proc/partitions is readable — host disk layout exposed",
	}
}

func checkModulesLeak() Result {
	data, err := os.ReadFile("/proc/modules")
	if err != nil {
		return Result{
			Name:     "modules_leak",
			Status:   Pass,
			Severity: Low,
			Detail:   "/proc/modules is not accessible",
		}
	}
	modCount := strings.Count(string(data), "\n")
	return Result{
		Name:     "modules_leak",
		Status:   Fail,
		Severity: Low,
		Detail:   fmt.Sprintf("/proc/modules is readable — %d kernel modules exposed", modCount),
	}
}

func checkKernelVersion() Result {
	data, err := os.ReadFile("/proc/version")
	if err != nil {
		return Result{
			Name:     "kernel_version",
			Status:   Pass,
			Severity: Info,
			Detail:   "Kernel version not accessible",
		}
	}
	return Result{
		Name:     "kernel_version",
		Status:   Pass,
		Severity: Info,
		Detail:   fmt.Sprintf("Kernel: %s", strings.TrimSpace(string(data))),
	}
}
