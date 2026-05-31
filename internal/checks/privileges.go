package checks

import (
	"fmt"
	"os"
	"strings"
	"syscall"
)

type PrivilegeCheck struct{}

func (p *PrivilegeCheck) Category() string { return "Privileges" }
func (p *PrivilegeCheck) Weight() int      { return 0 } // folded into Capabilities score

func (p *PrivilegeCheck) Run() []Result {
	var results []Result

	results = append(results, checkRunningAsRoot())
	results = append(results, checkNoNewPrivs())
	results = append(results, checkAppArmor())
	results = append(results, checkSeccompMode())

	return results
}


func checkRunningAsRoot() Result {
	uid := syscall.Getuid()
	if uid == 0 {
		return Result{
			Name:     "running_as_root",
			Status:   Fail,
			Severity: Medium,
			Detail:   "Process is running as root (UID 0)",
		}
	}
	return Result{
		Name:     "running_as_root",
		Status:   Pass,
		Severity: Medium,
		Detail:   fmt.Sprintf("Process is running as UID %d", uid),
	}
}

func checkNoNewPrivs() Result {
	status := readProcStatus()
	val, ok := status["NoNewPrivs"]
	if !ok {
		return Result{
			Name:     "no_new_privs",
			Status:   Skip,
			Severity: Medium,
			Detail:   "Could not determine NoNewPrivs status",
		}
	}
	if val == "0" {
		return Result{
			Name:     "no_new_privs",
			Status:   Warn,
			Severity: Medium,
			Detail:   "NoNewPrivs is not set — process could gain additional privileges",
		}
	}
	return Result{
		Name:     "no_new_privs",
		Status:   Pass,
		Severity: Medium,
		Detail:   "NoNewPrivs is set — privilege escalation via exec restricted",
	}
}

func checkAppArmor() Result {
	data, err := os.ReadFile("/proc/self/attr/current")
	if err != nil {
		data, err = os.ReadFile("/proc/self/attr/apparmor/current")
		if err != nil {
			return Result{
				Name:     "apparmor_profile",
				Status:   Skip,
				Severity: Low,
				Detail:   "AppArmor status not available",
			}
		}
	}
	profile := strings.TrimSpace(string(data))
	if profile == "unconfined" || profile == "" {
		return Result{
			Name:     "apparmor_profile",
			Status:   Warn,
			Severity: Low,
			Detail:   "AppArmor profile is unconfined",
		}
	}
	return Result{
		Name:     "apparmor_profile",
		Status:   Pass,
		Severity: Low,
		Detail:   fmt.Sprintf("AppArmor profile active: %s", profile),
	}
}

func checkSeccompMode() Result {
	status := readProcStatus()
	val, ok := status["Seccomp"]
	if !ok {
		return Result{
			Name:     "seccomp_mode",
			Status:   Skip,
			Severity: Info,
			Detail:   "Seccomp status not available",
		}
	}
	switch val {
	case "0":
		return Result{
			Name:     "seccomp_mode",
			Status:   Fail,
			Severity: High,
			Detail:   "Seccomp is disabled",
		}
	case "1":
		return Result{
			Name:     "seccomp_mode",
			Status:   Pass,
			Severity: Info,
			Detail:   "Seccomp mode: strict",
		}
	case "2":
		return Result{
			Name:     "seccomp_mode",
			Status:   Pass,
			Severity: Info,
			Detail:   "Seccomp mode: filter",
		}
	default:
		return Result{
			Name:     "seccomp_mode",
			Status:   Skip,
			Severity: Info,
			Detail:   fmt.Sprintf("Unknown seccomp mode: %s", val),
		}
	}
}
