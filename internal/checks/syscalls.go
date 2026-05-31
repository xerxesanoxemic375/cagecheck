//go:build linux

package checks

import (
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"syscall"
)

var dangerousSyscalls = []struct {
	Num  uintptr
	Name string
}{
	{sysMount, "mount"},
	{sysUmount2, "umount2"},
	{sysPtrace, "ptrace"},
	{sysReboot, "reboot"},
	{sysPivotRoot, "pivot_root"},
	{sysMknod, "mknod"},
	{sysInitModule, "init_module"},
	{sysFinitModule, "finit_module"},
	{sysDeleteModule, "delete_module"},
	{sysKexecLoad, "kexec_load"},
	{sysUnshare, "unshare"},
	{sysSetns, "setns"},
}

var ioUringSyscalls = []struct {
	Num  uintptr
	Name string
}{
	{sysIoUringSetup, "io_uring_setup"},
	{sysIoUringEnter, "io_uring_enter"},
	{sysIoUringRegister, "io_uring_register"},
}

type SyscallCheck struct{}

func (s *SyscallCheck) Category() string { return "Syscall Filtering" }

func (s *SyscallCheck) Run() []Result {
	var results []Result

	seccompResult := checkSeccompEnabled()
	results = append(results, seccompResult)

	seccompMode := readProcStatus()["Seccomp"]

	if seccompMode == "0" {
		results = append(results, Result{
			Name:     "syscall_probe_skipped",
			Status:   Fail,
			Severity: Critical,
			Detail:   "Seccomp disabled — all syscalls are available, probing skipped",
		})
		return results
	}

	useChildProbe := seccompMode == "2"

	results = append(results, checkDangerousSyscalls(useChildProbe)...)
	results = append(results, checkIoUring(useChildProbe)...)
	results = append(results, checkSyscallCoverage(useChildProbe))

	return results
}

func checkSeccompEnabled() Result {
	data := readProcStatus()
	val, ok := data["Seccomp"]
	if !ok {
		return Result{
			Name:     "seccomp_enabled",
			Status:   Skip,
			Severity: Critical,
			Detail:   "Could not read /proc/self/status",
		}
	}
	if val == "0" {
		return Result{
			Name:     "seccomp_enabled",
			Status:   Fail,
			Severity: Critical,
			Detail:   "Seccomp is disabled — no syscall filtering active",
		}
	}
	mode := "filter"
	if val == "1" {
		mode = "strict"
	}
	return Result{
		Name:     "seccomp_enabled",
		Status:   Pass,
		Severity: Critical,
		Detail:   fmt.Sprintf("Seccomp is enabled (mode: %s)", mode),
	}
}

func checkDangerousSyscalls(useChild bool) []Result {
	var results []Result
	for _, sc := range dangerousSyscalls {
		blocked := probeSyscallSafe(sc.Num, useChild)
		status := Pass
		if !blocked {
			status = Fail
		}
		sev := Critical
		if sc.Name == "unshare" || sc.Name == "setns" {
			sev = High
		}
		detail := fmt.Sprintf("%s is blocked", sc.Name)
		if !blocked {
			detail = fmt.Sprintf("%s is allowed — potential escape vector", sc.Name)
		}
		results = append(results, Result{
			Name:     "syscall_" + sc.Name,
			Status:   status,
			Severity: sev,
			Detail:   detail,
		})
	}
	return results
}

func checkIoUring(useChild bool) []Result {
	var results []Result
	for _, sc := range ioUringSyscalls {
		blocked := probeSyscallSafe(sc.Num, useChild)
		status := Pass
		if !blocked {
			status = Fail
		}
		detail := fmt.Sprintf("%s is blocked", sc.Name)
		if !blocked {
			detail = fmt.Sprintf("%s is allowed — increasingly used for kernel exploits", sc.Name)
		}
		results = append(results, Result{
			Name:     "syscall_" + sc.Name,
			Status:   status,
			Severity: High,
			Detail:   detail,
		})
	}
	return results
}

func checkSyscallCoverage(useChild bool) Result {
	const maxSyscall = 450
	blocked := 0
	total := 0
	for i := uintptr(0); i < maxSyscall; i++ {
		total++
		if probeSyscallSafe(i, useChild) {
			blocked++
		}
	}
	pct := (blocked * 100) / total
	return Result{
		Name:     "syscall_coverage",
		Status:   Pass,
		Severity: Medium,
		Detail:   fmt.Sprintf("%d/%d syscalls blocked (%d%%)", blocked, total, pct),
		Data:     map[string]int{"blocked": blocked, "total": total, "percent": pct},
	}
}

// probeSyscallSafe probes whether a syscall is blocked.
// When seccomp uses SECCOMP_RET_KILL, RawSyscall kills the thread,
// so we fork a child process to do the probe — if the child is killed
// by SIGSYS (signal 31), the syscall is blocked.
func probeSyscallSafe(num uintptr, useChild bool) bool {
	if useChild {
		return probeSyscallChild(num)
	}
	return probeSyscallDirect(num)
}

func probeSyscallDirect(num uintptr) bool {
	_, _, errno := syscall.RawSyscall(num, 0, 0, 0)
	return errno == syscall.EPERM || errno == syscall.EACCES || errno == syscall.ENOSYS
}

// probeSyscallChild re-execs ourselves with a special env var to probe
// a single syscall in a child process. If the child exits 0, the syscall
// returned EPERM/EACCES/ENOSYS (blocked). If killed by signal, it was KILL-blocked.
// If exits non-zero, the syscall was allowed (returned some other error).
func probeSyscallChild(num uintptr) bool {
	exe, err := os.Executable()
	if err != nil {
		return false
	}
	cmd := exec.Command(exe)
	cmd.Env = append(os.Environ(), fmt.Sprintf("__CAGECHECK_PROBE_SYSCALL=%d", num))
	err = cmd.Run()
	if err == nil {
		return true // child exited 0 = blocked (EPERM/EACCES/ENOSYS)
	}
	if exitErr, ok := err.(*exec.ExitError); ok {
		ws := exitErr.Sys().(syscall.WaitStatus)
		if ws.Signaled() {
			return true // killed by signal (SIGSYS) = blocked
		}
		// exit code 2 = syscall returned other errno = allowed
		return false
	}
	return false
}

// RunProbeChild is called when the binary is re-exec'd for syscall probing.
// It probes a single syscall and exits with code 0 (blocked) or 2 (allowed).
func RunProbeChild() bool {
	val := os.Getenv("__CAGECHECK_PROBE_SYSCALL")
	if val == "" {
		return false
	}
	num, err := strconv.ParseUint(val, 10, 64)
	if err != nil {
		os.Exit(2)
	}
	_, _, errno := syscall.RawSyscall(uintptr(num), 0, 0, 0)
	if errno == syscall.EPERM || errno == syscall.EACCES || errno == syscall.ENOSYS {
		os.Exit(0) // blocked
	}
	os.Exit(2) // allowed
	return true
}
