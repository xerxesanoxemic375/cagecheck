//go:build !linux

package checks

type SyscallCheck struct{}

func (s *SyscallCheck) Category() string { return "Syscall Filtering" }

func (s *SyscallCheck) Run() []Result {
	return []Result{{
		Name:     "syscall_probe",
		Status:   Skip,
		Severity: Info,
		Detail:   "Syscall probing requires Linux",
	}}
}


func RunProbeChild() bool { return false }
