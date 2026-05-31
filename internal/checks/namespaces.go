package checks

import (
	"fmt"
	"os"
	"strings"
)

var namespaceTypes = []struct {
	Name     string
	NSFile   string
	Severity Severity
}{
	{"pid", "pid", High},
	{"net", "net", High},
	{"mnt", "mnt", High},
	{"user", "user", High},
	{"uts", "uts", Medium},
	{"ipc", "ipc", Medium},
	{"cgroup", "cgroup", Medium},
}

type NamespaceCheck struct{}

func (n *NamespaceCheck) Category() string { return "Namespace Isolation" }

func (n *NamespaceCheck) Run() []Result {
	var results []Result

	selfNS := readNamespaceInodes("/proc/self/ns")
	initNS := readNamespaceInodes("/proc/1/ns")

	for _, ns := range namespaceTypes {
		r := checkNamespace(ns.Name, ns.NSFile, ns.Severity, selfNS, initNS)
		results = append(results, r)
	}

	results = append(results, checkUserMapping())
	results = append(results, checkPIDVisibility())

	return results
}

func checkNamespace(name, nsFile string, sev Severity, selfNS, initNS map[string]string) Result {
	selfInode := selfNS[nsFile]
	initInode := initNS[nsFile]

	if selfInode == "" {
		return Result{
			Name:     "ns_" + name,
			Status:   Skip,
			Severity: sev,
			Detail:   fmt.Sprintf("Could not read %s namespace inode", name),
		}
	}

	if initInode != "" && selfInode == initInode {
		return Result{
			Name:     "ns_" + name,
			Status:   Fail,
			Severity: sev,
			Detail:   fmt.Sprintf("%s namespace is shared with init (likely host namespace)", name),
		}
	}

	return Result{
		Name:     "ns_" + name,
		Status:   Pass,
		Severity: sev,
		Detail:   fmt.Sprintf("%s namespace is isolated", name),
	}
}

func checkUserMapping() Result {
	data, err := os.ReadFile("/proc/self/uid_map")
	if err != nil {
		return Result{
			Name:     "user_ns_mapping",
			Status:   Skip,
			Severity: High,
			Detail:   "Could not read uid_map",
		}
	}
	content := strings.TrimSpace(string(data))
	if strings.Contains(content, "0          0 4294967295") ||
		strings.Contains(content, "0\t0\t4294967295") {
		return Result{
			Name:     "user_ns_mapping",
			Status:   Fail,
			Severity: High,
			Detail:   "No user namespace remapping — container root is host root",
		}
	}
	return Result{
		Name:     "user_ns_mapping",
		Status:   Pass,
		Severity: High,
		Detail:   "User namespace remapping active — container root maps to unprivileged host user",
	}
}

func checkPIDVisibility() Result {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return Result{
			Name:     "pid_visibility",
			Status:   Skip,
			Severity: Info,
			Detail:   "Could not read /proc",
		}
	}
	pidCount := 0
	for _, e := range entries {
		if e.Name()[0] >= '0' && e.Name()[0] <= '9' {
			pidCount++
		}
	}
	if pidCount > 50 {
		return Result{
			Name:     "pid_visibility",
			Status:   Warn,
			Severity: Medium,
			Detail:   fmt.Sprintf("%d PIDs visible in /proc — may include host processes", pidCount),
			Data:     map[string]int{"pid_count": pidCount},
		}
	}
	return Result{
		Name:     "pid_visibility",
		Status:   Pass,
		Severity: Info,
		Detail:   fmt.Sprintf("%d PIDs visible in /proc", pidCount),
		Data:     map[string]int{"pid_count": pidCount},
	}
}

func readNamespaceInodes(base string) map[string]string {
	result := make(map[string]string)
	for _, ns := range namespaceTypes {
		path := base + "/" + ns.NSFile
		link, err := os.Readlink(path)
		if err != nil {
			continue
		}
		result[ns.NSFile] = link
	}
	return result
}
