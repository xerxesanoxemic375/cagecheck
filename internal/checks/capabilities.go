package checks

import (
	"fmt"
	"strconv"
	"strings"
)

type capDef struct {
	Bit      uint
	Name     string
	Severity Severity
}

var dangerousCaps = []capDef{
	{21, "CAP_SYS_ADMIN", Critical},
	{19, "CAP_SYS_PTRACE", Critical},
	{16, "CAP_SYS_MODULE", Critical},
	{2, "CAP_DAC_READ_SEARCH", Critical},
	{17, "CAP_SYS_RAWIO", High},
	{12, "CAP_NET_ADMIN", High},
	{13, "CAP_NET_RAW", Medium},
	{7, "CAP_SETUID", Medium},
	{6, "CAP_SETGID", Medium},
	{22, "CAP_SYS_BOOT", Medium},
	{34, "CAP_SYSLOG", Low},
	{18, "CAP_SYS_CHROOT", Low},
}


type CapabilityCheck struct{}

func (c *CapabilityCheck) Category() string { return "Capabilities" }

func (c *CapabilityCheck) Run() []Result {
	var results []Result
	status := readProcStatus()

	capEff := parseCapHex(status["CapEff"])
	capBnd := parseCapHex(status["CapBnd"])
	capAmb := parseCapHex(status["CapAmb"])

	combined := capEff | capAmb

	if isFullCaps(combined) {
		results = append(results, Result{
			Name:     "privileged_mode",
			Status:   Fail,
			Severity: Critical,
			Detail:   "Container is running in privileged mode (all capabilities granted)",
		})
	} else {
		results = append(results, Result{
			Name:     "privileged_mode",
			Status:   Pass,
			Severity: Critical,
			Detail:   "Container is not running in privileged mode",
		})
	}

	foundDangerous := 0
	for _, cap := range dangerousCaps {
		mask := uint64(1) << cap.Bit
		hasCap := (combined & mask) != 0
		inBounding := (capBnd & mask) != 0

		status := Pass
		detail := fmt.Sprintf("%s is dropped", cap.Name)

		if hasCap {
			status = Fail
			detail = fmt.Sprintf("%s is granted (effective/ambient)", cap.Name)
			foundDangerous++
		} else if inBounding {
			status = Warn
			detail = fmt.Sprintf("%s is in bounding set but not effective", cap.Name)
		}

		results = append(results, Result{
			Name:     "cap_" + cap.Name,
			Status:   status,
			Severity: cap.Severity,
			Detail:   detail,
		})
	}

	results = append(results, Result{
		Name:     "dangerous_cap_count",
		Status:   boolToStatus(foundDangerous == 0),
		Severity: Info,
		Detail:   fmt.Sprintf("%d dangerous capabilities found", foundDangerous),
		Data:     map[string]int{"count": foundDangerous},
	})

	return results
}


func parseCapHex(s string) uint64 {
	s = strings.TrimSpace(s)
	v, err := strconv.ParseUint(s, 16, 64)
	if err != nil {
		return 0
	}
	return v
}

