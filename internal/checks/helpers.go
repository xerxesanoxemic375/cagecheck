package checks

import (
	"os"
	"strings"
)

func readProcStatus() map[string]string {
	return readProcFile("/proc/self/status")
}

func readProcFile(path string) map[string]string {
	result := make(map[string]string)
	data, err := os.ReadFile(path)
	if err != nil {
		return result
	}
	lines := strings.Split(string(data), "\n")
	for _, line := range lines {
		parts := strings.SplitN(line, ":", 2)
		if len(parts) == 2 {
			result[parts[0]] = strings.TrimSpace(parts[1])
		}
	}
	return result
}

func boolToStatus(ok bool) Status {
	if ok {
		return Pass
	}
	return Fail
}

// fullCapMask returns the bitmask with all capability bits set for the
// running kernel. It reads /proc/sys/kernel/cap_last_cap to determine
// the highest capability number, so it works on any kernel version
// without hardcoding.
func fullCapMask() uint64 {
	data, err := os.ReadFile("/proc/sys/kernel/cap_last_cap")
	if err != nil {
		return 0x000001ffffffffff // fallback: 41 caps (Linux 5.x default)
	}
	n := 0
	for _, c := range strings.TrimSpace(string(data)) {
		if c >= '0' && c <= '9' {
			n = n*10 + int(c-'0')
		}
	}
	if n == 0 || n > 63 {
		return 0x000001ffffffffff
	}
	return (1 << uint(n+1)) - 1
}

// isFullCaps returns true if the given effective capability bitmask
// has all bits set (privileged mode).
func isFullCaps(capEff uint64) bool {
	return capEff != 0 && capEff == fullCapMask()
}
