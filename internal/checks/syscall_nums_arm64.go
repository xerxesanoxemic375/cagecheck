//go:build linux && arm64

package checks

// Linux arm64 syscall numbers (asm-generic table).
const (
	sysMount        = 40
	sysUmount2      = 39
	sysPtrace       = 117
	sysReboot       = 142
	sysPivotRoot    = 41
	sysMknod        = 33
	sysInitModule   = 105
	sysFinitModule  = 273
	sysDeleteModule = 106
	sysKexecLoad    = 104
	sysUnshare      = 97
	sysSetns        = 268

	sysIoUringSetup    = 425
	sysIoUringEnter    = 426
	sysIoUringRegister = 427
)
