//go:build linux && amd64

package checks

// Linux amd64 syscall numbers.
const (
	sysMount        = 165
	sysUmount2      = 166
	sysPtrace       = 101
	sysReboot       = 169
	sysPivotRoot    = 155
	sysMknod        = 133
	sysInitModule   = 175
	sysFinitModule  = 313
	sysDeleteModule = 176
	sysKexecLoad    = 246
	sysUnshare      = 272
	sysSetns        = 308

	sysIoUringSetup    = 425
	sysIoUringEnter    = 426
	sysIoUringRegister = 427
)
