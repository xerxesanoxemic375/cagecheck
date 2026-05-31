package checks

type Severity int

const (
	Critical Severity = iota
	High
	Medium
	Low
	Info
)

func (s Severity) String() string {
	switch s {
	case Critical:
		return "CRIT"
	case High:
		return "HIGH"
	case Medium:
		return "MED"
	case Low:
		return "LOW"
	case Info:
		return "INFO"
	default:
		return "UNKNOWN"
	}
}

func (s Severity) MarshalJSON() ([]byte, error) {
	return []byte(`"` + s.String() + `"`), nil
}

type Status int

const (
	Pass Status = iota
	Fail
	Warn
	Skip
	NA // not applicable to this environment
)

func (s Status) String() string {
	switch s {
	case Pass:
		return "PASS"
	case Fail:
		return "FAIL"
	case Warn:
		return "WARN"
	case Skip:
		return "SKIP"
	case NA:
		return "N/A"
	default:
		return "UNKNOWN"
	}
}

func (s Status) MarshalJSON() ([]byte, error) {
	return []byte(`"` + s.String() + `"`), nil
}

type Result struct {
	Name     string   `json:"name"`
	Status   Status   `json:"status"`
	Severity Severity `json:"severity"`
	Detail   string   `json:"detail"`
	Data     any      `json:"data,omitempty"`
}

type Category struct {
	Name    string   `json:"name"`
	Results []Result `json:"results"`
}

type Check interface {
	Category() string
	Run() []Result
}

// EscapeItem is one line in the final escape checklist.
type EscapeItem struct {
	Name   string `json:"name"`
	Status Status `json:"status"`
	Detail string `json:"detail"`
}

// BoundaryType represents the isolation boundary detected.
type BoundaryType int

const (
	BoundaryUnknown   BoundaryType = iota
	BoundaryKernel                         // containers: namespaces, seccomp, caps
	BoundarySyscall                        // gVisor: userspace kernel
	BoundaryHardware                       // Firecracker, Kata, QEMU: hypervisor
)

func (b BoundaryType) String() string {
	switch b {
	case BoundaryKernel:
		return "kernel"
	case BoundarySyscall:
		return "syscall-interception"
	case BoundaryHardware:
		return "hardware"
	default:
		return "unknown"
	}
}

func (b BoundaryType) MarshalJSON() ([]byte, error) {
	return []byte(`"` + b.String() + `"`), nil
}
