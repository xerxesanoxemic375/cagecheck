package runner

import (
	"github.com/declaw-ai/cagecheck/internal/checks"
)

var allChecks = []checks.Check{
	&checks.SyscallCheck{},
	&checks.CapabilityCheck{},
	&checks.NamespaceCheck{},
	&checks.FilesystemCheck{},
	&checks.NetworkCheck{},
	&checks.InfoLeakageCheck{},
	&checks.EscapeVectorCheck{},
	&checks.PrivilegeCheck{},
}

func RunFindings(filter map[string]bool) []checks.Category {
	var categories []checks.Category
	for _, chk := range allChecks {
		if len(filter) > 0 && !filter[chk.Category()] {
			continue
		}
		results := chk.Run()
		categories = append(categories, checks.Category{
			Name:    chk.Category(),
			Results: results,
		})
	}
	return categories
}

func RunChecklist(boundary checks.BoundaryType) []checks.EscapeItem {
	return checks.BuildChecklist(boundary)
}
