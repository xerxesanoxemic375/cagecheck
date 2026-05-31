package output

import (
	"fmt"
	"strings"

	"github.com/declaw-ai/cagecheck/internal/checks"
	"github.com/declaw-ai/cagecheck/internal/detect"
	"github.com/declaw-ai/cagecheck/internal/report"
)

const (
	reset  = "\033[0m"
	bold   = "\033[1m"
	red    = "\033[31m"
	green  = "\033[32m"
	yellow = "\033[33m"
	cyan   = "\033[36m"
	dim    = "\033[2m"
)

func PrintTerminal(report report.Report) {
	fmt.Printf("\n%scagecheck%s %s%s%s\n\n", bold, reset, dim, report.Version, reset)
	fmt.Printf("  Environment:  %s%s%s\n", cyan, detect.FormatEnvironment(report.Environment), reset)
	fmt.Printf("  Boundary:     %s%s%s\n\n", cyan, report.Environment.Boundary.String(), reset)

	printChecklist(report.Checklist)
	printDetailedFindings(report.Findings)
}

func printChecklist(items []checks.EscapeItem) {
	fmt.Printf("  %sESCAPE CHECKLIST%s\n", bold, reset)
	fmt.Printf("  %s\n", strings.Repeat("─", 70))

	for _, item := range items {
		icon := ""
		color := ""
		switch item.Status {
		case checks.Pass:
			icon = "PASS"
			color = green
		case checks.Fail:
			icon = "FAIL"
			color = red
		case checks.Warn:
			icon = "WARN"
			color = yellow
		case checks.NA:
			icon = "N/A "
			color = dim
		case checks.Skip:
			icon = "SKIP"
			color = dim
		}
		fmt.Printf("  %s[%s]%s  %s\n", color, icon, reset, item.Detail)
	}

	passed := 0
	failed := 0
	warned := 0
	for _, item := range items {
		switch item.Status {
		case checks.Pass:
			passed++
		case checks.Fail:
			failed++
		case checks.Warn:
			warned++
		}
	}
	fmt.Println()
	if failed == 0 && warned == 0 {
		fmt.Printf("  %sAll checks passed.%s\n\n", green, reset)
	} else {
		parts := []string{}
		if failed > 0 {
			parts = append(parts, fmt.Sprintf("%s%d failed%s", red, failed, reset))
		}
		if warned > 0 {
			parts = append(parts, fmt.Sprintf("%s%d warnings%s", yellow, warned, reset))
		}
		parts = append(parts, fmt.Sprintf("%s%d passed%s", green, passed, reset))
		fmt.Printf("  %s\n\n", strings.Join(parts, ", "))
	}
}

func printDetailedFindings(categories []checks.Category) {
	hasFindings := false
	for _, cat := range categories {
		for _, r := range cat.Results {
			if r.Status == checks.Fail || r.Status == checks.Warn {
				hasFindings = true
				break
			}
		}
	}
	if !hasFindings {
		return
	}

	fmt.Printf("  %sDETAILED FINDINGS%s\n", bold, reset)
	fmt.Printf("  %s\n", strings.Repeat("─", 70))

	for _, cat := range categories {
		catHasFindings := false
		for _, r := range cat.Results {
			if r.Status == checks.Fail || r.Status == checks.Warn {
				catHasFindings = true
				break
			}
		}
		if !catHasFindings {
			continue
		}
		fmt.Printf("  %s%s%s\n", dim, cat.Name, reset)
		for _, r := range cat.Results {
			if r.Status != checks.Fail && r.Status != checks.Warn {
				continue
			}
			color := yellow
			if r.Severity == checks.Critical || r.Severity == checks.High {
				color = red
			}
			fmt.Printf("    %s[%s]%s %s\n", color, r.Severity.String(), reset, r.Detail)
		}
	}
	fmt.Println()
}
