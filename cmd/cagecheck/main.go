package main

import (
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/declaw-ai/cagecheck/internal/checks"
	"github.com/declaw-ai/cagecheck/internal/detect"
	"github.com/declaw-ai/cagecheck/internal/output"
	"github.com/declaw-ai/cagecheck/internal/runner"
	"github.com/declaw-ai/cagecheck/internal/report"
)

var version = "dev"

func main() {
	if checks.RunProbeChild() {
		return
	}

	jsonFlag := flag.Bool("json", false, "Output results as JSON")
	reportFlag := flag.Bool("report", false, "Output results as Markdown report")
	quietFlag := flag.Bool("quiet", false, "Suppress terminal output (implies --json)")
	findingsFlag := flag.Bool("findings", false, "Include detailed findings in output")
	versionFlag := flag.Bool("version", false, "Print version and exit")

	flag.Parse()

	if *versionFlag {
		fmt.Printf("cagecheck %s\n", version)
		os.Exit(0)
	}

	if *quietFlag {
		*jsonFlag = true
	}

	env := detect.DetectEnvironment()
	checklist := runner.RunChecklist(env.Boundary)

	var findings []checks.Category
	if *findingsFlag || *reportFlag {
		findings = runner.RunFindings(nil)
	}

	report := report.Report{
		Version:     version,
		Timestamp:   time.Now().UTC().Format(time.RFC3339),
		Environment: env,
		Checklist:   checklist,
		Findings:    findings,
	}

	if *reportFlag {
		output.PrintMarkdown(report)
	} else if *jsonFlag {
		if err := output.PrintJSON(report); err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(2)
		}
	}

	if !*quietFlag && !*reportFlag && !*jsonFlag {
		output.PrintTerminal(report)
	}

	for _, item := range checklist {
		if item.Status == checks.Fail {
			os.Exit(1)
		}
	}
}
