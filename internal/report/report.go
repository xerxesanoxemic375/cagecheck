package report

import (
	"github.com/declaw-ai/cagecheck/internal/checks"
	"github.com/declaw-ai/cagecheck/internal/detect"
)

type Report struct {
	Version     string              `json:"version"`
	Timestamp   string              `json:"timestamp"`
	Environment detect.Environment  `json:"environment"`
	Checklist   []checks.EscapeItem `json:"escape_checklist"`
	Findings    []checks.Category   `json:"findings"`
}
