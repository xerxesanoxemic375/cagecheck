package output

import (
	"encoding/json"
	"fmt"

	"github.com/declaw-ai/cagecheck/internal/report"
)

func PrintJSON(report report.Report) error {
	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return err
	}
	fmt.Println(string(data))
	return nil
}
