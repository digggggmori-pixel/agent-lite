// Package output handles CLI output formatting
package output

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/digggggmori-pixel/agent-lite/pkg/types"
)

// Options for output handler
type Options struct {
	Quiet   bool
	Verbose bool
	JSON    bool
}

// Handler manages CLI output
type Handler struct {
	opts Options
}

// New creates a new output handler
func New(opts Options) *Handler {
	return &Handler{opts: opts}
}

// PrintHeader prints the scan header
func (h *Handler) PrintHeader(version string) {
	if h.opts.Quiet || h.opts.JSON {
		return
	}

	hostname, _ := os.Hostname()
	fmt.Println()
	fmt.Println("╔══════════════════════════════════════════════════════════════════════╗")
	fmt.Printf("║  Agent Lite v%s - Baseline Security Scan                          ║\n", version)
	fmt.Printf("║  Host: %-60s║\n", hostname)
	fmt.Printf("║  Time: %-60s║\n", time.Now().UTC().Format("2006-01-02 15:04:05 UTC"))
	fmt.Println("╚══════════════════════════════════════════════════════════════════════╝")
	fmt.Println()
}

// PrintStep prints a scan step
func (h *Handler) PrintStep(current, total int, message string) {
	if h.opts.Quiet || h.opts.JSON {
		return
	}
	fmt.Printf("[%d/%d] %s\n", current, total, message)
}

// PrintDetail prints a detail line
func (h *Handler) PrintDetail(format string, args ...interface{}) {
	if h.opts.Quiet || h.opts.JSON {
		return
	}
	fmt.Printf("      └─ "+format+"\n", args...)
}

// PrintDone prints completion time
func (h *Handler) PrintDone(duration time.Duration) {
	if h.opts.Quiet || h.opts.JSON {
		return
	}
	fmt.Printf("      └─ Done (%.1fs)\n\n", duration.Seconds())
}

// PrintError prints an error message
func (h *Handler) PrintError(format string, args ...interface{}) {
	if h.opts.JSON {
		return
	}
	fmt.Printf("      └─ ERROR: "+format+"\n", args...)
}

// PrintDetectorResult prints detector result with alignment
func (h *Handler) PrintDetectorResult(name string, count int) {
	if h.opts.Quiet || h.opts.JSON {
		return
	}
	dots := 45 - len(name)
	if dots < 3 {
		dots = 3
	}
	dotStr := ""
	for i := 0; i < dots; i++ {
		dotStr += "."
	}
	fmt.Printf("      ├─ %s%s %d found\n", name, dotStr, count)
}

// PrintSummary prints the scan summary
func (h *Handler) PrintSummary(result *types.ScanResult, duration time.Duration) {
	if h.opts.JSON {
		return
	}

	total := result.Summary.Detections.Critical +
		result.Summary.Detections.High +
		result.Summary.Detections.Medium +
		result.Summary.Detections.Low

	fmt.Println()
	fmt.Println("╔══════════════════════════════════════════════════════════════════════╗")
	fmt.Printf("║  Scan Complete! (%.1fs total)                                        ║\n", duration.Seconds())
	fmt.Println("╠══════════════════════════════════════════════════════════════════════╣")
	fmt.Println("║  Detection Summary                                                   ║")
	fmt.Println("║  ─────────────────────────────────────────────────────────────────── ║")
	fmt.Printf("║  🔴 Critical: %2d                                                     ║\n", result.Summary.Detections.Critical)
	fmt.Printf("║  🟠 High:     %2d                                                     ║\n", result.Summary.Detections.High)
	fmt.Printf("║  🟡 Medium:   %2d                                                     ║\n", result.Summary.Detections.Medium)
	fmt.Printf("║  🟢 Low:      %2d                                                     ║\n", result.Summary.Detections.Low)
	fmt.Println("║  ─────────────────────────────────────────────────────────────────── ║")
	fmt.Printf("║  Total: %d detections                                                ║\n", total)
	fmt.Println("╚══════════════════════════════════════════════════════════════════════╝")
	fmt.Println()
}

// PrintHighSeverityDetections prints high and critical detections
func (h *Handler) PrintHighSeverityDetections(detections []types.Detection) {
	if h.opts.JSON {
		return
	}

	var highSeverity []types.Detection
	for _, d := range detections {
		if d.Severity == types.SeverityCritical || d.Severity == types.SeverityHigh {
			highSeverity = append(highSeverity, d)
		}
	}

	if len(highSeverity) == 0 {
		return
	}

	fmt.Println("High Severity Detections:")
	fmt.Println("┌────┬─────────────────────────────────────────────────────────────────┐")

	for i, d := range highSeverity {
		severityStr := "HIGH"
		if d.Severity == types.SeverityCritical {
			severityStr = "CRITICAL"
		}

		fmt.Printf("│ #%d │ [%s] %s\n", i+1, severityStr, truncate(d.Description, 50))

		if d.Process != nil {
			fmt.Printf("│    │ PID: %d", d.Process.PID)
			if d.Process.ParentName != "" {
				fmt.Printf(", Parent: %s (PID: %d)", d.Process.ParentName, d.Process.PPID)
			}
			fmt.Println()
			if d.Process.CommandLine != "" {
				fmt.Printf("│    │ Cmdline: %s\n", truncate(d.Process.CommandLine, 50))
			}
		}

		if len(d.SigmaRules) > 0 {
			fmt.Printf("│    │ Sigma: %s\n", d.SigmaRules[0])
		}

		if i < len(highSeverity)-1 {
			fmt.Println("├────┼─────────────────────────────────────────────────────────────────┤")
		}
	}

	fmt.Println("└────┴─────────────────────────────────────────────────────────────────┘")
	fmt.Println()
}

// PrintUploadStatus prints upload status
func (h *Handler) PrintUploadStatus(endpoint string, success bool) {
	if h.opts.Quiet || h.opts.JSON {
		return
	}

	fmt.Println("Uploading to server...")
	fmt.Printf("      └─ Endpoint: %s\n", endpoint)
	if success {
		fmt.Println("      └─ Upload complete (HTTP 200)")
	} else {
		fmt.Println("      └─ Upload failed")
	}
	fmt.Println()
}

// SaveResults saves scan results to file
func (h *Handler) SaveResults(result *types.ScanResult, outputDir string) {
	filename := fmt.Sprintf("scan_%s.json", time.Now().Format("2006-01-02_150405"))
	fullPath := filepath.Join(outputDir, filename)

	data, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		h.PrintError("Failed to marshal results: %v", err)
		return
	}

	if err := os.MkdirAll(outputDir, 0755); err != nil {
		h.PrintError("Failed to create output directory: %v", err)
		return
	}

	if err := os.WriteFile(fullPath, data, 0644); err != nil {
		h.PrintError("Failed to write results: %v", err)
		return
	}

	if !h.opts.Quiet && !h.opts.JSON {
		fmt.Printf("Full results: %s\n", fullPath)
	}
}

func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen-3] + "..."
}
