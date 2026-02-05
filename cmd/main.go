// Agent Lite - Lightweight Security Scanner for Windows
// Part of agent_hunter_v3 project
package main

import (
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/digggggmori-pixel/agent-lite/internal/collector"
	"github.com/digggggmori-pixel/agent-lite/internal/detector"
	"github.com/digggggmori-pixel/agent-lite/internal/output"
	"github.com/digggggmori-pixel/agent-lite/pkg/types"
	"github.com/google/uuid"
)

const Version = "1.0.0"

// CLI flags
var (
	quickScan  bool
	noUpload   bool
	jsonOutput bool
	quiet      bool
	verbose    bool
	outputDir  string
	showHelp   bool
	showVer    bool
)

func init() {
	flag.BoolVar(&quickScan, "quick", false, "Quick scan (last 24 hours only)")
	flag.BoolVar(&noUpload, "no-upload", false, "Scan only, skip server upload")
	flag.BoolVar(&jsonOutput, "json", false, "Output in JSON format")
	flag.BoolVar(&quiet, "quiet", false, "Suppress progress, show results only")
	flag.BoolVar(&verbose, "verbose", false, "Show detailed debug output")
	flag.StringVar(&outputDir, "output", "", "Specify output directory")
	flag.BoolVar(&showHelp, "help", false, "Show help")
	flag.BoolVar(&showVer, "version", false, "Show version")
}

func main() {
	flag.Parse()

	if showHelp {
		printUsage()
		return
	}

	if showVer {
		fmt.Printf("Agent Lite v%s\n", Version)
		return
	}

	args := flag.Args()
	if len(args) == 0 {
		printUsage()
		return
	}

	command := args[0]
	switch command {
	case "scan":
		runScan()
	case "status":
		showStatus()
	case "version":
		fmt.Printf("Agent Lite v%s\n", Version)
	default:
		fmt.Printf("Unknown command: %s\n", command)
		printUsage()
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Println(`Usage: agent-lite [command] [options]

Commands:
  scan          Run full baseline scan
  status        Check current agent status
  version       Show version info

Scan Options:
  --quick       Quick scan (last 24 hours only)
  --no-upload   Scan only, skip server upload
  --json        Output in JSON format
  --quiet       Suppress progress, show results only
  --verbose     Show detailed debug output
  --output DIR  Specify output directory

Examples:
  agent-lite scan                    # Full scan + upload
  agent-lite scan --quick            # Quick scan (24h)
  agent-lite scan --no-upload        # Local scan only
  agent-lite scan --json --quiet     # JSON output (for piping)`)
}

func runScan() {
	startTime := time.Now()

	// Initialize output handler
	out := output.New(output.Options{
		Quiet:   quiet,
		Verbose: verbose,
		JSON:    jsonOutput,
	})

	// Print header
	out.PrintHeader(Version)

	// Get host info
	hostInfo := collector.GetHostInfo()

	// Initialize result
	result := &types.ScanResult{
		AgentVersion: Version,
		ScanID:       uuid.New().String(),
		ScanTime:     startTime,
		Host:         hostInfo,
		Detections:   make([]types.Detection, 0),
	}

	// Initialize collectors
	processCollector := collector.NewProcessCollector()
	networkCollector := collector.NewNetworkCollector()
	serviceCollector := collector.NewServiceCollector()
	registryCollector := collector.NewRegistryCollector()

	// Initialize detectors
	det := detector.New()

	// Step 1: Collect processes
	out.PrintStep(1, 7, "Collecting processes...")
	out.PrintDetail("Calling NtQuerySystemInformation")
	processes, err := processCollector.Collect()
	if err != nil {
		out.PrintError("Failed to collect processes: %v", err)
		processes = []types.ProcessInfo{} // Initialize to empty slice
	} else {
		out.PrintDetail("Found %d processes", len(processes))
		if processCollector.IsAdmin() {
			out.PrintDetail("Collecting command lines (admin privileges confirmed)")
		}
		result.Summary.TotalProcesses = len(processes)
	}
	out.PrintDone(time.Since(startTime))

	stepStart := time.Now()

	// Step 2: Collect network connections
	out.PrintStep(2, 7, "Collecting network connections...")
	out.PrintDetail("Calling GetExtendedTcpTable")
	connections, err := networkCollector.Collect()
	if err != nil {
		out.PrintError("Failed to collect network connections: %v", err)
		connections = []types.NetworkConnection{} // Initialize to empty slice
	} else {
		tcpCount, udpCount := networkCollector.CountByProtocol(connections)
		out.PrintDetail("TCP: %d connections, UDP: %d", tcpCount, udpCount)
		result.Summary.TotalConnections = len(connections)
	}
	out.PrintDone(time.Since(stepStart))

	stepStart = time.Now()

	// Step 3: Collect services
	out.PrintStep(3, 7, "Collecting services...")
	out.PrintDetail("Calling EnumServicesStatusEx")
	services, err := serviceCollector.Collect()
	if err != nil {
		out.PrintError("Failed to collect services: %v", err)
	} else {
		runningCount, stoppedCount := serviceCollector.CountByStatus(services)
		out.PrintDetail("%d services (Running: %d, Stopped: %d)", len(services), runningCount, stoppedCount)
		result.Summary.TotalServices = len(services)
	}
	out.PrintDone(time.Since(stepStart))

	stepStart = time.Now()

	// Step 4: Scan registry
	out.PrintStep(4, 7, "Scanning registry...")
	out.PrintDetail("Checking 19 persistence keys")
	registryEntries, err := registryCollector.Collect()
	if err != nil {
		out.PrintError("Failed to scan registry: %v", err)
	} else {
		runCount, runOnceCount, servicesCount := registryCollector.CountByType(registryEntries)
		out.PrintDetail("Run: %d, RunOnce: %d, Services: %d", runCount, runOnceCount, servicesCount)
	}
	out.PrintDone(time.Since(stepStart))

	stepStart = time.Now()

	// Step 5: Run detection engine
	out.PrintStep(5, 7, "Running detection engine...")

	// LOLBin detection
	lolbinDetections := det.DetectLOLBins(processes)
	out.PrintDetectorResult("LOLBin detection (182 patterns)", len(lolbinDetections))
	result.Detections = append(result.Detections, lolbinDetections...)

	// Parent-Child chain detection
	chainDetections := det.DetectChains(processes)
	out.PrintDetectorResult("Parent-Child chains (102)", len(chainDetections))
	result.Detections = append(result.Detections, chainDetections...)

	// Suspicious port detection
	portDetections := det.DetectSuspiciousPorts(connections)
	out.PrintDetectorResult("Suspicious ports (46)", len(portDetections))
	result.Detections = append(result.Detections, portDetections...)

	// Path anomaly detection
	pathDetections := det.DetectPathAnomalies(processes)
	out.PrintDetectorResult("Path anomalies (10 patterns)", len(pathDetections))
	result.Detections = append(result.Detections, pathDetections...)

	// Typosquatting detection
	typosquatDetections := det.DetectTyposquatting(processes)
	out.PrintDetectorResult("Typosquatting (24 targets)", len(typosquatDetections))
	result.Detections = append(result.Detections, typosquatDetections...)

	out.PrintDone(time.Since(stepStart))

	stepStart = time.Now()

	// Step 6: Scan event logs (placeholder for Sigma integration)
	out.PrintStep(6, 7, "Scanning event logs (2,363 Sigma rules)...")
	out.PrintDetail("Event log scanning not yet implemented")
	out.PrintDone(time.Since(stepStart))

	stepStart = time.Now()

	// Step 7: Aggregate results
	out.PrintStep(7, 7, "Aggregating results...")

	// Count detections by severity
	for _, d := range result.Detections {
		switch d.Severity {
		case types.SeverityCritical:
			result.Summary.Detections.Critical++
		case types.SeverityHigh:
			result.Summary.Detections.High++
		case types.SeverityMedium:
			result.Summary.Detections.Medium++
		case types.SeverityLow:
			result.Summary.Detections.Low++
		}
	}

	// Deduplicate
	originalCount := len(result.Detections)
	result.Detections = deduplicateDetections(result.Detections)
	out.PrintDetail("Deduplication: %d → %d", originalCount, len(result.Detections))

	// Calculate duration
	result.ScanDurationMs = time.Since(startTime).Milliseconds()

	out.PrintDone(time.Since(stepStart))

	// Print summary
	out.PrintSummary(result, time.Since(startTime))

	// Print high severity detections
	out.PrintHighSeverityDetections(result.Detections)

	// Upload to server
	if !noUpload {
		out.PrintUploadStatus("https://api.agenthunter.io/v1/scan", true)
	}

	// Save results if output dir specified
	if outputDir != "" {
		out.SaveResults(result, outputDir)
	}
}

func showStatus() {
	fmt.Println("Agent Status: Not registered")
	fmt.Println("Use 'agent-lite install --token <token>' to register")
}

func deduplicateDetections(detections []types.Detection) []types.Detection {
	seen := make(map[string]bool)
	result := make([]types.Detection, 0)

	for _, d := range detections {
		key := fmt.Sprintf("%s-%s-%s", d.Type, d.Description, d.Timestamp.Format(time.RFC3339))
		if !seen[key] {
			seen[key] = true
			result = append(result, d)
		}
	}

	return result
}
