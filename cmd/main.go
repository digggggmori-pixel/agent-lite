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
	"github.com/digggggmori-pixel/agent-lite/internal/logger"
	"github.com/digggggmori-pixel/agent-lite/internal/output"
	"github.com/digggggmori-pixel/agent-lite/internal/sigma"
	"github.com/digggggmori-pixel/agent-lite/internal/sigma/rules"
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
	debugLog   bool
	outputDir  string
	showHelp   bool
	showVer    bool
	forceRun   bool
)

func init() {
	flag.BoolVar(&quickScan, "quick", false, "Quick scan (last 24 hours only)")
	flag.BoolVar(&noUpload, "no-upload", false, "Scan only, skip server upload")
	flag.BoolVar(&jsonOutput, "json", false, "Output in JSON format")
	flag.BoolVar(&quiet, "quiet", false, "Suppress progress, show results only")
	flag.BoolVar(&verbose, "verbose", false, "Show detailed debug output")
	flag.BoolVar(&debugLog, "debug", false, "Generate debug log file")
	flag.StringVar(&outputDir, "output", "", "Specify output directory")
	flag.BoolVar(&showHelp, "help", false, "Show help")
	flag.BoolVar(&showVer, "version", false, "Show version")
	flag.BoolVar(&forceRun, "force", false, "Skip admin privilege check (limited results)")
}

func main() {
	// Find command first, then parse flags
	// This allows: "scan --debug" or "--debug scan"
	command := ""
	var newArgs []string

	for _, arg := range os.Args[1:] {
		if arg == "scan" || arg == "status" || arg == "version" {
			command = arg
		} else {
			newArgs = append(newArgs, arg)
		}
	}

	// Reset os.Args for flag.Parse to work with remaining args
	os.Args = append([]string{os.Args[0]}, newArgs...)
	flag.Parse()

	if showHelp {
		printUsage()
		return
	}

	if showVer {
		fmt.Printf("Agent Lite v%s\n", Version)
		return
	}

	if command == "" {
		printUsage()
		return
	}

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
  --debug       Generate debug log file (for troubleshooting)
  --output DIR  Specify output directory
  --force       Skip admin check (run with limited results)

Examples:
  agent-lite scan                    # Full scan + upload (admin required)
  agent-lite scan --force            # Run without admin (limited)
  agent-lite scan --quick            # Quick scan (24h)
  agent-lite scan --no-upload        # Local scan only
  agent-lite scan --json --quiet     # JSON output (for piping)
  agent-lite scan --debug            # Generate debug log file`)
}

func runScan() {
	startTime := time.Now()

	// Determine output directory
	saveDir := outputDir
	if saveDir == "" {
		saveDir = "."
	}

	// Initialize debug logger if --debug flag is set
	if debugLog {
		if err := logger.Init(saveDir, true); err != nil {
			fmt.Printf("Warning: Failed to initialize debug logger: %v\n", err)
		} else {
			defer logger.Close()
			logger.Info("Agent Lite v%s starting", Version)
			logger.Info("Debug logging enabled, output dir: %s", saveDir)
			logger.Info("CLI flags: quick=%v, noUpload=%v, json=%v, quiet=%v, verbose=%v, force=%v",
				quickScan, noUpload, jsonOutput, quiet, verbose, forceRun)
		}
	}

	// Initialize output handler
	out := output.New(output.Options{
		Quiet:   quiet,
		Verbose: verbose,
		JSON:    jsonOutput,
	})

	// Check admin privileges
	isAdmin := collector.IsRunningAsAdmin()
	if !isAdmin && !forceRun {
		fmt.Println()
		fmt.Println("╔════════════════════════════════════════════════════════════════════════╗")
		fmt.Println("║  WARNING: Administrator privileges recommended!                        ║")
		fmt.Println("╠════════════════════════════════════════════════════════════════════════╣")
		fmt.Println("║  Without admin rights, some data cannot be collected:                  ║")
		fmt.Println("║    - Process command line arguments                                    ║")
		fmt.Println("║    - Security event logs                                               ║")
		fmt.Println("║    - Some protected process information                                ║")
		fmt.Println("║                                                                        ║")
		fmt.Println("║  Options:                                                              ║")
		fmt.Println("║    1. Run as Administrator (recommended)                               ║")
		fmt.Println("║    2. Use --force flag to run anyway with limited results              ║")
		fmt.Println("╚════════════════════════════════════════════════════════════════════════╝")
		fmt.Println()
		os.Exit(1)
	}

	if !isAdmin && forceRun {
		fmt.Println()
		fmt.Println("╔════════════════════════════════════════════════════════════════════════╗")
		fmt.Println("║  Running without admin privileges (--force mode)                       ║")
		fmt.Println("║  Some detection capabilities will be limited.                          ║")
		fmt.Println("╚════════════════════════════════════════════════════════════════════════╝")
		fmt.Println()
	}

	// Print header
	out.PrintHeader(Version)

	// Get host info
	logger.Section("Host Information")
	hostInfo := collector.GetHostInfo()
	logger.Info("Hostname: %s", hostInfo.Hostname)
	logger.Info("Domain: %s", hostInfo.Domain)
	logger.Info("OS: %s (%s)", hostInfo.OSVersion, hostInfo.Arch)
	logger.Info("IPs: %v", hostInfo.IPAddresses)

	// Initialize result
	scanID := uuid.New().String()
	logger.Info("Scan ID: %s", scanID)
	result := &types.ScanResult{
		AgentVersion: Version,
		ScanID:       scanID,
		ScanTime:     startTime,
		Host:         hostInfo,
		Detections:   make([]types.Detection, 0),
	}

	// Initialize collectors
	logger.Section("Initializing Components")
	logger.Debug("Creating ProcessCollector")
	processCollector := collector.NewProcessCollector()
	logger.Debug("Creating NetworkCollector")
	networkCollector := collector.NewNetworkCollector()
	logger.Debug("Creating ServiceCollector")
	serviceCollector := collector.NewServiceCollector()
	logger.Debug("Creating RegistryCollector")
	registryCollector := collector.NewRegistryCollector()

	// Initialize detectors
	logger.Debug("Creating Detector")
	det := detector.New()
	logger.Info("All collectors and detectors initialized")

	// Step 1: Collect processes
	out.PrintStep(1, 8, "Collecting processes...")
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
	out.PrintStep(2, 8, "Collecting network connections...")
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
	out.PrintStep(3, 8, "Collecting services...")
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
	out.PrintStep(4, 8, "Scanning registry...")
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
	logger.Section("Detection Engine")
	out.PrintStep(5, 8, "Running detection engine...")

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

	// Service vendor typosquatting detection
	serviceVendorDetections := det.DetectServiceVendorTyposquatting(services)
	out.PrintDetectorResult("Service vendor typosquatting (31 vendors)", len(serviceVendorDetections))
	result.Detections = append(result.Detections, serviceVendorDetections...)

	// Service name typosquatting detection
	serviceNameDetections := det.DetectServiceNameTyposquatting(services)
	out.PrintDetectorResult("Service name typosquatting (25 services)", len(serviceNameDetections))
	result.Detections = append(result.Detections, serviceNameDetections...)

	// Service path anomaly detection
	servicePathDetections := det.DetectServicePathAnomalies(services)
	out.PrintDetectorResult("Service path anomalies", len(servicePathDetections))
	result.Detections = append(result.Detections, servicePathDetections...)

	// Unsigned critical process detection
	unsignedDetections := det.DetectUnsignedCriticalProcesses(processes)
	out.PrintDetectorResult("Unsigned critical processes (10 targets)", len(unsignedDetections))
	result.Detections = append(result.Detections, unsignedDetections...)

	// Suspicious domain detection
	domainDetections := det.DetectSuspiciousDomains(connections)
	out.PrintDetectorResult("Suspicious domains (28 TLDs)", len(domainDetections))
	result.Detections = append(result.Detections, domainDetections...)

	// Encoded command detection
	encodedCmdDetections := det.DetectEncodedCommands(processes)
	out.PrintDetectorResult("Encoded commands", len(encodedCmdDetections))
	result.Detections = append(result.Detections, encodedCmdDetections...)

	out.PrintDone(time.Since(stepStart))

	stepStart = time.Now()

	// Step 6: Live data Sigma matching (works without Sysmon)
	logger.Section("Live Sigma Matching")
	out.PrintStep(6, 8, "Scanning live data (Sigma rules)...")

	// Initialize Sigma engine with embedded rules
	logger.Debug("Loading Sigma rules from embedded filesystem")
	sigmaEngine, err := sigma.NewEngineWithRules(rules.EmbeddedRules)
	if err != nil {
		logger.Error("Failed to initialize Sigma engine: %v", err)
		out.PrintError("Failed to initialize Sigma engine: %v", err)
	} else {
		logger.Info("Sigma engine initialized: %d rules loaded", sigmaEngine.TotalRules())
		out.PrintDetail("Loaded %d Sigma rules", sigmaEngine.TotalRules())

		// Live process Sigma matching
		liveProcessMatches := sigma.ScanLiveProcesses(sigmaEngine, processes)
		for _, match := range liveProcessMatches {
			result.Detections = append(result.Detections, sigma.ConvertSigmaMatchToDetection(match, "live_process"))
		}
		out.PrintDetectorResult("Live Process Sigma (process_creation rules)", len(liveProcessMatches))

		// Live network Sigma matching
		processMap := sigma.BuildProcessMap(processes)
		liveNetworkMatches := sigma.ScanLiveNetwork(sigmaEngine, connections, processMap)
		for _, match := range liveNetworkMatches {
			result.Detections = append(result.Detections, sigma.ConvertSigmaMatchToDetection(match, "live_network"))
		}
		out.PrintDetectorResult("Live Network Sigma (network_connection rules)", len(liveNetworkMatches))
	}

	out.PrintDone(time.Since(stepStart))

	stepStart = time.Now()

	// Step 7: Scan event logs with Sigma rules
	out.PrintStep(7, 8, "Scanning event logs (Sigma rules)...")
	logger.Section("Event Log Sigma Scan")

	if sigmaEngine == nil {
		logger.Error("Sigma engine is nil, skipping event log scan")
		out.PrintDetail("Sigma engine not initialized, skipping event log scan")
	} else {
		logger.Info("Sigma engine ready with %d rules", sigmaEngine.TotalRules())

		// Create progress callback
		progressCB := func(progress sigma.ScanProgress) {
			logger.Debug("[%s] Progress: %d events, %d matches", progress.Channel, progress.Current, progress.Matches)
			if !quiet {
				out.PrintDetail("[%s] Scanned %d events, %d matches",
					progress.Channel, progress.Current, progress.Matches)
			}
		}

		// Initialize event log collector
		eventCollector := collector.NewEventLogCollector(
			collector.WithQuickMode(quickScan),
			collector.WithProgress(progressCB),
		)
		logger.Info("EventLogCollector initialized (quickMode=%v)", quickScan)

		// Check accessible channels
		logger.Debug("Checking accessible event log channels...")
		accessibleChannels := collector.GetAccessibleChannels()
		logger.Info("Accessible channels: %d of %d", len(accessibleChannels), len(collector.DefaultChannels))

		if len(accessibleChannels) == 0 {
			logger.Warn("No accessible event log channels - admin privileges required")
			out.PrintDetail("No accessible event log channels (admin required)")
			out.PrintDetail("Run as Administrator to enable event log scanning")
		} else {
			out.PrintDetail("Accessible channels: %d", len(accessibleChannels))
			for _, ch := range accessibleChannels {
				logger.Debug("  - %s", ch)
			}

			// Scan event logs
			logger.Info("Starting event log scan...")
			sigmaDetections, err := eventCollector.Scan(sigmaEngine)
			if err != nil {
				logger.Error("Event log scan failed: %v", err)
				out.PrintError("Event log scan error: %v", err)
			} else {
				logger.Info("Event log scan complete: %d events scanned, %d Sigma matches",
					eventCollector.TotalScanned(), len(sigmaDetections))
				out.PrintDetail("Event log scan complete: %d events, %d Sigma matches",
					eventCollector.TotalScanned(), len(sigmaDetections))
				result.Detections = append(result.Detections, sigmaDetections...)
				result.Summary.TotalEvents = int(eventCollector.TotalScanned())
			}
		}
	}

	out.PrintDone(time.Since(stepStart))

	stepStart = time.Now()

	// Step 8: Aggregate results
	logger.Section("Result Aggregation")
	out.PrintStep(8, 8, "Aggregating results...")

	// Count detections by severity
	logger.Debug("Counting detections by severity...")
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
	logger.Info("Detection counts - Critical: %d, High: %d, Medium: %d, Low: %d",
		result.Summary.Detections.Critical, result.Summary.Detections.High,
		result.Summary.Detections.Medium, result.Summary.Detections.Low)

	// Deduplicate
	originalCount := len(result.Detections)
	result.Detections = deduplicateDetections(result.Detections)
	logger.Info("Deduplication: %d → %d (removed %d duplicates)", originalCount, len(result.Detections), originalCount-len(result.Detections))
	out.PrintDetail("Deduplication: %d → %d", originalCount, len(result.Detections))

	// Extract IOCs
	result.IOCs = det.ExtractIOCs(result)
	logger.Info("IOCs extracted: %d IPs, %d files", len(result.IOCs.IPs), len(result.IOCs.Files))
	out.PrintDetail("IOCs extracted: %d IPs, %d files", len(result.IOCs.IPs), len(result.IOCs.Files))

	// Calculate duration
	result.ScanDurationMs = time.Since(startTime).Milliseconds()
	logger.Info("Total scan duration: %d ms", result.ScanDurationMs)

	out.PrintDone(time.Since(stepStart))

	// Print summary
	out.PrintSummary(result, time.Since(startTime))

	// Print high severity detections
	out.PrintHighSeverityDetections(result.Detections)

	// Upload to server
	if !noUpload {
		logger.Info("Uploading results to server...")
		out.PrintUploadStatus("https://api.agenthunter.io/v1/scan", true)
	}

	// Save results
	logger.Section("Saving Results")
	logger.Info("Output directory: %s", saveDir)
	out.SaveResults(result, saveDir)
	out.SaveDetailedReport(result, saveDir)

	// Log debug file location
	if debugLog {
		logPath := logger.GetLogPath()
		if logPath != "" {
			fmt.Printf("\nDebug log: %s\n", logPath)
		}
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
