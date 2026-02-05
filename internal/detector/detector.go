package detector

import (
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/digggggmori-pixel/agent-lite/pkg/types"
)

// Detector is the main detection engine
type Detector struct {
	pathPatterns []*regexp.Regexp
}

// New creates a new Detector instance
func New() *Detector {
	d := &Detector{
		pathPatterns: make([]*regexp.Regexp, 0, len(PathAnomalyPatterns)),
	}

	// Compile path anomaly patterns
	for _, pattern := range PathAnomalyPatterns {
		if re, err := regexp.Compile("(?i)" + pattern); err == nil {
			d.pathPatterns = append(d.pathPatterns, re)
		}
	}

	return d
}

// DetectLOLBins detects LOLBin execution
func (d *Detector) DetectLOLBins(processes []types.ProcessInfo) []types.Detection {
	var detections []types.Detection

	for i := range processes {
		proc := processes[i] // Copy to avoid pointer issues
		nameLower := strings.ToLower(proc.Name)

		if AllLOLBins[nameLower] {
			category := LOLBinCategory(nameLower)
			severity := determineLOLBinSeverity(nameLower, proc.CommandLine)

			procCopy := proc // Make a copy for the pointer
			detection := types.Detection{
				ID:          fmt.Sprintf("lolbin-%d-%d", proc.PID, time.Now().UnixNano()),
				Type:        types.DetectionTypeLOLBin,
				Severity:    severity,
				Confidence:  0.7,
				Timestamp:   proc.CreateTime,
				Description: fmt.Sprintf("LOLBin %s (%s) executed", proc.Name, category),
				Process:     &procCopy,
				MITRE:       getLOLBinMITRE(category),
			}

			// Increase confidence based on suspicious command line
			if hasSuspiciousArgs(proc.CommandLine) {
				detection.Confidence = 0.9
				detection.Severity = types.SeverityHigh
			}

			detections = append(detections, detection)
		}
	}

	return detections
}

// DetectChains detects suspicious parent-child process chains
func (d *Detector) DetectChains(processes []types.ProcessInfo) []types.Detection {
	var detections []types.Detection

	for i := range processes {
		proc := processes[i]
		parentName := strings.ToLower(proc.ParentName)
		childName := strings.ToLower(proc.Name)

		if suspiciousChildren, exists := SuspiciousChains[parentName]; exists {
			for _, suspChild := range suspiciousChildren {
				if childName == suspChild {
					procCopy := proc
					detection := types.Detection{
						ID:          fmt.Sprintf("chain-%d-%d", proc.PID, time.Now().UnixNano()),
						Type:        types.DetectionTypeChain,
						Severity:    types.SeverityHigh,
						Confidence:  0.85,
						Timestamp:   proc.CreateTime,
						Description: fmt.Sprintf("Suspicious chain: %s → %s", proc.ParentName, proc.Name),
						Process:     &procCopy,
						MITRE:       getChainMITRE(parentName),
					}

					detections = append(detections, detection)
					break
				}
			}
		}
	}

	return detections
}

// DetectSuspiciousPorts detects connections to suspicious ports
func (d *Detector) DetectSuspiciousPorts(connections []types.NetworkConnection) []types.Detection {
	var detections []types.Detection

	for i := range connections {
		conn := connections[i]

		// Check remote port for outbound connections
		if conn.State == "ESTABLISHED" && conn.RemotePort > 0 {
			if description, suspicious := SuspiciousPorts[conn.RemotePort]; suspicious {
				connCopy := conn
				detection := types.Detection{
					ID:          fmt.Sprintf("port-%d-%d", conn.OwningPID, time.Now().UnixNano()),
					Type:        types.DetectionTypePort,
					Severity:    determinPortSeverity(conn.RemotePort),
					Confidence:  0.75,
					Timestamp:   time.Now(),
					Description: fmt.Sprintf("Connection to suspicious port %d (%s)", conn.RemotePort, description),
					Network:     &connCopy,
					MITRE: &types.MITREMapping{
						Tactics:    []string{"Command and Control"},
						Techniques: []string{"T1071"},
					},
				}

				detections = append(detections, detection)
			}
		}

		// Check local port for listening services
		if conn.State == "LISTEN" {
			if description, suspicious := SuspiciousPorts[conn.LocalPort]; suspicious {
				connCopy := conn
				detection := types.Detection{
					ID:          fmt.Sprintf("listen-%d-%d", conn.OwningPID, time.Now().UnixNano()),
					Type:        types.DetectionTypePort,
					Severity:    types.SeverityMedium,
					Confidence:  0.6,
					Timestamp:   time.Now(),
					Description: fmt.Sprintf("Listening on suspicious port %d (%s)", conn.LocalPort, description),
					Network:     &connCopy,
					MITRE: &types.MITREMapping{
						Tactics:    []string{"Command and Control", "Persistence"},
						Techniques: []string{"T1571"},
					},
				}

				detections = append(detections, detection)
			}
		}
	}

	return detections
}

// DetectPathAnomalies detects suspicious process paths
func (d *Detector) DetectPathAnomalies(processes []types.ProcessInfo) []types.Detection {
	var detections []types.Detection

	for i := range processes {
		proc := processes[i]
		if proc.Path == "" {
			continue
		}

		for j, pattern := range d.pathPatterns {
			if pattern.MatchString(proc.Path) {
				procCopy := proc
				detection := types.Detection{
					ID:          fmt.Sprintf("path-%d-%d", proc.PID, time.Now().UnixNano()),
					Type:        types.DetectionTypePath,
					Severity:    types.SeverityMedium,
					Confidence:  0.7,
					Timestamp:   proc.CreateTime,
					Description: fmt.Sprintf("Suspicious path pattern: %s", getPathPatternDescription(j)),
					Process:     &procCopy,
					MITRE: &types.MITREMapping{
						Tactics:    []string{"Defense Evasion"},
						Techniques: []string{"T1036"},
					},
				}

				detections = append(detections, detection)
				break // Only report first matching pattern
			}
		}
	}

	return detections
}

// DetectTyposquatting detects typosquatted process names
func (d *Detector) DetectTyposquatting(processes []types.ProcessInfo) []types.Detection {
	var detections []types.Detection

	for i := range processes {
		proc := processes[i]
		nameLower := strings.ToLower(proc.Name)
		pathLower := strings.ToLower(proc.Path)

		for targetName, expectedPath := range TyposquatTargets {
			targetLower := strings.ToLower(targetName)

			// Check if name is similar but not exact
			if nameLower != targetLower && isSimilar(nameLower, targetLower) {
				procCopy := proc
				detection := types.Detection{
					ID:          fmt.Sprintf("typo-%d-%d", proc.PID, time.Now().UnixNano()),
					Type:        types.DetectionTypeTyposquat,
					Severity:    types.SeverityHigh,
					Confidence:  0.85,
					Timestamp:   proc.CreateTime,
					Description: fmt.Sprintf("Possible typosquatting: %s (similar to %s)", proc.Name, targetName),
					Process:     &procCopy,
					MITRE: &types.MITREMapping{
						Tactics:    []string{"Defense Evasion"},
						Techniques: []string{"T1036.005"},
					},
				}

				detections = append(detections, detection)
			}

			// Check if name matches but path doesn't
			if nameLower == targetLower && !strings.EqualFold(pathLower, expectedPath) {
				// Verify it's not just a different valid path
				if !isValidSystemPath(proc.Path, targetName) {
					procCopy := proc
					detection := types.Detection{
						ID:          fmt.Sprintf("masq-%d-%d", proc.PID, time.Now().UnixNano()),
						Type:        types.DetectionTypeTyposquat,
						Severity:    types.SeverityCritical,
						Confidence:  0.95,
						Timestamp:   proc.CreateTime,
						Description: fmt.Sprintf("Process masquerading: %s running from unexpected path", proc.Name),
						Process:     &procCopy,
						MITRE: &types.MITREMapping{
							Tactics:    []string{"Defense Evasion"},
							Techniques: []string{"T1036.005"},
						},
						Details: map[string]interface{}{
							"expected_path": expectedPath,
							"actual_path":   proc.Path,
						},
					}

					detections = append(detections, detection)
				}
			}
		}
	}

	return detections
}

// Helper functions

func determineLOLBinSeverity(name, cmdline string) string {
	// High severity LOLBins
	highSeverity := map[string]bool{
		"certutil.exe": true, "bitsadmin.exe": true, "mshta.exe": true,
		"regsvr32.exe": true, "rundll32.exe": true, "msbuild.exe": true,
		"cmstp.exe": true, "installutil.exe": true,
	}

	if highSeverity[name] {
		return types.SeverityHigh
	}

	// Check for suspicious command line patterns
	if hasSuspiciousArgs(cmdline) {
		return types.SeverityHigh
	}

	return types.SeverityMedium
}

func hasSuspiciousArgs(cmdline string) bool {
	if cmdline == "" {
		return false
	}

	cmdLower := strings.ToLower(cmdline)
	suspiciousPatterns := []string{
		"-encodedcommand", "-enc ", "-e ", "-ec ",
		"downloadstring", "downloadfile", "invoke-webrequest",
		"iex(", "invoke-expression",
		"-urlcache", "-split",
		"http://", "https://", "ftp://",
		"bypass", "-nop", "-noprofile", "-w hidden",
		"frombase64", "tobase64",
		"-exec bypass", "unrestricted",
	}

	for _, pattern := range suspiciousPatterns {
		if strings.Contains(cmdLower, pattern) {
			return true
		}
	}

	return false
}

func getLOLBinMITRE(category string) *types.MITREMapping {
	mapping := &types.MITREMapping{}

	switch category {
	case "Execute":
		mapping.Tactics = []string{"Execution"}
		mapping.Techniques = []string{"T1059"}
	case "Download":
		mapping.Tactics = []string{"Command and Control"}
		mapping.Techniques = []string{"T1105"}
	case "Bypass":
		mapping.Tactics = []string{"Defense Evasion"}
		mapping.Techniques = []string{"T1218"}
	case "Recon":
		mapping.Tactics = []string{"Discovery"}
		mapping.Techniques = []string{"T1082", "T1083"}
	case "Persist":
		mapping.Tactics = []string{"Persistence"}
		mapping.Techniques = []string{"T1053", "T1543"}
	case "Credential Access":
		mapping.Tactics = []string{"Credential Access"}
		mapping.Techniques = []string{"T1003"}
	case "Lateral Movement":
		mapping.Tactics = []string{"Lateral Movement"}
		mapping.Techniques = []string{"T1021"}
	case "Compile":
		mapping.Tactics = []string{"Defense Evasion"}
		mapping.Techniques = []string{"T1027.004"}
	default:
		mapping.Tactics = []string{"Execution"}
		mapping.Techniques = []string{"T1059"}
	}

	return mapping
}

func getChainMITRE(parentName string) *types.MITREMapping {
	mapping := &types.MITREMapping{}

	switch {
	case strings.Contains(parentName, "w3wp") || strings.Contains(parentName, "httpd") ||
		strings.Contains(parentName, "tomcat") || strings.Contains(parentName, "java"):
		mapping.Tactics = []string{"Initial Access", "Execution"}
		mapping.Techniques = []string{"T1190", "T1059"}
	case strings.Contains(parentName, "word") || strings.Contains(parentName, "excel") ||
		strings.Contains(parentName, "outlook"):
		mapping.Tactics = []string{"Initial Access", "Execution"}
		mapping.Techniques = []string{"T1566", "T1204"}
	case strings.Contains(parentName, "wmiprvse"):
		mapping.Tactics = []string{"Execution"}
		mapping.Techniques = []string{"T1047"}
	default:
		mapping.Tactics = []string{"Execution"}
		mapping.Techniques = []string{"T1059"}
	}

	return mapping
}

func determinPortSeverity(port uint16) string {
	// Critical ports (common C2/reverse shell)
	criticalPorts := map[uint16]bool{
		4444: true, 5555: true, 6666: true, 1337: true, 31337: true,
	}

	if criticalPorts[port] {
		return types.SeverityCritical
	}

	// High severity ports
	highPorts := map[uint16]bool{
		8080: true, 8443: true, 4443: true, 6667: true, 9001: true,
	}

	if highPorts[port] {
		return types.SeverityHigh
	}

	return types.SeverityMedium
}

func getPathPatternDescription(index int) string {
	descriptions := []string{
		"UNC path (remote execution)",
		"Alternate Data Stream",
		"Double extension",
		"Numeric filename",
		"Fake system path",
		"Temp folder executable",
		"AppData executable",
		"Public folder executable",
		"ProgramData executable",
		"Recycle bin execution",
	}

	if index < len(descriptions) {
		return descriptions[index]
	}
	return "Unknown pattern"
}

// isSimilar checks if two strings are similar (Levenshtein distance 1-2)
func isSimilar(a, b string) bool {
	distance := levenshteinDistance(a, b)
	return distance > 0 && distance <= 2
}

// levenshteinDistance calculates the edit distance between two strings
func levenshteinDistance(a, b string) int {
	if len(a) == 0 {
		return len(b)
	}
	if len(b) == 0 {
		return len(a)
	}

	// Create matrix
	matrix := make([][]int, len(a)+1)
	for i := range matrix {
		matrix[i] = make([]int, len(b)+1)
		matrix[i][0] = i
	}
	for j := range matrix[0] {
		matrix[0][j] = j
	}

	// Fill matrix
	for i := 1; i <= len(a); i++ {
		for j := 1; j <= len(b); j++ {
			cost := 1
			if a[i-1] == b[j-1] {
				cost = 0
			}
			matrix[i][j] = min(
				matrix[i-1][j]+1,      // deletion
				matrix[i][j-1]+1,      // insertion
				matrix[i-1][j-1]+cost, // substitution
			)
		}
	}

	return matrix[len(a)][len(b)]
}

func min(values ...int) int {
	m := values[0]
	for _, v := range values[1:] {
		if v < m {
			m = v
		}
	}
	return m
}

func isValidSystemPath(path, processName string) bool {
	pathLower := strings.ToLower(path)
	nameLower := strings.ToLower(processName)

	// Check for valid Windows system paths
	validPaths := []string{
		`c:\windows\system32\`,
		`c:\windows\syswow64\`,
		`c:\windows\`,
		`c:\windows\system32\wbem\`,
	}

	for _, validPath := range validPaths {
		if strings.HasPrefix(pathLower, validPath) && strings.HasSuffix(pathLower, nameLower) {
			return true
		}
	}

	return false
}
