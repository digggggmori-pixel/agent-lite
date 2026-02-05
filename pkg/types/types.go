// Package types defines the core data structures for Agent Lite
package types

import "time"

// ProcessInfo represents a running process
type ProcessInfo struct {
	PID         uint32    `json:"pid"`
	PPID        uint32    `json:"ppid"`
	Name        string    `json:"name"`
	Path        string    `json:"path"`
	CommandLine string    `json:"cmdline,omitempty"`
	CreateTime  time.Time `json:"create_time"`
	User        string    `json:"user,omitempty"`
	ParentName  string    `json:"parent_name,omitempty"`
	ParentPath  string    `json:"parent_path,omitempty"`
}

// NetworkConnection represents a TCP/UDP connection
type NetworkConnection struct {
	Protocol    string `json:"protocol"`
	LocalAddr   string `json:"local_addr"`
	LocalPort   uint16 `json:"local_port"`
	RemoteAddr  string `json:"remote_addr"`
	RemotePort  uint16 `json:"remote_port"`
	State       string `json:"state"`
	OwningPID   uint32 `json:"owning_pid"`
	ProcessName string `json:"process_name"`
}

// ServiceInfo represents a Windows service
type ServiceInfo struct {
	Name        string `json:"name"`
	DisplayName string `json:"display_name"`
	Status      string `json:"status"`
	StartType   string `json:"start_type"`
	BinaryPath  string `json:"binary_path"`
}

// RegistryEntry represents a registry key/value
type RegistryEntry struct {
	Key       string `json:"key"`
	ValueName string `json:"value_name"`
	ValueData string `json:"value_data"`
	ValueType string `json:"value_type"`
}

// EventLogEntry represents a Windows event log entry
type EventLogEntry struct {
	Channel   string                 `json:"channel"`
	Provider  string                 `json:"provider"`
	EventID   uint32                 `json:"event_id"`
	Timestamp time.Time              `json:"timestamp"`
	Data      map[string]interface{} `json:"data"`
}

// Detection represents a security detection
type Detection struct {
	ID          string                 `json:"id"`
	Type        string                 `json:"type"`
	Severity    string                 `json:"severity"`
	Confidence  float64                `json:"confidence"`
	Timestamp   time.Time              `json:"timestamp"`
	Description string                 `json:"description"`
	Process     *ProcessInfo           `json:"process,omitempty"`
	Network     *NetworkConnection     `json:"network,omitempty"`
	Registry    *RegistryEntry         `json:"registry,omitempty"`
	MITRE       *MITREMapping          `json:"mitre,omitempty"`
	SigmaRules  []string               `json:"sigma_rules,omitempty"`
	Details     map[string]interface{} `json:"details,omitempty"`
}

// MITREMapping represents MITRE ATT&CK mapping
type MITREMapping struct {
	Tactics    []string `json:"tactics"`
	Techniques []string `json:"techniques"`
}

// HostInfo represents the host system information
type HostInfo struct {
	Hostname    string   `json:"hostname"`
	Domain      string   `json:"domain,omitempty"`
	OSVersion   string   `json:"os_version"`
	Arch        string   `json:"arch"`
	IPAddresses []string `json:"ip_addresses"`
}

// ScanSummary represents the summary of a scan
type ScanSummary struct {
	TotalProcesses   int            `json:"total_processes"`
	TotalConnections int            `json:"total_connections"`
	TotalServices    int            `json:"total_services"`
	TotalEvents      int            `json:"total_events"`
	Detections       DetectionCount `json:"detections"`
}

// DetectionCount represents detection counts by severity
type DetectionCount struct {
	Critical int `json:"critical"`
	High     int `json:"high"`
	Medium   int `json:"medium"`
	Low      int `json:"low"`
}

// IOCCollection represents collected Indicators of Compromise
type IOCCollection struct {
	IPs   []IOCEntry `json:"ips,omitempty"`
	URLs  []IOCEntry `json:"urls,omitempty"`
	Files []IOCEntry `json:"files,omitempty"`
}

// IOCEntry represents a single IOC
type IOCEntry struct {
	Value   string `json:"value"`
	Context string `json:"context"`
}

// ScanResult represents the complete scan result
type ScanResult struct {
	AgentVersion   string         `json:"agent_version"`
	ScanID         string         `json:"scan_id"`
	ScanTime       time.Time      `json:"scan_time"`
	ScanDurationMs int64          `json:"scan_duration_ms"`
	Host           HostInfo       `json:"host"`
	Summary        ScanSummary    `json:"summary"`
	Detections     []Detection    `json:"detections"`
	IOCs           IOCCollection  `json:"iocs"`
}

// Severity constants
const (
	SeverityCritical = "critical"
	SeverityHigh     = "high"
	SeverityMedium   = "medium"
	SeverityLow      = "low"
	SeverityInfo     = "info"
)

// Detection type constants
const (
	DetectionTypeLOLBin      = "lolbin_execution"
	DetectionTypeChain       = "suspicious_chain"
	DetectionTypePort        = "suspicious_port"
	DetectionTypePath        = "path_anomaly"
	DetectionTypeTyposquat   = "typosquatting"
	DetectionTypeSigma       = "sigma_match"
	DetectionTypePersistence = "persistence"
)
