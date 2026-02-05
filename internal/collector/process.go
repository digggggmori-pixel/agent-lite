// Package collector provides data collection from Windows APIs
package collector

import (
	"fmt"
	"strings"
	"time"
	"unsafe"

	"github.com/digggggmori-pixel/agent-lite/pkg/types"
	"golang.org/x/sys/windows"
)

// ProcessCollector collects process information
type ProcessCollector struct {
	isAdmin bool
}

// NewProcessCollector creates a new process collector
func NewProcessCollector() *ProcessCollector {
	return &ProcessCollector{
		isAdmin: checkAdminPrivileges(),
	}
}

// IsAdmin returns whether the collector has admin privileges
func (c *ProcessCollector) IsAdmin() bool {
	return c.isAdmin
}

// Collect gathers all running processes
func (c *ProcessCollector) Collect() ([]types.ProcessInfo, error) {
	// Create a snapshot of all processes
	snapshot, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return nil, fmt.Errorf("CreateToolhelp32Snapshot failed: %w", err)
	}
	defer windows.CloseHandle(snapshot)

	var processes []types.ProcessInfo
	processMap := make(map[uint32]*types.ProcessInfo)

	var pe windows.ProcessEntry32
	pe.Size = uint32(unsafe.Sizeof(pe))

	// First pass: collect all processes
	err = windows.Process32First(snapshot, &pe)
	if err != nil {
		return nil, fmt.Errorf("Process32First failed: %w", err)
	}

	for {
		name := windows.UTF16ToString(pe.ExeFile[:])

		proc := types.ProcessInfo{
			PID:        pe.ProcessID,
			PPID:       pe.ParentProcessID,
			Name:       name,
			CreateTime: time.Now(), // Will be updated if we can get actual time
		}

		// Try to get more details (path, command line)
		if details, err := c.getProcessDetails(pe.ProcessID); err == nil {
			proc.Path = details.Path
			proc.CommandLine = details.CommandLine
			proc.User = details.User
			proc.CreateTime = details.CreateTime
		}

		processes = append(processes, proc)
		processMap[pe.ProcessID] = &processes[len(processes)-1]

		err = windows.Process32Next(snapshot, &pe)
		if err != nil {
			break
		}
	}

	// Second pass: fill in parent info
	for i := range processes {
		if parent, exists := processMap[processes[i].PPID]; exists {
			processes[i].ParentName = parent.Name
			processes[i].ParentPath = parent.Path
		}
	}

	return processes, nil
}

type processDetails struct {
	Path        string
	CommandLine string
	User        string
	CreateTime  time.Time
}

func (c *ProcessCollector) getProcessDetails(pid uint32) (*processDetails, error) {
	details := &processDetails{
		CreateTime: time.Now(),
	}

	// System and Idle process can't be opened
	if pid == 0 || pid == 4 {
		return details, nil
	}

	// Open process with query information access
	access := uint32(windows.PROCESS_QUERY_LIMITED_INFORMATION)
	if c.isAdmin {
		access = windows.PROCESS_QUERY_INFORMATION | windows.PROCESS_VM_READ
	}

	handle, err := windows.OpenProcess(access, false, pid)
	if err != nil {
		return details, err
	}
	defer windows.CloseHandle(handle)

	// Get executable path
	var pathBuf [windows.MAX_PATH]uint16
	pathLen := uint32(len(pathBuf))
	err = windows.QueryFullProcessImageName(handle, 0, &pathBuf[0], &pathLen)
	if err == nil {
		details.Path = windows.UTF16ToString(pathBuf[:pathLen])
	}

	// Get command line (requires admin for other processes)
	if c.isAdmin {
		if cmdline, err := getProcessCommandLine(handle); err == nil {
			details.CommandLine = cmdline
		}
	}

	// Get process user
	if user, err := getProcessUser(handle); err == nil {
		details.User = user
	}

	// Get creation time
	var creationTime, exitTime, kernelTime, userTime windows.Filetime
	err = windows.GetProcessTimes(handle, &creationTime, &exitTime, &kernelTime, &userTime)
	if err == nil {
		details.CreateTime = time.Unix(0, creationTime.Nanoseconds())
	}

	return details, nil
}

// getProcessCommandLine retrieves command line for a process (admin required)
func getProcessCommandLine(handle windows.Handle) (string, error) {
	// This requires reading from PEB which needs PROCESS_VM_READ
	// For simplicity, we'll use WMI or NtQueryInformationProcess
	// This is a placeholder - full implementation would use NtQueryInformationProcess
	return "", fmt.Errorf("not implemented without admin")
}

// getProcessUser retrieves the user running a process
func getProcessUser(handle windows.Handle) (string, error) {
	var token windows.Token
	err := windows.OpenProcessToken(handle, windows.TOKEN_QUERY, &token)
	if err != nil {
		return "", err
	}
	defer token.Close()

	tokenUser, err := token.GetTokenUser()
	if err != nil {
		return "", err
	}

	account, domain, _, err := tokenUser.User.Sid.LookupAccount("")
	if err != nil {
		return "", err
	}

	return fmt.Sprintf("%s\\%s", domain, account), nil
}

// checkAdminPrivileges checks if running with admin privileges
func checkAdminPrivileges() bool {
	var sid *windows.SID
	err := windows.AllocateAndInitializeSid(
		&windows.SECURITY_NT_AUTHORITY,
		2,
		windows.SECURITY_BUILTIN_DOMAIN_RID,
		windows.DOMAIN_ALIAS_RID_ADMINS,
		0, 0, 0, 0, 0, 0,
		&sid)
	if err != nil {
		return false
	}
	defer windows.FreeSid(sid)

	// Get current process token
	var token windows.Token
	proc := windows.CurrentProcess()
	err = windows.OpenProcessToken(proc, windows.TOKEN_QUERY, &token)
	if err != nil {
		return false
	}
	defer token.Close()

	member, err := token.IsMember(sid)
	if err != nil {
		return false
	}

	return member
}

// BuildProcessTree builds a tree structure from process list
func BuildProcessTree(processes []types.ProcessInfo) map[uint32][]types.ProcessInfo {
	tree := make(map[uint32][]types.ProcessInfo)
	for _, p := range processes {
		tree[p.PPID] = append(tree[p.PPID], p)
	}
	return tree
}

// GetProcessByPID finds a process by PID
func GetProcessByPID(processes []types.ProcessInfo, pid uint32) *types.ProcessInfo {
	for i := range processes {
		if processes[i].PID == pid {
			return &processes[i]
		}
	}
	return nil
}

// GetProcessByName finds processes by name (case-insensitive)
func GetProcessByName(processes []types.ProcessInfo, name string) []types.ProcessInfo {
	var result []types.ProcessInfo
	nameLower := strings.ToLower(name)
	for _, p := range processes {
		if strings.ToLower(p.Name) == nameLower {
			result = append(result, p)
		}
	}
	return result
}
