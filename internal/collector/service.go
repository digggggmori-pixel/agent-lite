package collector

import (
	"fmt"
	"syscall"
	"unsafe"

	"github.com/digggggmori-pixel/agent-lite/pkg/types"
	"golang.org/x/sys/windows"
)

var (
	modadvapi32                = syscall.NewLazyDLL("advapi32.dll")
	procEnumServicesStatusExW  = modadvapi32.NewProc("EnumServicesStatusExW")
	procQueryServiceConfigW    = modadvapi32.NewProc("QueryServiceConfigW")
)

// Service type and state constants
const (
	SERVICE_WIN32            = 0x00000030
	SERVICE_STATE_ALL        = 0x00000003
	SC_ENUM_PROCESS_INFO     = 0
	SERVICE_QUERY_CONFIG     = 0x0001
)

// Service states
const (
	SERVICE_STOPPED          = 0x00000001
	SERVICE_START_PENDING    = 0x00000002
	SERVICE_STOP_PENDING     = 0x00000003
	SERVICE_RUNNING          = 0x00000004
	SERVICE_CONTINUE_PENDING = 0x00000005
	SERVICE_PAUSE_PENDING    = 0x00000006
	SERVICE_PAUSED           = 0x00000007
)

// Service start types
const (
	SERVICE_BOOT_START   = 0x00000000
	SERVICE_SYSTEM_START = 0x00000001
	SERVICE_AUTO_START   = 0x00000002
	SERVICE_DEMAND_START = 0x00000003
	SERVICE_DISABLED     = 0x00000004
)

// ENUM_SERVICE_STATUS_PROCESS structure
type ENUM_SERVICE_STATUS_PROCESS struct {
	ServiceName          *uint16
	DisplayName          *uint16
	ServiceStatusProcess SERVICE_STATUS_PROCESS
}

// SERVICE_STATUS_PROCESS structure
type SERVICE_STATUS_PROCESS struct {
	ServiceType             uint32
	CurrentState            uint32
	ControlsAccepted        uint32
	Win32ExitCode           uint32
	ServiceSpecificExitCode uint32
	CheckPoint              uint32
	WaitHint                uint32
	ProcessId               uint32
	ServiceFlags            uint32
}

// QUERY_SERVICE_CONFIG structure
type QUERY_SERVICE_CONFIG struct {
	ServiceType      uint32
	StartType        uint32
	ErrorControl     uint32
	BinaryPathName   *uint16
	LoadOrderGroup   *uint16
	TagId            uint32
	Dependencies     *uint16
	ServiceStartName *uint16
	DisplayName      *uint16
}

// ServiceCollector collects Windows service information
type ServiceCollector struct{}

// NewServiceCollector creates a new service collector
func NewServiceCollector() *ServiceCollector {
	return &ServiceCollector{}
}

// Collect gathers all Windows services
func (c *ServiceCollector) Collect() ([]types.ServiceInfo, error) {
	// Open Service Control Manager
	scm, err := windows.OpenSCManager(nil, nil, windows.SC_MANAGER_ENUMERATE_SERVICE)
	if err != nil {
		return nil, fmt.Errorf("OpenSCManager failed: %w", err)
	}
	defer windows.CloseServiceHandle(scm)

	var services []types.ServiceInfo

	// First call to get required buffer size
	var bytesNeeded, servicesReturned, resumeHandle uint32
	ret, _, err := procEnumServicesStatusExW.Call(
		uintptr(scm),
		SC_ENUM_PROCESS_INFO,
		SERVICE_WIN32,
		SERVICE_STATE_ALL,
		0,
		0,
		uintptr(unsafe.Pointer(&bytesNeeded)),
		uintptr(unsafe.Pointer(&servicesReturned)),
		uintptr(unsafe.Pointer(&resumeHandle)),
		0,
	)

	// First call should fail with ERROR_MORE_DATA (234)
	if ret != 0 || bytesNeeded == 0 {
		return nil, fmt.Errorf("EnumServicesStatusExW size query failed: %v", err)
	}

	// Allocate buffer
	buf := make([]byte, bytesNeeded)
	ret, _, err = procEnumServicesStatusExW.Call(
		uintptr(scm),
		SC_ENUM_PROCESS_INFO,
		SERVICE_WIN32,
		SERVICE_STATE_ALL,
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(bytesNeeded),
		uintptr(unsafe.Pointer(&bytesNeeded)),
		uintptr(unsafe.Pointer(&servicesReturned)),
		uintptr(unsafe.Pointer(&resumeHandle)),
		0,
	)

	if ret == 0 {
		return nil, fmt.Errorf("EnumServicesStatusExW failed: %v", err)
	}

	// Parse services
	entrySize := unsafe.Sizeof(ENUM_SERVICE_STATUS_PROCESS{})
	for i := uint32(0); i < servicesReturned; i++ {
		offset := uintptr(i) * entrySize
		entry := (*ENUM_SERVICE_STATUS_PROCESS)(unsafe.Pointer(&buf[offset]))

		svcName := windows.UTF16PtrToString(entry.ServiceName)
		displayName := windows.UTF16PtrToString(entry.DisplayName)

		svc := types.ServiceInfo{
			Name:        svcName,
			DisplayName: displayName,
			Status:      serviceStateToString(entry.ServiceStatusProcess.CurrentState),
		}

		// Get service config for binary path and start type
		if config, err := c.getServiceConfig(scm, svcName); err == nil {
			svc.BinaryPath = config.BinaryPath
			svc.StartType = config.StartType
		}

		services = append(services, svc)
	}

	return services, nil
}

type serviceConfig struct {
	BinaryPath string
	StartType  string
}

func (c *ServiceCollector) getServiceConfig(scm windows.Handle, serviceName string) (*serviceConfig, error) {
	// Open the service
	serviceNamePtr, err := syscall.UTF16PtrFromString(serviceName)
	if err != nil {
		return nil, err
	}

	svc, err := windows.OpenService(scm, serviceNamePtr, SERVICE_QUERY_CONFIG)
	if err != nil {
		return nil, err
	}
	defer windows.CloseServiceHandle(svc)

	// Query config
	var bytesNeeded uint32
	ret, _, _ := procQueryServiceConfigW.Call(
		uintptr(svc),
		0,
		0,
		uintptr(unsafe.Pointer(&bytesNeeded)),
	)

	if bytesNeeded == 0 {
		return nil, fmt.Errorf("QueryServiceConfigW size query failed")
	}

	buf := make([]byte, bytesNeeded)
	ret, _, _ = procQueryServiceConfigW.Call(
		uintptr(svc),
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(bytesNeeded),
		uintptr(unsafe.Pointer(&bytesNeeded)),
	)

	if ret == 0 {
		return nil, fmt.Errorf("QueryServiceConfigW failed")
	}

	config := (*QUERY_SERVICE_CONFIG)(unsafe.Pointer(&buf[0]))

	return &serviceConfig{
		BinaryPath: windows.UTF16PtrToString(config.BinaryPathName),
		StartType:  startTypeToString(config.StartType),
	}, nil
}

// CountByStatus counts services by status
func (c *ServiceCollector) CountByStatus(services []types.ServiceInfo) (running, stopped int) {
	for _, svc := range services {
		if svc.Status == "Running" {
			running++
		} else if svc.Status == "Stopped" {
			stopped++
		}
	}
	return
}

func serviceStateToString(state uint32) string {
	switch state {
	case SERVICE_STOPPED:
		return "Stopped"
	case SERVICE_START_PENDING:
		return "Start Pending"
	case SERVICE_STOP_PENDING:
		return "Stop Pending"
	case SERVICE_RUNNING:
		return "Running"
	case SERVICE_CONTINUE_PENDING:
		return "Continue Pending"
	case SERVICE_PAUSE_PENDING:
		return "Pause Pending"
	case SERVICE_PAUSED:
		return "Paused"
	default:
		return fmt.Sprintf("Unknown(%d)", state)
	}
}

func startTypeToString(startType uint32) string {
	switch startType {
	case SERVICE_BOOT_START:
		return "Boot"
	case SERVICE_SYSTEM_START:
		return "System"
	case SERVICE_AUTO_START:
		return "Automatic"
	case SERVICE_DEMAND_START:
		return "Manual"
	case SERVICE_DISABLED:
		return "Disabled"
	default:
		return fmt.Sprintf("Unknown(%d)", startType)
	}
}

// GetRunningServices filters for running services
func GetRunningServices(services []types.ServiceInfo) []types.ServiceInfo {
	var result []types.ServiceInfo
	for _, svc := range services {
		if svc.Status == "Running" {
			result = append(result, svc)
		}
	}
	return result
}

// GetAutoStartServices filters for auto-start services
func GetAutoStartServices(services []types.ServiceInfo) []types.ServiceInfo {
	var result []types.ServiceInfo
	for _, svc := range services {
		if svc.StartType == "Automatic" || svc.StartType == "Boot" || svc.StartType == "System" {
			result = append(result, svc)
		}
	}
	return result
}
