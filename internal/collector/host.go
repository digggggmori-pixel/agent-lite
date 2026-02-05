package collector

import (
	"fmt"
	"net"
	"os"
	"runtime"
	"syscall"
	"unsafe"

	"github.com/digggggmori-pixel/agent-lite/pkg/types"
	"golang.org/x/sys/windows"
)

var (
	modkernel32          = syscall.NewLazyDLL("kernel32.dll")
	modnetapi32          = syscall.NewLazyDLL("netapi32.dll")
	modntdll             = syscall.NewLazyDLL("ntdll.dll")
	procGetVersionExW    = modkernel32.NewProc("GetVersionExW")
	procNetWkstaGetInfo  = modnetapi32.NewProc("NetWkstaGetInfo")
	procNetApiBufferFree = modnetapi32.NewProc("NetApiBufferFree")
	procRtlGetVersion    = modntdll.NewProc("RtlGetVersion")
)

// OSVERSIONINFOEXW structure
type OSVERSIONINFOEXW struct {
	OSVersionInfoSize uint32
	MajorVersion      uint32
	MinorVersion      uint32
	BuildNumber       uint32
	PlatformId        uint32
	CSDVersion        [128]uint16
	ServicePackMajor  uint16
	ServicePackMinor  uint16
	SuiteMask         uint16
	ProductType       byte
	Reserved          byte
}

// WKSTA_INFO_100 structure
type WKSTA_INFO_100 struct {
	PlatformId  uint32
	ComputerName *uint16
	LanGroup    *uint16
	VerMajor    uint32
	VerMinor    uint32
}

// GetHostInfo collects information about the host system
func GetHostInfo() types.HostInfo {
	hostname, _ := os.Hostname()

	info := types.HostInfo{
		Hostname:    hostname,
		Arch:        runtime.GOARCH,
		IPAddresses: getIPAddresses(),
	}

	// Get domain name
	if domain, err := getDomainName(); err == nil {
		info.Domain = domain
	}

	// Get OS version
	if version, err := getOSVersion(); err == nil {
		info.OSVersion = version
	}

	return info
}

func getIPAddresses() []string {
	var addresses []string

	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return addresses
	}

	for _, addr := range addrs {
		if ipnet, ok := addr.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
			if ipnet.IP.To4() != nil {
				addresses = append(addresses, ipnet.IP.String())
			}
		}
	}

	return addresses
}

func getDomainName() (string, error) {
	var buffer *byte
	ret, _, _ := procNetWkstaGetInfo.Call(
		0, // local computer
		100,
		uintptr(unsafe.Pointer(&buffer)),
	)

	if ret != 0 {
		return "", fmt.Errorf("NetWkstaGetInfo failed: %d", ret)
	}

	defer procNetApiBufferFree.Call(uintptr(unsafe.Pointer(buffer)))

	info := (*WKSTA_INFO_100)(unsafe.Pointer(buffer))
	domain := windows.UTF16PtrToString(info.LanGroup)

	return domain, nil
}

func getOSVersion() (string, error) {
	// Use RtlGetVersion as GetVersionEx is deprecated and may return incorrect values
	var version OSVERSIONINFOEXW
	version.OSVersionInfoSize = uint32(unsafe.Sizeof(version))

	ret, _, _ := procRtlGetVersion.Call(uintptr(unsafe.Pointer(&version)))
	if ret != 0 {
		return "", fmt.Errorf("RtlGetVersion failed: %d", ret)
	}

	// Determine Windows version name
	versionName := getWindowsVersionName(version.MajorVersion, version.MinorVersion, version.BuildNumber)

	return fmt.Sprintf("%s (Build %d)", versionName, version.BuildNumber), nil
}

func getWindowsVersionName(major, minor, build uint32) string {
	switch {
	case major == 10 && build >= 22000:
		return "Windows 11"
	case major == 10:
		return "Windows 10"
	case major == 6 && minor == 3:
		return "Windows 8.1"
	case major == 6 && minor == 2:
		return "Windows 8"
	case major == 6 && minor == 1:
		return "Windows 7"
	case major == 6 && minor == 0:
		return "Windows Vista"
	case major == 5 && minor == 2:
		return "Windows Server 2003"
	case major == 5 && minor == 1:
		return "Windows XP"
	default:
		return fmt.Sprintf("Windows %d.%d", major, minor)
	}
}

// IsRunningAsAdmin checks if the current process has admin privileges
func IsRunningAsAdmin() bool {
	return checkAdminPrivileges()
}

// GetEnvironmentInfo returns environment variables of interest for security analysis
func GetEnvironmentInfo() map[string]string {
	envVars := []string{
		"COMPUTERNAME",
		"USERDOMAIN",
		"USERNAME",
		"LOGONSERVER",
		"PROCESSOR_ARCHITECTURE",
		"NUMBER_OF_PROCESSORS",
		"TEMP",
		"TMP",
		"SYSTEMROOT",
		"WINDIR",
		"PROGRAMFILES",
		"PROGRAMFILES(X86)",
		"APPDATA",
		"LOCALAPPDATA",
		"USERPROFILE",
	}

	result := make(map[string]string)
	for _, key := range envVars {
		if value, ok := os.LookupEnv(key); ok {
			result[key] = value
		}
	}

	return result
}
