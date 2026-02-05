package collector

import (
	"fmt"
	"strings"

	"github.com/digggggmori-pixel/agent-lite/pkg/types"
	"golang.org/x/sys/windows/registry"
)

// PersistenceKeys are the 19 registry keys commonly used for persistence
var PersistenceKeys = []RegistryKeyDef{
	// HKLM Run keys
	{Hive: registry.LOCAL_MACHINE, Path: `SOFTWARE\Microsoft\Windows\CurrentVersion\Run`, Category: "Run"},
	{Hive: registry.LOCAL_MACHINE, Path: `SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce`, Category: "RunOnce"},
	{Hive: registry.LOCAL_MACHINE, Path: `SOFTWARE\Microsoft\Windows\CurrentVersion\RunServices`, Category: "RunServices"},
	{Hive: registry.LOCAL_MACHINE, Path: `SOFTWARE\Microsoft\Windows\CurrentVersion\RunServicesOnce`, Category: "RunServicesOnce"},
	{Hive: registry.LOCAL_MACHINE, Path: `SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Run`, Category: "Run"},
	{Hive: registry.LOCAL_MACHINE, Path: `SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnce`, Category: "RunOnce"},

	// HKCU Run keys
	{Hive: registry.CURRENT_USER, Path: `SOFTWARE\Microsoft\Windows\CurrentVersion\Run`, Category: "Run"},
	{Hive: registry.CURRENT_USER, Path: `SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce`, Category: "RunOnce"},
	{Hive: registry.CURRENT_USER, Path: `SOFTWARE\Microsoft\Windows\CurrentVersion\RunServices`, Category: "RunServices"},
	{Hive: registry.CURRENT_USER, Path: `SOFTWARE\Microsoft\Windows\CurrentVersion\RunServicesOnce`, Category: "RunServicesOnce"},

	// Winlogon
	{Hive: registry.LOCAL_MACHINE, Path: `SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`, Category: "Winlogon"},
	{Hive: registry.LOCAL_MACHINE, Path: `SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\Notify`, Category: "WinlogonNotify"},

	// Image File Execution Options (debugger injection)
	{Hive: registry.LOCAL_MACHINE, Path: `SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options`, Category: "IFEO"},
	{Hive: registry.LOCAL_MACHINE, Path: `SOFTWARE\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Image File Execution Options`, Category: "IFEO"},

	// Services
	{Hive: registry.LOCAL_MACHINE, Path: `SYSTEM\CurrentControlSet\Services`, Category: "Services"},

	// Explorer
	{Hive: registry.LOCAL_MACHINE, Path: `SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects`, Category: "BHO"},
	{Hive: registry.CURRENT_USER, Path: `SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects`, Category: "BHO"},

	// Shell extensions
	{Hive: registry.LOCAL_MACHINE, Path: `SOFTWARE\Microsoft\Windows\CurrentVersion\ShellServiceObjectDelayLoad`, Category: "ShellServiceObject"},
	{Hive: registry.CURRENT_USER, Path: `SOFTWARE\Microsoft\Windows\CurrentVersion\ShellServiceObjectDelayLoad`, Category: "ShellServiceObject"},
}

// RegistryKeyDef defines a registry key to scan
type RegistryKeyDef struct {
	Hive     registry.Key
	Path     string
	Category string
}

// RegistryCollector collects registry entries for persistence analysis
type RegistryCollector struct{}

// NewRegistryCollector creates a new registry collector
func NewRegistryCollector() *RegistryCollector {
	return &RegistryCollector{}
}

// Collect gathers registry entries from persistence keys
func (c *RegistryCollector) Collect() ([]types.RegistryEntry, error) {
	var entries []types.RegistryEntry

	for _, keyDef := range PersistenceKeys {
		keyEntries, err := c.collectKey(keyDef)
		if err != nil {
			// Key might not exist, skip silently
			continue
		}
		entries = append(entries, keyEntries...)
	}

	return entries, nil
}

func (c *RegistryCollector) collectKey(keyDef RegistryKeyDef) ([]types.RegistryEntry, error) {
	key, err := registry.OpenKey(keyDef.Hive, keyDef.Path, registry.READ)
	if err != nil {
		return nil, err
	}
	defer key.Close()

	var entries []types.RegistryEntry

	// Get all value names
	valueNames, err := key.ReadValueNames(-1)
	if err != nil {
		return nil, err
	}

	fullPath := hiveName(keyDef.Hive) + "\\" + keyDef.Path

	for _, valueName := range valueNames {
		// Read the value
		value, valueType, err := readRegistryValue(key, valueName)
		if err != nil {
			continue
		}

		entry := types.RegistryEntry{
			Key:       fullPath,
			ValueName: valueName,
			ValueData: value,
			ValueType: registryTypeToString(valueType),
		}
		entries = append(entries, entry)
	}

	// For some keys like Services and IFEO, we need to enumerate subkeys
	if keyDef.Category == "Services" || keyDef.Category == "IFEO" {
		subkeyEntries, _ := c.collectSubkeys(keyDef)
		entries = append(entries, subkeyEntries...)
	}

	return entries, nil
}

func (c *RegistryCollector) collectSubkeys(keyDef RegistryKeyDef) ([]types.RegistryEntry, error) {
	key, err := registry.OpenKey(keyDef.Hive, keyDef.Path, registry.READ)
	if err != nil {
		return nil, err
	}
	defer key.Close()

	var entries []types.RegistryEntry

	// Get subkey names
	subkeyNames, err := key.ReadSubKeyNames(-1)
	if err != nil {
		return nil, err
	}

	fullPath := hiveName(keyDef.Hive) + "\\" + keyDef.Path

	// Limit to first 100 subkeys for performance
	limit := len(subkeyNames)
	if limit > 100 {
		limit = 100
	}

	for i := 0; i < limit; i++ {
		subkeyName := subkeyNames[i]
		subkeyPath := keyDef.Path + "\\" + subkeyName

		subkey, err := registry.OpenKey(keyDef.Hive, subkeyPath, registry.READ)
		if err != nil {
			continue
		}

		// For Services, get ImagePath
		if keyDef.Category == "Services" {
			if imagePath, _, err := subkey.GetStringValue("ImagePath"); err == nil {
				entry := types.RegistryEntry{
					Key:       fullPath + "\\" + subkeyName,
					ValueName: "ImagePath",
					ValueData: imagePath,
					ValueType: "REG_SZ",
				}
				entries = append(entries, entry)
			}
		}

		// For IFEO, get Debugger
		if keyDef.Category == "IFEO" {
			if debugger, _, err := subkey.GetStringValue("Debugger"); err == nil {
				entry := types.RegistryEntry{
					Key:       fullPath + "\\" + subkeyName,
					ValueName: "Debugger",
					ValueData: debugger,
					ValueType: "REG_SZ",
				}
				entries = append(entries, entry)
			}
		}

		subkey.Close()
	}

	return entries, nil
}

// CountByType counts entries by category
func (c *RegistryCollector) CountByType(entries []types.RegistryEntry) (run, runOnce, services int) {
	for _, entry := range entries {
		switch {
		case strings.Contains(entry.Key, "\\Run\\") || strings.HasSuffix(entry.Key, "\\Run"):
			run++
		case strings.Contains(entry.Key, "\\RunOnce"):
			runOnce++
		case strings.Contains(entry.Key, "\\Services\\"):
			services++
		}
	}
	return
}

func readRegistryValue(key registry.Key, valueName string) (string, uint32, error) {
	// Try string first
	value, valueType, err := key.GetStringValue(valueName)
	if err == nil {
		return value, valueType, nil
	}

	// Try DWORD
	dwordValue, valueType, err := key.GetIntegerValue(valueName)
	if err == nil {
		return fmt.Sprintf("%d", dwordValue), valueType, nil
	}

	// Try binary (return as hex)
	binValue, valueType, err := key.GetBinaryValue(valueName)
	if err == nil {
		return fmt.Sprintf("%x", binValue), valueType, nil
	}

	return "", 0, fmt.Errorf("failed to read value")
}

func hiveName(hive registry.Key) string {
	switch hive {
	case registry.CLASSES_ROOT:
		return "HKCR"
	case registry.CURRENT_USER:
		return "HKCU"
	case registry.LOCAL_MACHINE:
		return "HKLM"
	case registry.USERS:
		return "HKU"
	case registry.CURRENT_CONFIG:
		return "HKCC"
	default:
		return fmt.Sprintf("0x%x", hive)
	}
}

func registryTypeToString(valueType uint32) string {
	switch valueType {
	case registry.NONE:
		return "REG_NONE"
	case registry.SZ:
		return "REG_SZ"
	case registry.EXPAND_SZ:
		return "REG_EXPAND_SZ"
	case registry.BINARY:
		return "REG_BINARY"
	case registry.DWORD:
		return "REG_DWORD"
	case registry.DWORD_BIG_ENDIAN:
		return "REG_DWORD_BIG_ENDIAN"
	case registry.LINK:
		return "REG_LINK"
	case registry.MULTI_SZ:
		return "REG_MULTI_SZ"
	case registry.QWORD:
		return "REG_QWORD"
	default:
		return fmt.Sprintf("REG_UNKNOWN(%d)", valueType)
	}
}

// FilterByCategory filters entries by category
func FilterByCategory(entries []types.RegistryEntry, category string) []types.RegistryEntry {
	var result []types.RegistryEntry
	for _, entry := range entries {
		if strings.Contains(entry.Key, category) {
			result = append(result, entry)
		}
	}
	return result
}
