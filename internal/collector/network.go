package collector

import (
	"encoding/binary"
	"fmt"
	"net"
	"syscall"
	"unsafe"

	"github.com/digggggmori-pixel/agent-lite/pkg/types"
)

var (
	modiphlpapi            = syscall.NewLazyDLL("iphlpapi.dll")
	procGetExtendedTcpTable = modiphlpapi.NewProc("GetExtendedTcpTable")
	procGetExtendedUdpTable = modiphlpapi.NewProc("GetExtendedUdpTable")
)

// TCP states
const (
	MIB_TCP_STATE_CLOSED     = 1
	MIB_TCP_STATE_LISTEN     = 2
	MIB_TCP_STATE_SYN_SENT   = 3
	MIB_TCP_STATE_SYN_RCVD   = 4
	MIB_TCP_STATE_ESTAB      = 5
	MIB_TCP_STATE_FIN_WAIT1  = 6
	MIB_TCP_STATE_FIN_WAIT2  = 7
	MIB_TCP_STATE_CLOSE_WAIT = 8
	MIB_TCP_STATE_CLOSING    = 9
	MIB_TCP_STATE_LAST_ACK   = 10
	MIB_TCP_STATE_TIME_WAIT  = 11
	MIB_TCP_STATE_DELETE_TCB = 12
)

// TCP table class
const (
	TCP_TABLE_OWNER_PID_ALL = 5
	UDP_TABLE_OWNER_PID     = 1
	AF_INET                 = 2
)

// MIB_TCPROW_OWNER_PID structure
type MIB_TCPROW_OWNER_PID struct {
	State      uint32
	LocalAddr  uint32
	LocalPort  uint32
	RemoteAddr uint32
	RemotePort uint32
	OwningPid  uint32
}

// MIB_UDPROW_OWNER_PID structure
type MIB_UDPROW_OWNER_PID struct {
	LocalAddr uint32
	LocalPort uint32
	OwningPid uint32
}

// NetworkCollector collects network connection information
type NetworkCollector struct {
	processNames map[uint32]string
}

// NewNetworkCollector creates a new network collector
func NewNetworkCollector() *NetworkCollector {
	return &NetworkCollector{
		processNames: make(map[uint32]string),
	}
}

// SetProcessNames sets the process name map for PID resolution
func (c *NetworkCollector) SetProcessNames(names map[uint32]string) {
	c.processNames = names
}

// Collect gathers all TCP and UDP connections
func (c *NetworkCollector) Collect() ([]types.NetworkConnection, error) {
	var connections []types.NetworkConnection

	// Collect TCP connections
	tcpConns, err := c.collectTCP()
	if err != nil {
		return nil, fmt.Errorf("failed to collect TCP connections: %w", err)
	}
	connections = append(connections, tcpConns...)

	// Collect UDP connections
	udpConns, err := c.collectUDP()
	if err != nil {
		return nil, fmt.Errorf("failed to collect UDP connections: %w", err)
	}
	connections = append(connections, udpConns...)

	return connections, nil
}

func (c *NetworkCollector) collectTCP() ([]types.NetworkConnection, error) {
	var size uint32

	// First call to get required buffer size
	ret, _, _ := procGetExtendedTcpTable.Call(
		0,
		uintptr(unsafe.Pointer(&size)),
		0,
		AF_INET,
		TCP_TABLE_OWNER_PID_ALL,
		0,
	)

	if ret != 0 && ret != uintptr(syscall.ERROR_INSUFFICIENT_BUFFER) {
		return nil, fmt.Errorf("GetExtendedTcpTable size query failed: %d", ret)
	}

	buf := make([]byte, size)
	ret, _, _ = procGetExtendedTcpTable.Call(
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(unsafe.Pointer(&size)),
		0,
		AF_INET,
		TCP_TABLE_OWNER_PID_ALL,
		0,
	)

	if ret != 0 {
		return nil, fmt.Errorf("GetExtendedTcpTable failed: %d", ret)
	}

	// Parse the table
	numEntries := binary.LittleEndian.Uint32(buf[0:4])
	var connections []types.NetworkConnection

	rowSize := uint32(unsafe.Sizeof(MIB_TCPROW_OWNER_PID{}))
	for i := uint32(0); i < numEntries; i++ {
		offset := 4 + i*rowSize
		if offset+rowSize > uint32(len(buf)) {
			break
		}

		row := (*MIB_TCPROW_OWNER_PID)(unsafe.Pointer(&buf[offset]))

		conn := types.NetworkConnection{
			Protocol:    "TCP",
			LocalAddr:   intToIP(row.LocalAddr),
			LocalPort:   uint16(ntohs(uint16(row.LocalPort))),
			RemoteAddr:  intToIP(row.RemoteAddr),
			RemotePort:  uint16(ntohs(uint16(row.RemotePort))),
			State:       tcpStateToString(row.State),
			OwningPID:   row.OwningPid,
			ProcessName: c.processNames[row.OwningPid],
		}
		connections = append(connections, conn)
	}

	return connections, nil
}

func (c *NetworkCollector) collectUDP() ([]types.NetworkConnection, error) {
	var size uint32

	// First call to get required buffer size
	ret, _, _ := procGetExtendedUdpTable.Call(
		0,
		uintptr(unsafe.Pointer(&size)),
		0,
		AF_INET,
		UDP_TABLE_OWNER_PID,
		0,
	)

	if ret != 0 && ret != uintptr(syscall.ERROR_INSUFFICIENT_BUFFER) {
		return nil, fmt.Errorf("GetExtendedUdpTable size query failed: %d", ret)
	}

	buf := make([]byte, size)
	ret, _, _ = procGetExtendedUdpTable.Call(
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(unsafe.Pointer(&size)),
		0,
		AF_INET,
		UDP_TABLE_OWNER_PID,
		0,
	)

	if ret != 0 {
		return nil, fmt.Errorf("GetExtendedUdpTable failed: %d", ret)
	}

	// Parse the table
	numEntries := binary.LittleEndian.Uint32(buf[0:4])
	var connections []types.NetworkConnection

	rowSize := uint32(unsafe.Sizeof(MIB_UDPROW_OWNER_PID{}))
	for i := uint32(0); i < numEntries; i++ {
		offset := 4 + i*rowSize
		if offset+rowSize > uint32(len(buf)) {
			break
		}

		row := (*MIB_UDPROW_OWNER_PID)(unsafe.Pointer(&buf[offset]))

		conn := types.NetworkConnection{
			Protocol:    "UDP",
			LocalAddr:   intToIP(row.LocalAddr),
			LocalPort:   uint16(ntohs(uint16(row.LocalPort))),
			RemoteAddr:  "*",
			RemotePort:  0,
			State:       "*",
			OwningPID:   row.OwningPid,
			ProcessName: c.processNames[row.OwningPid],
		}
		connections = append(connections, conn)
	}

	return connections, nil
}

// CountByProtocol counts connections by protocol
func (c *NetworkCollector) CountByProtocol(connections []types.NetworkConnection) (tcp, udp int) {
	for _, conn := range connections {
		if conn.Protocol == "TCP" {
			tcp++
		} else {
			udp++
		}
	}
	return
}

// Helper functions

func intToIP(addr uint32) string {
	return net.IPv4(
		byte(addr),
		byte(addr>>8),
		byte(addr>>16),
		byte(addr>>24),
	).String()
}

func ntohs(port uint16) uint16 {
	return (port>>8)&0xff | (port&0xff)<<8
}

func tcpStateToString(state uint32) string {
	switch state {
	case MIB_TCP_STATE_CLOSED:
		return "CLOSED"
	case MIB_TCP_STATE_LISTEN:
		return "LISTEN"
	case MIB_TCP_STATE_SYN_SENT:
		return "SYN_SENT"
	case MIB_TCP_STATE_SYN_RCVD:
		return "SYN_RCVD"
	case MIB_TCP_STATE_ESTAB:
		return "ESTABLISHED"
	case MIB_TCP_STATE_FIN_WAIT1:
		return "FIN_WAIT1"
	case MIB_TCP_STATE_FIN_WAIT2:
		return "FIN_WAIT2"
	case MIB_TCP_STATE_CLOSE_WAIT:
		return "CLOSE_WAIT"
	case MIB_TCP_STATE_CLOSING:
		return "CLOSING"
	case MIB_TCP_STATE_LAST_ACK:
		return "LAST_ACK"
	case MIB_TCP_STATE_TIME_WAIT:
		return "TIME_WAIT"
	case MIB_TCP_STATE_DELETE_TCB:
		return "DELETE_TCB"
	default:
		return fmt.Sprintf("UNKNOWN(%d)", state)
	}
}

// GetEstablishedConnections filters for established TCP connections
func GetEstablishedConnections(connections []types.NetworkConnection) []types.NetworkConnection {
	var result []types.NetworkConnection
	for _, conn := range connections {
		if conn.Protocol == "TCP" && conn.State == "ESTABLISHED" {
			result = append(result, conn)
		}
	}
	return result
}

// GetListeningPorts filters for listening ports
func GetListeningPorts(connections []types.NetworkConnection) []types.NetworkConnection {
	var result []types.NetworkConnection
	for _, conn := range connections {
		if conn.State == "LISTEN" || conn.Protocol == "UDP" {
			result = append(result, conn)
		}
	}
	return result
}
