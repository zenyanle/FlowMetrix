package extractor

import (
	"FlowMetrix/types"
	"bytes"
	"encoding/binary"
	"net"
	"time"
)

// PacketData represents structured network packet data for time-series database
type PacketData struct {
	Timestamp   time.Time        // Capture timestamp
	PacketSize  int              // Packet size in bytes
	EtherType   uint16           // Ethernet frame type
	SrcMAC      net.HardwareAddr // Source MAC address
	DstMAC      net.HardwareAddr // Destination MAC address
	Protocol    uint8            // IP protocol number (e.g., TCP=6, UDP=17)
	SrcIP       net.IP           // Source IP address
	DstIP       net.IP           // Destination IP address
	SrcPort     uint16           // Source port
	DstPort     uint16           // Destination port
	TCPFlags    uint8            // TCP flags (SYN, ACK, etc.)
	PacketType  string           // Packet type (IPv4, IPv6, ARP, etc.)
	Application string           // Application protocol (based on ports)
}

// DataExtractor extracts packet data and sends it through a channel
type DataExtractor struct {
	vmwareOffset int
	packetChan   chan<- PacketData
}

// NewDataExtractor creates a new packet data extractor
func NewDataExtractor(vmwareOffset int, packetChan chan<- PacketData) *DataExtractor {
	return &DataExtractor{
		vmwareOffset: vmwareOffset,
		packetChan:   packetChan,
	}
}

// ProcessPacket extracts data from a packet and sends it to the channel
func (de *DataExtractor) ProcessPacket(payload []byte) {
	if len(payload) == 0 {
		return
	}

	// Find the best offset for parsing (handling VMware packets)
	detectedData, offset := de.findBestVMwarePacket(payload)

	// Extract metrics and send them through the channel
	packetData := de.extractPacketData(detectedData, offset)
	de.packetChan <- packetData
}

// findBestVMwarePacket handles VMware-specific packet format
// This is a simplified version of PacketPrinter.findBestVMwarePacket
func (de *DataExtractor) findBestVMwarePacket(payload []byte) ([]byte, int) {
	// For packets over 64 bytes, try to find valid Ethernet frames
	if len(payload) >= 64 {
		// Try specific offsets
		possibleOffsets := []int{0, 18, 24}
		for _, offset := range possibleOffsets {
			if len(payload) < offset+14 {
				continue
			}

			ethType := binary.BigEndian.Uint16(payload[offset+12 : offset+14])
			if isCommonEtherType(ethType) &&
				isValidMACPair(payload[offset:offset+6], payload[offset+6:offset+12]) {
				return payload, offset
			}
		}

		// Look for IPv4 patterns
		for i := 0; i < len(payload)-20; i++ {
			// Search for IPv4 version(4) and header length(5), usually 0x45
			if payload[i] == 0x45 && i+20 <= len(payload) {
				// Verify more IPv4 header fields to increase confidence
				ipLen := binary.BigEndian.Uint16(payload[i+2 : i+4])
				if ipLen >= 20 && ipLen <= uint16(len(payload)-i) {
					return payload, i - 14
				}
			}
		}
	}

	// If no better position is found, use the configured offset
	return payload, de.vmwareOffset
}

// Helper functions from PacketPrinter
func isCommonEtherType(etherType uint16) bool {
	return etherType == 0x0800 || // IPv4
		etherType == 0x0806 || // ARP
		etherType == 0x86DD || // IPv6
		etherType == 0x8100 // VLAN
}

func isValidMACPair(dstMAC, srcMAC []byte) bool {
	return isValidMAC(dstMAC) && isValidMAC(srcMAC)
}

func isValidMAC(mac []byte) bool {
	if len(mac) != 6 {
		return false
	}

	// Check for all zeros
	allZero := true
	for _, b := range mac {
		if b != 0 {
			allZero = false
			break
		}
	}
	if allZero {
		return false
	}

	// Check for all F's
	allF := true
	for _, b := range mac {
		if b != 0xFF {
			allF = false
			break
		}
	}
	if allF {
		return false
	}

	// Some special values often appear in fake Ethernet headers
	if mac[0] == 0xFF && mac[1] == 0xFF && mac[2] == 0xFF {
		return false
	}

	return true
}

// extractPacketData extracts data from the packet
func (de *DataExtractor) extractPacketData(payload []byte, offset int) PacketData {
	packetData := PacketData{
		Timestamp:  time.Now(),
		PacketSize: len(payload),
	}

	// Ensure we have enough data to parse Ethernet header
	if len(payload) < offset+14 {
		return packetData
	}

	// Extract Ethernet information
	realEthernet := payload[offset:]
	eth := &types.EthernetHeader{}
	reader := bytes.NewReader(realEthernet)
	if err := binary.Read(reader, binary.BigEndian, eth); err != nil {
		return packetData
	}

	packetData.EtherType = eth.EtherType
	packetData.SrcMAC = net.HardwareAddr(eth.SrcMAC[:])
	packetData.DstMAC = net.HardwareAddr(eth.DstMAC[:])

	// Parse upper layer protocols based on EtherType
	if eth.EtherType == 0x0800 && len(realEthernet) >= 34 { // IPv4
		packetData.PacketType = "IPv4"
		de.extractIPv4Data(realEthernet[14:], &packetData)
	} else if eth.EtherType == 0x0806 && len(realEthernet) >= 42 { // ARP
		packetData.PacketType = "ARP"
		// ARP-specific fields could be added here if needed
	} else if eth.EtherType == 0x86DD && len(realEthernet) >= 54 { // IPv6
		packetData.PacketType = "IPv6"
		de.extractIPv6Data(realEthernet[14:], &packetData)
	}

	// Infer application layer protocol
	packetData.Application = inferApplication(packetData.SrcPort, packetData.DstPort)

	return packetData
}

// extractIPv4Data extracts IPv4 data
func (de *DataExtractor) extractIPv4Data(data []byte, packetData *PacketData) {
	if len(data) < 20 {
		return
	}

	packetData.Protocol = data[9]
	packetData.SrcIP = net.IP(data[12:16])
	packetData.DstIP = net.IP(data[16:20])

	headerLen := (data[0] & 0x0F) * 4

	// Parse transport layer
	if len(data) >= int(headerLen) {
		switch packetData.Protocol {
		case 6: // TCP
			de.extractTCPData(data[headerLen:], packetData)
		case 17: // UDP
			de.extractUDPData(data[headerLen:], packetData)
		}
	}
}

// extractIPv6Data extracts IPv6 data
func (de *DataExtractor) extractIPv6Data(data []byte, packetData *PacketData) {
	if len(data) < 40 {
		return
	}

	packetData.Protocol = data[6] // Next Header
	packetData.SrcIP = net.IP(data[8:24])
	packetData.DstIP = net.IP(data[24:40])

	// Parse transport layer
	if len(data) >= 40 {
		switch packetData.Protocol {
		case 6: // TCP
			de.extractTCPData(data[40:], packetData)
		case 17: // UDP
			de.extractUDPData(data[40:], packetData)
		}
	}
}

// extractTCPData extracts TCP data
func (de *DataExtractor) extractTCPData(data []byte, packetData *PacketData) {
	if len(data) < 20 {
		return
	}

	packetData.SrcPort = binary.BigEndian.Uint16(data[0:2])
	packetData.DstPort = binary.BigEndian.Uint16(data[2:4])
	packetData.TCPFlags = data[13]
}

// extractUDPData extracts UDP data
func (de *DataExtractor) extractUDPData(data []byte, packetData *PacketData) {
	if len(data) < 8 {
		return
	}

	packetData.SrcPort = binary.BigEndian.Uint16(data[0:2])
	packetData.DstPort = binary.BigEndian.Uint16(data[2:4])
}

// inferApplication infers application layer protocol based on port numbers
func inferApplication(srcPort, dstPort uint16) string {
	// Check common ports
	wellKnownPorts := map[uint16]string{
		20: "FTP-DATA", 21: "FTP", 22: "SSH", 23: "TELNET",
		25: "SMTP", 53: "DNS", 80: "HTTP", 443: "HTTPS",
		110: "POP3", 143: "IMAP", 161: "SNMP", 162: "SNMPTRAP",
		389: "LDAP", 636: "LDAPS", 3306: "MySQL", 5432: "PostgreSQL",
		27017: "MongoDB", 6379: "Redis", 11211: "Memcached",
	}

	// Check destination port first
	if app, ok := wellKnownPorts[dstPort]; ok {
		return app
	}

	// Then check source port
	if app, ok := wellKnownPorts[srcPort]; ok {
		return app
	}

	// Unknown application
	return "UNKNOWN"
}
