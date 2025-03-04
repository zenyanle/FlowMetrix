package main

import (
	"encoding/binary"
	"fmt"
	"net"
)

// parseIPv4 解析IPv4数据包 - 修复IP地址显示
func (p *PacketPrinter) parseIPv4(payload []byte) {
	if len(payload) < 20 {
		fmt.Println("IPv4 header too short")
		// 如果我们不能完整解析IP头，但知道协议类型，至少显示这个信息
		if len(payload) >= 10 {
			fmt.Printf("  Protocol: %d\n", payload[9])
		}
		return
	}

	// 直接读取关键字段，避免结构体对齐问题
	versionIHL := payload[0]
	version := versionIHL >> 4
	ihl := versionIHL & 0x0F
	headerLen := int(ihl) * 4

	// 确保我们可以访问所有需要的字段
	if len(payload) < headerLen {
		fmt.Printf("  Version: %d\n", version)
		fmt.Printf("  Header Length: %d bytes (data only %d bytes)\n", headerLen, len(payload))
		return
	}

	tos := payload[1]
	totalLen := binary.BigEndian.Uint16(payload[2:4])
	id := binary.BigEndian.Uint16(payload[4:6])
	ttl := payload[8]
	protocol := payload[9]
	checksum := binary.BigEndian.Uint16(payload[10:12])

	// IP地址
	srcIP := make([]byte, 4)
	dstIP := make([]byte, 4)

	// 复制IP地址 - 确保我们不会越界
	copy(srcIP, payload[12:16])
	copy(dstIP, payload[16:20])

	fmt.Printf("\nIPv4:\n")
	fmt.Printf("  Version: %d\n", version)
	fmt.Printf("  Header Length: %d bytes\n", headerLen)
	fmt.Printf("  Src IP: %s\n", net.IP(srcIP).String())
	fmt.Printf("  Dst IP: %s\n", net.IP(dstIP).String())
	fmt.Printf("  Protocol: %d\n", protocol)

	if p.verbose {
		fmt.Printf("  TTL: %d\n", ttl)
		fmt.Printf("  Total Length: %d\n", totalLen)
		fmt.Printf("  Identification: 0x%04x\n", id)
		fmt.Printf("  TOS: 0x%02x\n", tos)
		fmt.Printf("  Checksum: 0x%04x\n", checksum)
	}

	// 解析传输层 (如果数据足够)
	if len(payload) >= headerLen {
		switch protocol {
		case 6: // TCP
			p.parseTCP(payload[headerLen:])
		case 17: // UDP
			p.parseUDP(payload[headerLen:])
		case 1: // ICMP
			p.parseICMP(payload[headerLen:])
		}
	}
}

// parseIPv6 解析IPv6数据包
func (p *PacketPrinter) parseIPv6(payload []byte) {
	if len(payload) < 40 {
		fmt.Println("IPv6 header too short")
		return
	}

	// IPv6头部的简单结构
	version := payload[0] >> 4
	trafficClass := ((payload[0] & 0x0F) << 4) | (payload[1] >> 4)
	flowLabel := ((uint32(payload[1]) & 0x0F) << 16) | (uint32(payload[2]) << 8) | uint32(payload[3])
	payloadLen := binary.BigEndian.Uint16(payload[4:6])
	nextHeader := payload[6]
	hopLimit := payload[7]

	// 提取源IP和目标IP
	srcIP := net.IP(payload[8:24])
	dstIP := net.IP(payload[24:40])

	fmt.Printf("\nIPv6:\n")
	fmt.Printf("  Version: %d\n", version)
	fmt.Printf("  Src IP: %s\n", srcIP.String())
	fmt.Printf("  Dst IP: %s\n", dstIP.String())
	fmt.Printf("  Next Header: %d\n", nextHeader)

	if p.verbose {
		fmt.Printf("  Traffic Class: 0x%02x\n", trafficClass)
		fmt.Printf("  Flow Label: 0x%06x\n", flowLabel)
		fmt.Printf("  Payload Length: %d\n", payloadLen)
		fmt.Printf("  Hop Limit: %d\n", hopLimit)
	}

	// 解析传输层
	if len(payload) >= 40 {
		switch nextHeader {
		case 6: // TCP
			p.parseTCP(payload[40:])
		case 17: // UDP
			p.parseUDP(payload[40:])
		case 58: // ICMPv6
			fmt.Println("  Protocol: ICMPv6")
		}
	}
}

// parseARP 解析ARP数据包
func (p *PacketPrinter) parseARP(payload []byte) {
	if len(payload) < 28 {
		fmt.Println("ARP packet too short")
		return
	}

	hardwareType := binary.BigEndian.Uint16(payload[0:2])
	protocolType := binary.BigEndian.Uint16(payload[2:4])
	hardwareSize := payload[4]
	protocolSize := payload[5]
	operation := binary.BigEndian.Uint16(payload[6:8])

	// 提取硬件地址和协议地址
	senderMAC := net.HardwareAddr(payload[8:14])
	senderIP := net.IP(payload[14:18])
	targetMAC := net.HardwareAddr(payload[18:24])
	targetIP := net.IP(payload[24:28])

	fmt.Printf("\nARP:\n")
	fmt.Printf("  Operation: %d (%s)\n", operation, arpOperation(operation))
	fmt.Printf("  Sender MAC: %s\n", senderMAC)
	fmt.Printf("  Sender IP: %s\n", senderIP)
	fmt.Printf("  Target MAC: %s\n", targetMAC)
	fmt.Printf("  Target IP: %s\n", targetIP)

	if p.verbose {
		fmt.Printf("  Hardware Type: %d\n", hardwareType)
		fmt.Printf("  Protocol Type: 0x%04x\n", protocolType)
		fmt.Printf("  Hardware Size: %d\n", hardwareSize)
		fmt.Printf("  Protocol Size: %d\n", protocolSize)
	}
}

// parseICMP 解析ICMP数据包
func (p *PacketPrinter) parseICMP(payload []byte) {
	if len(payload) < 8 {
		fmt.Println("ICMP packet too short")
		return
	}

	icmpType := payload[0]
	icmpCode := payload[1]
	checksum := binary.BigEndian.Uint16(payload[2:4])

	fmt.Printf("\nICMP:\n")
	fmt.Printf("  Type: %d\n", icmpType)
	fmt.Printf("  Code: %d\n", icmpCode)

	if p.verbose {
		fmt.Printf("  Checksum: 0x%04x\n", checksum)

		// 根据类型显示不同的信息
		if icmpType == 8 || icmpType == 0 { // Echo请求或回复
			identifier := binary.BigEndian.Uint16(payload[4:6])
			sequence := binary.BigEndian.Uint16(payload[6:8])
			fmt.Printf("  Identifier: %d\n", identifier)
			fmt.Printf("  Sequence: %d\n", sequence)
		}
	}
}

// parseTCP 解析TCP数据包
func (p *PacketPrinter) parseTCP(payload []byte) {
	if len(payload) < 20 {
		fmt.Println("TCP header too short")
		return
	}

	// 直接读取关键字段，避免结构体对齐问题
	srcPort := binary.BigEndian.Uint16(payload[0:2])
	dstPort := binary.BigEndian.Uint16(payload[2:4])
	seqNum := binary.BigEndian.Uint32(payload[4:8])
	ackNum := binary.BigEndian.Uint32(payload[8:12])

	// 高4位是数据偏移(头部长度), 低4位是保留位
	dataOffset := (payload[12] >> 4) * 4
	flags := payload[13] // 控制位
	window := binary.BigEndian.Uint16(payload[14:16])
	checksum := binary.BigEndian.Uint16(payload[16:18])

	fmt.Printf("\nTCP:\n")
	fmt.Printf("  Src Port: %d\n", srcPort)
	fmt.Printf("  Dst Port: %d\n", dstPort)

	if p.verbose {
		fmt.Printf("  Sequence Number: %d\n", seqNum)
		fmt.Printf("  Acknowledgment Number: %d\n", ackNum)
		fmt.Printf("  Header Length: %d bytes\n", dataOffset)

		// 解析标志位
		fmt.Printf("  Flags: ")
		if (flags & 0x01) != 0 {
			fmt.Print("FIN ")
		}
		if (flags & 0x02) != 0 {
			fmt.Print("SYN ")
		}
		if (flags & 0x04) != 0 {
			fmt.Print("RST ")
		}
		if (flags & 0x08) != 0 {
			fmt.Print("PSH ")
		}
		if (flags & 0x10) != 0 {
			fmt.Print("ACK ")
		}
		if (flags & 0x20) != 0 {
			fmt.Print("URG ")
		}
		fmt.Println()

		fmt.Printf("  Window Size: %d\n", window)
		fmt.Printf("  Checksum: 0x%04x\n", checksum)

		// 通过端口号猜测应用协议
		fmt.Printf("  Application Protocol: %s\n", guessProtocol(srcPort, dstPort))
	}
}

// parseUDP 解析UDP数据包
func (p *PacketPrinter) parseUDP(payload []byte) {
	if len(payload) < 8 {
		fmt.Println("UDP header too short")
		return
	}

	// 直接读取字段，避免结构体对齐问题
	srcPort := binary.BigEndian.Uint16(payload[0:2])
	dstPort := binary.BigEndian.Uint16(payload[2:4])
	length := binary.BigEndian.Uint16(payload[4:6])
	checksum := binary.BigEndian.Uint16(payload[6:8])

	fmt.Printf("\nUDP:\n")
	fmt.Printf("  Src Port: %d\n", srcPort)
	fmt.Printf("  Dst Port: %d\n", dstPort)

	if p.verbose {
		fmt.Printf("  Length: %d\n", length)
		fmt.Printf("  Checksum: 0x%04x\n", checksum)

		// 通过端口号猜测应用协议
		fmt.Printf("  Application Protocol: %s\n", guessProtocol(srcPort, dstPort))
	}
}

// guessProtocol 根据端口号猜测应用层协议
func guessProtocol(srcPort, dstPort uint16) string {
	ports := map[uint16]string{
		20: "FTP Data", 21: "FTP Control",
		22: "SSH", 23: "Telnet",
		25: "SMTP", 53: "DNS",
		67: "DHCP Server", 68: "DHCP Client",
		80: "HTTP", 443: "HTTPS",
		3389: "RDP", 5900: "VNC",
	}

	if proto, ok := ports[srcPort]; ok {
		return proto
	}
	if proto, ok := ports[dstPort]; ok {
		return proto
	}
	return "Unknown"
}

// arpOperation 返回ARP操作码的字符串表示
func arpOperation(opcode uint16) string {
	switch opcode {
	case 1:
		return "Request"
	case 2:
		return "Reply"
	default:
		return "Unknown"
	}
}
