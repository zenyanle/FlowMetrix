package printer

import (
	"FlowMetrix/types"
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
	"time"
)

// PacketPrinter 负责数据包显示逻辑
type PacketPrinter struct {
	showHex      bool
	verbose      bool
	vmwareOffset int
	maxBytes     int
	stats        struct {
		packets uint64
		bytes   uint64
	}
	startTime time.Time
}

// NewPacketPrinter 创建新的数据包打印器
func NewPacketPrinter(showHex, verbose bool, vmwareOffset int, detectVMware bool, maxBytes int) *PacketPrinter {
	return &PacketPrinter{
		showHex:      showHex,
		verbose:      verbose,
		vmwareOffset: vmwareOffset,
		maxBytes:     maxBytes,
		startTime:    time.Now(),
	}
}

// isCommonEtherType 检查是否为常见的EtherType
func isCommonEtherType(etherType uint16) bool {
	return etherType == 0x0800 || // IPv4
		etherType == 0x0806 || // ARP
		etherType == 0x86DD || // IPv6
		etherType == 0x8100 // VLAN
}

// isValidMACPair 检查源MAC和目标MAC是否同时有效
func isValidMACPair(dstMAC, srcMAC []byte) bool {
	return isValidMAC(dstMAC) && isValidMAC(srcMAC)
}

// isValidMAC 检查MAC地址是否有效
func isValidMAC(mac []byte) bool {
	if len(mac) != 6 {
		return false
	}

	// 检查是否为全0
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

	// 检查是否为全F
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

	// 有些特殊值经常出现在假的以太网头部中
	if mac[0] == 0xFF && mac[1] == 0xFF && mac[2] == 0xFF {
		return false
	}

	return true
}

// findBestVMwarePacket 处理VMware特有的数据包格式，找到最佳解析位置
func (p *PacketPrinter) findBestVMwarePacket(payload []byte) ([]byte, int) {
	if p.verbose {
		fmt.Printf("DEBUG: 分析 %d 字节的数据包\n", len(payload))
	}

	// 特别处理VMware重复包
	if len(payload) >= 64 {
		// 1. 在特定偏移量检查有效的以太网帧
		possibleOffsets := []int{0, 18, 24}
		for _, offset := range possibleOffsets {
			if len(payload) < offset+14 {
				continue
			}

			ethType := binary.BigEndian.Uint16(payload[offset+12 : offset+14])
			if isCommonEtherType(ethType) &&
				isValidMACPair(payload[offset:offset+6], payload[offset+6:offset+12]) {
				if p.verbose {
					fmt.Printf("DEBUG: 在偏移量 %d 找到有效以太网帧\n", offset)
					srcMAC := net.HardwareAddr(payload[offset+6 : offset+12])
					dstMAC := net.HardwareAddr(payload[offset : offset+6])
					fmt.Printf("DEBUG: MAC: %s -> %s, EtherType: 0x%04x\n",
						srcMAC, dstMAC, ethType)
				}
				return payload, offset
			}
		}

		// 2. 查找IPv4特征
		for i := 0; i < len(payload)-20; i++ {
			// 寻找IPv4版本(4)和头部长度(5)，通常为0x45
			if payload[i] == 0x45 && i+20 <= len(payload) {
				// 验证更多IPv4头部字段以增加可信度
				ipLen := binary.BigEndian.Uint16(payload[i+2 : i+4])
				if ipLen >= 20 && ipLen <= uint16(len(payload)-i) {
					if p.verbose {
						fmt.Printf("DEBUG: 在偏移量 %d 找到可能的IPv4头部\n", i)
					}

					// 如果是纯IP数据包，处理为有偏移的以太网包
					return payload, i - 14
				}
			}
		}
	}

	// 如果没找到更好的位置，使用配置的偏移量
	return payload, p.vmwareOffset
}

// PrintPacket 打印数据包内容
func (p *PacketPrinter) PrintPacket(payload []byte) {
	if len(payload) == 0 {
		fmt.Println("Error: 空数据包")
		return
	}

	// 更新统计信息
	p.stats.packets++
	p.stats.bytes += uint64(len(payload))

	// 打印数据包信息
	fmt.Printf("\n=== 捕获数据包 [%s] ===\n", time.Now().Format("2006-01-02 15:04:05.000000"))
	fmt.Printf("数据包大小: %d 字节\n", len(payload))

	// 如果数据包超过最大显示字节数，截断它
	actualData := payload
	if len(actualData) > p.maxBytes {
		if p.verbose {
			fmt.Printf("DEBUG: 限制显示数据从 %d 到 %d 字节\n", len(actualData), p.maxBytes)
		}
		actualData = actualData[:p.maxBytes]
	}

	// 始终使用 findBestVMwarePacket 尝试找到最佳解析位置
	detectedData, offset := p.findBestVMwarePacket(actualData)

	// 解析以太网头部
	if len(detectedData) < offset+14 {
		fmt.Printf("数据包过短，无法解析以太网头部 (需要偏移+14=%d 字节)\n", offset+14)
		if p.showHex {
			fmt.Println("\n原始数据十六进制:")
			p.printHexDump(actualData)
		}
		return
	}

	// 获取实际的以太网帧数据
	realEthernet := detectedData[offset:]

	// 确保有足够的数据构成有效以太网帧
	if len(realEthernet) < 14 {
		fmt.Println("调整偏移后以太网帧过短")
		return
	}

	eth := &types.EthernetHeader{}
	reader := bytes.NewReader(realEthernet)
	if err := binary.Read(reader, binary.BigEndian, eth); err != nil {
		fmt.Printf("读取以太网头部错误: %v\n", err)
		return
	}

	fmt.Printf("\n以太网:\n")
	fmt.Printf("  源MAC: %s\n", net.HardwareAddr(eth.SrcMAC[:]))
	fmt.Printf("  目标MAC: %s\n", net.HardwareAddr(eth.DstMAC[:]))
	fmt.Printf("  类型: 0x%04x\n", eth.EtherType)

	// 根据EtherType解析上层协议
	if eth.EtherType == 0x0800 && len(realEthernet) >= 34 {
		p.parseIPv4(realEthernet[14:])
	} else if eth.EtherType == 0x0806 && len(realEthernet) >= 42 {
		p.parseARP(realEthernet[14:])
	} else if eth.EtherType == 0x86DD && len(realEthernet) >= 54 {
		p.parseIPv6(realEthernet[14:])
	}

	// 显示十六进制数据
	if p.showHex {
		fmt.Println("\n十六进制数据:")
		p.printHexDump(realEthernet)
	}

	// 定期打印统计信息
	elapsed := time.Since(p.startTime)
	if elapsed.Seconds() >= 1 {
		p.printStats()
		p.startTime = time.Now()
		p.stats.packets = 0
		p.stats.bytes = 0
	}
}

// parseIPv4 解析IPv4数据包
func (p *PacketPrinter) parseIPv4(data []byte) {
	if len(data) < 20 {
		fmt.Println("IPv4数据包过短")
		return
	}

	version := data[0] >> 4
	headerLen := (data[0] & 0x0F) * 4
	totalLen := binary.BigEndian.Uint16(data[2:4])
	protocol := data[9]
	srcIP := net.IP(data[12:16])
	dstIP := net.IP(data[16:20])

	fmt.Printf("\nIPv4:\n")
	fmt.Printf("  版本: %d\n", version)
	fmt.Printf("  头部长度: %d 字节\n", headerLen)
	fmt.Printf("  总长度: %d 字节\n", totalLen)
	fmt.Printf("  协议: %d", protocol)

	// 显示协议名称
	switch protocol {
	case 1:
		fmt.Print(" (ICMP)")
	case 6:
		fmt.Print(" (TCP)")
	case 17:
		fmt.Print(" (UDP)")
	}
	fmt.Println()

	fmt.Printf("  源IP: %s\n", srcIP)
	fmt.Printf("  目标IP: %s\n", dstIP)

	// 如果有足够的数据，解析传输层
	if len(data) >= int(headerLen) && headerLen >= 20 {
		switch protocol {
		case 6: // TCP
			p.parseTCP(data[headerLen:], srcIP, dstIP)
		case 17: // UDP
			p.parseUDP(data[headerLen:], srcIP, dstIP)
		}
	}
}

// parseARP 解析ARP数据包
func (p *PacketPrinter) parseARP(data []byte) {
	if len(data) < 28 {
		fmt.Println("ARP数据包过短")
		return
	}

	hwType := binary.BigEndian.Uint16(data[0:2])
	protoType := binary.BigEndian.Uint16(data[2:4])
	hwSize := data[4]
	protoSize := data[5]
	operation := binary.BigEndian.Uint16(data[6:8])

	fmt.Printf("\nARP:\n")
	fmt.Printf("  硬件类型: %d\n", hwType)
	fmt.Printf("  协议类型: 0x%04x\n", protoType)
	fmt.Printf("  硬件地址长度: %d\n", hwSize)
	fmt.Printf("  协议地址长度: %d\n", protoSize)
	fmt.Printf("  操作码: %d", operation)

	switch operation {
	case 1:
		fmt.Print(" (请求)")
	case 2:
		fmt.Print(" (响应)")
	}
	fmt.Println()

	if len(data) >= 28 && hwSize == 6 && protoSize == 4 {
		senderMAC := net.HardwareAddr(data[8:14])
		senderIP := net.IP(data[14:18])
		targetMAC := net.HardwareAddr(data[18:24])
		targetIP := net.IP(data[24:28])

		fmt.Printf("  发送方MAC: %s\n", senderMAC)
		fmt.Printf("  发送方IP: %s\n", senderIP)
		fmt.Printf("  目标MAC: %s\n", targetMAC)
		fmt.Printf("  目标IP: %s\n", targetIP)
	}
}

// parseIPv6 解析IPv6数据包
func (p *PacketPrinter) parseIPv6(data []byte) {
	if len(data) < 40 {
		fmt.Println("IPv6数据包过短")
		return
	}

	version := data[0] >> 4
	trafficClass := ((data[0] & 0x0F) << 4) | ((data[1] & 0xF0) >> 4)
	flowLabel := uint32(data[1]&0x0F)<<16 | uint32(data[2])<<8 | uint32(data[3])
	payloadLen := binary.BigEndian.Uint16(data[4:6])
	nextHeader := data[6]
	hopLimit := data[7]
	srcIP := net.IP(data[8:24])
	dstIP := net.IP(data[24:40])

	fmt.Printf("\nIPv6:\n")
	fmt.Printf("  版本: %d\n", version)
	fmt.Printf("  流量类: %d\n", trafficClass)
	fmt.Printf("  流标签: 0x%05x\n", flowLabel)
	fmt.Printf("  负载长度: %d\n", payloadLen)
	fmt.Printf("  下一个头部: %d\n", nextHeader)
	fmt.Printf("  跳数限制: %d\n", hopLimit)
	fmt.Printf("  源地址: %s\n", srcIP)
	fmt.Printf("  目标地址: %s\n", dstIP)

	// 如果有足够的数据，解析下一层协议
	if len(data) >= 40 {
		switch nextHeader {
		case 6: // TCP
			p.parseTCP(data[40:], srcIP, dstIP)
		case 17: // UDP
			p.parseUDP(data[40:], srcIP, dstIP)
		}
	}
}

// parseTCP 解析TCP报文
func (p *PacketPrinter) parseTCP(data []byte, srcIP, dstIP net.IP) {
	if len(data) < 20 {
		return
	}

	srcPort := binary.BigEndian.Uint16(data[0:2])
	dstPort := binary.BigEndian.Uint16(data[2:4])
	seqNum := binary.BigEndian.Uint32(data[4:8])
	ackNum := binary.BigEndian.Uint32(data[8:12])
	dataOffset := (data[12] >> 4) * 4
	flags := data[13]

	fmt.Printf("\nTCP:\n")
	fmt.Printf("  源端口: %d\n", srcPort)
	fmt.Printf("  目标端口: %d\n", dstPort)
	fmt.Printf("  序列号: %d\n", seqNum)
	fmt.Printf("  确认号: %d\n", ackNum)
	fmt.Printf("  头部长度: %d 字节\n", dataOffset)
	fmt.Printf("  标志: 0x%02x", flags)

	// 打印标志名称
	if flags&0x01 != 0 {
		fmt.Print(" FIN")
	}
	if flags&0x02 != 0 {
		fmt.Print(" SYN")
	}
	if flags&0x04 != 0 {
		fmt.Print(" RST")
	}
	if flags&0x08 != 0 {
		fmt.Print(" PSH")
	}
	if flags&0x10 != 0 {
		fmt.Print(" ACK")
	}
	if flags&0x20 != 0 {
		fmt.Print(" URG")
	}
	fmt.Println()

	// 打印连接信息
	fmt.Printf("  连接: %s:%d -> %s:%d\n", srcIP, srcPort, dstIP, dstPort)
}

// parseUDP 解析UDP报文
func (p *PacketPrinter) parseUDP(data []byte, srcIP, dstIP net.IP) {
	if len(data) < 8 {
		return
	}

	srcPort := binary.BigEndian.Uint16(data[0:2])
	dstPort := binary.BigEndian.Uint16(data[2:4])
	length := binary.BigEndian.Uint16(data[4:6])

	fmt.Printf("\nUDP:\n")
	fmt.Printf("  源端口: %d\n", srcPort)
	fmt.Printf("  目标端口: %d\n", dstPort)
	fmt.Printf("  长度: %d 字节\n", length)
	fmt.Printf("  连接: %s:%d -> %s:%d\n", srcIP, srcPort, dstIP, dstPort)
}

// printHexDump 打印十六进制数据
func (p *PacketPrinter) printHexDump(data []byte) {
	const bytesPerLine = 16
	for i := 0; i < len(data); i += bytesPerLine {
		// 打印偏移量
		fmt.Printf("%04x  ", i)

		// 打印十六进制值
		end := min(i+bytesPerLine, len(data))

		for j := i; j < end; j++ {
			fmt.Printf("%02x ", data[j])
			if j == i+7 {
				fmt.Print(" ")
			}
		}

		// 对齐空格
		if end-i < bytesPerLine {
			spaces := (bytesPerLine - (end - i)) * 3
			if end-i <= 8 {
				spaces += 1 // 额外空格
			}
			for j := 0; j < spaces; j++ {
				fmt.Print(" ")
			}
		}

		// 打印ASCII
		fmt.Print(" |")
		for j := i; j < end; j++ {
			if data[j] >= 32 && data[j] <= 126 {
				fmt.Printf("%c", data[j])
			} else {
				fmt.Print(".")
			}
		}
		fmt.Println("|")
	}
}

// printStats 打印统计信息
func (p *PacketPrinter) printStats() {
	elapsed := time.Since(p.startTime).Seconds()
	fmt.Printf("\n=== 统计信息 ===\n")
	fmt.Printf("数据包: %d, 字节数: %d\n", p.stats.packets, p.stats.bytes)
	fmt.Printf("速率: %.2f pps, %.2f Mbps\n",
		float64(p.stats.packets)/elapsed,
		float64(p.stats.bytes*8)/(elapsed*1000000))
}

// min 返回两个整数中较小的一个
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
