package main

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"log"
	"net"
	"regexp"
	"time"
)

// PacketPrinter 数据包打印器
type PacketPrinter struct {
	showHex      bool
	verbose      bool
	vmwareOffset int
	detectVMware bool
	maxBytes     int
	stats        struct {
		packets uint64
		bytes   uint64
	}
	startTime      time.Time
	lastOffsetUsed int // 缓存最后使用的有效偏移量
}

// NewPacketPrinter 创建新的数据包打印器
func NewPacketPrinter(showHex, verbose bool, vmwareOffset int, detectVMware bool, maxBytes int) *PacketPrinter {
	return &PacketPrinter{
		showHex:        showHex,
		verbose:        verbose,
		vmwareOffset:   vmwareOffset,
		detectVMware:   detectVMware,
		maxBytes:       maxBytes,
		startTime:      time.Now(),
		lastOffsetUsed: -1, // 初始值为-1表示未确定
	}
}

// detectRealEthernetOffset 尝试找出真正的以太网头在哪里 - 完全重写
func (p *PacketPrinter) detectRealEthernetOffset(payload []byte) int {
	// 如果数据包太短，无法处理
	if len(payload) < 14 {
		return 0
	}

	// 检查常见的偏移量，优先使用
	commonOffsets := []int{0, 24, 18}

	// 对于常见的VMware包大小，直接使用经验值
	if len(payload) == 52 {
		// 52字节的包通常以太网头部在偏移24
		return 24
	} else if len(payload) >= 108 {
		// 108字节通常是重复格式，我们优先选择偏移量0
		return 0
	}

	// 首先检查最可能的偏移量
	for _, offset := range commonOffsets {
		if len(payload) >= offset+14 {
			ethType := binary.BigEndian.Uint16(payload[offset+12 : offset+14])
			if isCommonEtherType(ethType) &&
				isValidMACPair(payload[offset:offset+6], payload[offset+6:offset+12]) {
				if debug {
					log.Printf("Found valid Ethernet frame at common offset %d", offset)
				}
				// 缓存此有效偏移量
				p.lastOffsetUsed = offset
				return offset
			}
		}
	}

	// 没有找到最常见位置的有效帧，全面扫描
	for i := 0; i <= len(payload)-14; i += 2 { // 以2字节步进，更可能找到对齐的帧
		// 跳过已经检查过的常见偏移量
		if i == 0 || i == 18 || i == 24 {
			continue
		}

		ethType := binary.BigEndian.Uint16(payload[i+12 : i+14])
		if isCommonEtherType(ethType) &&
			isValidMACPair(payload[i:i+6], payload[i+6:i+12]) {
			if debug {
				log.Printf("Found valid Ethernet frame at offset %d", i)
				// 打印MAC地址和EtherType以便确认
				srcMAC := net.HardwareAddr(payload[i+6 : i+12])
				dstMAC := net.HardwareAddr(payload[i : i+6])
				log.Printf("MAC: %s -> %s, EtherType: 0x%04x", srcMAC, dstMAC, ethType)
			}
			// 缓存此有效偏移量
			p.lastOffsetUsed = i
			return i
		}
	}

	// 如果没有找到，使用配置的默认偏移
	if debug {
		log.Printf("No valid Ethernet frame found, using default offset %d", p.vmwareOffset)
	}
	p.lastOffsetUsed = p.vmwareOffset
	return p.vmwareOffset
}

// isCommonEtherType 检查是否为常见的EtherType
func isCommonEtherType(etherType uint16) bool {
	// 常见的以太网类型
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

// isValidMACAddress 检查MAC地址字符串是否有效
func isValidMACAddress(mac string) bool {
	// 简单检查：MAC地址格式为xx:xx:xx:xx:xx:xx
	pattern := regexp.MustCompile(`^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$`)
	if !pattern.MatchString(mac) {
		return false
	}

	// 排除全0或全F的MAC
	zeroPattern := regexp.MustCompile(`^([0]{2}[:-]){5}([0]{2})$`)
	ffPattern := regexp.MustCompile(`^([Ff]{2}[:-]){5}([Ff]{2})$`)
	return !zeroPattern.MatchString(mac) && !ffPattern.MatchString(mac)
}

// findBestVMwarePacket 处理VMware特有的数据包格式，找到最佳解析位置
func (p *PacketPrinter) findBestVMwarePacket(payload []byte) ([]byte, bool) {
	// 特别处理108字节的VMware重复包
	if len(payload) >= 108 {
		// 这种包通常有两个以太网帧：
		// 1. 在偏移0处的初始帧，只有部分信息
		// 2. 在后半部分（通常偏移量44或48左右）的完整帧

		// 查找第二个有效的以太网帧
		for i := 30; i <= len(payload)-14; i += 2 {
			// 只检查这一段区域
			if i > 60 {
				break
			}

			ethType := binary.BigEndian.Uint16(payload[i+12 : i+14])
			if isCommonEtherType(ethType) &&
				isValidMACPair(payload[i:i+6], payload[i+6:i+12]) {

				// 确认这是个重复的MAC头部（与起始处相同）
				if bytes.Equal(payload[i:i+12], payload[0:12]) {
					// 找到了重复的以太网头
					// 选择第二个帧，因为它通常包含更完整的信息
					secondFrame := payload[i:]
					if debug {
						log.Printf("Found duplicate frame at offset %d, using it for better data", i)
					}

					// 检查它是否有足够的数据来解析完整的IP和TCP头
					if len(secondFrame) >= 54 { // 14(以太网) + 20(IP) + 20(TCP)
						return secondFrame, true
					}
				}
			}
		}
	}

	// 没有找到更好的帧，返回原始数据
	return payload, false
}

// PrintPacket 打印数据包内容，处理VMware偏移
func (p *PacketPrinter) PrintPacket(meta *PacketMetadata, payload []byte) {
	// 更新统计信息
	p.stats.packets++
	p.stats.bytes += uint64(meta.PacketSize)

	// 打印数据包信息
	fmt.Printf("\n=== Packet Captured at %s ===\n",
		time.Unix(0, int64(meta.Timestamp)).Format("2006-01-02 15:04:05.000000"))

	// 限制处理的最大字节数(确保不超过实际捕获大小)
	actualCaptured := min(int(meta.CapturedSize), len(payload))
	if actualCaptured > p.maxBytes {
		if debug {
			log.Printf("Limiting payload from %d to %d bytes", actualCaptured, p.maxBytes)
		}
		actualCaptured = p.maxBytes
		payload = payload[:actualCaptured]
	}

	fmt.Printf("Original Size: %d bytes, Captured: %d bytes\n",
		meta.PacketSize, actualCaptured)

	// 增强调试信息
	if debug {
		fmt.Printf("Protocol from metadata: %d (0x%04x)\n", meta.Protocol, meta.Protocol)
		fmt.Printf("Payload length: %d bytes\n", len(payload))
	}

	// 尝试找到VMware特有格式中的最佳数据包
	improvedPayload, found := p.findBestVMwarePacket(payload)
	if found {
		payload = improvedPayload
	}

	// 检测真实以太网帧的偏移量
	offset := p.detectRealEthernetOffset(payload)

	// 解析以太网头部
	if len(payload) < offset+14 {
		fmt.Println("Packet too short for Ethernet header after offset")

		// 如果开启调试，显示原始内容
		if debug {
			fmt.Printf("Raw data (%d bytes): %s\n", len(payload),
				hex.EncodeToString(payload))
		}
		return
	}

	// 获取实际的以太网帧数据
	realEthernet := payload[offset:]

	// 确保只处理有效的以太网帧数据
	if len(realEthernet) < 14 {
		fmt.Println("Ethernet frame too short after offset adjustment")
		return
	}

	eth := &EthernetHeader{}
	reader := bytes.NewReader(realEthernet)
	if err := binary.Read(reader, binary.BigEndian, eth); err != nil {
		fmt.Printf("Error reading Ethernet header: %v\n", err)
		return
	}

	fmt.Printf("\nEthernet:\n")
	fmt.Printf("  Src MAC: %s\n", net.HardwareAddr(eth.SrcMAC[:]))
	fmt.Printf("  Dst MAC: %s\n", net.HardwareAddr(eth.DstMAC[:]))
	fmt.Printf("  Type: 0x%04x\n", eth.EtherType)

	// 根据EtherType解析上层协议
	if eth.EtherType == 0x0800 && len(realEthernet) >= 34 { // 以太网头(14) + IP头(20)
		p.parseIPv4(realEthernet[14:])
	} else if eth.EtherType == 0x0806 && len(realEthernet) >= 42 { // ARP
		p.parseARP(realEthernet[14:])
	} else if eth.EtherType == 0x86DD && len(realEthernet) >= 54 { // IPv6
		p.parseIPv6(realEthernet[14:])
	}

	// 显示十六进制数据
	if p.showHex {
		fmt.Println("\nHex dump:")
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

// printHexDump 打印十六进制数据
func (p *PacketPrinter) printHexDump(data []byte) {
	const bytesPerLine = 16
	for i := 0; i < len(data); i += bytesPerLine {
		// 打印偏移量
		fmt.Printf("%04x  ", i)

		// 打印十六进制值
		end := i + bytesPerLine
		if end > len(data) {
			end = len(data)
		}

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
	fmt.Printf("\n=== Statistics ===\n")
	fmt.Printf("Packets: %d, Bytes: %d\n", p.stats.packets, p.stats.bytes)
	fmt.Printf("Rate: %.2f pps, %.2f Mbps\n",
		float64(p.stats.packets)/elapsed,
		float64(p.stats.bytes*8)/(elapsed*1000000))
}
