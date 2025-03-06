package extractor

import (
	"FlowMetrix/types"
	"bytes"
	"encoding/binary"
	"net"
	"time"
)

// PacketData 表示用于时序数据库的结构化网络包数据
type PacketData struct {
	Timestamp time.Time // 捕获时间戳
	// PacketSize  int              // 包大小，单位为字节
	EtherType   uint16           // 以太网帧类型
	SrcMAC      net.HardwareAddr // 源 MAC 地址
	DstMAC      net.HardwareAddr // 目的 MAC 地址
	Protocol    uint8            // IP 协议号 (例如, TCP=6, UDP=17)
	SrcIP       net.IP           // 源 IP 地址 TAG
	DstIP       net.IP           // 目的 IP 地址
	SrcPort     uint16           // 源端口
	DstPort     uint16           // 目的端口 TAG
	TCPFlags    uint8            // TCP 标志 (SYN, ACK, 等)
	PacketType  string           // 包类型 (IPv4, IPv6, ARP, 等) TAG
	Application string           // 应用层协议 (基于端口) TAG
}

// DataExtractor 提取包数据并通过通道发送
type DataExtractor struct {
	vmwareOffset int               // VMware 偏移量
	packetChan   chan<- PacketData // 用于发送包数据的通道
}

// NewDataExtractor 创建一个新的包数据提取器
func NewDataExtractor(vmwareOffset int, packetChan chan<- PacketData) *DataExtractor {
	return &DataExtractor{
		vmwareOffset: vmwareOffset,
		packetChan:   packetChan,
	}
}

// ProcessPacket 从数据包中提取数据并将其发送到通道
func (de *DataExtractor) ProcessPacket(payload []byte) {
	if len(payload) == 0 {
		return
	}

	// 找到最佳的解析偏移量 (处理 VMware 数据包)
	detectedData, offset := de.findBestVMwarePacket(payload)

	// 提取指标并通过通道发送
	packetData := de.extractPacketData(detectedData, offset)
	de.packetChan <- packetData
}

// findBestVMwarePacket 处理 VMware 特定的数据包格式
// 这是 PacketPrinter.findBestVMwarePacket 的简化版本
func (de *DataExtractor) findBestVMwarePacket(payload []byte) ([]byte, int) {
	// 对于超过 64 字节的数据包，尝试查找有效的以太网帧
	if len(payload) >= 64 {
		// 尝试特定的偏移量
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

		// 查找 IPv4 模式
		for i := 0; i < len(payload)-20; i++ {
			// 搜索 IPv4 版本 (4) 和报头长度 (5)，通常为 0x45
			if payload[i] == 0x45 && i+20 <= len(payload) {
				// 验证更多 IPv4 报头字段以提高可信度
				ipLen := binary.BigEndian.Uint16(payload[i+2 : i+4])
				if ipLen >= 20 && ipLen <= uint16(len(payload)-i) {
					return payload, i - 14
				}
			}
		}
	}

	// 如果没有找到更好的位置，则使用配置的偏移量
	return payload, de.vmwareOffset
}

// 来自 PacketPrinter 的辅助函数
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

	// 检查是否全部为零
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

	// 检查是否全部为 F
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

	// 一些特殊值经常出现在伪造的以太网报头中
	if mac[0] == 0xFF && mac[1] == 0xFF && mac[2] == 0xFF {
		return false
	}

	return true
}

// extractPacketData 从数据包中提取数据
func (de *DataExtractor) extractPacketData(payload []byte, offset int) PacketData {
	packetData := PacketData{
		Timestamp: time.Now(),
		// PacketSize: len(payload),
	}

	// 确保我们有足够的数据来解析以太网报头
	if len(payload) < offset+14 {
		return packetData
	}

	// 提取以太网信息
	realEthernet := payload[offset:]
	eth := &types.EthernetHeader{}
	reader := bytes.NewReader(realEthernet)
	if err := binary.Read(reader, binary.BigEndian, eth); err != nil {
		return packetData
	}

	packetData.EtherType = eth.EtherType
	packetData.SrcMAC = net.HardwareAddr(eth.SrcMAC[:])
	packetData.DstMAC = net.HardwareAddr(eth.DstMAC[:])

	// 根据 EtherType 解析上层协议
	if eth.EtherType == 0x0800 && len(realEthernet) >= 34 { // IPv4
		packetData.PacketType = "IPv4"
		de.extractIPv4Data(realEthernet[14:], &packetData)
	} else if eth.EtherType == 0x0806 && len(realEthernet) >= 42 { // ARP
		packetData.PacketType = "ARP"
		// 如果需要，可以在此处添加特定于 ARP 的字段
	} else if eth.EtherType == 0x86DD && len(realEthernet) >= 54 { // IPv6
		packetData.PacketType = "IPv6"
		de.extractIPv6Data(realEthernet[14:], &packetData)
	}

	// 推断应用层协议
	packetData.Application = inferApplication(packetData.SrcPort, packetData.DstPort)

	return packetData
}

// extractIPv4Data 提取 IPv4 数据
func (de *DataExtractor) extractIPv4Data(data []byte, packetData *PacketData) {
	if len(data) < 20 {
		return
	}

	packetData.Protocol = data[9]
	packetData.SrcIP = net.IP(data[12:16])
	packetData.DstIP = net.IP(data[16:20])

	headerLen := (data[0] & 0x0F) * 4

	// 解析传输层
	if len(data) >= int(headerLen) {
		switch packetData.Protocol {
		case 6: // TCP
			de.extractTCPData(data[headerLen:], packetData)
		case 17: // UDP
			de.extractUDPData(data[headerLen:], packetData)
		}
	}
}

// extractIPv6Data 提取 IPv6 数据
func (de *DataExtractor) extractIPv6Data(data []byte, packetData *PacketData) {
	if len(data) < 40 {
		return
	}

	packetData.Protocol = data[6] // 下一个报头
	packetData.SrcIP = net.IP(data[8:24])
	packetData.DstIP = net.IP(data[24:40])

	// 解析传输层
	if len(data) >= 40 {
		switch packetData.Protocol {
		case 6: // TCP
			de.extractTCPData(data[40:], packetData)
		case 17: // UDP
			de.extractUDPData(data[40:], packetData)
		}
	}
}

// extractTCPData 提取 TCP 数据
func (de *DataExtractor) extractTCPData(data []byte, packetData *PacketData) {
	if len(data) < 20 {
		return
	}

	packetData.SrcPort = binary.BigEndian.Uint16(data[0:2])
	packetData.DstPort = binary.BigEndian.Uint16(data[2:4])
	packetData.TCPFlags = data[13]
}

// extractUDPData 提取 UDP 数据
func (de *DataExtractor) extractUDPData(data []byte, packetData *PacketData) {
	if len(data) < 8 {
		return
	}

	packetData.SrcPort = binary.BigEndian.Uint16(data[0:2])
	packetData.DstPort = binary.BigEndian.Uint16(data[2:4])
}

// inferApplication 基于端口号推断应用层协议
func inferApplication(srcPort, dstPort uint16) string {
	// 检查常用端口
	wellKnownPorts := map[uint16]string{
		20: "FTP-DATA", 21: "FTP", 22: "SSH", 23: "TELNET",
		25: "SMTP", 53: "DNS", 80: "HTTP", 443: "HTTPS",
		110: "POP3", 143: "IMAP", 161: "SNMP", 162: "SNMPTRAP",
		389: "LDAP", 636: "LDAPS", 3306: "MySQL", 5432: "PostgreSQL",
		27017: "MongoDB", 6379: "Redis", 11211: "Memcached",
	}

	// 首先检查目标端口
	if app, ok := wellKnownPorts[dstPort]; ok {
		return app
	}

	// 然后检查源端口
	if app, ok := wellKnownPorts[srcPort]; ok {
		return app
	}

	// 未知应用
	return "UNKNOWN"
}
