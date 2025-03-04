package main

// 常量定义
const (
	MaxPacketSize = 512 // 增大支持的数据包大小
	VMwareOffset  = 24  // VMware头部默认偏移量
)

// PacketMetadata 对应内核传来的元数据
type PacketMetadata struct {
	PacketSize   uint32
	CapturedSize uint32
	Protocol     uint32 // 协议类型
	Flags        uint32
	Timestamp    uint64
}

// EthernetHeader 以太网头部
type EthernetHeader struct {
	DstMAC    [6]byte
	SrcMAC    [6]byte
	EtherType uint16
}

// IPv4Header IPv4头部
type IPv4Header struct {
	VersionIHL uint8 // 版本(4位) + 头部长度(4位)
	TOS        uint8
	TotalLen   uint16
	ID         uint16
	FlagsFragmentOffset uint16 // 标志(3位) + 片偏移(13位)
	TTL        uint8
	Protocol   uint8
	Checksum   uint16
	SrcIP      [4]byte
	DstIP      [4]byte
}

// TCPHeader TCP头部
type TCPHeader struct {
	SrcPort    uint16
	DstPort    uint16
	SeqNum     uint32
	AckNum     uint32
	DataOffset uint8 // 高4位 + 保留位和标志
	Flags      uint8
	Window     uint16
	Checksum   uint16
	UrgPtr     uint16
}

// UDPHeader UDP头部
type UDPHeader struct {
	SrcPort  uint16
	DstPort  uint16
	Length   uint16
	Checksum uint16
}
