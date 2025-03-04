package main

import (
	"encoding/binary"
	"fmt"
	"time"
)

// min函数用于获取两个整数的较小值
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// 辅助函数：将网络字节序(大端)转换为主机字节序
func ntohs(value uint16) uint16 {
	bytes := make([]byte, 2)
	binary.BigEndian.PutUint16(bytes, value)
	return binary.LittleEndian.Uint16(bytes)
}

// 辅助函数：将主机字节序转换为网络字节序(大端)
func htons(value uint16) uint16 {
	bytes := make([]byte, 2)
	binary.LittleEndian.PutUint16(bytes, value)
	return binary.BigEndian.Uint16(bytes)
}

// FormatTimestamp 格式化时间戳为可读格式
func FormatTimestamp(timestamp uint64) string {
	return time.Unix(0, int64(timestamp)).Format("2006-01-02 15:04:05.000000")
}

// 辅助函数：将字节数格式化为人类可读形式
func FormatBytes(bytes uint64) string {
	const unit = 1024
	if bytes < unit {
		return fmt.Sprintf("%d B", bytes)
	}
	div, exp := uint64(unit), 0
	for n := bytes / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(bytes)/float64(div), "KMGTPE"[exp])
}

// 辅助函数：将比特率格式化为人类可读形式
func FormatBitrate(bitsPerSecond float64) string {
	if bitsPerSecond < 1000 {
		return fmt.Sprintf("%.1f bps", bitsPerSecond)
	} else if bitsPerSecond < 1000000 {
		return fmt.Sprintf("%.1f Kbps", bitsPerSecond/1000)
	} else if bitsPerSecond < 1000000000 {
		return fmt.Sprintf("%.1f Mbps", bitsPerSecond/1000000)
	}
	return fmt.Sprintf("%.1f Gbps", bitsPerSecond/1000000000)
}
