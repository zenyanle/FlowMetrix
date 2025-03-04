package main

import (
	"FlowMetrix/pkg/logger"
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"flag"
	"fmt"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"
	"github.com/cilium/ebpf/rlimit"
	"net"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"
)

// 命令行参数
var (
	interfaceName string
	showHex       bool
	verbose       bool
	debug         bool
	vmwareOffset  int  // VMware头部偏移选项
	detectVMware  bool // 自动检测VMware头部
	maxBytes      int  // 最大显示字节数
)

// EventBuffer 用于存储和处理eBPF事件
type EventBuffer struct {
	pendingMeta  map[uint64]*PacketMetadata // 等待处理的元数据
	pendingData  map[uint64][]byte          // 等待处理的数据包
	mu           sync.Mutex                 // 保护上述映射
	nextEventID  uint64                     // 下一个事件ID
	cleanupTimer *time.Timer                // 清理定时器
}

// NewEventBuffer 创建新的事件缓冲区
func NewEventBuffer() *EventBuffer {
	eb := &EventBuffer{
		pendingMeta: make(map[uint64]*PacketMetadata),
		pendingData: make(map[uint64][]byte),
		nextEventID: 1,
	}

	// 设置定期清理未匹配事件的定时器
	eb.cleanupTimer = time.AfterFunc(5*time.Second, eb.cleanup)

	return eb
}

// cleanup 清理超过5秒未匹配的事件
func (eb *EventBuffer) cleanup() {
	eb.mu.Lock()
	defer eb.mu.Unlock()

	// 设置下一次定时器
	eb.cleanupTimer.Reset(5 * time.Second)

	// 没有需要清理的数据
	if len(eb.pendingMeta) == 0 && len(eb.pendingData) == 0 {
		return
	}

	now := time.Now()
	threshold := now.Add(-5 * time.Second).UnixNano()

	// 清理过期的元数据
	for id, meta := range eb.pendingMeta {
		if int64(meta.Timestamp) < threshold {
			if debug {
				logger.Printf("Cleaning up stale metadata ID %d (age: %.2fs)",
					id, float64(now.UnixNano()-int64(meta.Timestamp))/1e9)
			}
			delete(eb.pendingMeta, id)
		}
	}

	// 对于没有元数据匹配的数据，生成合成元数据并处理
	if len(eb.pendingData) > 0 && debug {
		logger.Printf("Pending data packets: %d", len(eb.pendingData))
	}
}

// AddMetadata 添加元数据
func (eb *EventBuffer) AddMetadata(meta *PacketMetadata) uint64 {
	eb.mu.Lock()
	defer eb.mu.Unlock()

	id := eb.nextEventID
	eb.nextEventID++

	// 存储元数据
	eb.pendingMeta[id] = meta

	// 检查是否有匹配的数据
	if _, ok := eb.pendingData[id]; ok {
		// 找到匹配的数据，可以直接返回ID和数据
		delete(eb.pendingData, id)
		return id
	}

	return id
}

// AddData 添加数据包内容
func (eb *EventBuffer) AddData(id uint64, data []byte) {
	eb.mu.Lock()
	defer eb.mu.Unlock()

	// 存储数据
	eb.pendingData[id] = data
}

// GetData 获取指定ID的数据
func (eb *EventBuffer) GetData(id uint64) ([]byte, bool) {
	eb.mu.Lock()
	defer eb.mu.Unlock()

	data, ok := eb.pendingData[id]
	if ok {
		delete(eb.pendingData, id)
	}
	return data, ok
}

// GetMetadata 获取指定ID的元数据
func (eb *EventBuffer) GetMetadata(id uint64) (*PacketMetadata, bool) {
	eb.mu.Lock()
	defer eb.mu.Unlock()

	meta, ok := eb.pendingMeta[id]
	if ok {
		delete(eb.pendingMeta, id)
	}
	return meta, ok
}

// GetExtraMeta 获取最前面的一个等待处理的元数据
func (eb *EventBuffer) GetExtraMeta() (*PacketMetadata, uint64, bool) {
	eb.mu.Lock()
	defer eb.mu.Unlock()

	// 没有等待的元数据
	if len(eb.pendingMeta) == 0 {
		return nil, 0, false
	}

	// 找到最小的ID
	var minID uint64 = ^uint64(0)
	for id := range eb.pendingMeta {
		if id < minID {
			minID = id
		}
	}

	meta := eb.pendingMeta[minID]
	delete(eb.pendingMeta, minID)
	return meta, minID, true
}

// GetExtraData 获取最前面的一个等待处理的数据
func (eb *EventBuffer) GetExtraData() ([]byte, uint64, bool) {
	eb.mu.Lock()
	defer eb.mu.Unlock()

	// 没有等待的数据
	if len(eb.pendingData) == 0 {
		return nil, 0, false
	}

	// 找到最小的ID
	var minID uint64 = ^uint64(0)
	for id := range eb.pendingData {
		if id < minID {
			minID = id
		}
	}

	data := eb.pendingData[minID]
	delete(eb.pendingData, minID)
	return data, minID, true
}

func main() {
	// 解析命令行参数
	flag.StringVar(&interfaceName, "i", "", "Interface to attach XDP program to")
	flag.BoolVar(&showHex, "x", false, "Show hex dump of packets")
	flag.BoolVar(&verbose, "v", false, "Verbose output")
	flag.BoolVar(&debug, "d", false, "Enable debug output")
	flag.IntVar(&vmwareOffset, "offset", VMwareOffset, "VMware header offset (default: 24)")
	flag.BoolVar(&detectVMware, "auto-detect", true, "Auto-detect VMware header offset")
	flag.IntVar(&maxBytes, "max-bytes", 512, "Maximum bytes to process (default: 512)")
	flag.Parse()

	if interfaceName == "" {
		logger.Fatal("Please specify an interface with -i")
	}

	// 移除内存锁限制
	if err := rlimit.RemoveMemlock(); err != nil {
		logger.Fatal(err)
	}

	// 加载预编译的BPF程序
	objs := sampler_kernObjects{}
	if err := loadSampler_kernObjects(&objs, nil); err != nil {
		logger.Fatalf("Loading objects: %v", err)
	}
	defer objs.Close()

	iface, err := net.InterfaceByName(interfaceName)
	if err != nil {
		logger.Fatalf("Finding interface %s: %v", interfaceName, err)
	}

	// 附加XDP程序到网络接口
	xdpLink, err := link.AttachXDP(link.XDPOptions{
		Program:   objs.Sampler,
		Interface: iface.Index,
	})
	if err != nil {
		logger.Fatalf("Attaching XDP: %v", err)
	}
	defer xdpLink.Close()

	// 创建perf reader
	rd, err := perf.NewReader(objs.Events, os.Getpagesize()*128)
	if err != nil {
		logger.Fatalf("Creating perf reader: %v", err)
	}
	defer rd.Close()

	// 创建数据包打印器
	printer := NewPacketPrinter(showHex, verbose, vmwareOffset, detectVMware, maxBytes)

	// 创建事件缓冲区
	eventBuffer := NewEventBuffer()

	// 处理信号
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)

	fmt.Printf("Listening on interface %s (Press Ctrl+C to stop)\n", interfaceName)
	if detectVMware {
		fmt.Println("Auto-detection of VMware header enabled")
	} else {
		fmt.Printf("Using fixed VMware header offset: %d bytes\n", vmwareOffset)
	}
	fmt.Printf("Maximum packet bytes to process: %d\n", maxBytes)

	metadataSize := binary.Size(PacketMetadata{})

	if debug {
		logger.Printf("Expected metadata size: %d bytes", metadataSize)
	}

	// 创建一个定时器，用于定期处理缓冲事件
	processTicker := time.NewTicker(200 * time.Millisecond)
	defer processTicker.Stop()

	// 使用goroutine定期处理未匹配的事件
	go func() {
		for {
			select {
			case <-processTicker.C:
				// 尝试处理任何未匹配的事件
				for {
					// 检查是否有额外的元数据和数据可以匹配
					meta, metaID, hasMeta := eventBuffer.GetExtraMeta()
					data, dataID, hasData := eventBuffer.GetExtraData()

					if !hasMeta && !hasData {
						break // 没有未匹配的事件了
					}

					if hasMeta && hasData {
						if debug {
							logger.Printf("Processing unmatched events: meta=%d, data=%d", metaID, dataID)
						}

						// 处理数据包
						printer.PrintPacket(meta, data)
					} else if hasData {
						// 有数据但没有元数据，创建合成元数据
						syntheticMeta := &PacketMetadata{
							PacketSize:   uint32(len(data)),
							CapturedSize: uint32(len(data)),
							Protocol:     0,
							Timestamp:    uint64(time.Now().UnixNano()),
							Flags:        0,
						}

						if debug {
							logger.Printf("Processing unmatched data (%d bytes) with synthetic metadata", len(data))
						}

						printer.PrintPacket(syntheticMeta, data)
					} else {
						// 退出循环，等待下一轮检查
						break
					}
				}
			case <-sig:
				return
			}
		}
	}()

	// 主循环 - 完全重写的事件处理逻辑
	for {
		select {
		case <-sig:
			fmt.Println("\nReceived signal, exiting...")
			return
		default:
			record, err := rd.Read()
			if err != nil {
				if err == perf.ErrClosed {
					return
				}
				logger.Printf("Reading perf event: %v", err)
				continue
			}

			// 处理丢失的样本
			if record.LostSamples != 0 {
				logger.Printf("Lost %d samples", record.LostSamples)
				continue
			}

			if debug {
				logger.Printf("Received event of size %d bytes", len(record.RawSample))
				if len(record.RawSample) > 0 && len(record.RawSample) <= 32 {
					logger.Printf("Event hex dump: %s", hex.EncodeToString(record.RawSample))
				}
			}

			// 基于大小的特征识别事件类型
			if len(record.RawSample) == metadataSize {
				// 这是元数据
				var meta PacketMetadata
				if err := binary.Read(bytes.NewReader(record.RawSample), binary.LittleEndian, &meta); err != nil {
					logger.Printf("Error parsing metadata: %v", err)
					continue
				}

				metaCopy := meta // 创建一个副本

				// 存储元数据并获取事件ID
				eventID := eventBuffer.AddMetadata(&metaCopy)

				if debug {
					logger.Printf("Stored metadata (ID=%d): size=%d captured=%d proto=0x%x",
						eventID, meta.PacketSize, meta.CapturedSize, meta.Protocol)
				}

				// 尝试获取下一个事件作为数据包内容
				dataRecord, err := rd.Read()
				if err != nil {
					if err != perf.ErrClosed {
						logger.Printf("Error reading packet data: %v", err)
					}
					continue
				}

				if dataRecord.LostSamples != 0 {
					logger.Printf("Lost samples between metadata and data")
					continue
				}

				// 处理数据包
				if len(dataRecord.RawSample) > 0 {
					// 打印数据包
					printer.PrintPacket(&metaCopy, dataRecord.RawSample)
				} else {
					logger.Printf("Received empty packet data")
				}

			} else if len(record.RawSample) >= 14 {
				// 这似乎是直接的数据包内容，没有元数据
				// 创建一个合成的元数据并直接处理
				syntheticMeta := PacketMetadata{
					PacketSize:   uint32(len(record.RawSample)),
					CapturedSize: uint32(len(record.RawSample)),
					Protocol:     0, // 未知协议，由PrintPacket解析
					Timestamp:    uint64(time.Now().UnixNano()),
					Flags:        0,
				}

				if debug {
					logger.Printf("Processing direct packet data: %d bytes", len(record.RawSample))
				}

				// 打印数据包
				printer.PrintPacket(&syntheticMeta, record.RawSample)

			} else if debug {
				// 未知格式，记录调试信息
				logger.Printf("Ignoring unrecognized event format: %d bytes", len(record.RawSample))
			}
		}
	}
}
