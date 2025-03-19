package main

import (
	"FlowMetrix/internal/bpf"
	"FlowMetrix/internal/extractor"
	"FlowMetrix/internal/repository"
	"FlowMetrix/pkg/logger"
	"encoding/hex"
	"flag"
	"github.com/cilium/ebpf/ringbuf"
	"log"
	"os"
	"os/signal"
	"syscall"
)

const (
	MaxPacketSize = 512 // 增大支持的数据包大小
	VMwareOffset  = 24  // VMware头部默认偏移量
)

// 命令行参数
var (
	interfaceName string
	// showHex       bool
	// verbose       bool
	debug        bool
	vmwareOffset int  // VMware头部偏移选项
	detectVMware bool // 自动检测VMware头部
	disableLog   bool
	// maxBytes      int  // 最大显示字节数
)

/*type PerfEventData struct {
	Timestamp   uint64
	PacketSize  uint32
	CaptureSize uint32
	Data        [54]byte // 最大捕获字节数
}*/

func main() {
	// 解析命令行参数
	flag.StringVar(&interfaceName, "i", "", "Interface to attach XDP program to")
	// flag.BoolVar(&showHex, "x", false, "Show hex dump of packets")
	// flag.BoolVar(&verbose, "v", false, "Verbose output")
	flag.BoolVar(&debug, "d", false, "Enable debug output")
	flag.IntVar(&vmwareOffset, "offset", VMwareOffset, "VMware header offset (default: 24)")
	flag.BoolVar(&detectVMware, "auto-detect", false, "Auto-detect VMware header offset")
	flag.BoolVar(&disableLog, "no-log", false, "Disable logrus output")
	// flag.IntVar(&maxBytes, "max-bytes", 512, "Maximum bytes to process (default: 512)")
	flag.Parse()

	if disableLog {
		logger.DisableLogOutput()
	}

	rd, xdplink, obj := bpf.NewRingReader(interfaceName)

	defer obj.Close()
	defer xdplink.Close()
	defer rd.Close()

	// 创建数据包打印器
	// p := printer.NewPacketPrinter(showHex, verbose, vmwareOffset, detectVMware, maxBytes)

	packetChan := make(chan extractor.PacketData)

	de := extractor.NewDataExtractor(vmwareOffset, packetChan)

	gc, err := repository.NewGreptimeConnection(packetChan)
	if err != nil {
		logger.Fatal(err)
	}
	defer gc.Close()

	// 处理信号
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)

	logger.Printf("Listening on interface %s (Press Ctrl+C to stop)\n", interfaceName)
	if detectVMware {
		logger.Print("Auto-detection of VMware header enabled")
	} else {
		logger.Printf("Using fixed VMware header offset: %d bytes\n", vmwareOffset)
	}
	// logger.Printf("Maximum packet bytes to process: %d\n", maxBytes)

	// 创建一个定时器，用于定期处理缓冲事件
	// processTicker := time.NewTicker(200 * time.Millisecond)
	// defer processTicker.Stop()
	/*	go func() {
		for {
			select {
			case data := <-packetChan:
				logger.Printf("%+v", data)
			}
		}
	}()*/
	// 主循环
	for {
		select {
		case <-sig:
			logger.Print("\nReceived signal, exiting...")
			return
		default:
			record, err := rd.Read()
			if err != nil {
				if err == ringbuf.ErrClosed {
					return
				}
				log.Printf("Error reading from ring buffer: %v", err)
				continue
			}

			if debug {
				logger.Printf("Received event of size %d bytes", len(record.RawSample))
				if len(record.RawSample) > 0 && len(record.RawSample) <= 32 {
					logger.Printf("Event hex dump: %s", hex.EncodeToString(record.RawSample))
				}
			}
			packetData := make([]byte, len(record.RawSample))
			copy(packetData, record.RawSample)
			// 打印数据包
			// p.PrintPacket(record.RawSample)
			// time.Sleep(10 * time.Millisecond)
			de.ProcessPacket(packetData)

		}
	}

}
