package repository

import (
	"FlowMetrix/internal/extractor"
	greptime "github.com/GreptimeTeam/greptimedb-ingester-go"
	"github.com/GreptimeTeam/greptimedb-ingester-go/table"
	"sync"
	"time"
)

type GreptimeConnection struct {
	client     *greptime.Client
	tbl        *table.Table
	ticker     *time.Ticker
	packetChan chan extractor.PacketData
	buffer     []extractor.PacketData
	mu         sync.Mutex
}

func NewGreptimeConnection() (*GreptimeConnection, error) {
	cfg := greptime.NewConfig("127.0.0.1").
		// 将数据库名称更改为你的数据库名称
		WithDatabase("test")
	// 默认端口 4001
	// WithPort(4001).
	// 如果服务配置了 TLS ，设置 TLS 选项来启用安全连接
	// WithInsecure(false).
	// 设置鉴权信息
	// 如果数据库不需要鉴权，移除 WithAuth 方法即可
	// WithAuth("username", "password")

	cli, err := greptime.NewClient(cfg)
	tbl, _ := table.New("test")
	ticker := time.NewTicker(1 * time.Second)
	buffer := []extractor.PacketData{}
	return &GreptimeConnection{
		client: cli,
		tbl:    tbl,
		ticker: ticker,
		buffer: buffer,
	}, err
}

func (d *GreptimeConnection) Write() {
	defer d.ticker.Stop()
	for {
		select {
		case data := <-d.packetChan:
			d.buffer = append(d.buffer, data)
			if len(d.buffer) == 100 {
				go d.Flush(d.buffer)
				d.buffer = []extractor.PacketData{}
			}
		}
	}
}

func (d *GreptimeConnection) Flush(buffer []extractor.PacketData) {
	d.mu.Lock()
	defer d.mu.Unlock()

	for _, data := range buffer {
		d.tbl.AddRow(data)
	}
	d.client.StreamWrite(context.Background(), d.tbl)
	tbl, _ := table.New("test")
	d.tbl = tbl
}
