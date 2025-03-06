package repository

import (
	"FlowMetrix/internal/extractor"
	"FlowMetrix/pkg/logger"
	"context"
	greptime "github.com/GreptimeTeam/greptimedb-ingester-go"
	"github.com/GreptimeTeam/greptimedb-ingester-go/table"
	"github.com/GreptimeTeam/greptimedb-ingester-go/table/types"
)

type GreptimeConnection struct {
	client     *greptime.Client
	packetChan <-chan extractor.PacketData
	buffer     []extractor.PacketData
	closeChan  chan struct{}
}

func NewGreptimeConnection(packetChan chan extractor.PacketData) (*GreptimeConnection, error) {
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

	gc := GreptimeConnection{
		client:     cli,
		buffer:     make([]extractor.PacketData, 100),
		packetChan: packetChan,
	}

	go gc.Write()

	return &gc, err
}

func (d *GreptimeConnection) Write() {
	for {
		select {
		case <-d.closeChan:
			logger.Print("Greptimedb connection closed")
			return
		case data := <-d.packetChan:
			d.buffer = append(d.buffer, data)
			if len(d.buffer) == 100 {
				go d.Flush(d.buffer)
				d.buffer = make([]extractor.PacketData, 100)
			}
		}
	}
}

func (d *GreptimeConnection) Flush(buffer []extractor.PacketData) {
	tbl := d.GetNewTable()
	for _, data := range buffer {
		tbl.AddRow(data)
	}
	d.client.StreamWrite(context.Background(), tbl)
}

func (d *GreptimeConnection) GetNewTable() *table.Table {
	grpcLatenciesTable, err := table.New("grpc_latencies")
	if err != nil {
		logger.Printf("Error creating table: %v\n", err)
		logger.Panic(err) // 或 panic(err)
	}

	// 添加 'ts' 列 (时间戳)
	grpcLatenciesTable.AddTimestampColumn("ts", types.TIMESTAMP)

	// 添加 'host' 列 (主机名)
	grpcLatenciesTable.AddTagColumn("host", types.STRING)

	// 添加 'method_name' 列 (gRPC 方法名)
	grpcLatenciesTable.AddTagColumn("method_name", types.STRING)

	// 添加 'latency' 列 (延迟，毫秒)
	grpcLatenciesTable.AddFieldColumn("latency", types.FLOAT)

	return grpcLatenciesTable
}

func (d *GreptimeConnection) Close() {
	close(d.closeChan)
	d.client.CloseStream(context.Background())
}
