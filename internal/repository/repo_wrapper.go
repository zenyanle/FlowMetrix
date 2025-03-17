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
	table      *table.Table
	rowCount   int
	closeChan  chan struct{}
}

func NewGreptimeConnection(packetChan chan extractor.PacketData) (*GreptimeConnection, error) {
	cfg := greptime.NewConfig("127.0.0.1").
		// 将数据库名称更改为你的数据库名称
		WithDatabase("test").
	// 默认端口 4001
	// WithPort(4001).
	// 如果服务配置了 TLS ，设置 TLS 选项来启用安全连接
	// WithInsecure(false).
	// 设置鉴权信息
	// 如果数据库不需要鉴权，移除 WithAuth 方法即可
	       WithAuth("greptime_user", "greptime_pwd")

	cli, err := greptime.NewClient(cfg)
	if err != nil {
		return nil, err
	}

	tbl, err := createPacketTable()
	if err != nil {
		return nil, err
	}

	gc := &GreptimeConnection{
		client:     cli,
		table:      tbl,
		rowCount:   0,
		packetChan: packetChan,
		closeChan:  make(chan struct{}),
	}

	go gc.Write()

	return gc, nil
}

func (d *GreptimeConnection) Write() {
	for {
		select {
		case <-d.closeChan:
			logger.Print("Greptimedb connection closed")
			// Flush any remaining data
			if d.rowCount > 0 {
				d.Flush(d.table)
			}
			return
		case data := <-d.packetChan:
			err := addPacketRow(d.table, &data)
			if err != nil {
				logger.Printf("Error adding row to table: %v\n", err)
				continue
			}
			d.rowCount++

			if d.rowCount >= 100 {
				go d.Flush(d.table)
				var err2 error
				d.table, err2 = createPacketTable()
				if err2 != nil {
					logger.Printf("Error recreating table: %v\n", err2)
					logger.Panic(err2)
				}
				d.rowCount = 0
			}
		}
	}
}

func (d *GreptimeConnection) Flush(tbl *table.Table) {
	resp, err := d.client.Write(context.Background(), tbl)
	if err != nil {
		logger.Printf("Error writing to GreptimeDB: %v\n", err)
	}
	logger.Printf("affected rows: %d\n", resp.GetAffectedRows().GetValue())
}

func (d *GreptimeConnection) Close() {
	close(d.closeChan)
	// d.client.CloseStream(context.Background())
}

func createPacketTable() (*table.Table, error) {
	// 创建名为 packet_data 的表
	packetTable, err := table.New("packet_data")
	if err != nil {
		return nil, err
	}

	// 按照结构体中的字段顺序添加列
	// 1. Timestamp - 时间戳列
	err = packetTable.AddTimestampColumn("ts", types.TIMESTAMP)
	if err != nil {
		return nil, err
	}

	// new: packet_size - 字段列
	err = packetTable.AddFieldColumn("packet_size", types.UINT16)
	if err != nil {
		return nil, err
	}

	// 2. EtherType - 字段列
	err = packetTable.AddFieldColumn("ether_type", types.UINT16)
	if err != nil {
		return nil, err
	}

	// 3. SrcMAC - 字段列
	err = packetTable.AddFieldColumn("src_mac", types.STRING)
	if err != nil {
		return nil, err
	}

	// 4. DstMAC - 字段列
	err = packetTable.AddFieldColumn("dst_mac", types.STRING)
	if err != nil {
		return nil, err
	}

	// 5. Protocol - 字段列
	err = packetTable.AddFieldColumn("protocol", types.UINT8)
	if err != nil {
		return nil, err
	}

	// 6. SrcIP - 标签列
	err = packetTable.AddTagColumn("src_ip", types.STRING)
	if err != nil {
		return nil, err
	}

	// 7. DstIP - 字段列
	err = packetTable.AddFieldColumn("dst_ip", types.STRING)
	if err != nil {
		return nil, err
	}

	// 8. SrcPort - 字段列
	err = packetTable.AddFieldColumn("src_port", types.UINT16)
	if err != nil {
		return nil, err
	}

	// 9. DstPort - 标签列
	err = packetTable.AddTagColumn("dst_port", types.UINT16)
	if err != nil {
		return nil, err
	}

	// 10. TCPFlags - 字段列
	err = packetTable.AddFieldColumn("tcp_flags", types.UINT8)
	if err != nil {
		return nil, err
	}

	// 11. PacketType - 标签列
	err = packetTable.AddTagColumn("packet_type", types.STRING)
	if err != nil {
		return nil, err
	}

	// 12. Application - 标签列
	err = packetTable.AddTagColumn("application", types.STRING)
	if err != nil {
		return nil, err
	}

	return packetTable, nil
}

func addPacketRow(t *table.Table, data *extractor.PacketData) error {
	// 转换 MAC 和 IP 地址为字符串表示
	srcMACStr := data.SrcMAC.String()
	dstMACStr := data.DstMAC.String()
	srcIPStr := data.SrcIP.String()
	dstIPStr := data.DstIP.String()

	// 添加行，参数必须与表结构中列的确切顺序相匹配
	return t.AddRow(
		data.Timestamp,   // 1. timestamp
		data.PacketSize,  // new: packet_size
		data.EtherType,   // 2. ether_type
		srcMACStr,        // 3. src_mac
		dstMACStr,        // 4. dst_mac
		data.Protocol,    // 5. protocol
		srcIPStr,         // 6. src_ip (TAG)
		dstIPStr,         // 7. dst_ip
		data.SrcPort,     // 8. src_port
		data.DstPort,     // 9. dst_port (TAG)
		data.TCPFlags,    // 10. tcp_flags
		data.PacketType,  // 11. packet_type (TAG)
		data.Application, // 12. application (TAG)
	)
}
