FlowMetrix
FlowMetrix 是一款基于 eBPF 的高效网络流量监控和指标提取工具。
它能够捕获网络数据包，解析关键信息，并将结构化数据存储至 GreptimeDB 时序数据库，
用于网络流量分析和监控。

特性
高效数据包捕获：
采用 eBPF 在内核层捕获数据包，极低性能开销。
灵活的接口选择：
允许用户指定网络接口进行监听。
VMware 兼容性：
适配 VMware 虚拟化环境，自动检测或手动设置 VMware 头部偏移，精准解析流量。
多协议支持：
支持解析 以太网、IPv4、IPv6、TCP、UDP、ARP，并提取：
源/目标 MAC 地址
IP 地址
端口号
协议类型
TCP 标志
应用层协议识别：
通过端口号推断常见的应用层协议。
结构化数据输出：
解析后的数据通过 Channel 发送，便于处理和存储。
GreptimeDB 集成：
自动创建表结构
数据写入 GreptimeDB，便于查询与分析
可配置日志：
使用 logrus 记录日志
支持 Debug 模式，便于调试
简单的 CLI 配置：
提供命令行参数
支持网络接口、Debug 模式、VMware 头部偏移配置
技术栈
技术	说明
Go	主要开发语言
eBPF (Extended Berkeley Packet Filter)	高性能网络数据包捕获与过滤
cilium/ebpf	eBPF Go 库，用于管理 eBPF 程序
GreptimeDB	开源时序数据库，存储与分析流量数据
GreptimeTeam/greptimedb-ingester-go	GreptimeDB Go 客户端
sirupsen/logrus	结构化日志库
spf13/viper	配置管理库
快速开始
运行环境
确保以下环境满足要求：

Linux 系统：
FlowMetrix 依赖 eBPF，需要在 Linux 环境下运行。

BPF 支持：
Linux 内核版本需不低于 4.9（建议 5.x 及以上）。

libpcap（可选）：
编译 eBPF 代码时可能需要 libpcap 开发库。

GreptimeDB：
需运行 GreptimeDB 实例，默认连接 127.0.0.1:4001，数据库名 test。

Go 环境：
需安装 Go 1.22 及以上版本。
