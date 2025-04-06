FlowMetrix：基于 eBPF 与 GreptimeDB 的高性能网络监控系统

Go Version
License

FlowMetrix 利用 Linux 内核中的 eBPF（Extended Berkeley Packet Filter） 技术，实现了高效、低开销的网络数据捕获，并将结构化数据写入 GreptimeDB，实现对网络流量的实时监控、分析与可观测性。
✨ 主要特性

    🚀 高性能捕获：使用 eBPF 的 XDP 模式在内核态捕获数据包，极大减少 CPU 使用率。

    🔍 详细数据解析：支持解析 Ethernet、IPv4、IPv6、TCP、UDP、ARP 等协议，提取 MAC、IP、端口、协议、TCP Flags 等关键字段。

    💡 应用层协议推断：根据端口号识别常见协议（如 HTTP、DNS、SSH 等）。

    ⚙️ 高效内核-用户态通信：通过 eBPF Ring Buffer 实现低延迟数据传输。

    📊 时间序列存储：与 GreptimeDB 无缝集成，自动建表并写入结构化网络指标。

    🧠 智能采样：在 eBPF 程序中实现基础采样逻辑，降低数据量（采样率写死于 sampler_kern.c）。

    🛠️ VMware 环境适配：支持自动/手动配置头部偏移，处理 VMware 网络数据异常问题。

    📝 结构化日志：使用 Logrus 提供可配置的日志系统，支持 debug 模式。

    💻 简洁 CLI 接口：通过命令行快速配置接口、调试模式、VMware 偏移等。

🧱 架构概览

FlowMetrix 包含两个核心部分：
1. 内核空间（eBPF）

    使用 XDP 挂载在指定网卡上（如 eth0）。

    捕获数据包元数据和部分有效载荷。

    添加 2 字节原始长度字段。

    执行基本采样逻辑。

    将数据写入 Ring Buffer，供用户态读取。

2. 用户空间（Go 应用）

    使用 cilium/ebpf 加载 eBPF 程序。

    从 Ring Buffer 读取数据。

    extractor 模块解析原始字节，处理 VMware 偏移并输出结构化 PacketData。

    repository 模块批量写入 GreptimeDB。

    使用 Logrus 输出日志，预留 Viper 做未来配置扩展。

+--------------------+    +---------------------+    +---------------------+    +---------------------+    +-----------------+
| 网络接口 (eth0等)  |--->| eBPF XDP 程序       |--->| eBPF Ring Buffer    |--->| Go 用户态处理程序    |--->| GreptimeDB      |
+--------------------+    +---------------------+    +---------------------+    +---------------------+    +-----------------+
|                                          ↑           ↑                    配置来自 CLI 参数与 Logrus 输出
|                                          |
|                                    配置与日志

🧰 技术栈
技术	描述
Go	用户态核心语言
eBPF (XDP)	内核级高性能数据处理技术
C	eBPF 程序编写语言
cilium/ebpf	Go 的 eBPF 加载与交互库
GreptimeDB	网络指标的时间序列数据库
greptimedb-ingester-go	GreptimeDB 官方 Go 写入库
logrus	日志库
viper	配置管理库（目前仅部分使用）
Linux Kernel ≥ 4.9	eBPF 支持所需内核版本，推荐 5.x 以上
✅ 前置条件

在运行 FlowMetrix 前，请确保你具备以下环境：

    Linux 系统（支持 eBPF）

    内核版本 ≥ 4.9（建议 5.x+）

    Go 1.22+（安装指南）

    Clang/LLVM 10+（用于编译 eBPF C 代码，需匹配 gen.go 中的版本号）

    libpcap 开发头文件（如 sudo apt install libpcap-dev）

    对应内核头文件（如 sudo apt install linux-headers-$(uname -r)）

    已部署的 GreptimeDB 实例（默认连接 127.0.0.1:4001，数据库 test）

📦 安装步骤

    克隆项目：

git clone https://github.com/YOUR_GITHUB_USERNAME/FlowMetrix.git
cd FlowMetrix

    生成 eBPF 绑定代码：

go generate ./internal/bpf/...

    构建 Go 应用：

go build -o flowmetrix ./cmd/main.go

⚙️ 配置方式

FlowMetrix 主要通过命令行参数配置：
参数	说明
-i <接口>	必填，指定监听的网络接口（如 eth0）
-d	开启 debug 日志
-offset <字节>	设置 VMware 网络偏移（默认 24）
-auto-detect	自动检测 VMware 偏移（不一定准确）
-no-log	完全关闭日志输出

GreptimeDB 连接配置：当前硬编码于 internal/repository/repo_wrapper.go，后续计划通过 configs/config.yaml 配合 Viper 加载。
🚀 使用示例

需要以 root 权限 运行：

sudo ./flowmetrix -i eth0 -d

按 Ctrl+C 可优雅退出，自动卸载 eBPF 程序并关闭连接。
📚 数据表结构（GreptimeDB 中的 packet_data）
字段名	类型	说明	用途
ts	时间戳	数据包捕获时间	时间索引
packet_size	UInt16	原始数据包长度	字段
ether_type	UInt16	Ethernet 类型（如 0x0800=IPv4）	字段
src_mac	String	源 MAC 地址	字段
dst_mac	String	目的 MAC 地址	字段
protocol	UInt8	IP 协议号（6=TCP, 17=UDP）	字段
src_ip	String	源 IP 地址	标签
dst_ip	String	目的 IP 地址	字段
src_port	UInt16	源端口	字段
dst_port	UInt16	目的端口	标签
tcp_flags	UInt8	TCP 标志位	字段
packet_type	String	网络协议类型（IPv4, ARP 等）	标签
application	String	应用层协议推断结果（HTTP 等）	标签
