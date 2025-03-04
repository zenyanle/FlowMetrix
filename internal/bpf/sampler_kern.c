//go:build ignore
// +build ignore

/* SPDX-License-Identifier: GPL-2.0 */
#include <linux/bpf.h>
#include <linux/types.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>
#include <linux/ip.h>

// 常量定义
#define MAX_PACKET_SIZE 512
#define MAX_CPUS 16
#define ETH_HDR_SIZE 14       // 以太网头部固定大小
#define MIN_CAPTURE 34        // 至少捕获以太网+IPv4头部(14+20)
#define MAX_CAPTURE 54        // 最大尝试捕获到以太网+IPv4+TCP(14+20+20)

// 定义发送到用户空间的完整结构
// 包含元数据和数据包内容
struct perf_event_data {
    __u64 timestamp;           // 时间戳
    __u32 packet_size;         // 原始数据包大小
    __u32 capture_size;        // 实际捕获大小
    __u8 data[MAX_CAPTURE];    // 数据包内容
};

// 定义临时工作缓冲区
struct packet_buffer {
    struct perf_event_data event;
};

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, __u32);
    __type(value, struct packet_buffer);
    __uint(max_entries, 1);
} packet_data_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __type(key, int);
    __type(value, int);
    __uint(max_entries, MAX_CPUS);
} events SEC(".maps");

SEC("xdp")
int sampler(struct xdp_md *ctx)
{
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    
    // 确保至少有以太网头部
    if (data + ETH_HDR_SIZE > data_end)
        return XDP_PASS;

    // 获取元数据缓冲区
    __u32 zero = 0;

    // 获取数据包缓冲区
    struct packet_buffer *buffer = bpf_map_lookup_elem(&packet_data_map, &zero);
    if (!buffer)
        return XDP_PASS;

    // 安全地计算数据包大小
    __u64 packet_size = data_end - data;
    
    // 初始化事件数据
    buffer->event.timestamp = bpf_ktime_get_ns();  // 获取当前内核时间
    buffer->event.packet_size = packet_size;       // 保存原始数据包大小
    
    // 解析以太网头部
    struct ethhdr {
        __u8 h_dest[6];
        __u8 h_source[6];
        __u16 h_proto;
    } __attribute__((packed));
    
    // 明确检查边界，确保我们可以安全访问以太网头部
    struct ethhdr *eth = data;
    if ((void*)(eth + 1) > data_end)
        return XDP_PASS;
        
    // 获取以太网协议类型
    __u16 eth_proto = bpf_ntohs(eth->h_proto);

    __u32 capture_size = ETH_HDR_SIZE;  // 至少捕获以太网头部

    // 复制以太网头部到事件数据
    buffer->event.data[0] = eth->h_dest[0];
    buffer->event.data[1] = eth->h_dest[1];
    buffer->event.data[2] = eth->h_dest[2];
    buffer->event.data[3] = eth->h_dest[3];
    buffer->event.data[4] = eth->h_dest[4];
    buffer->event.data[5] = eth->h_dest[5];
    
    buffer->event.data[6] = eth->h_source[0];
    buffer->event.data[7] = eth->h_source[1];
    buffer->event.data[8] = eth->h_source[2];
    buffer->event.data[9] = eth->h_source[3];
    buffer->event.data[10] = eth->h_source[4];
    buffer->event.data[11] = eth->h_source[5];
    
    buffer->event.data[12] = (__u8)(eth_proto >> 8);
    buffer->event.data[13] = (__u8)(eth_proto & 0xFF);
    
    // 尝试复制更多数据 - 从以太网头部之后开始
    if (data + ETH_HDR_SIZE < data_end) {
        // 复制第15个字节
        if (data + ETH_HDR_SIZE + 1 <= data_end)
            buffer->event.data[14] = *(__u8 *)(data + ETH_HDR_SIZE);
            
        // 复制第16个字节
        if (data + ETH_HDR_SIZE + 2 <= data_end)
            buffer->event.data[15] = *(__u8 *)(data + ETH_HDR_SIZE + 1);
            
        // 复制第17-20个字节
        if (data + ETH_HDR_SIZE + 6 <= data_end) {
            buffer->event.data[16] = *(__u8 *)(data + ETH_HDR_SIZE + 2);
            buffer->event.data[17] = *(__u8 *)(data + ETH_HDR_SIZE + 3);
            buffer->event.data[18] = *(__u8 *)(data + ETH_HDR_SIZE + 4);
            buffer->event.data[19] = *(__u8 *)(data + ETH_HDR_SIZE + 5);
        }
        
        // 继续复制更多数据...
        // 这里使用静态展开而不是循环，以确保通过验证器
        // 复制IPv4头部的关键字段(协议、源IP、目标IP)
        if (eth_proto == 0x0800) {
            // 协议字段(第10个字节)
            if (data + ETH_HDR_SIZE + 10 <= data_end) {
                buffer->event.data[ETH_HDR_SIZE + 9] = *(__u8 *)(data + ETH_HDR_SIZE + 9);
            }
            
            // 源IP地址(第13-16个字节)
            if (data + ETH_HDR_SIZE + 16 <= data_end) {
                buffer->event.data[ETH_HDR_SIZE + 12] = *(__u8 *)(data + ETH_HDR_SIZE + 12);
                buffer->event.data[ETH_HDR_SIZE + 13] = *(__u8 *)(data + ETH_HDR_SIZE + 13);
                buffer->event.data[ETH_HDR_SIZE + 14] = *(__u8 *)(data + ETH_HDR_SIZE + 14);
                buffer->event.data[ETH_HDR_SIZE + 15] = *(__u8 *)(data + ETH_HDR_SIZE + 15);
            }
            
            // 目标IP地址(第17-20个字节)
            if (data + ETH_HDR_SIZE + 20 <= data_end) {
                buffer->event.data[ETH_HDR_SIZE + 16] = *(__u8 *)(data + ETH_HDR_SIZE + 16);
                buffer->event.data[ETH_HDR_SIZE + 17] = *(__u8 *)(data + ETH_HDR_SIZE + 17);
                buffer->event.data[ETH_HDR_SIZE + 18] = *(__u8 *)(data + ETH_HDR_SIZE + 18);
                buffer->event.data[ETH_HDR_SIZE + 19] = *(__u8 *)(data + ETH_HDR_SIZE + 19);
            }
            
            // 继续复制更多数据，如果是TCP或UDP协议
            if (data + ETH_HDR_SIZE + 10 <= data_end) {
                __u8 ip_proto = *(__u8 *)(data + ETH_HDR_SIZE + 9);
                if (ip_proto == 6 || ip_proto == 17) {  // TCP或UDP
                    // 复制端口号
                    if (data + ETH_HDR_SIZE + 24 <= data_end) {
                        buffer->event.data[ETH_HDR_SIZE + 20] = *(__u8 *)(data + ETH_HDR_SIZE + 20);
                        buffer->event.data[ETH_HDR_SIZE + 21] = *(__u8 *)(data + ETH_HDR_SIZE + 21);
                        buffer->event.data[ETH_HDR_SIZE + 22] = *(__u8 *)(data + ETH_HDR_SIZE + 22);
                        buffer->event.data[ETH_HDR_SIZE + 23] = *(__u8 *)(data + ETH_HDR_SIZE + 23);
                    }
                }
            }
        }
    }
    
    __u32 data_size = capture_size;
    if (data_size > MAX_CAPTURE)
        data_size = MAX_CAPTURE;  // 确保不超过最大值

    // 保存实际捕获的大小
    buffer->event.capture_size = data_size;
    
    // 计算要通过perf发送的总大小
    // 包括时间戳(8字节)、包大小(4字节)、捕获大小(4字节)和实际数据
    __u32 event_size = sizeof(__u64) + sizeof(__u32) + sizeof(__u32) + data_size;
    
    // 发送整个事件结构到perf缓冲区
    // 注意：我们只发送结构体的前部分(时间戳+大小+数据)，不发送整个MAX_CAPTURE
    bpf_perf_event_output(ctx, &events, 
                         BPF_F_CURRENT_CPU | ((__u64)event_size << 32), 
                         &buffer->event, event_size);

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
