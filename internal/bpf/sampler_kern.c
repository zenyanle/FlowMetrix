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
#define MAX_CPUS 16
#define MAX_CAPTURE 64  // 最大捕获64字节

// 定义数据缓冲区结构
struct packet_buffer {
    __u8 data[MAX_CAPTURE];
};

// 定义maps
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
    
    // 确保至少有可处理的数据
    if (data >= data_end)
        return XDP_PASS;

    // 获取数据包缓冲区
    __u32 zero = 0;
    struct packet_buffer *buffer = bpf_map_lookup_elem(&packet_data_map, &zero);
    if (!buffer)
        return XDP_PASS;
    
    // 计算可以捕获的字节数
    __u32 available_bytes = data_end - data;
    __u32 capture_size = available_bytes;
    if (capture_size > MAX_CAPTURE)
        capture_size = MAX_CAPTURE;
    
    // 使用bpf_probe_read安全复制内存
    // 这个函数能确保即使数据指针有问题，也不会导致内核崩溃
    long ret = bpf_probe_read_kernel(buffer->data, capture_size, data);
    if (ret < 0) {
        return XDP_PASS;  // 读取失败就继续传递数据包
    }
    
    // 直接发送数据包内容，使用实际捕获的大小
    bpf_perf_event_output(ctx, &events, 
                                BPF_F_CURRENT_CPU, 
                                buffer->data, capture_size);
    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";