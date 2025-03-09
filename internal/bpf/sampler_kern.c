// go:build ignore
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
#define MAX_CAPTURE 66     // 最大捕获64字节
#define LENGTH_FIELD_SIZE 2  // 帧长度占用的字节数
#define MAX_FRAME_LENGTH 0xFFFF // 两个字节能表示的最大长度 (65535)

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

    // 计算以太网帧长度
    __u32 frame_length = data_end - data;

    // 防止长度溢出两个字节的存储空间
    __u16 stored_length;
    if (frame_length > MAX_FRAME_LENGTH) {
        stored_length = MAX_FRAME_LENGTH; // 如果超过65535，就只存储最大值
    } else {
        stored_length = (__u16)frame_length;
    }

    // 在buffer的前两个字节中存入帧长度（大端序）
    buffer->data[0] = (stored_length >> 8) & 0xFF;  // 高字节
    buffer->data[1] = stored_length & 0xFF;         // 低字节

    // 计算可以捕获的字节数（需要减去已经用于存储长度的字节数）
    __u32 available_bytes = data_end - data;
    __u32 capture_size = available_bytes;
    if (capture_size > MAX_CAPTURE - LENGTH_FIELD_SIZE)
        capture_size = MAX_CAPTURE - LENGTH_FIELD_SIZE;

    // 使用bpf_probe_read安全复制内存到buffer的第3个字节开始的位置
    // 这个函数能确保即使数据指针有问题，也不会导致内核崩溃
    long ret = bpf_probe_read_kernel(buffer->data + LENGTH_FIELD_SIZE, capture_size, data);
    if (ret < 0) {
        return XDP_PASS;  // 读取失败就继续传递数据包
    }

    // 发送数据包内容，总大小为实际捕获的数据加上长度字段的大小
    bpf_perf_event_output(ctx, &events,
                          BPF_F_CURRENT_CPU,
                          buffer->data,
                          capture_size + LENGTH_FIELD_SIZE);

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";