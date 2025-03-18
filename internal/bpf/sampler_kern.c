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
#define MAX_CAPTURE 66     // 最大捕获64字节
#define LENGTH_FIELD_SIZE 2  // 帧长度占用的字节数
#define MAX_FRAME_LENGTH 0xFFFF // 两个字节能表示的最大长度 (65535)

// 采样率相关常量
#define SAMPLING_RATE 10   // 采样比例1:10，即采样约10%的包

// 定义数据结构
struct packet_data {
    __u8 data[MAX_CAPTURE];
};

// 定义ring buffer
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1024 * 1024); // 1MB ring buffer
} rb SEC(".maps");

// 定义用于采样决策的MAP
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u32));
    __uint(max_entries, 1);
} sampling_map SEC(".maps");

static __always_inline __u32 hash_packet(void *data, __u32 length)
{
    // 简单的哈希函数，用于决定是否采样
    __u32 hash = 0;
    unsigned char *p = (unsigned char *)data;
    __u32 bytes_to_hash = length > 20 ? 20 : length; // 最多使用前20字节计算哈希

    for (int i = 0; i < bytes_to_hash; i++) {
        // 修正指针比较，避免不同类型指针比较
        if (i >= length)
            break;
        hash = hash * 31 + p[i];
    }

    return hash;
}

SEC("xdp")
int sampler(struct xdp_md *ctx)
{
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    // 确保至少有可处理的数据
    if (data >= data_end)
        return XDP_PASS;

    // 计算以太网帧长度
    __u32 frame_length = data_end - data;

    // 采样决策 - 根据数据包哈希值决定是否采样
    __u32 hash_value = hash_packet(data, frame_length);
    if (hash_value % SAMPLING_RATE != 0) {
        // 不符合采样条件，直接通过数据包
        return XDP_PASS;
    }

    // 防止长度溢出两个字节的存储空间
    __u16 stored_length;
    if (frame_length > MAX_FRAME_LENGTH) {
        stored_length = MAX_FRAME_LENGTH; // 如果超过65535，就只存储最大值
    } else {
        stored_length = (__u16)frame_length;
    }

    // 计算可以捕获的字节数
    __u32 available_bytes = data_end - data;
    __u32 capture_size = available_bytes;
    if (capture_size > MAX_CAPTURE - LENGTH_FIELD_SIZE)
        capture_size = MAX_CAPTURE - LENGTH_FIELD_SIZE;

    // 分配空间，ringbuf不需要预先分配缓冲区
    struct packet_data *packet;
    packet = bpf_ringbuf_reserve(&rb, sizeof(struct packet_data), 0);
    if (!packet)
        return XDP_PASS;

    // 在packet的前两个字节中存入帧长度（大端序）
    packet->data[0] = (stored_length >> 8) & 0xFF;  // 高字节
    packet->data[1] = stored_length & 0xFF;         // 低字节

    // 使用bpf_probe_read安全复制内存到packet的第3个字节开始的位置
    long ret = bpf_probe_read_kernel(packet->data + LENGTH_FIELD_SIZE, capture_size, data);
    if (ret < 0) {
        bpf_ringbuf_discard(packet, 0);
        return XDP_PASS;  // 读取失败就继续传递数据包
    }

    // 提交数据到ring buffer
    bpf_ringbuf_submit(packet, 0);

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";