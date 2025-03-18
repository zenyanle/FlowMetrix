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
#define SAMPLING_RATE 10   // 采样率：每10个包采样1个

// 定义数据结构
struct packet_data {
    __u8 data[MAX_CAPTURE];
};

// 定义ring buffer
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1024 * 1024); // 1MB ring buffer
} rb SEC(".maps");

// 定义采样计数器的MAP
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u32));
    __uint(max_entries, 1);
} counter_map SEC(".maps");

SEC("xdp")
int sampler(struct xdp_md *ctx)
{
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    // 确保至少有可处理的数据
    if (data >= data_end)
        return XDP_PASS;

    // 采样决策处理
    __u32 key = 0;
    __u32 *counter = bpf_map_lookup_elem(&counter_map, &key);
    __u32 current_counter = 1; // 默认值，确保首次运行时采样

    if (counter) {
        current_counter = *counter;
    }

    // 递减计数器并更新
    if (current_counter > 1) {
        current_counter--;
        bpf_map_update_elem(&counter_map, &key, &current_counter, BPF_ANY);
        return XDP_PASS; // 不采样，直接通过
    } else {
        // 重置计数器
        current_counter = SAMPLING_RATE;
        bpf_map_update_elem(&counter_map, &key, &current_counter, BPF_ANY);
        // 继续执行后续代码，采样此数据包
    }

    // 计算以太网帧长度
    __u32 frame_length = data_end - data;

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