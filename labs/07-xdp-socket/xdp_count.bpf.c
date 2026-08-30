// SPDX-License-Identifier: GPL-2.0
// Lab 07a: XDP —— 在驱动收包后最早点处理数据包（对应原书 Ch10）
//
// XDP 程序返回动作码：PASS / DROP / TX / REDIRECT / ABORTED。
// 策略：UDP 目的端口 9999 的包直接 DROP（在网卡层丢弃，
// 连内核协议栈都不进入 —— 与 iptables 的栈中丢弃对比是 HFT 视角
// 最关心的一点：越早丢越省 CPU）。
//
// 挂在 lo 上用 generic(SKB) 模式演示；真网卡上 native XDP 收益更大。
// 手工解析包头：data/data_end 边界检查是 verifier 强制的，
// 每一步解引用前都要证明指针没越界。

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define XDP_DROP_PORT 9999

/* per-CPU 计数：免锁，读写各自 CPU 的槽位，dump 时求和 */
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(key_size, sizeof(__u32));
	__uint(value_size, sizeof(__u64) * 3);	/* [0]pkts [1]bytes [2]drops */
	__uint(max_entries, 1);
} stats SEC(".maps");

SEC("xdp")
int xdp_count(struct xdp_md *ctx)
{
	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;
	__u64 *cnt;
	__u32 key = 0;

	cnt = bpf_map_lookup_elem(&stats, &key);
	if (cnt) {
		cnt[0] += 1;
		cnt[1] += data_end - data;
	}

	/* --- 以太网头 --- */
	struct ethhdr *eth = data;
	if ((void *)(eth + 1) > data_end)
		return XDP_PASS;	/* 边界检查：截断包直接放行 */

	if (eth->h_proto != bpf_htons(ETH_P_IP))
		return XDP_PASS;

	/* --- IP 头 --- */
	struct iphdr *ip = (void *)(eth + 1);
	if ((void *)(ip + 1) > data_end)
		return XDP_PASS;
	if (ip->protocol != IPPROTO_UDP)
		return XDP_PASS;

	/* --- UDP 头（只看 8 字节定长部分） --- */
	struct udphdr *udp = (void *)ip + ip->ihl * 4;
	if ((void *)(udp + 1) > data_end)
		return XDP_PASS;

	if (udp->dest == bpf_htons(XDP_DROP_PORT)) {
		if (cnt)
			cnt[2] += 1;
		return XDP_DROP;	/* 网卡层丢弃，不进协议栈 */
	}
	return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
