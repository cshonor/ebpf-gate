// SPDX-License-Identifier: GPL-2.0
// Lab 07b: socket filter —— BPF 的老祖宗（对应原书 Ch10 socket filter）
//
// SO_ATTACH_BPF 把 eBPF 程序挂在 raw socket 上，
// 返回值 = 交给这个 socket 的字节数（0 = 包被过滤掉）。
// 这就是 tcpdump/libpcap 过滤表达式的引擎底层（1992 年的 BSD BPF）。
//
// 策略：只统计 IPv4 包（ethertype == 0x0800），其余直接返回 0 丢弃。

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(key_size, sizeof(__u32));
	__uint(value_size, sizeof(__u64) * 2);	/* [0]seen [1]passed */
	__uint(max_entries, 1);
} stats SEC(".maps");

SEC("socket")
int filter_ipv4(struct __sk_buff *skb)
{
	void *data = (void *)(long)skb->data;
	void *data_end = (void *)(long)skb->data_end;
	__u64 *cnt;
	__u32 key = 0;

	cnt = bpf_map_lookup_elem(&stats, &key);
	if (cnt)
		cnt[0] += 1;

	struct ethhdr *eth = data;
	if ((void *)(eth + 1) > data_end)
		return 0;

	if (eth->h_proto != bpf_htons(ETH_P_IP))
		return 0;	/* 非 IPv4：这个 socket 不收 */

	if (cnt)
		cnt[1] += 1;
	/* 返回包长 = 全部交给用户态；0 = 静默丢弃 */
	return data_end - data;
}

char LICENSE[] SEC("license") = "GPL";
