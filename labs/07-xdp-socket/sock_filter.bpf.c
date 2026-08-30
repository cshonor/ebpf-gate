// SPDX-License-Identifier: GPL-2.0
// Lab 07b: socket filter —— BPF 的老祖宗（对应原书 Ch10 socket filter）
//
// SO_ATTACH_BPF 把 eBPF 程序挂在 raw socket 上，
// 返回值 = 交给这个 socket 的字节数（0 = 包被过滤掉）。
// 这就是 tcpdump/libpcap 过滤表达式的引擎底层（1992 年的 BSD BPF）。
//
// 策略：只统计/放行 IPv4 包（protocol 字段判断），其余返回 0 丢弃。
//
// ⚠️【真机发现 2026-08-30】本内核（6.18.34+rpt-rpi）的 SOCKET_FILTER
// 程序不能直接解引用 data/data_end 指针（invalid bpf_context access
// off=76/80）——比 XDP 的限制严。改用 __sk_buff 的 protocol 字段过滤，
// 这也是更接近 tcpdump 实战的做法。

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
	__u32 key = 0;
	__u64 *cnt;

	cnt = bpf_map_lookup_elem(&stats, &key);
	if (cnt)
		cnt[0] += 1;

	/* __sk_buff->protocol：packet socket 上就是 ethertype */
	if (skb->protocol == bpf_htons(ETH_P_IP)) {
		if (cnt)
			cnt[1] += 1;
		/* 返回包长 = 全部交给用户态 */
		return skb->len;
	}
	return 0;	/* 非 IPv4：这个 socket 静默不收 */
}

char LICENSE[] SEC("license") = "GPL";
