// SPDX-License-Identifier: GPL-2.0
// 拒绝案例 5b: 无界循环 —— infinite loop detected
//
// 没有退出条件的循环，verifier 无法证明有限步终止。
// 注意死循环即使到了 6.18 内核依然被拒：bounded loop 的前提是
// 「界」能被证明。clang 不会替你消除 for(;;)。
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u64);
} target_map SEC(".maps");

SEC("tracepoint/syscalls/sys_enter_openat")
int unbounded_loop(void *ctx)
{
	__u64 sum = 0;
	__u32 key = 0;

	for (;;)
		sum++;		/* 永不退出：verifier 拒绝，否则会卡死一个 CPU */

	bpf_map_update_elem(&target_map, &key, &sum, BPF_ANY);
	return 0;
}

char LICENSE[] SEC("license") = "GPL";
