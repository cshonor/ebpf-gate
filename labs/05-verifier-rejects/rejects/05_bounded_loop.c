// SPDX-License-Identifier: GPL-2.0
// 对照案例 5a: 有界循环 —— 应当「通过」验证
//
// 内核 5.3 起 verifier 支持 bounded loop：只要能静态证明循环
// 会在有限步内退出（循环变量在 verifier 状态里被追踪）。
// 6.18 内核上这里应该看到它通过 —— 与下一个案例形成对照。
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u64);
} target_map SEC(".maps");

SEC("tracepoint/syscalls/sys_enter_openat")
int bounded_loop(void *ctx)
{
	__u64 sum = 0;
	__u32 key = 0;

	for (__u32 i = 0; i < 10; i++)
		sum += i;	/* 有界循环：verifier 追踪 i 的范围 0..9 */

	bpf_map_update_elem(&target_map, &key, &sum, BPF_ANY);
	return 0;
}

char LICENSE[] SEC("license") = "GPL";
