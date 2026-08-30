// SPDX-License-Identifier: GPL-2.0
// 拒绝案例 1: 读取未初始化的栈内存（原书 §6.1 经典案例）
//
// 把一个从未赋值的栈变量当作 map value 写入：
// verifier 必须能证明「写进 map 的每个字节都有确定值」，
// 否则内核态可能把内核栈上的陈旧数据（可能含敏感信息）泄漏给用户态。
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u64);
} target_map SEC(".maps");

SEC("tracepoint/syscalls/sys_enter_openat")
int uninit_stack(void *ctx)
{
	__u32 key = 0;
	__u64 val;	/* 从未初始化 */

	bpf_map_update_elem(&target_map, &key, &val, BPF_ANY);
	return 0;
}

char LICENSE[] SEC("license") = "GPL";
