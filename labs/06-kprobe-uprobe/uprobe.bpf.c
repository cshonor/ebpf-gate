// SPDX-License-Identifier: GPL-2.0
// Lab 06b: uprobe —— 在用户态函数入口设断（对应原书 Ch8）
//
// 挂 libc 的 malloc：每次库函数调用都会触发，参数 PARM1 = 请求大小。
// uprobe 的妙处：不需要目标程序任何配合（无源码/无重编译），
// 内核通过替换指令断点（arm64 上是 BRK）在调度进函数时切回 eBPF。
//
// 注意 malloc 调用频率极高，ringbuf 会被打爆 —— 这里故意用 HASH
// 按 size 分桶计数，体会「高频钩子选 map 而非事件流」的取舍。

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, __u64);		/* malloc 请求字节数 */
	__type(value, __u64);		/* 调用次数 */
	__uint(max_entries, 4096);
} malloc_by_size SEC(".maps");

SEC("uprobe")
int up_malloc(struct pt_regs *ctx)
{
	__u64 size = PT_REGS_PARM1(ctx);
	__u64 one = 1, *count;

	count = bpf_map_lookup_elem(&malloc_by_size, &size);
	if (count)
		__sync_fetch_and_add(count, 1);
	else
		bpf_map_update_elem(&malloc_by_size, &size, &one, BPF_ANY);
	return 0;
}

char LICENSE[] SEC("license") = "GPL";
