// SPDX-License-Identifier: GPL-2.0
// 拒绝案例 4: 访问上下文指针的非法偏移（invalid bpf_context access）
//
// lab02 踩过 off=4（tracepoint ctx 的 common_pid 属于禁读区）；
// 这里更进一步：访问一个完全超出上下文结构体范围的大偏移。
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u64);
} target_map SEC(".maps");

SEC("tracepoint/syscalls/sys_enter_openat")
int bad_ctx_offset(struct pt_regs *ctx)
{
	/* ctx 指向 tracepoint 上下文（~48 字节），偏移 9999 远超范围 */
	__u64 val = *(__u64 *)((char *)ctx + 9999);
	__u32 key = 0;

	bpf_map_update_elem(&target_map, &key, &val, BPF_ANY);
	return 0;
}

char LICENSE[] SEC("license") = "GPL";
