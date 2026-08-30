// SPDX-License-Identifier: GPL-2.0
// 拒绝案例 3: 不可达指令（unreachable instruction）
//
// verifier 从第一条指令开始做有向图遍历，exit 之后还有字节码
// 就意味着「有人绕过了前端校验」，一律拒绝。
//
// ⚠️ C 语言里写在 return 之后的死代码根本没用——clang 前端在
// codegen 阶段就直接丢弃 unreachable 基本块（-O0 也一样，
// 这也是本 lab 的一手发现）。要真正制造不可达指令，
// 唯一的办法是内联汇编注入：asm 块中间放一个 exit，
// 后面的指令对 verifier 就是 unreachable。
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u64);
} target_map SEC(".maps");

SEC("tracepoint/syscalls/sys_enter_openat")
int unreachable(void *ctx)
{
	__u32 key = 0;
	__u64 val = 42;

	bpf_map_update_elem(&target_map, &key, &val, BPF_ANY);

	/* asm 块：exit 之后还有 r0=1; exit —— 不可达指令 */
	asm volatile(
		"r0 = 0\n\t"
		"exit\n\t"
		"r0 = 1\n\t"	/* verifier: unreachable instruction */
		"exit\n\t"
	);
	return 0;
}

char LICENSE[] SEC("license") = "GPL";
