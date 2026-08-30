// SPDX-License-Identifier: GPL-2.0
// 拒绝案例 3: return 之后的不可达指令（unreachable instruction）
//
// verifier 从第一条指令开始做有向图遍历，任何永远走不到的指令
// 都被视为程序错误（字节码里出现 verifier 探索不到的指令意味着
// 有人绕过了前端校验，verifier 不信任）。
//
// 注意：必须用 -O0 编译本文件——clang -O2 会把 return 之后的死代码
// 直接消除掉，程序反而能通过验证（这本身就是个有趣的对照实验）。
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
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
	return 0;

	/* 死代码：-O0 下会原样生成字节码，verifier 报 unreachable */
	bpf_map_update_elem(&target_map, &key, &val, BPF_ANY);
	return 1;
}

char LICENSE[] SEC("license") = "GPL";
