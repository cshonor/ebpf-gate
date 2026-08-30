// SPDX-License-Identifier: GPL-2.0
// 案例 1: 读取未初始化的栈内存（原书 §6.1 经典案例）
//
// 【真机结论 2026-08-30】这个案例在内核 6.18 + sudo 加载下是 ACCEPTED！
// 根因是内核 commit 6715df8d5d24 "bpf: Allow reads from uninit stack"
// (Eduard Zingerman, 2024)：加载者持有 CAP_PERFMON/CAP_SYS_ADMIN 时
// env->allow_uninit_stack=1，未初始化栈读被放行（当作全范围任意值参与
// 验证，换来 30-70% 的状态比较提速）；非特权模式下依旧拒绝——
// 但本内核 unprivileged BPF 又被禁用，所以根本没法走非特权路径复刻。
// 书上（2023 年出版）的拒绝日志在新内核特权模式下已经不可复现。
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u64);
} target_map SEC(".maps");

SEC("tracepoint/syscalls/sys_enter_openat")
int uninit_stack(void *ctx)
{
	__u32 key = 0;
	__u64 val;	/* 从未初始化 */

	/* 真正「读」未初始化值参与运算（-O0 下必然生成栈 load）
	 * —— 而不是只把它的地址传给 helper。
	 * 注：只传地址的形态（&val 做 helper 参数）在 6.18 上居然被放行
	 * （现代 verifier 对此类 uninit 槽位的处理已演化），这也是一手发现。*/
	__u64 x = val + 1;
	bpf_map_update_elem(&target_map, &key, &x, BPF_ANY);
	return 0;
}

char LICENSE[] SEC("license") = "GPL";
