// SPDX-License-Identifier: GPL-2.0
// 拒绝案例 2: map 查找结果未判 NULL 就解引用（原书 §6.3 invalid memory access）
//
// bpf_map_lookup_elem() 返回的指针类型在 verifier 眼里是
// PTR_TO_MAP_VALUE_OR_NULL —— 只有走过 NULL 检查之后才能访问。
//
// ⚠️ 必须用 HASH map：若用 ARRAY map + 常量 key（如本例 key=0），
// verifier 能静态推断 slot 必存在 → lookup 返回值直接标为非 NULL，
// 不写 NULL 检查也能通过！这是本 lab 的一手发现（2026-08-30 真机验证）。
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

struct {
	__uint(type, BPF_MAP_TYPE_HASH);	/* HASH: key 可能 miss */
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u64);
} target_map SEC(".maps");

SEC("tracepoint/syscalls/sys_enter_openat")
int null_deref(void *ctx)
{
	__u32 key = 0;
	__u64 *p = bpf_map_lookup_elem(&target_map, &key);

	*p += 1;	/* 未检查 NULL —— hash 不存在 key 时内核态空指针 */
	return 0;
}

char LICENSE[] SEC("license") = "GPL";
