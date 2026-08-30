// SPDX-License-Identifier: GPL-2.0
/* lab04: 最小计数程序 —— 专为 strace 拆解 bpf() syscall 序列而设计
 *
 * 对照原书 §4.2 的 hello-buffer-config.py（BCC 版）:
 *   - config hash: 用户态写开关 (对应 BPF_MAP_UPDATE_ELEM)
 *   - counts hash: 内核态计数 (dump 时对应 GET_NEXT_KEY / LOOKUP_ELEM)
 * rpi 内核无 BTF，本程序不 include 任何内核类型头，只用基本 u32/u64。
 */
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

char LICENSE[] SEC("license") = "GPL";

/* 用户态通过 BPF_MAP_UPDATE_ELEM 写 config[0] = 1 打开计数 */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 16);
	__type(key, __u32);
	__type(value, __u64);
} config SEC(".maps");

/* 内核态按 pid 计数 openat */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1024);
	__type(key, __u32);
	__type(value, __u64);
} counts SEC(".maps");

SEC("tracepoint/syscalls/sys_enter_openat")
int count_openat(void *ctx)
{
	__u32 pid = bpf_get_current_pid_tgid() >> 32;
	__u64 *cnt;

	__u32 key = 0;
	__u64 *enabled = bpf_map_lookup_elem(&config, &key);
	if (!enabled || !*enabled)
		return 0;

	cnt = bpf_map_lookup_elem(&counts, &pid);
	if (cnt) {
		__sync_fetch_and_add(cnt, 1);
	} else {
		__u64 one = 1;
		bpf_map_update_elem(&counts, &pid, &one, BPF_ANY);
	}
	return 0;
}
