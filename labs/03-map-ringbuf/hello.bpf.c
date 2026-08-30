// SPDX-License-Identifier: GPL-2.0
// Lab 03: BPF Map + Ring Buffer —— 从"调试打印"到"结构化数据通道"
//
// 仍追踪 sys_enter_openat（与 lab02 相同的钩子，方便对比）：
//   1) HASH map 按 pid 累计 open 次数        → 拉模式（用户态轮询读）
//   2) RINGBUF 每次事件推送 {pid,comm,fname} → 推模式（事件驱动回调）
//
// 关键点：map 的 BTF 定义式语法（SEC(".maps") + __uint/__type）用的是
// ELF 文件自己的 BTF（clang -g 生成，libbpf 解析），跟"内核有没有 BTF"
// 无关——所以无 CONFIG_DEBUG_INFO_BTF 的 rpi 内核照样能用。

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

/* 手工还原 syscall tracepoint 上下文（lab02 同款，无 BTF 绕行） */
struct sys_enter_openat_ctx {
	unsigned short common_type;		/* offset 0, 禁读 */
	unsigned char  common_flags;		/* offset 2, 禁读 */
	unsigned char  common_preempt_count;	/* offset 3, 禁读 */
	int            common_pid;		/* offset 4, 禁读 */
	long __syscall_nr;			/* offset 8 */
	long dfd;				/* offset 16 */
	const char *filename;			/* offset 24 */
	long flags;				/* offset 32 */
	long mode;				/* offset 40 */
};

/* 推送给用户态的事件（内核、用户两侧共用同一布局） */
struct event {
	__u32 pid;
	char comm[16];
	char fname[64];
};

/* 计数表：key=pid, value=open 累计次数 */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, __u32);
	__type(value, __u64);
	__uint(max_entries, 1024);
} open_counts SEC(".maps");

/* 事件通道：全机一个共享缓冲（对比 perf buffer 的每核一个） */
struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 4096);	/* 1 页 */
} events SEC(".maps");

SEC("tracepoint/syscalls/sys_enter_openat")
int trace_openat(struct sys_enter_openat_ctx *ctx)
{
	__u32 pid = bpf_get_current_pid_tgid() >> 32;
	__u64 one = 1, *count;

	/* --- 拉模式：HASH map 原子累加 --- */
	count = bpf_map_lookup_elem(&open_counts, &pid);
	if (count)
		__sync_fetch_and_add(count, 1);	/* 原子自增，多核并发安全 */
	else
		bpf_map_update_elem(&open_counts, &pid, &one, BPF_ANY);

	/* --- 推模式：ringbuf reserve→填充→submit --- */
	struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e)				/* 缓冲满则丢弃，不阻塞内核路径 */
		return 0;
	e->pid = pid;
	bpf_get_current_comm(e->comm, sizeof(e->comm));
	/* filename 是用户态指针，必须经 helper 安全拷贝（lab02 踩过的坑） */
	bpf_probe_read_user_str(e->fname, sizeof(e->fname), ctx->filename);
	bpf_ringbuf_submit(e, 0);
	return 0;
}

char LICENSE[] SEC("license") = "GPL";
