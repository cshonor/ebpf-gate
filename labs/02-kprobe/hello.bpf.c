// SPDX-License-Identifier: GPL-2.0
/* lab02: 无 CO-RE 的最小 libbpf tracepoint 程序
 *
 * 环境: 树莓派 5 / Debian 13 / 内核 6.18 (rpi 内核未开 BTF, 没有 vmlinux.h 可用)
 * 做法: 手工按 tracefs 的 format 文件定义上下文结构 —— 这正是 CO-RE 本该替我们做的事
 */
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

/* 来源: /sys/kernel/tracing/events/syscalls/sys_enter_openat/format (aarch64)
 *
 *   offset 0  : u16 common_type / u8 common_flags / u8 common_preempt_count
 *   offset 4  : s32 common_pid
 *   offset 8  : s32 __syscall_nr + 4 字节对齐填充
 *   offset 16 : u64 dfd
 *   offset 24 : const char *filename   <== 我们要的字段
 *   offset 32 : u64 flags
 *   offset 40 : u64 mode
 */
struct sys_enter_openat_ctx {
	/* --- common 头: 所有 tracepoint 共有的 8 字节 --- */
	unsigned short common_type;
	unsigned char  common_flags;
	unsigned char  common_preempt_count;
	int            common_pid;
	/* --- syscall 专属 --- */
	int            __syscall_nr;
	int            __pad0;          /* offset 12, 对齐填充 */
	unsigned long long dfd;          /* offset 16 */
	const char    *filename;         /* offset 24 */
	unsigned long long flags;        /* offset 32 */
	unsigned long long mode;        /* offset 40 */
};

char LICENSE[] SEC("license") = "GPL";

SEC("tracepoint/syscalls/sys_enter_openat")
int trace_openat(struct sys_enter_openat_ctx *ctx)
{
	char fname[64] = {};

	/* filename 是用户态指针!
	 * 内核里直接解引用用户地址会崩, 必须用 helper 安全拷贝
	 * (verifier 会在加载时强制检查这一点) */
	bpf_probe_read_user_str(fname, sizeof(fname), ctx->filename);

	char fmt[] = "openat(pid=%d): %s\n";
	bpf_trace_printk(fmt, sizeof(fmt), ctx->common_pid, fname);
	return 0;
}
