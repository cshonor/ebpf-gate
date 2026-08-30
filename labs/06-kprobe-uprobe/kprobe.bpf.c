// SPDX-License-Identifier: GPL-2.0
// Lab 06a: kprobe —— 在任意内核函数入口设断（对应原书 Ch7/Ch8）
//
// 与 lab02/03 的 tracepoint 对比：
//   tracepoint: 内核提供的稳定 ABI，格式写在 TraceFS，字段保证兼容
//   kprobe:     动态打断任意导出符号，拿到的是 struct pt_regs
//               —— 参数只能靠 PT_REGS_PARMx 宏从寄存器里抠
//
// 无 BTF 绕行说明：PT_REGS_PARMx 只是 libc 头文件里的偏移宏
// （bpf/bpf_tracing.h 按 __TARGET_ARCH_arm64 展开），不需要 vmlinux.h。

#include <linux/bpf.h>
#include <asm/ptrace.h>		/* struct user_pt_regs: arm64 用户态头文件 */
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

struct event {
	__u32 pid;
	char comm[16];
	char fname[64];
};

/* 计数表：dump 时对比 tracepoint 版（lab03）的数字是否一致。
 * key=pid 的 hash；注意 uprobe 高频钩子不要用 ringbuf，kprobe 频率
 * 相对可控所以双通道并存。 */

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 4096);
} events SEC(".maps");

/* 计数表：dump 时对比 tracepoint 版（lab03）的数字是否一致 */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, __u32);
	__type(value, __u64);
	__uint(max_entries, 1024);
} kprobe_counts SEC(".maps");

/* 真机符号勘察（6.18.34+rpt-rpi，bpftrace 验证）：
 *   openat 系统调用 → do_sys_openat2（实测 ls 触发 160 次）
 *   do_sys_open     → 只有老式 open syscall 才走（实测 0 次）
 *
 * ⚠️ 关键一手发现：6.18 的 do_sys_openat2 签名和旧版书里不同——
 *   实测（bpftrace str(uptr(arg1)) 直接读出路径）PARM2 就是
 *   const char __user *filename（用户态指针），
 *   不是 struct filename*（那是更内层的 do_filp_open 时代产物）。
 *   所以这里和 tracepoint 一样：一次 probe_read_user_str 即可。
 *   kprobe 勘察的方法论：先 bpftrace 探参数语义，再写 C。 */
SEC("kprobe/do_sys_openat2")
int kp_openat(struct user_pt_regs *ctx)
{
	/* PARM2 = filename（用户态指针，bpftrace 实测验证） */
	const char *filename = (const char *)PT_REGS_PARM2(ctx);
	struct event *e;
	__u32 pid = bpf_get_current_pid_tgid() >> 32;
	__u64 one = 1, *count;

	count = bpf_map_lookup_elem(&kprobe_counts, &pid);
	if (count)
		__sync_fetch_and_add(count, 1);
	else
		bpf_map_update_elem(&kprobe_counts, &pid, &one, BPF_ANY);

	e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e)
		return 0;
	e->pid = pid;
	bpf_get_current_comm(e->comm, sizeof(e->comm));
	/* 用户态指针必须经 helper 安全拷贝（同 lab02/03 的 tracepoint） */
	bpf_probe_read_user_str(e->fname, sizeof(e->fname), filename);
	bpf_ringbuf_submit(e, 0);
	return 0;
}

char LICENSE[] SEC("license") = "GPL";
