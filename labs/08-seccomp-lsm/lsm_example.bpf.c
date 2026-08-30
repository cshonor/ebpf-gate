// SPDX-License-Identifier: GPL-2.0
// Lab 08b: BPF LSM 示例代码（**本机不可运行**，见注释）
//
// 原书 Ch9 的安全例子：挂 LSM 钩子返回 -EPERM「拒绝」而非观察。
// 这台树莓派跑不了它的两个前提：
//   1) 启动参数 lsm=...bpf 未开启（见 lsm_probe.sh）
//   2) LSM BPF 程序强依赖 CO-RE（struct file 的定义来自 vmlinux.h），
//      而本内核没有 CONFIG_DEBUG_INFO_BTF
//
// 所以这里只保留「形态正确的代码」作为对照学习：换一台 BTF 内核 +
// lsm=bpf 的机器，这份代码原样可跑。

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

/* 正常情况这里应该 #include "vmlinux.h"（bpftool btf dump 生成） */

SEC("lsm/file_open")
int BPF_PROG(restrict_open, struct file *file, int mask)
{
	/* 拿不到 vmlinux.h 里的完整类型信息，这里只示意结构：
	 * 可以读 file->f_path.dentry->d_name 判断文件名，
	 * 返回 -EPERM 即拒绝这次 open。 */
	char name[64];
	struct dentry *dentry = BPF_CORE_READ(file, f_path.dentry);

	bpf_probe_read_kernel_str(name, sizeof(name),
				   BPF_CORE_READ(dentry, d_name.name));
	bpf_printk("LSM file_open: %s\n", name);
	return 0;	/* 0 = 放行；-EPERM = 拒绝 */
}

char LICENSE[] SEC("license") = "GPL";
