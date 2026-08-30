# Lab 06 — kprobe 与 uprobe：tracepoint 之外的两种断点

> 原书 Ch7（程序类型）/ Ch8（追踪）。tracepoint 是内核明写的钩子，
> kprobe 是动态打断任意内核函数，uprobe 是打断用户态函数。
> 本 lab 在真机上跑通 kprobe 版 openat 追踪，并勘察 uprobe 的
> 真机可行性（结论：这台内核做不了，但限制本身很有信息量）。
>
> **理论对照**（hft 仓库读书笔记）：
> [Ch7 程序附加类型](https://github.com/cshonor/hft-embedded-linux-study/tree/main/06.7-bpf-observability/learning-ebpf/chapter-07-program-attachment-types) ·
> [Ch8 追踪](https://github.com/cshonor/hft-embedded-linux-study/tree/main/06.7-bpf-observability/learning-ebpf/chapter-08-tracing)

## 代码结构

| 文件 | 角色 |
|---|---|
| `kprobe.bpf.c` | kprobe 挂 `do_sys_openat2`：ringbuf 事件流 + hash 计数（与 lab03 tracepoint 版同构，方便对比数字） |
| `loader_kprobe.c` | 用户侧：attach kprobe（符号名可用 argv 覆盖）→ poll → dump |
| `uprobe.bpf.c` | uprobe 挂 libc `malloc`：按请求字节数分桶的 hash（高频钩子选 map 不选事件流） |
| `loader_uprobe.c` | 用户侧：`attach_uprobe_opts` 的 func_name 形态 + UPROBES 可用性检测 |

## 编译运行

```bash
make
sudo ./loader_kprobe            # kprobe 版 openat 追踪
sudo ./loader_uprobe             # uprobe（本内核会明确报告不支持，退出码 77）
```

## 一手结论（树莓派 5 · 6.18.34 · 2026-08-30）

### 1. kprobe vs tracepoint：同一个 openat，两种视角

| 维度 | tracepoint（lab02/03） | kprobe（本 lab） |
|---|---|---|
| 挂点 | `sys_enter_openat`（TraceFS 注册的固定 ABI） | `do_sys_openat2`（任意 kallsyms 符号） |
| ctx | 内核定义好的 format 结构（手工还原） | `struct pt_regs`（寄存器现场，`PT_REGS_PARMx` 抠参数） |
| filename 所在 | ctx->filename（offset 24，用户态指针） | PARM2（用户态指针，见发现 2） |
| 稳定性 | 内核承诺字段不变（tracepoint 就是为此发明的） | 函数签名随内核大版本变，升级即碎 |
| 头文件依赖 | 无 BTF 时手写 format 结构 | `bpf/bpf_tracing.h` + `asm/ptrace.h`（用户态头，无 BTF 可用） |

### 2. 符号勘察：openat 实际走哪条路

kallsyms + bpftrace 双重验证（`ls` 触发 160 次）：

```
$ grep -w 'do_sys_openat\|do_sys_openat2\|do_sys_open' /proc/kallsyms
0000000000000000 t do_sys_openat2     ← openat 系统调用的实际落点
0000000000000000 T do_sys_open         ← 只有老式 open syscall 才走（实测 0 次）
```

教训：**挂 kprobe 前先用 bpftrace 验证路径**，猜符号名必错。

另一个反直觉发现：6.18 的 `do_sys_openat2` 的 PARM2 直接就是
`const char __user *filename`（用 `str(uptr(arg1))` 一层就读出路径），
不是旧资料说的 `struct filename *`（那是更内层 `do_filp_open` 时代的
产物）。内核重构会改函数语义，书里的签名按"真机实测"为准。

### 3. 运行输出（节选）

```
$ sudo ./loader_kprobe
已挂 kprobe/do_sys_openat2（Ctrl+C 结束）
PID     COMM             FILENAME
30327   cat              /etc/ld.so.cache
30327   cat              /lib/aarch64-linux-gnu/libc.so.6
30327   cat              /etc/hostname
30328   ls               /etc/ld.so.cache
...
=== kprobe openat 计数（按 pid）===
PID     COUNT
30331   sleep   10
30326   seq     3
...
```

（空 FILENAME 的行是 dynamic linker 的匿名映射，正常。）

### 4. uprobe 真机限制：内核根本没编 UPROBES

```
$ cat /boot/config-6.18.34+rpt-rpi-2712 | grep UPROBE
# CONFIG_UPROBE_EVENTS is not set      ← 树莓派官方内核默认不开
```

外部表现链条：

1. `attach_uprobe` 返回 ENOENT（libbpf 日志：`failed to create uprobe ... perf event: No such file or directory`）
2. `/sys/kernel/tracing/uprobe_events` 不存在（kprobe_events 在、uprobe_events 不在）
3. kallsyms 里只剩 `bpf_uprobe_multi_*` 的符号桩（供多 uprobe attach 的 BPF API 存在，但底层 UPROBE_EVENTS 没开）

要跑原书 Ch8 的 uprobe 例子：自编内核开 `CONFIG_UPROBE_EVENTS=y`，
或换 Debian 官方 arm64 内核（顺带解决 BTF/CO-RE——见路线图的换内核选项）。

### 5. arm64 无 BTF 写 kprobe 的姿势（和 tracepoint 一致的哲学）

```c
#include <asm/ptrace.h>          /* struct user_pt_regs：用户态头文件就有 */
#include <bpf/bpf_tracing.h>    /* PT_REGS_PARMx 宏按 __TARGET_ARCH_arm64 展开 */

int kp_openat(struct user_pt_regs *ctx)   /* 声明成 user_pt_regs 即可 */
{
    const char *filename = (const char *)PT_REGS_PARM2(ctx);
    bpf_probe_read_user_str(e->fname, sizeof(e->fname), filename);
}
```

不需要 vmlinux.h——`PT_REGS_PARMx` 只是寄存器偏移宏，CO-RE 与否无关。
