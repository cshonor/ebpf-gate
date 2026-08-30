# Lab 02 — 追踪 openat：第一个 C 写的 eBPF 程序

> 呼应 TLPI 第 4 章（文件 I/O）。你在用户态调 `open()`，glibc 转成 `openat` syscall，
> 这个实验就在内核入口处把它截下来。**没有 BTF 也完全能跑。**
>
> **理论对照**（hft 仓库读书笔记）：verifier 拒绝实录见
> [Learning eBPF Ch6 §3.6](https://github.com/cshonor/hft-embedded-linux-study/blob/main/06.7-bpf-observability/learning-ebpf/chapter-06-verifier/notes/section-3-六类典型验证失败.md)；
> 无 BTF 内核的绕行方案见 [Ch5 §3.5](https://github.com/cshonor/hft-embedded-linux-study/blob/main/06.7-bpf-observability/learning-ebpf/chapter-05-core-btf-libbpf/notes/section-3-BTF深入.md)。

## 文件

| 文件 | 角色 |
|---|---|
| `hello.bpf.c` | BPF 程序（编译成 `hello.bpf.o` 字节码，进内核跑） |
| `loader.c` | 用户态加载器：open ELF → load（verifier 在此跑）→ attach |
| `Makefile` | 两条编译命令：clang 交叉编译字节码 + gcc 编加载器 |

## 编译和运行

```bash
cd ~/ebpf-gate/labs/02-kprobe
make                # 产出 hello.bpf.o 和 loader
sudo ./loader       # 挂 10 秒
# 另一个终端观察：
sudo cat /sys/kernel/tracing/trace_pipe
```

预期输出（打开任何文件都会刷一行）：

```
           <...>-3821    [000] .....  1234.5678: 0: openat(pid=3821): /etc/ld.so.cache
```

## 本实验的三个核心知识点

### 1. 没有 vmlinux.h，怎么办？

`tracepoint/syscalls/sys_enter_openat` 的上下文布局不在任何标准头文件里，
常规做法是从 `vmlinux.h`（BTF 导出）拿。我们的内核没有 BTF，所以：

```bash
sudo cat /sys/kernel/tracing/events/syscalls/sys_enter_openat/format
```

按 format 文件**手工定义结构体**（`hello.bpf.c` 里有完整注释）。这一步的意义：
等你以后用上 CO-RE，你会确切知道 `vmlinux.h` 帮你省掉的是什么。

### 2. 用户态指针不能直接解引用

```c
bpf_probe_read_user_str(fname, sizeof(fname), ctx->filename);
```

`filename` 是用户进程传进来的**用户态地址**。BPF 程序跑在内核上下文，
直接 `ctx->filename[0]` 会被 verifier 拒绝（甚至加载都过不去）。
必须用 `bpf_probe_read_user_str` 安全拷贝——它内部带 `access_ok()` 检查和缺页处理。

### 3. trace_printk 是调试通道，不是产品通道

`bpf_trace_printk` 写 `/sys/kernel/tracing/trace_pipe`，全局共享、无结构化、
每次调用锁内核——学习用，生产用 map + ring buffer。

## bpftrace 对照版（一行顶我们整个 C 程序）

```bash
sudo bpftrace -e 'tracepoint:syscalls:sys_enter_openat { printf("%s %s\n", comm, str(args->filename)); }'
```

bpftrace 内部做的事和我们的 C 代码完全一样：读 format 文件 → 生成结构体 →
probe_read_user → trace_printk。**我们手写的，就是它的代码生成器。**

## 思考

1. 为什么 format 文件里 `flags` 的 size 是 8（明明 `openat` 的 flags 参数是 int）？
   （提示：aarch64 的 syscall 参数传递全部走 x0–x5 寄存器，tracepoint 按 64 位槽位记录）
2. 把 `bpf_probe_read_user_str` 换成 `bpf_probe_read_kernel_str` 还能读到文件名吗？
3. kprobe 版本：`SEC("kprobe/do_sys_openat2")` + `PT_REGS_PARM2`（需要 `bpf_tracing.h`），
   和 tracepoint 版本哪个更稳？为什么本实验选了 tracepoint？

## 遇到的坑（实录）

- rpi 内核没开 `CONFIG_DEBUG_INFO_BTF` → 用不了 `vmlinux.h`，本文的 format 手工法就是绕行方案
- `clang -target bpf` 找不到 `asm/types.h` → 编译命令要加
  `-D__TARGET_ARCH_arm64 -I/usr/include/aarch64-linux-gnu`
- **syscall tracepoint 的 ctx 只开放参数区（offset ≥ 8）**：直接读 `common_pid`（offset 4）被
  verifier 拒绝：`invalid bpf_context access off=4 size=4`。参数区（如 `filename`）可以直读。
  拿 pid 用 `bpf_get_current_pid_tgid() >> 32`
- `bpf_trace_printk` 的 `%s` 参数是**指针**，传本地数组 `fname` 没问题，但传用户指针就不行
  （所以必须先 probe_read 再打印，不能一步到位）
