# ebpf-gate

eBPF 学习仓库 —— 从内核层面理解并使用 eBPF（HFT / 嵌入式方向）。

## 学习路线

| 阶段 | 内容 | 状态 |
|---|---|---|
| 01 | bpftrace 快速体感 | ✅ |
| 02 | libbpf：手写第一个 BPF 程序（tracepoint，无 CO-RE 绕行方案） | ✅ |
| 03 | 《Learning eBPF》随书代码实验 | ⬜ |
| 04 | kprobe / XDP / tc 挂钩点实战 | ⬜ |
| 05 | 延迟观测（sched、off-cpu、网络栈追踪） | ⬜ |

## 环境

- 实机：树莓派 5（aarch64，内核 6.18.34+rpt-rpi-2712，Debian 13 trixie）
- 工具链：bpftrace 0.23.2 / clang 19.1.7 / bpftool 7.7.0 / libbpf 1.5
- ⚠️ rpi 内核未开 BTF：CO-RE（vmlinux.h）不可用，实验用 tracefs format 手工法绕行

## 目录规划

```
notes/       # 学习笔记（按章节）
labs/        # 实验代码（libbpf / bpftrace 脚本）
tools/       # 自研小工具
```
