# ebpf-gate

eBPF 学习仓库 —— 从内核层面理解并使用 eBPF（HFT / 嵌入式方向）。

## 学习路线

| 阶段 | 内容 | 状态 |
|---|---|---|
| 01 | bpftrace 快速体感 | ⬜ |
| 02 | libbpf + CO-RE：手写第一个 BPF 程序 | ⬜ |
| 03 | 《Learning eBPF》随书代码实验 | ⬜ |
| 04 | kprobe / tracepoint / XDP / tc 挂钩点实战 | ⬜ |
| 05 | 延迟观测（sched、off-cpu、网络栈追踪） | ⬜ |

## 环境

- Linux 内核 >= 5.15（WSL2 需自定义内核开启 `CONFIG_DEBUG_INFO_BTF`）
- 工具链：clang/LLVM、libbpf-dev、bpftool

## 目录规划

```
notes/       # 学习笔记（按章节）
labs/        # 实验代码（libbpf / bpftrace 脚本）
tools/       # 自研小工具
```
