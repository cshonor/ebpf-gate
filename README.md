# ebpf-gate

eBPF 学习仓库 —— 从内核层面理解并使用 eBPF（HFT / 嵌入式方向）。

## 定位：本仓库是"动手"，读书笔记在 hft 仓库

本仓库只放**实验代码与一手结论**；理论精读笔记在 [hft-embedded-linux-study](https://github.com/cshonor/hft-embedded-linux-study) 的 `06.7-bpf-observability/` 模块：

| 理论（hft 仓库，读书笔记） | 实践（本仓库，动手实验） |
|---|---|
| [learning-ebpf/](https://github.com/cshonor/hft-embedded-linux-study/tree/main/06.7-bpf-observability/learning-ebpf)（Liz Rice，11 章精读） | labs/——随进度逐一做，实验结论回灌笔记对应章节 |
| [bpf-performance-tools/](https://github.com/cshonor/hft-embedded-linux-study/tree/main/06.7-bpf-observability/bpf-performance-tools)（Brendan Gregg） | 阶段 05 延迟观测的参考方法论 |

工作流：**读书 → 本仓库做 lab → 踩坑 → 把一手结论回灌笔记**（首批已于 2026-08 回灌 Ch2/Ch3/Ch5/Ch6）。

## 学习路线

| 阶段 | 内容 | 状态 | 对应书章 |
|---|---|---|---|
| 01 | bpftrace 快速体感 | ✅ | Learning eBPF Ch1–2 入门 |
| 02 | libbpf：手写第一个 BPF 程序（tracepoint，无 CO-RE 绕行方案） | ✅ | Ch3 + Ch6（verifier 实录）+ Ch5 §3.5（无 BTF 绕行） |
| 03 | map / ringbuf 数据通道 → 《Learning eBPF》随书代码实验 | 🟡 | lab03 ✅（map+ringbuf，Ch2 §2–3）；bpf syscall / CO-RE 待做 |
| 04 | kprobe / XDP / tc 挂钩点实战 | ⬜ | Ch7 附加类型 + Ch8 网络 |
| 05 | 延迟观测（sched、off-cpu、网络栈追踪） | ⬜ | Gregg 工具谱系 → HFT 落地 |

## 环境

- 实机：树莓派 5（aarch64，内核 6.18.34+rpt-rpi-2712，Debian 13 trixie）
- 工具链：bpftrace 0.23.2 / clang 19.1.7 / bpftool 7.7.0 / libbpf 1.5
- ⚠️ rpi 内核未开 BTF：CO-RE（vmlinux.h）不可用，实验用 tracefs format 手工法绕行

## 目录规划

```
notes/       # 实验记录（一手结论/踩坑实录；理论精读在 hft 仓库，不放这）
labs/        # 实验代码（libbpf / bpftrace 脚本），每个 lab 的 README 链接对应书章笔记
tools/       # 自研小工具
```
