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
| 03 | map / ringbuf 数据通道 → 《Learning eBPF》随书代码实验 | ✅ | lab03（map+ringbuf）+ lab04（bpf syscall strace 拆解，Ch4 §1–2）；CO-RE 待做 |
| 04 | kprobe / uprobe / verifier 拒绝实验 / 网络 XDP | ✅ | lab05（Ch6 拒绝实验集）+ lab06（Ch7/8 kprobe✅·uprobe 勘察）+ lab07（Ch10 XDP+socket filter）+ lab08（Ch9 seccomp✅·LSM 勘察） |
| 05 | 延迟观测（sched、off-cpu、网络栈追踪） | ⬜ | Gregg 工具谱系 → HFT 落地 |

## 《Learning eBPF》全书例子覆盖表

随书仓库 [lizrice/learning-ebpf](https://github.com/lizrice/learning-ebpf) 的例子逐个在本仓库真机复刻（树莓派 5 / aarch64 / libbpf 1.5 / 无 vmlinux BTF）：

| 书章 | 原书例子 | 本仓库实现 | 说明 |
|---|---|---|---|
| Ch2 | hello（tracepoint sys_enter_write） | lab02 | 改用 sys_enter_openat（TraceFS 手工 format 结构体绕行无 BTF） |
| Ch2 | hello_map（按 uid 计数） | lab03 | 改按 pid 计数，另加 ringbuf 事件流 |
| Ch2/Ch4 | hello_ring_buffer / hello_buffer_config | lab03 + lab04 | config+counts 双 hash，strace 拆解加载序列 |
| Ch3 | bpftrace one-liners / clang -S 汇编对比 | lab01 | `-S -emit-llvm` 汇编对比并入 lab01 README |
| Ch4 | bpf() syscall 与文件描述符 | lab04 | 50 个 bpf() 调用全景 + memfd placeholder fd 发现 |
| Ch5 | CO-RE / vmlinux.h / BTF 重定位 | 结论回灌 | 无 vmlinux BTF 内核 CO-RE 不可用，替代路线见 hft Ch5 §3.5；bpftool btf dump 实验见 lab08 |
| Ch6 | verifier 六类拒绝 | lab05 | 真机复刻故意失败的程序，抓一手拒绝日志 |
| Ch7 | program types 全景（kprobe 路线） | lab06 | kprobe `do_sys_openat` + `PT_REGS` 宏 |
| Ch8 | kprobe / uprobe / perf event 追踪 | lab06 | uprobe 挂 libc `strlen`/`malloc`，perf event 采样 |
| Ch9 | security（LSM / seccomp BPF） | lab08 | seccomp filter 真机实验 + BPF LSM 可行性检测 |
| Ch10 | networking（XDP / TC / socket filter） | lab07 | XDP 包计数 + 受控 DROP + SO_ATTACH_BPF |
| Ch11 | 未来方向 | — | 无代码，笔记见 hft Ch11 |

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
