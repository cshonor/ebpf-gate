# Lab 03 — BPF Map + Ring Buffer：结构化数据通道

> 告别 `bpf_trace_printk`（lab02 的调试手段，全局共享一个 trace_pipe、抢输出、只能看不能处理）。
> 这个实验在**同一个钩子**（sys_enter_openat）上同时演示两种数据通道：
> **map 拉模式**（用户态来取）和 **ring buffer 推模式**（内核来送）。
>
> **理论对照**（hft 仓库读书笔记）：
> [Ch2 §2 BPF Maps](https://github.com/cshonor/hft-embedded-linux-study/blob/main/06.7-bpf-observability/01-learning-ebpf/chapter-02-hello-world/notes/2.1_HelloWorld与数据通道.md) 与
> [Ch2 §3 Perf/RingBuffer](https://github.com/cshonor/hft-embedded-linux-study/blob/main/06.7-bpf-observability/01-learning-ebpf/chapter-02-hello-world/notes/2.1_HelloWorld与数据通道.md)
> 已合并到同一文件 `2.1_HelloWorld与数据通道.md`。

## 代码结构

| 文件 | 角色 |
|---|---|
| `hello.bpf.c` | BPF 侧：一个 tracepoint 程序 + 两张 map（HASH 计数 / RINGBUF 事件） |
| `loader.c` | 用户侧：attach → ringbuf 事件回调实时打印 → Ctrl+C 后整表 dump 计数 |
| `Makefile` | 与 lab02 同款（aarch64 include 路径，无 CO-RE） |

## 编译运行

```bash
make
sudo ./loader        # Ctrl+C 结束；结束时自动 dump HASH map 计数
```

## 这个实验要看的四件事

1. **map 的 BTF 定义式语法不需要内核 BTF**。`SEC(".maps")` + `__uint/__type`
   描述的 BTF 来自 ELF 文件本身（clang `-g` 生成、libbpf 解析），与内核的
   `CONFIG_DEBUG_INFO_BTF` 无关——后者只有 CO-RE 重定位才需要。
   这是"无 BTF 内核"上仍然现代写 map 的正解。
2. **拉 vs 推**：`dump_counts()` 手写 get_next_key/lookup 循环体会 map 的
   "用户态轮询"本质；`ring_buffer__poll()` 是 epoll 包装的事件驱动。
   无事件时推模式零开销——HFT 观测面要的就是这个性质。
3. **原子性**：`__sync_fetch_and_add(count, 1)` 让多核并发累加不丢增量；
   若去掉，verifier 照样放行，但计数会在竞态下变少（正确性靠自己）。
   讲究极致时换 per-CPU map（免原子操作，HFT 关联节展开过）。
4. **ringbuf 满了不阻塞**：`bpf_ringbuf_reserve` 失败直接丢事件返回。
   内核路径上永远不能等用户态——这是与生俱来的背压模型。

## 实测输出（树莓派 5 · 6.18 内核 · 2026-08-30）

```
=== 实时事件流（RINGBUF 推模式），Ctrl+C 结束 ===
PID     COMM             FILENAME
1       systemd          /proc/self/fdinfo/51
1       systemd          /proc/392/cgroup
1       systemd          /proc/383/cgroup
...
=== open 次数统计（HASH map 拉模式 dump）===
PID     COUNT
1       6
```

两条通道交叉验证：事件流条数 = map 计数，数据一致。
（顺带看到：桌面闲置时最大的 openat 噪声源是 systemd 周期性轮询
`/proc/self/fdinfo` 与各 cgroup——HFT 上做观测前先想清楚噪声底。）

## 坑点（实测实录）

1. **`sudo git pull` 会让新目录变 root 属主** → 之后 `make` 报
   `Permission denied` 写不了 `hello.bpf.o`。修法：`sudo chown -R wzp:wzp ~/ebpf-gate`。
   教训：仓库操作别带 sudo，只有运行 loader 才需要。
2. loader 忘 include `<errno.h>` → `-EINTR` 未声明（C 的老朋友）。
3. **BTF 式 map 定义在无 BTF 内核上照常工作**——不是坑，是反直觉的
   重要事实：map 定义用的 BTF 在 ELF 里（clang `-g` 生成），libbpf 从
   对象文件解析；内核的 `CONFIG_DEBUG_INFO_BTF` 只有 CO-RE 才需要。
