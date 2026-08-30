# Lab 04 — bpf() 系统调用 strace 拆解：libbpf 到底发了什么

> 原书 §4.2 用 strace 看 BCC 的 hello-buffer-config.py，得到 5 行干净的
> `bpf()` 序列。真实世界里 libbpf 一次最小加载发出 **50 个 bpf() 调用**——
> 这个实验把每一条都拆开：哪些是特性探测（失败的才是常态），哪些才是
> 真活儿。读 syscall 序列 = 读 libbpf 与内核的"能力协商协议"。
>
> **理论对照**（hft 仓库读书笔记）：
> [Ch4 §1 bpf总览与strace实例](https://github.com/cshonor/hft-embedded-linux-study/blob/main/06.7-bpf-observability/learning-ebpf/chapter-04-bpf-syscall/notes/4.1_bpf总览与strace实例.md)

## 代码结构

| 文件 | 角色 |
|---|---|
| `hello.bpf.c` | BPF 侧最小程序：config hash（用户态写开关）+ counts hash（内核态按 pid 计数），刻意对照原书 hello-buffer-config 的双 map 结构 |
| `loader.c` | 用户侧：open → load → attach → 写 config → sleep → dump，最短路径走完 bpf() 全生命周期 |
| `Makefile` | 与 lab02/03 同款；`make strace` 直接跑带过滤的 strace |

## 编译运行

```bash
make
sudo ./loader                 # 裸跑：3 秒采样 openat 计数
sudo strace -f -tt -yy -o strace_full.log ./loader   # 全量 strace（含 openat/close/dup3）
make strace                   # 只过滤 bpf/perf_event_open/ioctl 的版本
```

## 一手结论（树莓派 5 · 6.18.34 · libbpf 1.5 · 2026-08-30）

### 1. 全景：50 个 bpf() 调用，八成是"探测噪声"

```bash
$ grep -o 'bpf(BPF_[A-Z_]*' strace.log | sort | uniq -c | sort -rn
     14 BPF_MAP_GET_NEXT_KEY     ← dump 循环（13 个 key + 1 个 ENOENT 终止）
     13 BPF_MAP_LOOKUP_ELEM      ← dump 循环
     11 BPF_BTF_LOAD             ← 10 个特性探测 + 1 个真 BTF
      6 BPF_PROG_LOAD            ← 5 个探测 + 1 个真程序
      2 BPF_MAP_CREATE           ← config + counts（真活儿）
      2 BPF_LINK_CREATE          ← 1 个探测 + 1 个真挂载
      1 BPF_TOKEN_CREATE         ← 探测（EOPNOTSUPP）
      1 BPF_MAP_UPDATE_ELEM      ← config[0]=1（真活儿）
```

全部探测在 **1.6 毫秒内**跑完（26.868369 → 26.870195）。书里那 5 行是过滤后的骨架，
真实序列的"信噪比"大概是 1:9——读 strace 先学会把探测和真活儿分开。

### 2. 真活儿序列（去掉探测后的骨架）

```
bpf(BPF_BTF_LOAD, {btf_size=1120})              = 3   ← ELF 里的 BTF（map+prog 类型）
bpf(BPF_MAP_CREATE, {HASH, key 4B, value 8B,
     max_entries=16, map_name="config",
     btf_fd=3, btf_key_type_id=8, ...})         = 6 → dup3 到 fd 4
bpf(BPF_MAP_CREATE, {HASH, ..., max_entries=1024,
     map_name="counts", btf_fd=3})              = 6 → dup3 到 fd 5
bpf(BPF_PROG_LOAD, {TRACEPOINT, insn_cnt=34,
     kern_version=KERNEL_VERSION(6, 18, 34),
     prog_name="count_openat", prog_btf_fd=3,
     expected_attach_type=BPF_CGROUP_INET_INGRESS}) = 6
perf_event_open({PERF_TYPE_TRACEPOINT, config=652}) = 7   ← tracepoint id!
bpf(BPF_LINK_CREATE, {prog_fd=6, target_fd=7,
     attach_type=BPF_PERF_EVENT})               = 8
ioctl(7, PERF_EVENT_IOC_ENABLE)                 = 0
bpf(BPF_MAP_UPDATE_ELEM, {map_fd=4, ...})        = 0   ← 用户态写 config 开关
--- sleep(3) 内核侧跑 34 条指令 × 每次 openat ---
bpf(BPF_MAP_GET_NEXT_KEY, {map_fd=5, key=NULL}) = 0   ← dump：游标从 NULL 起
bpf(BPF_MAP_LOOKUP_ELEM, {map_fd=5})            = 0   ← ... 循环 ...
bpf(BPF_MAP_GET_NEXT_KEY, ...)                  = -1 ENOENT  ← 遍历终止哨兵
```

### 3. 五个书上没有/需要修正的认知

**① BPF_BTF_LOAD 在"无 BTF 内核"上照样成功。**
`/sys/kernel/btf/vmlinux` 不存在（无内核 BTF，CO-RE 不可用），但加载
**ELF 自带的 BTF blob** 给 map/prog 用是另一回事——内核只是没有"自己的类型信息"，
不代表它不能持有你喂给它的类型信息。书里说"老内核看不到这条 syscall"指的是
不支持 BTF_LOAD 的老内核（<5.0 时代），而不是没有 vmlinux BTF 的内核。
这把 Ch5 的"无 BTF 绕行"结论又收紧了一圈：**MAP_CREATE 带 btf_fd=3、
btf_key_type_id=8 全部生效**，bpftool 漂亮打印在这台机器上完全可用。

**② 挂载路径：BPF_LINK_CREATE，不是老的 ioctl(PERF_EVENT_IOC_SET_BPF)。**
现代三步走：`perf_event_open(tracepoint id) → BPF_LINK_CREATE(attach_type=BPF_PERF_EVENT) →
ioctl(PERF_EVENT_IOC_ENABLE)`。link 是有 fd 的一等对象（fd 8），生命周期独立于
perf event，销毁即卸载。libbpf 先用 `target_fd=-1` 发一个注定 EBADF 的
BPF_LINK_CREATE 探测内核支不支持这条路径。

**③ perf_event_open 的 config=652 就是 tracepoint id。**
`/sys/kernel/tracing/events/syscalls/sys_enter_openat/id` 读出来正是 652
（读这个文件也要 root）。

**④ fd 4/5 是 libbpf 预留的槽位（memfd placeholder）。**
MAP_CREATE 明明返回 6，为什么 UPDATE 用的是 map_fd=4？全量 strace 揭晓：

```
memfd_create("libbpf-placeholder-fd", MFD_CLOEXEC) = 4    ← open 阶段就占了坑
memfd_create("libbpf-placeholder-fd", MFD_CLOEXEC) = 5
bpf(BPF_MAP_CREATE config)                            = 6
dup3(6<bpf-map>, 4<placeholder>, O_CLOEXEC)           = 4  ← 真身搬进槽位
close(6)
```

libbpf 用 memfd 占住低位 fd，创建成功后 dup3 顶进去。目的：map fd 在加载
流程早期就稳定（内部 map/inner map 互相引用时不会拿到乱序 fd）。**只看
过滤后的 strace 会以为 fd 乱跳——这是读 strace 的经典陷阱。**

**⑤ expected_attach_type=BPF_CGROUP_INET_INGRESS 确实出现在 tracepoint 程序上。**
验证了书里的解释：该字段对 kprobe/tracepoint 无意义，这里只是枚举值 0 的默认占位。

### 4. 失败清单：哪些 errno 是"正常的"

| 调用 | 返回 | 含义 |
|---|---|---|
| `BPF_TOKEN_CREATE` | EOPNOTSUPP | 探测 bpffs token（委派特权）支持，6.18 rpi 内核没开 |
| `BPF_LINK_CREATE(target_fd=-1)` | EBADF | libbpf 故意的：探测 link 挂载路径存在性 |
| `BPF_MAP_GET_NEXT_KEY`(最后一次) | ENOENT | dump 遍历的正常终止哨兵，不是错误 |

**strace 里看到错误返回值 ≠ 程序有 bug**——库拿 syscall 当问答协议用，
"问内核你行不行"，不行就换旧路径。
