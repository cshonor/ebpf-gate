# 00 — eBPF 是什么：从内核视角理解

> 学习仓库开篇笔记。对应《Learning eBPF》Chapter 1–2 的理解整理。

## 一句话定义

eBPF 是**内核里的一个可编程虚拟机**：你把一段 C 写的（编译成 BPF 字节码的）小程序提交给内核，内核先由 **verifier 静态验证安全性**，再把它 JIT 成本机指令，挂到某个**触发点（hook）**上执行。

## 两条关键链路

```
用户态视角：
  C 源码 --clang -target bpf--> BPF 字节码 --bpf() syscall--> 内核

内核视角（这是重点）：
  bpf(BPF_PROG_LOAD) → verifier 检查 → JIT 编译 → attach 到 hook
```

### 1. verifier —— 为什么 BPF 程序不会让内核崩溃

加载时逐条指令做静态分析：

| 检查项 | 含义 |
|---|---|
| 无界循环 | 必须能在有限步内结束（老内核直接禁止循环，5.3+ 允许有界循环） |
| 越界访问 | 对 map / 栈 / 包数据的每次读写都要证明在范围内 |
| 指针检查 | 未经验证的指针不能直接解引用 |

### 2. hook 点 —— 程序挂在哪

| 类型 | 触发点 | HFT/嵌入式关联 |
|---|---|---|
| kprobe | 任意内核函数入口 | 测 syscall/调度延迟 |
| tracepoint | 内核静态埋点 | 比 kprobe 稳定，开销略低 |
| XDP | 网卡收包最早处 | 极致收包路径，丢包/负载均衡 |
| tc | 流量控制层 | 包修改、重定向 |
| perf event | 性能计数器溢出 | 采样分析 |

## 和用户态的关系（TLPI 视角）

- eBPF 程序的加载用的是 `bpf()` **系统调用** —— 和 `open()`/`write()` 一样是 syscall，本质是用户态请求内核服务
- 用户态 ↔ BPF 程序之间靠 **map**（内核里的键值结构）双向传数据
- 加载器（libbpf）做的事：打开 ELF、重定位、创建 map、逐个加载程序、attach

## 环境就绪检查清单

```bash
uname -r                        # 内核 >= 5.15 较稳
grep CONFIG_DEBUG_INFO_BTF /boot/config-$(uname -r)   # CO-RE 需要 BTF
ls /sys/kernel/btf/vmlinux      # BTF 文件存在则 CO-RE 可用
bpftrace -e 'BEGIN { printf("hi\n"); }'   # 工具链冒烟测试
```

## 自测

<details>
<summary>Q1: BPF 程序为什么不能有无限循环？</summary>
verifier 无法静态证明程序会终止，内核必须保证 BPF 程序不会占死 CPU（BPF 程序不可抢占、在软中断上下文运行）。
</details>

<details>
<summary>Q2: kprobe 和 tracepoint 选哪个？</summary>
优先 tracepoint：内核版本间稳定（有 ABI 保证）；kprobe 挂函数符号，内核一改函数名就失效。但 tracepoint 覆盖不全，没有对应埋点时才退回 kprobe。
</details>

<details>
<summary>Q3: CO-RE 解决什么问题？</summary>
内核结构体布局随版本变化（如 task_struct 字段增删）。CO-RE 用 BTF 记录"哪个字段在哪个偏移"，加载时根据目标机器的 BTF 重定位，实现"一次编译，到处运行"。没有 BTF 就只能现场编译（BCC 的做法）。
</details>
