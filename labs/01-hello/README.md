# Lab 01 — Hello eBPF：两个视角看同一个世界

本实验不需要写 C 代码，用 bpftrace 体感「程序在内核里跑」。

## 1. 冒烟测试

```bash
sudo bpftrace -e 'BEGIN { printf("hello from kernel\n"); exit(); }'
```

## 2. 盯住 syscall（TLPI 主线的呼应）

统计 10 秒内系统上所有进程的 syscall 次数：

```bash
sudo bpftrace -e 'tracepoint:raw_syscalls:sys_enter { @[comm] = count(); } interval:s:10 { exit(); }'
```

试试 `ls /` 再看看计数变化——你每次敲一个命令，内核里这个 map 就在涨。

## 3. 看调度器（CFS 关联）

```bash
# 哪些任务最常被调度
sudo bpftrace -e 'tracepoint:sched:sched_switch { @[comm] = count(); }'
```

## 4. 一行看懂 bpftrace 语法

```
probe /filter/ { action }
```

- `probe`：挂钩点（`tracepoint:子系统:事件` / `kprobe:函数名`）
- `@name`：map 的名字，`count()`/`sum()`/`hist()` 是聚合函数
- `comm`：当前进程名（内置变量）

## 思考

1. 为什么这些命令都要 `sudo`？（提示：`perf_event_paranoid` 与 `CAP_BPF`）
2. `count()` 统计发生在内核还是用户态？数据怎么到你的终端上的？
