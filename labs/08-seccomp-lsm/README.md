# Lab 08 — seccomp 与 LSM：BPF 的"拒绝"面

> 原书 Ch9（安全）。前七个 lab 的 BPF 都是观察者（read-only），
> 安全场景的 BPF 是执法者（可以拒绝操作）。本 lab 真机跑通
> seccomp-BPF 沙箱（无 root、经典 BPF 字节码），并勘察 BPF LSM
> 的可行性（结论：本内核可检测、暂不可运行）。
>
> **理论对照**（hft 仓库读书笔记）：
> [Ch9 安全](https://github.com/cshonor/hft-embedded-linux-study/tree/main/06.7-bpf-observability/learning-ebpf/chapter-09-security)

## 代码结构

| 文件 | 角色 |
|---|---|
| `seccomp_demo.c` | 手写 classic BPF filter 禁止 `getpid()`：ERRNO 版（返回 -1）+ KILL 版（SIGSYS 杀进程），fork 子进程实测 |
| `lsm_probe.sh` | BPF LSM 可行性检测：LSM 链 / 启动参数 / 内核配置三路排查 |
| `lsm_example.bpf.c` | LSM hook 的形态正确代码（本机不可运行，见限制说明） |

## 编译运行

```bash
make run      # seccomp 实验（无需 root）
make probe    # LSM 可行性检测
```

## 一手结论（树莓派 5 · 6.18.34 · 2026-08-30）

### 1. seccomp 实测：一 filter 双结果

```
$ ./seccomp_demo
父进程(无 filter): getpid() = 30671
子进程(有 filter): getpid() = -1, errno = 0        ← ERRNO|EPERM 拦截
子进程其他 syscall 不受影响: getppid() = 30671      ← 只禁了一个 syscall
子进程正常退出: yes
KILL 版子进程: 即将调用 getpid()...
KILL 版子进程被信号终止: yes (SIGSYS=31)             ← KILL_PROCESS 直接杀
```

要点：

- **安装三件套**：`PR_SET_NO_NEW_PRIVS`（先放弃提权路径，否则非 root
  不许装）→ 构造 `sock_filter[]`（classic BPF 短指令，不是 eBPF 字节码）
  → `seccomp(SECCOMP_SET_MODE_FILTER)`
- **数据包换成了 `struct seccomp_data`**：arch / syscall nr / args，
  classic BPF 的 `BPF_ABS` 加载语义照旧——1992 年的机制，2005 年进内核，
  今天仍是 Docker/Chrome/OpenSSH 沙箱的地基
- **必须检查 arch**：`AUDIT_ARCH_AARCH64` 不符直接拒绝——防 32 位
  模式下 syscall 号重映射伪造（x86 上教训深刻）
- **glibc 小观察**：被 ERRNO 拦截后 ret=-1 确凿，但 glibc 的 getpid
  包装层没把 errno 设置出来（打印为 0）——判定拦截要看返回值，
  别只信 errno

### 2. classic BPF 的跳转偏移是手数的（血泪）

`BPF_JUMP(OP, K, jt, jf)` 的跳转目标是相对下一条指令的偏移。
第一版架构检查写 `jf=4` 越界 → `seccomp: Invalid argument`，
内核连装都不给装。6 条指令的 filter，跳偏移数三遍才对——
这就是为什么 libseccomp 要存在：让人写"禁什么"，跳转交给库。

### 3. `_exit()` 不走 stdio 清理

子进程 printf 完没 flush 直接 `_exit(0)` → 输出神秘消失。
fork 相关实验：**fork 前 flush 父进程，_exit 前 flush 子进程**。

### 4. BPF LSM 勘察结论（lsm_probe.sh）

```
$ sh lsm_probe.sh
1. 当前启用的 LSM 链: lockdown,integrity  （没有 bpf）
2. 启动参数里没有 lsm=
3. CONFIG_SECURITY=y，但 BPF_LSM 未启用
5. ❌ bpf 不在 LSM 链中
```

开启需要两步（都是这台机器做不到的）：

1. `/boot/firmware/cmdline.txt` 追加 `lsm=...,bpf` + 重启
2. LSM BPF 程序强依赖 CO-RE（`struct file` 等类型来自 vmlinux.h），
   本内核无 BTF——就算开了 bpf LSM 也得先换带 BTF 的内核

`lsm_example.bpf.c` 保留形态正确的 `SEC("lsm/file_open")` 代码
作为对照——换 BTF 内核后可原样跑。

## 三代"拒绝"机制的位置对比

| 机制 | 年代 | 挂钩点 | 本机状态 |
|---|---|---|---|
| classic BPF socket filter | 1992 | 抓包路径 | ✅ lab07 |
| seccomp-BPF | 2005 | syscall 入口 | ✅ 本 lab |
| BPF LSM | 2020（5.7） | 安全钩子（file_open 等） | ❌ 需换内核 |
