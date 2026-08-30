# Lab 05 — Verifier 拒绝实验集：故意写坏的程序，内核怎么骂你

> 原书 Ch6 讲 verifier 的六大失败类型。光看书不过瘾——把每种失败
> **故意写一遍**，在真机上抓内核的原话。结果比预期有意思得多：
> 三个"教科书级"拒绝在现代内核/编译器上**被洗白了**，这个 lab
> 的一半价值就在这些意外里。
>
> **理论对照**（hft 仓库读书笔记）：
> [Ch6 §2 典型验证失败与完成保证](https://github.com/cshonor/hft-embedded-linux-study/blob/main/06.7-bpf-observability/01-learning-ebpf/chapter-06-verifier/notes/6.2_典型验证失败与完成保证.md)

## 代码结构

| 文件 | 意图 | 真机结果 |
|---|---|---|
| `rejects/01_uninit_stack.c` | 未初始化栈读（原书 §6.1 经典） | ⚠️ **ACCEPTED**（见发现 1） |
| `rejects/02_null_deref.c` | map 查找未判 NULL 就解引用 | ❌ REJECTED（原书同款报错） |
| `rejects/03_unreachable.c` | 不可达指令 | ❌ REJECTED（但用内联汇编才做到，见发现 3） |
| `rejects/04_bad_ctx_offset.c` | ctx 指针超范围偏移访问 | ❌ REJECTED |
| `rejects/05_bounded_loop.c` | 有界循环（对照，应通过） | ✅ ACCEPTED |
| `rejects/06_unbounded_loop.c` | 无界循环 | ❌ REJECTED（`infinite loop detected`） |
| `try_load.c` | 通用加载器：open → load，把 verifier 日志原样打到 stderr | — |

## 编译运行

```bash
make run      # 编译全部 + 逐个尝试加载，日志收集到 verifier-logs/
```

## 一手结论（树莓派 5 · 6.18.34 · 2026-08-30）

### 拒绝时的原话（四条真日志）

```
02: 7: (79) r1 = *(u64 *)(r0 +0)
    R0 invalid mem access 'map_value_or_null'
    processed 7 insns (limit 1000000)

04: invalid bpf_context access off=9999 size=8
    processed 1 insns (limit 1000000)

06: infinite loop detected at insn 0
    cur state: R1=ctx() R10=fp0

03: unreachable instruction（asm 注入的 exit 后字节码）
```

### 发现 1：未初始化栈读已被现代内核"赦免"（01）

书 §6.1 说读未初始化的栈会被拒（防内核数据泄漏）。真机（6.18 + sudo）：
**ACCEPTED**。反汇编确认字节码里真的有 `r1 = *(u64 *)(r10 - 0x18)`（读从未写过的槽位），不是被 clang 优化掉的。

根因是内核 commit `6715df8d5d24`（"bpf: Allow reads from uninit stack",
Eduard Zingerman, 2024）：

- 加载者持有 CAP_PERFMON/CAP_SYS_ADMIN 时 `allow_uninit_stack=1`
- 未初始化栈读被放行（值域视为全范围任意数），换来状态比较 30-70% 提速
- 官方说明原话："This error is no longer possible in privileged mode"
- 非特权模式依旧拒绝——但本机 `kernel.unprivileged_bpf_disabled=2`，
  非特权 BPF 整个被禁，所以**此书的经典拒绝在本机不可复现**

### 发现 2：ARRAY map + 常量 key 能"洗白" NULL 解引用（02）

第一版用 `BPF_MAP_TYPE_ARRAY` + `key=0`：**ACCEPTED**！verifier 能静态
推断 ARRAY 的 slot 0 必然存在，直接把 lookup 返回值标为**非 NULL**，
于是不写 NULL 检查也不报错。换成 `HASH` map（key 可能 miss）后立刻
拿到原书同款报错 `R0 invalid mem access 'map_value_or_null'`。

写"验证失败"测试用例时 map 类型不是随便选的。

### 发现 3：C 语言根本写不出不可达指令（03）

`return 0;` 后面再写代码？clang 前端在 codegen 阶段就把 unreachable
基本块丢弃（-O0 也一样，反汇编只有 15 条指令，死代码根本没生成）。
真正的不可达指令要用内联汇编注入：

```c
asm volatile("r0 = 0\n\t" "exit\n\t"
             "r0 = 1\n\t"   /* exit 之后还有字节码 → unreachable */
             "exit\n\t");
```

顺带的启示：**verifier 拒绝的是"字节码形态"，不是"C 代码意图"**——
前端（clang）和后端（verifier）各守一段防线。

### 发现 4：有界循环是白送的（05）

`for (i = 0; i < 10; i++)` 直接通过——verifier 追踪循环变量范围，
bounded loop 自 5.3 起是内核原生能力。与 06 的对照说明放行的前提
永远是"界可证明"。

## 方法论沉淀

预期被拒却通过了，按顺序查三件事：

1. **clang 优化**——`-O2` 会把未初始化读、死代码洗掉（反汇编确认）
2. **verifier 推断**——ARRAY+常量 key、常量传播都可能改变检查结果
3. **内核行为演化**——拒绝规则本身会变（如 uninit stack 的赦免），
   书的出版年份 = 行为快照的年份
