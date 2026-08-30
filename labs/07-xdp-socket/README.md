# Lab 07 — XDP 与 socket filter：网络路径上的两代 BPF

> 原书 Ch10（网络）。socket filter 是 BPF 的出生地（1992 年 BSD
> 抓包过滤），XDP 是它的极客进化版（数据包进协议栈之前就处理）。
> 本 lab 在 `lo` 接口上跑通：XDP 按 UDP 端口丢包 + socket filter
> 按 ethertype 过滤，两者都是"在数据拷贝给用户态之前动手"。
>
> **理论对照**（hft 仓库读书笔记）：
> [Ch10 网络](https://github.com/cshonor/hft-embedded-linux-study/tree/main/06.7-bpf-observability/learning-ebpf/chapter-10-networking)

## 代码结构

| 文件 | 角色 |
|---|---|
| `xdp_count.bpf.c` | XDP 程序：逐层检查 eth→ip→udp 边界，目的端口 9999 返回 `XDP_DROP`，其余 PASS；per-CPU 计数 |
| `loader_xdp.c` | 挂 `lo`（SKB/generic 模式），每 2 秒 dump 计数，Ctrl+C 卸载 |
| `sock_filter.bpf.c` | socket filter：读 `skb->protocol`，非 IPv4 返回 0（这个 socket 不收） |
| `loader_sock.c` | AF_PACKET raw socket + `SO_ATTACH_BPF` + `MSG_TRUNC` 零拷贝收包长 |

## 编译运行

```bash
make
sudo ./loader_xdp lo          # XDP（另开终端: nc -u 127.0.0.1 9999 测 DROP）
sudo ./loader_sock lo         # socket filter（ping -4 放行 / ping -6 丢弃）
```

## 一手结论（树莓派 5 · 6.18.34 · 2026-08-30）

### 1. XDP 实测：网卡层丢包，协议栈都不知道

```
$ sudo ./loader_xdp lo
XDP 已挂 lo (SKB 模式)，UDP 目的端口 9999 将被 DROP
packets=0          bytes=0            drops=0        (Δ 0/0)
packets=4          bytes=376          drops=0        (Δ 4/0)   ← ping 放行
packets=9          bytes=823          drops=1        (Δ 5/1)   ← UDP 9999 开始丢
packets=11         bytes=933          drops=3        (Δ 2/2)
XDP 已从 lo 卸载
```

- ICMP、UDP 9998 正常放行（packets 增长）
- UDP 9999 被 DROP（drops 增长），**不进入内核协议栈**
- HFT 视角：丢弃越早，CPU 花在坏包上的开销越小——iptables 的 DROP
  在协议栈中段，XDP 的 DROP 在最前端，这是"在源头掐掉"的差距
- 本机是 SKB(generic) 模式（lo 无驱动支持）；真网卡上的 native XDP
  更早（DMA 后立刻），收益更大

### 2. XDP 的 verifier 味道：指针边界步步为营

每一层解引用前都要 `if ((ptr + 1) > data_end) return PASS;`——
这是 XDP 程序的固定范式，少一步 verifier 立刻拒绝。与 lab05 的
04 号案例呼应：ctx/data 指针的每次算术都要可证明有界。

### 3. socket filter 的意外：这个内核不让碰 data/data_end

最初照 XDP 的写法用 `skb->data`/`skb->data_end` 解析包头——
**直接被拒**：

```
0: (61) r7 = *(u32 *)(r1 +80)
invalid bpf_context access off=80 size=4     ← data_end
```

最小用例二分验证：读 `skb->len`（offset 0）→ ACCEPTED；读
`skb->data`（offset 76）→ REJECTED。结论：本内核 SOCKET_FILTER
的 ctx 白名单不含 data/data_end 指针字段（比 XDP 严格——XDP 的
`ctx->data/data_end` 是原生字段）。改用 `skb->protocol`
（ethertype）做过滤，反而更贴近 tcpdump 的实战写法。

### 4. socket filter 实测：filter 返回 0 的包用户态看不到

```
$ sudo ./loader_sock lo       #（同时 ping -4 ×3 与 ping -6 ×3）
socket filter 已挂 lo（只放行 IPv4），Ctrl+C 结束
seen=4    passed(IPv4)=4   recv_user=4    ← IPv4 ping：看见 = 收到
seen=8    passed(IPv4)=4   recv_user=0    ← IPv6 ping：看见 ≠ 收到（被滤掉）
seen=16   passed(IPv4)=12  recv_user=4
seen=20   passed(IPv4)=12  recv_user=0
```

`seen` 与 `recv_user` 的差值 = 被 filter 拦下的包。
`recv(sock, NULL, 0, MSG_TRUNC)` 只拿包长不拷贝——BPF 的性能哲学：
**过滤发生在 copy 之前**。

### 5. per-CPU map 的用户态读法

`BPF_MAP_TYPE_PERCPU_ARRAY` 免锁但 dump 时 value 缓冲要按
CPU 数扩容（`libbpf_num_possible_cpus()`），各 CPU 槽位求和——
`loader_xdp.c` 里有现成模板。
