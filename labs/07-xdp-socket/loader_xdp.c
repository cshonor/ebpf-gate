// SPDX-License-Identifier: GPL-2.0
// Lab 07a 加载器：把 XDP 程序挂到指定网卡（默认 lo，generic/SKB 模式）
// 每 2 秒 dump per-CPU 计数，Ctrl+C 退出并卸载。
//
// 用法: sudo ./loader_xdp [ifname]   # 默认 lo

#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define VALUE_U64S 3		/* [0]pkts [1]bytes [2]drops */

static volatile sig_atomic_t stop = 0;
static void on_sig(int sig) { stop = 1; }

static void dump_stats(int fd, int ncpus)
{
	static unsigned long long prev[VALUE_U64S];
	unsigned long long buf[VALUE_U64S * 64];	/* 最大支持 64 CPU */
	unsigned long long cur[VALUE_U64S] = {0};
	int zero = 0;

	if (bpf_map_lookup_elem(fd, &zero, buf)) {
		printf("stats lookup failed: %s\n", strerror(errno));
		return;
	}
	for (int c = 0; c < ncpus; c++)
		for (int i = 0; i < VALUE_U64S; i++)
			cur[i] += buf[c * VALUE_U64S + i];

	printf("packets=%-10llu bytes=%-12llu drops=%-8llu "
	       "(Δ %llu/%llu)\n",
	       cur[0], cur[1], cur[2],
	       cur[0] - prev[0], cur[2] - prev[2]);
	fflush(stdout);
	memcpy(prev, cur, sizeof(prev));
}

int main(int argc, char **argv)
{
	const char *ifname = argc > 1 ? argv[1] : "lo";
	struct bpf_object *obj;
	struct bpf_program *prog;
	int prog_fd, ifindex, ncpus, err;
	unsigned int flags = XDP_FLAGS_SKB_MODE;	/* generic 模式 */

	ifindex = if_nametoindex(ifname);
	if (!ifindex) {
		fprintf(stderr, "unknown interface: %s\n", ifname);
		return 1;
	}

	obj = bpf_object__open_file("xdp_count.bpf.o", NULL);
	if (!obj || bpf_object__load(obj)) {
		fprintf(stderr, "open/load xdp_count.bpf.o failed\n");
		return 1;
	}
	prog = bpf_object__find_program_by_name(obj, "xdp_count");
	prog_fd = bpf_program__fd(prog);

	err = bpf_xdp_attach(ifindex, prog_fd, flags, NULL);
	if (err) {
		fprintf(stderr, "xdp attach failed: %s\n", strerror(-err));
		return 1;
	}

	/* per-CPU map 的 dump 缓冲要按 CPU 数扩容 */
	ncpus = libbpf_num_possible_cpus();
	if (ncpus > 64)
		ncpus = 64;

	printf("XDP 已挂 %s (SKB 模式)，UDP 目的端口 9999 将被 DROP\n", ifname);
	printf("测试: nc -u %s 9999 </dev/zero &  （Ctrl+C 结束）\n", ifname);
	signal(SIGINT, on_sig);
	signal(SIGTERM, on_sig);

	while (!stop) {
		dump_stats(bpf_map__fd(
			bpf_object__find_map_by_name(obj, "stats")), ncpus);
		sleep(2);
	}

	bpf_xdp_detach(ifindex, flags, NULL);
	printf("XDP 已从 %s 卸载\n", ifname);
	bpf_object__close(obj);
	return 0;
}
