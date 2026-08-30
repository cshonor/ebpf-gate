// SPDX-License-Identifier: GPL-2.0
// Lab 07b 加载器：raw socket + SO_ATTACH_BPF 挂 socket filter
//
// 用 MSG_TRUNC|NULL 的 recv 只拿包长不拷贝数据 ——
// 被 filter 返回 0 的包根本不会出现在 recv 里，
// 这就是 BPF「在数据 copy 到用户态之前过滤」的性能本义。

#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <arpa/inet.h>
#include <errno.h>
#include <net/if.h>
#include <netpacket/packet.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

static volatile sig_atomic_t stop = 0;
static void on_sig(int sig) { stop = 1; }

static void dump_stats(int fd, int ncpus)
{
	static unsigned long long prev[2];
	unsigned long long buf[2 * 64];
	unsigned long long cur[2] = {0};
	int zero = 0;

	if (bpf_map_lookup_elem(fd, &zero, buf))
		return;
	for (int c = 0; c < ncpus; c++) {
		cur[0] += buf[c * 2 + 0];
		cur[1] += buf[c * 2 + 1];
	}
	printf("seen=%-10llu passed(IPv4)=%-10llu recv_user=%llu\n",
	       cur[0], cur[1], cur[1] - prev[1]);
	fflush(stdout);
	memcpy(prev, cur, sizeof(prev));
}

int main(int argc, char **argv)
{
	const char *ifname = argc > 1 ? argv[1] : "lo";
	struct bpf_object *obj;
	struct bpf_program *prog;
	struct sockaddr_ll sll = {0};
	int sock, prog_fd, ncpus, ifindex;

	ifindex = if_nametoindex(ifname);
	if (!ifindex) {
		fprintf(stderr, "unknown interface: %s\n", ifname);
		return 1;
	}

	/* 1) raw socket: 收链路层所有包 */
	sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
	if (sock < 0) {
		perror("socket(AF_PACKET)");	/* 需要 root/CAP_NET_RAW */
		return 1;
	}
	sll.sll_family = AF_PACKET;
	sll.sll_protocol = htons(ETH_P_ALL);
	sll.sll_ifindex = ifindex;
	if (bind(sock, (struct sockaddr *)&sll, sizeof(sll))) {
		perror("bind");
		return 1;
	}

	/* 2) 编译并加载 socket filter */
	obj = bpf_object__open_file("sock_filter.bpf.o", NULL);
	if (!obj || bpf_object__load(obj)) {
		fprintf(stderr, "open/load sock_filter.bpf.o failed\n");
		return 1;
	}
	prog = bpf_object__find_program_by_name(obj, "filter_ipv4");
	prog_fd = bpf_program__fd(prog);

	/* 3) 把 filter 挂到 socket 上 */
	if (setsockopt(sock, SOL_SOCKET, SO_ATTACH_BPF,
		       &prog_fd, sizeof(prog_fd))) {
		perror("SO_ATTACH_BPF");
		return 1;
	}

	ncpus = libbpf_num_possible_cpus();
	if (ncpus > 64)
		ncpus = 64;

	printf("socket filter 已挂 %s（只放行 IPv4），Ctrl+C 结束\n", ifname);
	signal(SIGINT, on_sig);
	signal(SIGTERM, on_sig);

	while (!stop) {
		/* NULL+MSG_TRUNC: 只返回包长，不拷贝 payload。
		 * filter 返回 0 的包不会让 recv 就绪 —— 用户态根本看不到。 */
		recv(sock, NULL, 0, MSG_TRUNC | MSG_DONTWAIT);
		dump_stats(bpf_map__fd(
			bpf_object__find_map_by_name(obj, "stats")), ncpus);
		sleep(1);
	}

	close(sock);
	bpf_object__close(obj);
	return 0;
}
