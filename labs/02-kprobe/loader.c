// SPDX-License-Identifier: GPL-2.0
/* lab02 用户态加载器: open -> load -> attach -> 挂 10 秒
 *
 * 编译: gcc loader.c -o loader -lbpf -lelf
 * 注意加载和 attach 都需要 root (CAP_BPF)
 */
#include <bpf/libbpf.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int main(void)
{
	struct bpf_object *obj;
	struct bpf_program *prog;
	struct bpf_link *link;
	int err;

	/* libbpf 1.x: 打开 ELF, 解析 map/程序/重定位 */
	obj = bpf_object__open_file("hello.bpf.o", NULL);
	err = libbpf_get_error(obj);
	if (err) {
		fprintf(stderr, "open hello.bpf.o 失败: %d\n", err);
		return 1;
	}

	/* bpf(BPF_PROG_LOAD): verifier 就在这一步跑 */
	if (bpf_object__load(obj)) {
		fprintf(stderr, "load 失败 (verifier 拒绝?)\n");
		return 1;
	}

	prog = bpf_object__find_program_by_name(obj, "trace_openat");
	if (!prog) {
		fprintf(stderr, "找不到程序 trace_openat\n");
		return 1;
	}

	/* attach 到 tracepoint: libbpf 按 SEC 名字定位 */
	link = bpf_program__attach(prog);
	if (!link) {
		fprintf(stderr, "attach 失败\n");
		return 1;
	}

	printf("已挂载 trace_openat, 运行 10 秒...\n");
	printf("观察输出: sudo cat /sys/kernel/tracing/trace_pipe\n");
	for (int i = 0; i < 10; i++) {
		putchar('.'); fflush(stdout); sleep(1);
	}
	printf("\n退出\n");

	bpf_link__destroy(link);
	bpf_object__close(obj);
	return 0;
}
