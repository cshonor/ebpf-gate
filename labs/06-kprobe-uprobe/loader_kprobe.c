// SPDX-License-Identifier: GPL-2.0
// Lab 06a 加载器：attach kprobe 到指定内核符号（默认 do_sys_openat）
// 用法: sudo ./loader_kprobe [kernel_symbol]

#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

struct event {
	unsigned int pid;
	char comm[16];
	char fname[64];
};

static volatile sig_atomic_t stop = 0;

static void on_sig(int sig) { stop = 1; }

static int on_event(void *ctx, void *data, size_t size)
{
	const struct event *e = data;
	printf("%-7u %-16s %s\n", e->pid, e->comm, e->fname);
	return 0;
}

static void dump_counts(int fd)
{
	unsigned int cur, next;
	unsigned long long val;
	int has_key = 0;

	printf("\n=== kprobe openat 计数（按 pid）===\n");
	printf("%-7s %s\n", "PID", "COUNT");
	for (;;) {
		if (bpf_map_get_next_key(fd, has_key ? &cur : NULL, &next))
			break;
		if (bpf_map_lookup_elem(fd, &next, &val) == 0)
			printf("%-7u %llu\n", next, val);
		cur = next;
		has_key = 1;
	}
}

int main(int argc, char **argv)
{
	const char *symbol = argc > 1 ? argv[1] : "do_sys_openat2";
	struct bpf_object *obj;
	struct bpf_program *prog;
	struct bpf_link *link;
	struct ring_buffer *rb;
	int err;

	obj = bpf_object__open_file("kprobe.bpf.o", NULL);
	if (!obj) {
		fprintf(stderr, "open kprobe.bpf.o failed\n");
		return 1;
	}
	err = bpf_object__load(obj);
	if (err) {
		fprintf(stderr, "load failed: %d\n", err);
		return 1;
	}
	prog = bpf_object__find_program_by_name(obj, "kp_openat");

	link = bpf_program__attach_kprobe(prog, /*retprobe=*/false, symbol);
	if (!link) {
		fprintf(stderr, "attach kprobe/%s failed: %s\n",
			symbol, strerror(errno));
		fprintf(stderr, "提示: grep -w %s /proc/kallsyms 确认符号存在\n",
			symbol);
		return 1;
	}
	printf("已挂 kprobe/%s（Ctrl+C 结束）\n", symbol);

	rb = ring_buffer__new(
		bpf_map__fd(bpf_object__find_map_by_name(obj, "events")),
		on_event, NULL, NULL);

	signal(SIGINT, on_sig);
	signal(SIGTERM, on_sig);
	printf("%-7s %-16s %s\n", "PID", "COMM", "FILENAME");

	while (!stop) {
		err = ring_buffer__poll(rb, 100);
		if (err == -EINTR)
			continue;
		fflush(stdout);
	}

	dump_counts(bpf_map__fd(
		bpf_object__find_map_by_name(obj, "kprobe_counts")));

	ring_buffer__free(rb);
	bpf_link__destroy(link);
	bpf_object__close(obj);
	return 0;
}
