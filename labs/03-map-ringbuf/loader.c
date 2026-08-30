// SPDX-License-Identifier: GPL-2.0
// Lab 03 用户态加载器：attach tracepoint + 双通道读数据
//   - RINGBUF: ring_buffer__poll() 事件驱动回调（推模式）
//   - HASH:    Ctrl+C 退出时整表遍历 dump（拉模式）

#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

struct event {
	unsigned int pid;
	char comm[16];
	char fname[64];
};

static volatile sig_atomic_t stop = 0;

static void on_sig(int sig)
{
	stop = 1;
}

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

	printf("\n=== open 次数统计（HASH map 拉模式 dump）===\n");
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

int main(void)
{
	struct bpf_object *obj;
	struct bpf_program *prog;
	struct bpf_link *link;
	struct bpf_map *rb_map, *cnt_map;
	struct ring_buffer *rb;
	int err;

	obj = bpf_object__open_file("hello.bpf.o", NULL);
	if (!obj) {
		fprintf(stderr, "open hello.bpf.o failed\n");
		return 1;
	}

	err = bpf_object__load(obj);	/* verifier 在这一步跑 */
	if (err) {
		fprintf(stderr, "load failed: %d\n", err);
		return 1;
	}

	prog = bpf_object__find_program_by_name(obj, "trace_openat");
	link = bpf_program__attach(prog);
	if (!link) {
		fprintf(stderr, "attach failed\n");
		return 1;
	}

	rb_map = bpf_object__find_map_by_name(obj, "events");
	rb = ring_buffer__new(bpf_map__fd(rb_map), on_event, NULL, NULL);
	if (!rb) {
		fprintf(stderr, "ringbuf init failed\n");
		return 1;
	}

	signal(SIGINT, on_sig);
	signal(SIGTERM, on_sig);

	printf("=== 实时事件流（RINGBUF 推模式），Ctrl+C 结束 ===\n");
	printf("%-7s %-16s %s\n", "PID", "COMM", "FILENAME");
	fflush(stdout);

	while (!stop) {
		err = ring_buffer__poll(rb, 100 /* ms */);
		if (err == -EINTR)
			continue;
		fflush(stdout);
	}

	cnt_map = bpf_object__find_map_by_name(obj, "open_counts");
	dump_counts(bpf_map__fd(cnt_map));

	ring_buffer__free(rb);
	bpf_link__destroy(link);
	bpf_object__close(obj);
	return 0;
}
