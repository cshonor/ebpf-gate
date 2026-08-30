// SPDX-License-Identifier: GPL-2.0
// Lab 06b 加载器：attach uprobe 到 libc 的 malloc
//
// libbpf >= 1.0 的 attach_uprobe 支持 func_name 选项：
//   - binary_path = 可执行文件或共享库的路径
//   - opts.func_name = 符号名（libbpf 解析 ELF 找偏移）
//   - pid = -1 表示所有进程（全局观察）
// 退出时 dump 按 size 分桶的计数表。
//
// 用法: sudo ./loader_uprobe [libc路径]    # 默认从 /proc/self/maps 解析

#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static volatile sig_atomic_t stop = 0;
static void on_sig(int sig) { stop = 1; }

/* 【真机结论 2026-08-30】树莓派官方内核未开 UPROBE：
 *   /boot/config-6.18.34+rpt-rpi-2712: "# CONFIG_UPROBE_EVENTS is not set"
 *   表现：attach 时 ENOENT，/sys/kernel/tracing/uprobe_events 不存在
 *   （kallsyms 里只剩 uprobe_multi 的 BPF 符号桩）。
 * 要跑本实验需自编内核开 CONFIG_UPROBE_EVENTS=y，或换发行版内核。
 * 本 loader 保留完整代码形态，检测到不支持时给出明确提示。 */
static int uprobe_supported(void)
{
	return access("/sys/kernel/tracing/uprobe_events", F_OK) == 0;
}

/* 从 /proc/self/maps 里解析本进程加载的 libc 路径 */
static const char *find_libc(const char *fallback)
{
	static char path[512];
	FILE *f = fopen("/proc/self/maps", "r");
	char line[1024];

	if (!f)
		return fallback;
	while (fgets(line, sizeof(line), f)) {
		if (strstr(line, "libc.so")) {
			char *p = strchr(line, '/');
			char *end;
			if (!p)
				continue;
			end = strchr(p, '\n');
			if (end)
				*end = '\0';
			snprintf(path, sizeof(path), "%s", p);
			fclose(f);
			return path;
		}
	}
	fclose(f);
	return fallback;
}

static void dump_counts(int fd)
{
	unsigned long long cur, next, val;
	int has_key = 0;
	unsigned long long total = 0;

	printf("\n=== malloc 按请求字节数分桶（top 示意）===\n");
	printf("%-12s %s\n", "SIZE", "COUNT");
	for (;;) {
		if (bpf_map_get_next_key(fd, has_key ? &cur : NULL, &next))
			break;
		if (bpf_map_lookup_elem(fd, &next, &val) == 0) {
			printf("%-12llu %llu\n", next, val);
			total += val;
		}
		cur = next;
		has_key = 1;
	}
	printf("总调用次数: %llu\n", total);
}

int main(int argc, char **argv)
{
	const char *libc = argc > 1 ? argv[1]
			: find_libc("/usr/lib/aarch64-linux-gnu/libc.so.6");
	struct bpf_object *obj;
	struct bpf_program *prog;
	struct bpf_link *link;
	LIBBPF_OPTS(bpf_uprobe_opts, opts,
		.func_name = "malloc",
		.retprobe = false,
	);
	int err;

	if (!uprobe_supported()) {
		fprintf(stderr,
			"本内核未开 CONFIG_UPROBE_EVENTS（树莓派官方内核默认），\n"
			"uprobe 无法注册。程序与加载器代码保留作为对照，\n"
			"详见本 lab README 的「真机限制」一节。\n");
		return 77;	/* EX_NOPERM 风格退出码：功能不可用 */
	}

	printf("目标: uprobe @ %s : %s\n", libc, opts.func_name);

	obj = bpf_object__open_file("uprobe.bpf.o", NULL);
	if (!obj) {
		fprintf(stderr, "open uprobe.bpf.o failed\n");
		return 1;
	}
	err = bpf_object__load(obj);
	if (err) {
		fprintf(stderr, "load failed: %d\n", err);
		return 1;
	}
	prog = bpf_object__find_program_by_name(obj, "up_malloc");

	/* pid = -1: 追踪所有进程的 malloc
	 * （libbpf 1.5 的 API：带 opts 的版本叫 attach_uprobe_opts，
	 *  不带 opts 的老签名第一个 bool 参数是 retprobe） */
	link = bpf_program__attach_uprobe_opts(prog, -1, libc, 0, &opts);
	if (!link) {
		fprintf(stderr, "attach uprobe failed: %s\n", strerror(errno));
		return 1;
	}
	printf("已挂 uprobe/malloc（全机），Ctrl+C 结束\n");

	signal(SIGINT, on_sig);
	signal(SIGTERM, on_sig);

	while (!stop)
		sleep(1);

	dump_counts(bpf_map__fd(
		bpf_object__find_map_by_name(obj, "malloc_by_size")));

	bpf_link__destroy(link);
	bpf_object__close(obj);
	return 0;
}
