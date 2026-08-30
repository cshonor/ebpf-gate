// SPDX-License-Identifier: GPL-2.0
/* lab04 用户态加载器: 最短路径走完 bpf() syscall 全生命周期
 *
 * 对照原书 §4.2 strace 序列: MAP_CREATE → PROG_LOAD → (attach) → MAP_UPDATE_ELEM
 *   → ... → GET_NEXT_KEY / LOOKUP_ELEM (dump) → close
 */
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <stdio.h>
#include <unistd.h>

int main(void)
{
	struct bpf_object *obj;
	struct bpf_program *prog;
	struct bpf_link *link;
	struct bpf_map *cfg, *cnt;
	__u32 key = 0, cur, next;
	__u64 val = 1, hits;
	int has_key = 0;

	obj = bpf_object__open_file("hello.bpf.o", NULL);
	if (!obj) {
		fprintf(stderr, "open hello.bpf.o failed\n");
		return 1;
	}

	if (bpf_object__load(obj)) {	/* verifier 在这一步跑 */
		fprintf(stderr, "load failed\n");
		return 1;
	}

	prog = bpf_object__find_program_by_name(obj, "count_openat");
	link = bpf_program__attach(prog);
	if (!link) {
		fprintf(stderr, "attach failed\n");
		return 1;
	}

	/* 用户态写 config[0]=1 —— strace 里对应的正是书中的 BPF_MAP_UPDATE_ELEM */
	cfg = bpf_object__find_map_by_name(obj, "config");
	if (bpf_map_update_elem(bpf_map__fd(cfg), &key, &val, BPF_ANY)) {
		fprintf(stderr, "update config failed\n");
		return 1;
	}

	printf("tracing openat for 3s ...\n");
	sleep(3);

	/* 拉模式 dump: GET_NEXT_KEY + LOOKUP_ELEM 循环（对照原书 §4.7） */
	cnt = bpf_object__find_map_by_name(obj, "counts");
	printf("%-7s %s\n", "PID", "OPENAT");
	for (;;) {
		if (bpf_map_get_next_key(bpf_map__fd(cnt), has_key ? &cur : NULL, &next))
			break;
		if (bpf_map_lookup_elem(bpf_map__fd(cnt), &next, &hits) == 0)
			printf("%-7u %llu\n", next, hits);
		cur = next;
		has_key = 1;
	}

	bpf_link__destroy(link);
	bpf_object__close(obj);
	return 0;
}
