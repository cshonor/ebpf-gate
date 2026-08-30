// SPDX-License-Identifier: GPL-2.0
// 通用「尝试加载」器：接收一个 .bpf.o，打开 + 加载（verifier 在此跑），
// 打印结论。用于逐个喂故意失败的程序，收集 verifier 拒绝日志。
//
// 用法: sudo ./try_load <file.bpf.o>
// verifier 日志走 libbpf 的打印回调，原样输出到 stderr（重定向收集）。

#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <stdio.h>
#include <stdlib.h>

static int print_libbpf(enum libbpf_print_level level,
			const char *fmt, va_list ap)
{
	/* verifier 的拒绝日志是 LIBBPF_WARN 级别，全都要 */
	return vfprintf(stderr, fmt, ap);
}

int main(int argc, char **argv)
{
	struct bpf_object *obj;
	int err;

	if (argc != 2) {
		fprintf(stderr, "usage: %s <prog.bpf.o>\n", argv[0]);
		return 2;
	}

	libbpf_set_print(print_libbpf);

	obj = bpf_object__open_file(argv[1], NULL);
	if (!obj) {
		fprintf(stderr, "open %s failed\n", argv[1]);
		return 2;
	}

	err = bpf_object__load(obj);	/* verifier 在这一步跑 */
	if (err)
		fprintf(stderr, "\n>>> RESULT: REJECTED (err=%d)\n", err);
	else
		fprintf(stderr, "\n>>> RESULT: ACCEPTED\n");

	bpf_object__close(obj);
	return err ? 1 : 0;
}
