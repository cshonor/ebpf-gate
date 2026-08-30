// SPDX-License-Identifier: GPL-2.0
// Lab 08a: seccomp-BPF —— 无特权沙箱的原生实现（对应原书 Ch9）
//
// seccomp 是 BPF 的「老前辈」用法（2005 年进入内核，早于 eBPF）：
// filter 用的是 classic BPF（sock_filter 短指令），不是 eBPF 字节码，
// 但概念一脉相承：数据包换成了 struct seccomp_data（syscall 元数据），
// 返回码换成了 SECCOMP_RET_*。
//
// 策略：禁止 getpid()（arm64 号码 172，无害好验证）。
// 流程：PR_SET_NO_NEW_PRIVS → SECCOMP_MODE_FILTER → fork 子进程实测。
//
// 这也是 Docker/Chrome/OpenSSH 沙箱的底层机制 —— 无需 root。

#include <errno.h>
#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <linux/unistd.h>
#include <signal.h>
#include <stddef.h>		/* offsetof */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <sys/wait.h>

#define ARRAY_SIZE(a) (sizeof(a) / sizeof((a)[0]))

static int install_seccomp(void)
{
	/* classic BPF filter：
	 *   ld  [4]         -> arch（低 32 位有效）
	 *   jne AARCH64 -> kill
	 *   ld  [0]         -> syscall nr
	 *   jeq __NR_getpid -> errno(EPERM)
	 *   ret ALLOW
	 */
	struct sock_filter filter[] = {
		BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
			 offsetof(struct seccomp_data, arch)),
		BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, AUDIT_ARCH_AARCH64,
			 0, 4),		/* 架构不符直接 KILL（防 32 位伪造号） */
		BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
			 offsetof(struct seccomp_data, nr)),
		BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_getpid,
			 0, 1),		/* 是 getpid？ */
		BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | (EPERM & 0xffff)),
		BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
	};
	struct sock_fprog prog = {
		.len = ARRAY_SIZE(filter),
		.filter = filter,
	};

	/* 必须先放弃特权提升路径，否则非 root 不允许装 filter */
	if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)) {
		perror("PR_SET_NO_NEW_PRIVS");
		return -1;
	}
	if (syscall(__NR_seccomp, SECCOMP_SET_MODE_FILTER, 0, &prog)) {
		perror("seccomp");
		return -1;
	}
	return 0;
}

int main(void)
{
	pid_t child;
	int status;

	/* 对照组：无 filter 的 getpid */
	printf("父进程(无 filter): getpid() = %d\n", getpid());

	/* 实验组：子进程装上 filter 再调 */
	child = fork();
	if (child == 0) {
		if (install_seccomp()) {
			fprintf(stderr, "install seccomp failed\n");
			_exit(1);
		}
		errno = 0;
		long ret = getpid();	/* 应返回 -1 且 errno=EPERM */
		printf("子进程(有 filter): getpid() = %ld, errno = %s\n",
		       ret, strerror(errno));
		printf("子进程其他 syscall 不受影响: getppid() = %d\n",
		       getppid());
		_exit(0);
	}
	waitpid(child, &status, 0);
	printf("子进程正常退出: %s\n", WIFEXITED(status) ? "yes" : "no");

	/* KILL 演示：被拒绝的另一种返回码（SIGSYS 终止） */
	child = fork();
	if (child == 0) {
		struct sock_filter kill_filter[] = {
			BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
				 offsetof(struct seccomp_data, nr)),
			BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_getpid,
				 0, 1),
			BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS),
			BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
		};
		struct sock_fprog kprog = {
			.len = ARRAY_SIZE(kill_filter),
			.filter = kill_filter,
		};
		prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
		syscall(__NR_seccomp, SECCOMP_SET_MODE_FILTER, 0, &kprog);
		printf("KILL 版子进程: 即将调用 getpid()...\n");
		fflush(stdout);
		getpid();		/* 进程将被 SIGSYS 直接杀死 */
		printf("这行永远打印不出来\n");
		_exit(0);
	}
	waitpid(child, &status, 0);
	printf("KILL 版子进程被信号终止: %s (SIGSYS=%d)\n",
	       WIFSIGNALED(status) ? "yes" : "no", SIGSYS);
	return 0;
}
