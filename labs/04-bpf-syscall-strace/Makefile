CLANG ?= clang
CC ?= gcc

all: hello.bpf.o loader

hello.bpf.o: hello.bpf.c
	$(CLANG) -target bpf -D__TARGET_ARCH_arm64 \
		-I/usr/include/$(shell uname -m)-linux-gnu \
		-O2 -g -c $< -o $@

loader: loader.c
	$(CC) -O2 -Wall $< -o $@ -lbpf -lelf

run: all
	sudo ./loader

# strace 拆解: 只跟 bpf/perf_event 相关 syscall, fd 标注来源
strace: all
	sudo strace -f -tt -yy -e trace=bpf,perf_event_open,ioctl \
		-o strace.log ./loader && echo "--- strace.log 写好了, 分析它"

clean:
	rm -f hello.bpf.o loader strace.log

.PHONY: all run strace clean
