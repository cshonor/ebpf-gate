CLANG ?= clang
CC ?= gcc

ARCH_INC := -I/usr/include/$(shell uname -m)-linux-gnu

all: kprobe.bpf.o uprobe.bpf.o loader_kprobe loader_uprobe

kprobe.bpf.o: kprobe.bpf.c
	$(CLANG) -target bpf -D__TARGET_ARCH_arm64 $(ARCH_INC) \
		-O2 -g -c $< -o $@

uprobe.bpf.o: uprobe.bpf.c
	$(CLANG) -target bpf -D__TARGET_ARCH_arm64 $(ARCH_INC) \
		-O2 -g -c $< -o $@

loader_kprobe: loader_kprobe.c
	$(CC) -O2 -Wall $< -o $@ -lbpf -lelf

loader_uprobe: loader_uprobe.c
	$(CC) -O2 -Wall $< -o $@ -lbpf -lelf

run_kprobe: all
	sudo ./loader_kprobe

run_uprobe: all
	sudo ./loader_uprobe

clean:
	rm -f kprobe.bpf.o uprobe.bpf.o loader_kprobe loader_uprobe

.PHONY: all run_kprobe run_uprobe clean
