CLANG ?= clang
CC ?= gcc

ARCH_INC := -I/usr/include/$(shell uname -m)-linux-gnu

all: xdp_count.bpf.o sock_filter.bpf.o loader_xdp loader_sock

xdp_count.bpf.o: xdp_count.bpf.c
	$(CLANG) -target bpf -D__TARGET_ARCH_arm64 $(ARCH_INC) \
		-O2 -g -c $< -o $@

sock_filter.bpf.o: sock_filter.bpf.c
	$(CLANG) -target bpf -D__TARGET_ARCH_arm64 $(ARCH_INC) \
		-O2 -g -c $< -o $@

loader_xdp: loader_xdp.c
	$(CC) -O2 -Wall $< -o $@ -lbpf -lelf

loader_sock: loader_sock.c
	$(CC) -O2 -Wall $< -o $@ -lbpf -lelf

run_xdp: all
	sudo ./loader_xdp

run_sock: all
	sudo ./loader_sock

clean:
	rm -f xdp_count.bpf.o sock_filter.bpf.o loader_xdp loader_sock

.PHONY: all run_xdp run_sock clean
