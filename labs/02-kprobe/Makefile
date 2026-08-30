CLANG ?= clang
CC ?= gcc

all: hello.bpf.o loader

hello.bpf.o: hello.bpf.c
	$(CLANG) -target bpf -O2 -g -c $< -o $@

loader: loader.c
	$(CC) -O2 -Wall $< -o $@ -lbpf -lelf

run: all
	sudo ./loader

clean:
	rm -f hello.bpf.o loader

.PHONY: all run clean
