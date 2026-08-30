CC ?= gcc

all: seccomp_demo

seccomp_demo: seccomp_demo.c
	$(CC) -O2 -Wall $< -o $@

run: all
	./seccomp_demo

probe: lsm_probe.sh
	sh lsm_probe.sh

clean:
	rm -f seccomp_demo

.PHONY: all run probe clean
