CLANG ?= clang
CC ?= gcc

REJECTS := 01_uninit_stack 02_null_deref 03_unreachable \
	   04_bad_ctx_offset 05_bounded_loop 06_unbounded_loop
OBJS := $(patsubst %,rejects/%.o,$(REJECTS))

# 注意：03_unreachable 必须用 -O0，否则 clang 消除死代码后程序「意外合法」
#      —— 这本身是个值得记录的对照：同一个 .c 在 -O2 下通过、-O0 下被拒。
O0_TARGET := rejects/03_unreachable.o

all: $(OBJS) try_load

$(filter-out $(O0_TARGET),$(OBJS)): rejects/%.o: rejects/%.c
	$(CLANG) -target bpf -D__TARGET_ARCH_arm64 \
		-I/usr/include/$(shell uname -m)-linux-gnu \
		-O2 -g -c $< -o $@

$(O0_TARGET): rejects/03_unreachable.c
	$(CLANG) -target bpf -D__TARGET_ARCH_arm64 \
		-I/usr/include/$(shell uname -m)-linux-gnu \
		-O0 -g -c $< -o $@

try_load: try_load.c
	$(CC) -O2 -Wall $< -o $@ -lbpf -lelf

# 逐个尝试加载，收集 verifier 日志到 verifier-logs/
run: all
	mkdir -p verifier-logs
	@for t in $(REJECTS); do \
		echo "=== $$t ==="; \
		sudo ./try_load rejects/$$t.o > verifier-logs/$$t.log 2>&1; \
		echo "exit=$$? (1=rejected 0=accepted)"; \
	done
	@echo "日志收集于 verifier-logs/"

clean:
	rm -f $(OBJS) try_load
	rm -rf verifier-logs

.PHONY: all run clean
