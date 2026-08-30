#!/usr/bin/env bash
# ebpf-gate 树莓派环境一键安装脚本（Raspberry Pi OS 64-bit / 任意 Debian ARM64）
# 用法：在树莓派上执行  bash setup-pi.sh
set -e

echo "=== 1/4 内核检查 ==="
UNAME_R=$(uname -r)
echo "内核版本: $UNAME_R"
ARCH=$(uname -m)
echo "架构: $ARCH"
if [ "$ARCH" != "aarch64" ]; then
  echo "!! 警告：当前是 $ARCH，不是 aarch64。"
  echo "!! 32 位系统 eBPF 支持残缺（bpftrace 不可用），建议用 Raspberry Pi Imager 重刷 64 位系统。"
  exit 1
fi
if [ ! -f "/sys/kernel/btf/vmlinux" ]; then
  echo "!! 警告：/sys/kernel/btf/vmlinux 不存在，CO-RE（libbpf）需要 BTF。"
  echo "!! 较新的 Raspberry Pi OS 内核自带 BTF；若缺失请 sudo rpi-update 升级内核。"
else
  echo "BTF 存在: $(ls -lh /sys/kernel/btf/vmlinux | awk '{print $5}')"
fi

echo "=== 2/4 安装工具链 ==="
sudo apt-get update
sudo apt-get install -y \
  clang llvm libelf-dev libbpf-dev \
  bpftrace bpftool \
  build-essential make pkg-config \
  linux-tools-$(uname -r) 2>/dev/null || \
sudo apt-get install -y linux-tools-common

echo "=== 3/4 版本确认 ==="
clang --version | head -1
bpftrace --version
bpftool version | head -1

echo "=== 4/4 冒烟测试 ==="
sudo bpftrace -e 'BEGIN { printf(">>> eBPF ready on %s (%s)\n", uname().sysname, uname().machine); exit(); }'

echo ""
echo "全部就绪。下一步：labs/01-hello"
