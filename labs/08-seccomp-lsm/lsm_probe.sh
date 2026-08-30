#!/bin/sh
# Lab 08b: BPF LSM 可行性检测（对应原书 Ch9 的 LSM 例子）
#
# BPF LSM 是 eBPF 用于「拒绝」而非「观察」的分支：可以在安全钩子
# （file_open、bprm_check_security 等）里返回 -EPERM 阻止操作。
# 前提：内核 CONFIG_BPF_LSM=y 且启动参数 lsm=...里包含 bpf。

echo "=== 1. 当前启用的 LSM 链 ==="
cat /sys/kernel/security/lsm 2>/dev/null || echo "读不到（可能未挂 securityfs）"

echo
echo "=== 2. 启动参数里有没有 lsm= ==="
cat /proc/cmdline
grep -o 'lsm=[^ ]*' /proc/cmdline || echo "无 lsm= 参数"

echo
echo "=== 3. 内核配置里的 BPF_LSM ==="
if [ -r /proc/config.gz ]; then
	zcat /proc/config.gz | grep -E '^CONFIG_(BPF_LSM|SECURITY|DEBUG_INFO_BTF)[= ]'
elif [ -r "/boot/config-$(uname -r)" ]; then
	grep -E '^CONFIG_(BPF_LSM|SECURITY|DEBUG_INFO_BTF)[= ]' \
		"/boot/config-$(uname -r)" || echo "配置文件里没有 BPF_LSM"
else
	echo "无 /proc/config.gz 也无 /boot/config-$(uname -r)（rpi 内核常见），"
	echo "改看 sysfs 线索："
fi

echo
echo "=== 4. sysfs 佐证 ==="
ls /sys/kernel/security/ 2>/dev/null || echo "/sys/kernel/security 不存在"

echo
echo "=== 5. 结论 ==="
if grep -q bpf /sys/kernel/security/lsm 2>/dev/null; then
	echo "✅ bpf 已在 LSM 链里，可以直接加载 lsm 程序（见 lsm_example.bpf.c）"
else
	echo "❌ bpf 不在 LSM 链中。开启方式（需要重启）："
	echo "   编辑 /boot/firmware/cmdline.txt，在行尾追加："
	echo "     lsm=list名,bpf    （list名 = 上面第 1 步输出的现有链）"
	echo "   例如: lsm=landlock,lockdown,yama,integrity,apparmor,bpf"
	echo "   然后 sudo reboot。"
	echo "   注意：rpi 内核还缺 vmlinux BTF，LSM BPF 程序需要 CO-RE，"
	echo "   就算开了 bpf LSM，仍要换带 BTF 的内核才能真正跑起来。"
fi
