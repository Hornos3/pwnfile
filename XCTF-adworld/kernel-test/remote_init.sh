#!/bin/sh
echo "INIT SCRIPT"
mkdir /tmp
mount -t proc none /proc
mount -t sysfs none /sys
mount -t devtmpfs none /dev
mount -t debugfs none /sys/kernel/debug
mount -t tmpfs none /tmp
cat /proc/kallsyms > /tmp/kallsyms

chown 0:0 flag
chmod 400 flag
exec 0</dev/console
exec 1>/dev/console
exec 2>/dev/console


insmod ./HRPKO.ko # 挂载内核模块
chmod 777 /dev/test

echo -e "Boot took $(cut -d' ' -f1 /proc/uptime) seconds"
setsid /bin/cttyhack setuidgid 1000 /bin/sh
#setsid /bin/cttyhack setuidgid 0 /bin/sh # 修改 uid gid 为 0 以提权 /bin/sh 至 root。
poweroff -f # 设置 shell 退出后则关闭机器