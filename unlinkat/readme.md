## 安装bpftool
```bash
apt install bpftool
```

## 生成vmlinux
```bash
bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h
```