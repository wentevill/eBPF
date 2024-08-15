## Install bpftool
```bash
apt install bpftool
```

## Generate vmlinux.h
```bash
bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h
```
