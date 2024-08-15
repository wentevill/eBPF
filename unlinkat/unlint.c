//go:build ignore

#include "vmlinux.h"

#include <bpf/bpf_endian.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

#define MAX_FILE_NAME 256

struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__uint(key_size, sizeof(__u32));
	__uint(value_size, sizeof(__u32));
} events SEC(".maps");


SEC("kprobe/do_unlinkat")
int BPF_KPROBE(do_unlinkat, int dfd, struct filename *name)
{
    char filename_buf[MAX_FILE_NAME];

	// Read the actual filename into the buffer
	int filename_length = bpf_probe_read_kernel_str(filename_buf, sizeof(filename_buf),  BPF_CORE_READ(name, name));
	if (filename_length < 0) {
		// Handle read error
		return 0;
	}

	// Ensure filename_length is non-negative and within buffer limits
	__u32 data_length = filename_length > MAX_FILE_NAME ? MAX_FILE_NAME : filename_length;

	// Output the filename to user space
    bpf_probe_read_kernel_str(filename_buf, sizeof(filename_buf), BPF_CORE_READ(name, name));
	bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, filename_buf, data_length);
    return 0;
}