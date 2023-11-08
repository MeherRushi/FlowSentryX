/* SPDX-License-Identifier: GPL-2.0 */
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

SEC("xdp")
int  trail(struct xdp_md *ctx)
{
	__u64 now = bpf_ktime_get_ns();
	bpf_printk("Hello, the time is : %llu",now);
	return XDP_PASS;
}

char _license[] SEC("license") = "GPL";