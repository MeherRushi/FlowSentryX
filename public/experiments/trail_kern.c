/* SPDX-License-Identifier: GPL-2.0 */
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

struct stats
{
	__u64 allowed;
};

struct
{
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 2);
	__type(key,__u32);
	__type(value,struct stats);
}stats_map SEC(".maps");


SEC("xdp")
int  trail(struct xdp_md *ctx)
{
	__u32 key = 1;
	// key 0 is accessed 

	// struct stats init_stat ;
	// init_stat.allowed = 0;

	// update = bpf_map_update_elem(&stats_map,&key,&init_stat,BPF_ANY);

	// bpf_printk("update val %lld", update);
	// if(update != 0)
	// {
	// 	bpf_printk("FAIL");
	// 	return -1;
	// }
	// else
	// {
	struct stats *status = bpf_map_lookup_elem(&stats_map,&key);
	if(status == NULL)
		{
			bpf_printk("NULL");
			return -1;
		}
	bpf_printk("Not NULL");
	(status->allowed)++;
	bpf_printk("value of struct stats allowed %llu", status->allowed);
	
	return XDP_PASS;

}

char _license[] SEC("license") = "GPL";