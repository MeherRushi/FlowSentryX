/* SPDX-License-Identifier: GPL-2.0 */

#include <linux/bpf.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

/* All the packet parsing helper function 
are in the parsing_herlper.h header file 
and structure of the values of the maps are
in the fsx_struct.h map */

#include "parsing_helper.h"
#include "fsx_struct.h"

/* Map declarations 
 We have 4 maps that we need to consider :
    1) stats_map - To store global variables - 1 entry
    of a struct which stores the total number of packets
    dropped and no of packets that are not dropped. 
    Since  this is a BPF_MAP_TYPE_ARRAY, we can access
    the element using the index 0. Ass it is the 
    only element, we take it and keep updating 
    it, we should also manually do error checks on 
    it else the verifier will reject


    2) ipv4_stats_map - This map is to keep track of stats
    per IP. So the key here is the IPv4 address of the
    incoming packet and the value is a struct with pps
    (packets per sec), bps(byte per second) and tracktime
    which are __u64 integers.

    3) ipv6_stats_map - This map is to keep track of stats
    per IPv6. So the key here is a IPv6 address of the incoming
    packet and the value is same as described in the 
    ipv4_stats_map.

    4)ipv4_blacklist_map - This map has only the IPv4 address
    of all the IPv4 addresses we want to blacklist and the time
    we have blacklisted it. So we will keep checking the difference
    between the current time and the time that the packet was 
    blacklisted and then if it greater than a certain threshold, the
    ip is whitelisted else the packet is dropped

    5)ipv6_blacklist_map - same concept as above but different key size

    We have different maps for IPv4 adn IPv6 because of the 
    different key size i.e __u32 and __u128 respectively

*/
struct 
{
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct stats);
}stats_map SEC(".maps");

struct
{
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, MAX_TRACK_IPS);
    __type(key, __u32);
    __type(value, struct ip_stats);
}ipv4_stats_map SEC(".maps");

struct 
{
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, MAX_TRACK_IPS);
    __type(key, __u128);
    __type(value, struct ip_stats);
}ipv6_stats_map SEC(".maps");

struct 
{
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, MAX_TRACK_IPS);
    __type(key, __u32);
    __type(value, __u64);
} ipv4_blacklist_map SEC(".maps");

struct 
{
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, MAX_TRACK_IPS);
    __type(key,__u128);
    __type(value, __u64);
} ipv6_blacklist_map SEC(".maps");


SEC("xdp_prog")
int xdp_prog_main(struct xdp_md *ctx)
{
    //Initialize the data pointers for the packet
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    struct ethhdr *eth;
    /* Default action XDP_PASS, imply everything we couldn't parse, or that
	 * we don't want to deal with, we just pass up the stack and let the
	 * kernel deal with it.
	 */
	__u32 action = XDP_PASS; /* Default action */

    /* These keep track of the next header type and iterator pointer */
	struct hdr_cursor nh;
	int nh_type;

    /* Start next header cursor position at data start */
	nh.pos = data;

    /* Packet parsing in steps: Get each header one at a time, aborting if
	 * parsing fails. Each helper function does sanity checking (is the
	 * header type in the packet correct?), and bounds checking.
	 */
	nh_type = parse_ethhdr(&nh, data_end, &eth);
    if(nh_type == -1) return XDP_DROP;	
	else if (nh_type != bpf_htons(ETH_P_IPV6) || nh_type != bpf_htons(ETH_P_IP))			
		goto out;				// Just pass the packet cause we only want to drop malicious IP packets

    /* Setting the default block time to 5 minutes (300 seconds) */
    __u64 blocktime = 300; 






    out :
        return XDP_PASS;

}

/* Packet parsing till the IP layer and updating the maps
 based on the IP address. Also refreshing the map after every
 60 seconds and shifting the IP to the Blacklist IP map. */








 /* Dropping packets whose IP is in the Blacklist IP map */