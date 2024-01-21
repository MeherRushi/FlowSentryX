/* SPDX-License-Identifier: GPL-2.0 */

#include <linux/bpf.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

/* All the packet parsing helper function 
are in the parsing_herlper.h header file 
and structure of the values of the maps are
in the fsx_struct.h map */

#include "fsx_struct.h"
#include "parsing_helper.h"

#ifndef memcpy
#define memcpy(dest, src, n) __builtin_memcpy((dest), (src), (n))
#endif

/* Map declarations 
 We have 5 maps that we need to consider :

    1) stats_map - To store global variables - 1 entry
    of a struct which stores the total number of packets5
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


SEC("xdp")
int fsx(struct xdp_md *ctx)
{
    /* Initialize the data pointers for the packet */
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    struct ethhdr *eth;
    struct iphdr *ip4hdr = NULL;
    struct ipv6hdr *ip6hdr = NULL;


    /* These keep track of the next header type and iterator pointer */
	struct hdr_cursor nh;
	int nh_type;

    /* Start next header cursor position at data start */
	nh.pos = data;

    /* Packet parsing in steps: Get each header one at a time, aborting if
	 * parsing fails. Each helper function does sanity checking (is the
	 * header type in the packet correct?), and bounds checking.
	 */

    /* Ignore non IP based packets - we donot filter them and let the system 
    handle such packets. Ideally in deployment phase we can block these packets
    or extend our filtering system to other layer 3 protocols */

	nh_type = parse_ethhdr(&nh, data_end, &eth);
    if(nh_type == -1) 
    {
        return XDP_DROP;	//Invalid packet parsing- Not considered the packet parsing
    }
	else if (nh_type != bpf_htons(ETH_P_IPV6) && nh_type != bpf_htons(ETH_P_IP)) 
    {
        return XDP_PASS; // Non IPv4 adn Non IPv6 packets - These are not considered in the stats as well
    }

    __u128 srcip6 = 0;

    /* We figure out if the packet is of  IPv4 or IPv6 type*/
    if(nh_type == bpf_htons(ETH_P_IPV6))
    {
        nh_type = parse_ip6hdr(&nh,data_end,&ip6hdr);
        if(nh_type == -1) return XDP_DROP; // Invalid Packet Parsing Drop
        memcpy(&srcip6,&ip6hdr->saddr.in6_u.u6_addr32,sizeof(srcip6));
    }
    else
    {
        nh_type = parse_ip4hdr(&nh,data_end,&ip4hdr);
        if(nh_type == -1) return XDP_DROP; // Invalid Packet Parsing Drop
    }




    __u64 now = bpf_ktime_get_ns();
    __u64 *ip_blocked_till_time = NULL;

    /* So, we first get data from the blacklist ip table regarding
    whether the ip address of the current packet is in the blacklist
    or not, if it present then we retrive the time till which it should
    be blacklisted. After that we decide whether to drop the current 
    packet or not based on the above factors. */

    if(ip6hdr)
    {
        ip_blocked_till_time = bpf_map_lookup_elem(&ipv6_blacklist_map,&srcip6);
        bpf_printk("ip6hder addr found in map");
        //bpf_printk("ipv6 packet address %llu\n",srcip6);
    }
    else if(ip4hdr)
    {
        ip_blocked_till_time = bpf_map_lookup_elem(&ipv4_blacklist_map,&ip4hdr->saddr);
        // for debugging purposes
        bpf_printk("IPv4 source address: %u.%u.",
                   ip4hdr->saddr & 0xFF,
                   (ip4hdr->saddr >> 8) & 0xFF);        
        
        bpf_printk("%u.%u\n",
                   (ip4hdr->saddr >> 16) & 0xFF,
                   (ip4hdr->saddr >> 24) & 0xFF);               

    }
    
    /* Accessing the stats map - Since it is a single element array. The value of the
    struct will be stored at index 0, so we set the stats_map_key to 0 and access the
    stats struct*/

    __u32 stats_map_key = 0;
    struct stats *stats = bpf_map_lookup_elem(&stats_map,&stats_map_key);


    /* If the IP is in the blacklist table (i.e, ip_blocked_till_time != NULL)
    then there is a high chance that we might need to drop this one as well
    so we first do that check before proceed to track the ip stats */

    if(ip_blocked_till_time != NULL && *ip_blocked_till_time > 0)
    {
        bpf_printk("Checking for blocked packet... Block time %llu.\n", *ip_blocked_till_time);

        if(now > *ip_blocked_till_time)
        {
            // Remove element from map.
            if (ip6hdr)
            {
                bpf_map_delete_elem(&ipv6_blacklist_map, &srcip6);
            }
            else if (ip4hdr)
            {
                bpf_map_delete_elem(&ipv4_blacklist_map, &ip4hdr->saddr);
            }
        }
        else
        {   
            // Increase with drop count in stats map
            if(stats)
            {
                stats->dropped++;
            }
            // The time currently is less the time that it should be blocked till 
            // so we still drop the packet
            return XDP_DROP;
        }
    }

    /* If packet is not to be dropped, then it will contribute to the
    no of pps and bps . So here we update the ip_stats maps for ipv4
    and ipv6 maps */

    __u64 pps = 0;
    __u64 bps = 0;

    struct ip_stats *ip_stats = NULL;

    if(ip6hdr)
    {
        ip_stats = bpf_map_lookup_elem(&ipv6_stats_map, &srcip6);
    }
    else if(ip4hdr)
    {
        ip_stats = bpf_map_lookup_elem(&ipv4_stats_map, &ip4hdr->saddr);
    }

    /* We first have to check if there is a entry for that particular ip
    in the ip_stats table. If it is not there we create one, and if it is 
    already there, then we check whether we need to refresh the stats 
    so as to keep track of the count per second (i.e if the now - track_time 
    of the entry) > 1 sec (10^9 nanosec). We reset the values to zero and start from
    scratch.*/

    if(ip_stats)
    {
        if(now - ip_stats->track_time > 1000000000)
        {
            ip_stats->pps = 0;
            ip_stats->bps = 0;
            ip_stats->track_time = now;
        }
        else
        {
            // Increment PPS and BPS using built-in functions.
            // We use sync_fetch_and_add for avoiding synchronization problems
            // This could be further improved by using a per_cpu_array
            // instead of a normal array and shifting the totalling calculation
            // to the user space.
            __sync_fetch_and_add(&ip_stats->pps, 1);
            __sync_fetch_and_add(&ip_stats->bps, ctx->data_end - ctx->data);
            
            pps = ip_stats->pps;
            bps = ip_stats->bps;
        }
    }
    else
    {
        struct ip_stats new;

        new.pps = 1;
        new.bps = ctx->data_end - ctx->data;
        new.track_time = now;

        pps = new.pps;
        bps = new.bps;

        if (ip6hdr)
        {
            bpf_map_update_elem(&ipv6_stats_map, &srcip6, &new, BPF_ANY);
        }
        else if (ip4hdr)
        {
            bpf_map_update_elem(&ipv4_stats_map, &ip4hdr->saddr, &new, BPF_ANY);
        } 
    }

    /* Here, we should write the packet parsing checks for layer 4 protocols
    Extension will be made to cover protocols such as TCP, UDP and ICMPv4 and v6 */
    

    /* Now, after all the updatation and basic checks on the packet have been 
    performed we will now go on implement the most basic rate limiting of static
    window thresholding algorithm. That is if the number of packets of any of the
    IP address is more than the threshold we drop the packet and add the IP to the 
    IP blacklist table for a particular amount of time (blocked_for_time) and also
    we update the global variables in the stats map */

    /* One potential Idea for rate limiting - We plan to introduce a factor of dynamic 
    nature to the rate limiting algorithm. Instead of setting a hard threshold per IP
    address, we set a total over-all threshold and we divide it by the number of IP's 
    that are connected to the device since the last 1 hour or so. Improvement to the 
    algortihm will be made and since this would lead to more computational requirements
    we can move it to the user space  */


    /* 
       Setting the default block time to 5 minutes (300 seconds) 
       Setting the default pps threshold as 1000000 packets (1 million packets)
       Setting the default bps threshold as 125000 GigaBytes per second (1Gbps - 1 Gigabit per second)
    */
    __u64 blocked_for_time = 10; 
    __u64 pps_threshold = 1000;
    __u64 bps_threshold = 125000000 ;

    if(pps > pps_threshold || bps > bps_threshold)
    {
        // Add the IP to the blacklist table and drop the packet
        // also update the drop count

        __u64 new_ip_blocked_till_time = now + (blocked_for_time * 1000000000);

        if(ip6hdr)
        {
            bpf_map_update_elem(&ipv6_blacklist_map, &srcip6, &new_ip_blocked_till_time, BPF_ANY);
        }
        else if(ip4hdr)
        {
            bpf_map_update_elem(&ipv4_blacklist_map, &ip4hdr->saddr, &new_ip_blocked_till_time, BPF_ANY);
        }

        if(stats) // Implementing access checks are compulsory else the ebpf verifier will not load it to the kernel

        {   
            bpf_printk("Rate limit exceeded \n pps : %llu \n bps : %llu \n", pps, bps);
            stats->dropped++;
            bpf_printk("No of packets dropped %llu\n", stats->dropped);
        }
        return XDP_DROP;
    }

    // update the allowed count and XDP_PASS. Implementing access checks are
    // compulsory else the ebpf verifier will not load it to the kernel
    if(stats)
    {   
        stats->allowed++;
        bpf_printk("No of packets allowed %llu\n", stats->allowed);
    }

    
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
