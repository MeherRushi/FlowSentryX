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
    1) stats_map - We have

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







/* Packet parsing till the IP layer and updating the maps
 based on the IP address. Also refreshing the map after every
 60 seconds and shifting the IP to the Blacklist IP map. */







 /* Dropping packets whose IP is in the Blacklist IP map */