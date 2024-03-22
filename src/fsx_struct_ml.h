#ifndef __MAP_STRUCTURES
#define __MAP_STRUCTURES

#include <linux/types.h>

#define MAX_PCKT_LENGTH 65536
#define MAX_TRACK_IPS 100000
#define PINNED_MAP_PATH "/sys/fs/bpf/q_weight_param"

#define __u128 __uint128_t

struct stats
{
    __u64 allowed;
    __u64 dropped;
};

struct ip_stats
{
    __u64 pps;        // packets per second
    __u64 bps;        // bytes per second
    __u64 track_time; // time at which the packet arrived
};

#endif