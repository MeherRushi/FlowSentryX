#ifndef __MAP_STRUCTURES
#define __MAP_STRUCTURES

#include <linux/types.h>

#define MAX_PCKT_LENGTH 65536
#define MAX_TRACK_IPS 100000

#define __u128 __uint128_t

struct stats    
{
    __u64 allowed;
    __u64 dropped;
};

struct ip_stats
{
    __u64 pps;
    __u64 bps;
    __u64 track_time;
};


#endif