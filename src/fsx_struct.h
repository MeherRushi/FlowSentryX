#ifndef __MAP_STRUCTURES
#define __MAP_STRUCTURES

#include <linux/types.h>

#define MAX_PCKT_LENGTH 65536
#define MAX_TRACK_IPS 100000

#define BLOCK_TIME 10               // time in minutes
#define PACKETS_THRESHOLD 100   // packets allowed per second
#define BYTES_THRESHOLD 125000000   // bytes allowed per second

#define REFILL_RATE 10      // Number of Tokens added for Token Bucket per second

#define BUCKET_SIZE 2     // Leaky Bucket Size
#define EMPTY_RATE 0.1

#define CASE_CODE 1
#define __u128 __uint128_t

struct stats    
{
    __u64 allowed;
    __u64 dropped;
};

struct ip_stats
{
    __u64 pps;          // packets per second
    __u64 bps;          // bytes per second
    __u64 track_time;   // time at which the packet arrived
};

struct token_bucket
{
    __u64 tokens;
    __u64 maxTokens;    // bucket capacity
    __u64 refillTime;   // time of the last bucket refill
};

struct leaky_bucket
{
    __u64 size;
    __u64 rate;
    __u64 arrival_time;
};

#endif