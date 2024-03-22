#ifndef __MAP_STRUCTURES
#define __MAP_STRUCTURES

#include <linux/types.h>
#include <stdint.h>
#include <math.h>

#define MAX_PCKT_LENGTH 65536
#define MAX_TRACK_IPS 100000
// #define PINNED_MAP_PATH "/sys/fs/bpf/q_weight_param"

// Define the size of the fixed-point representation
#define FXP_VALUE 8
#define ROUND_CONST (1 << (FXP_VALUE - 1)) // = 0.5 to before right shifting to improve rounding

// Define the feature list
#define DESTINATION_PORT 1
#define PACKET_LENGTH_MEAN 2
#define PACKET_LENGTH_STD 3
#define PACKET_LENGTH_VARIANCE 4
#define AVERAGE_PACKET_SIZE 5
#define FWD_IAT_MEAN 6
#define FWD_IAT_STD 7
#define FWD_IAT_MAX 8

// Define the number of features
#define NUM_FEATURES 8

// Define the ML model weights
#define NUM_WEIGHTS 8
static int8_t weights[NUM_WEIGHTS] = {0, -22, 13, 87, 127, -84, 23, -81};

// Define the scale and zero point for weights
#define WEIGHT_SCALE 317 // 1 / 0.003100323723629117
#define WEIGHT_ZERO_POINT 0

// Define sigmoid parameters
#define SIGMOID_SCALE (1 << FXP_VALUE)
#define SIGMOID_ZERO_POINT (1 << (FXP_VALUE - 1)) // 0.5 in fixed-point representation

// Helper function to calculate mean
static inline __u64 calc_mean(__u64 sum, __u32 count)
{
    return count ? sum / count : 0;
}

// Helper function to calculate variance
static inline __u64 calc_variance(__u64 sum, __u64 sum_squared, __u32 count)
{
    if (count == 0)
        return 0;
    __u64 mean = calc_mean(sum, count);
    return count > 1 ? (sum_squared - (sum * mean)) / (count - 1) : 0;
}

// Sigmoid activation function using fixed-point arithmetic
static inline int8_t sigmoid(int8_t x)
{
    // Convert x to fixed-point representation
    int16_t x_fixed = (x * SIGMOID_SCALE) + SIGMOID_ZERO_POINT;

    // Apply sigmoid function
    int16_t sigmoid_result = 0;
    if (x_fixed < 0)
    {
        sigmoid_result = 0;
    }
    else if (x_fixed >= (SIGMOID_SCALE << FXP_VALUE))
    {
        sigmoid_result = SIGMOID_SCALE;
    }
    else
    {
        // Compute sigmoid function using fixed-point arithmetic
        sigmoid_result = SIGMOID_SCALE / (1 + exp(-x_fixed / (float)SIGMOID_SCALE));
    }

    // Convert back to integer representation
    return sigmoid_result >> (FXP_VALUE - 8);
}

// Helper function to update feature statistics
static inline void update_feature_stats(__u32 key, __u64 value)
{
    struct feature_info *info = bpf_map_lookup_elem(&feature_stats, &key);
    if (!info)
    {
        struct feature_info new_info = {};
        new_info.sum = value;
        new_info.sum_squared = value * value;
        new_info.count = 1;
        bpf_map_update_elem(&feature_stats, &key, &new_info, BPF_ANY);
    }
    else
    {
        __sync_fetch_and_add(&info->sum, value);
        __sync_fetch_and_add(&info->sum_squared, value * value);
        __sync_fetch_and_add(&info->count, 1);
    }
}

// Structure for packet information
struct packet_info
{
    __u16 dest_port;
    __u32 packet_len;
    __u64 fwd_iat;
};

// Structure for feature information
struct feature_info
{
    __u64 sum;
    __u64 sum_squared;
    __u32 count;
};

// Structure for ML model input
struct model_input {
    int8_t features[NUM_FEATURES];
};

// Structure to hold packet timestamp
struct packet_timestamp
{
    __u64 timestamp;
};

int key = 0;
// Helper function to update packet timestamp
static inline void update_packet_timestamp(__u64 timestamp)
{
    struct packet_timestamp pkt_ts = {.timestamp = timestamp};
    bpf_map_update_elem(&packet_timestamps, &(key), &pkt_ts, BPF_ANY);
}

// Helper function to get packet timestamp
static inline __u64 get_packet_timestamp()
{
    struct packet_timestamp *pkt_ts = bpf_map_lookup_elem(&packet_timestamps, &(0));
    if (pkt_ts)
        return pkt_ts->timestamp;
    return 0;
}

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