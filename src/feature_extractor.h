#include <stddef.h>

#include <linux/bpf.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "fsx_struct.h"
#include "parsing_helper.h"

// Define the number of samples for calculating variance
#define NUM_SAMPLES 10

struct packet_info {
    __u32 len;
    __u32 fwd_iat;
};

struct feature_info{
	__u64 sum;
	__u64 sum_squared;
    __u64 sum_size;
    __u64 sum_size_squared;
	__u64 fwd_iat_sum;
	__u64 fwd_iat_sum_squared;
    __u32 count;
};

// BPF hash map to store statistics
struct {
        __uint(type, BPF_MAP_TYPE_LRU_HASH);
        __uint(max_entries, PACKETS_THRESHOLD);
        __type(key, __u32);
        __type(value, struct feature_info);
} feature_stats SEC(".maps");

// BPF hash map to store statistics
struct {
        __uint(type, BPF_MAP_TYPE_LRU_HASH);
        __uint(max_entries, PACKETS_THRESHOLD);
        __type(key, __u32);
        __type(value, struct packet_info);
} packet_stats SEC(".maps");


// Helper function to calculate mean
static inline __u64 calc_mean(__u64 sum, __u32 count) {
    return count ? sum / count : 0;
}

// Helper function to calculate variance
static inline __u64 calc_variance(__u64 sum, __u64 sum_squared, __u32 count) {
    if (count == 0)
        return 0;
    __u64 mean = calc_mean(sum, count);
    return count > 1 ? (sum_squared + ((mean - 2*sum)*mean)) / (count-1) : 0;
}

int packet_feature_extractor(struct __sk_buff *skb) {
    // Get packet data
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;

    // Check if packet is TCP
    struct ethhdr *eth = data;
    if (data + sizeof(*eth) > data_end)
        return 0;
    if (eth->h_proto != htons(ETH_P_IP))
        return 0;

    // Parse IP header
    struct iphdr *ip = data + sizeof(*eth);
    if (ip + 1 > data_end)
        return 0;

    // Get packet length and packet size
    __u64 packet_len = bpf_ntohs(ip->tot_len);
    __u64 packet_size = bpf_ntohs(ip->tot_len) + sizeof(struct ethhdr);

    // Calculate fwd_iat
    __u64 now = bpf_ktime_get_ns();
    __u32 fwd_iat = 0;
    __u64 *last_timestamp = skb->cb;
    if (last_timestamp) {
        fwd_iat = now - *last_timestamp;
        *last_timestamp = now;
    } else {
        skb->cb[0] = now;
    }

    // Update statistics
    __u32 key = 0; // Use a single key for all packets
    struct feature_info *info = bpf_map_lookup_elem(&feature_stats, &key);
    if (!info) {
        struct packet_info new_info = {};
        new_info.len = packet_len;
        new_info.fwd_iat = fwd_iat;
        bpf_map_update_elem(&packet_stats, &key, &new_info, BPF_ANY);
    } else {
        // Update mean and sum_squared
        __sync_fetch_and_add(&info->sum, packet_len);
        __sync_fetch_and_add(&info->sum_squared, packet_len * packet_len);
        __sync_fetch_and_add(&info->sum_size, packet_size);
        __sync_fetch_and_add(&info->sum_size_squared, packet_size * packet_size);
		__sync_fetch_and_add(&info->fwd_iat_sum, fwd_iat);
		__sync_fetch_and_add(&info->fwd_iat_sum_squared, fwd_iat * fwd_iat);
        __sync_fetch_and_add(&info->count, 1);
    }

    return 0;
}

struct {
        __uint(type, BPF_MAP_TYPE_LRU_HASH);
        __uint(max_entries, 1);
        __type(key, __u32);
        __type(value, struct feature_info);
} feature_read SEC(".maps");

// User-space function to read statistics
SEC("tracepoint/syscalls/sys_enter_recvmsg")
int syscall__sys_enter_recvmsg(struct trace_event_raw_sys_enter *ctx) {
    __u32 key = 0;
    struct feature_info{
        __u64 sum;
        __u64 sum_squared;
        __u64 sum_size;
        __u64 sum_size_squared;
		__u64 fwd_iat_sum;
		__u64 fwd_iat_sum_squared;
        __u32 count;
    };
	struct feature_info *info = bpf_map_lookup_elem(&feature_read, &key);
    if (info) {
        // Calculate mean and variance
        __u64 mean_packet_len = calc_mean(info->sum, info->count);
        __u64 mean_packet_size = calc_mean(info->sum_size, info->count);
        __u64 mean_fwd_iat = calc_mean(info->fwd_iat_sum, info->count);
        __u64 var_packet_len = calc_variance(info->sum, info->sum_squared, info->count);
        __u64 var_packet_size = calc_variance(info->sum, info->sum_size_squared, info->count);
        __u64 var_fwd_iat = calc_variance(info->fwd_iat_sum, info->fwd_iat_sum_squared, info->count);
        
		//Use the produced variables
    }
    return 0;
}
