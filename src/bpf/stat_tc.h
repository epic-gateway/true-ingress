#ifndef TC_STAT_H_
#define TC_STAT_H_

#include "bpf_elf.h"

#include "struct_tc.h"
#include "maps_tc.h"

static inline
__u32 stats_update(__u32 key, __u32 index, struct __sk_buff *skb)
{
    if (index >= STAT_IDX_MAX) {
        char msg[] = "stats_update: Invalid index %u\n";
        bpf_trace_printk(msg, sizeof(msg), index);
        return -1;
    }
    struct statistics *cnt = bpf_map_lookup_elem(&map_stats, &key);
    if (!cnt) {
        struct statistics value = { {0}, {0} };
        value.packets[index] = 1;
        value.bytes[index] = skb->len;
        bpf_map_update_elem(&map_stats, &key, &value, 0);

        return 1;
    } else {
        __sync_fetch_and_add(&cnt->packets[index], 1);
        __sync_fetch_and_add(&cnt->bytes[index], skb->len);

        return cnt->packets[index];
    }
}

static inline
void stats_print(__u32 key)
{
    struct statistics *cnt = bpf_map_lookup_elem(&map_stats, &key);
    if (!cnt) {
        char msg[] = "STAT[%u] %s : -- packets, -- Bytes\n";
        bpf_trace_printk(msg, sizeof(msg), key, "RX");
        bpf_trace_printk(msg, sizeof(msg), key, "TX");
    } else {
        char msg1[] = "STAT[%u] RX : %llu packets, %llu Bytes\n";
        bpf_trace_printk(msg1, sizeof(msg1), key, cnt->packets[STAT_IDX_RX], cnt->bytes[STAT_IDX_RX]);
        char msg2[] = "STAT[%u] TX : %llu packets, %llu Bytes\n";
        bpf_trace_printk(msg2, sizeof(msg2), key, cnt->packets[STAT_IDX_TX], cnt->bytes[STAT_IDX_TX]);
    }
}

#endif /* TC_STAT_H_ */
