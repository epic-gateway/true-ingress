#ifndef TC_STAT_H_
#define TC_STAT_H_

#include "bpf_elf.h"

#include "struct_tc.h"

#define MAP_SIZE_INCOMMING  0
#define MAP_SIZE_MAX        1024

struct bpf_elf_map SEC("maps") map_stats = {
    .type       = BPF_MAP_TYPE_HASH,
    .size_key   = sizeof(__u32),
    .size_value = sizeof(struct statistics),
    .pinning    = PIN_GLOBAL_NS, /* PIN_OBJECT_NS or PIN_GLOBAL_NS, or PIN_NONE */
    .max_elem   = MAP_SIZE_MAX,
};

static inline
int stats_update(__u32 key, struct __sk_buff *skb)
{
    struct statistics *cnt = bpf_map_lookup_elem(&map_stats, &key);
    if (!cnt) {
        return TC_ACT_SHOT;
    }

    __sync_fetch_and_add(&cnt->packets, 1);
    __sync_fetch_and_add(&cnt->bytes, skb->len);

    return TC_ACT_OK;
}

static inline
int stats_print(__u32 key)
{
    struct statistics *cnt = bpf_map_lookup_elem(&map_stats, &key);
    if (!cnt) {
        return TC_ACT_SHOT;
    }

    char msg[] = "STAT[%u] : %llu packets, %llu Bytes\n";
    bpf_trace_printk(msg, sizeof(msg), key, cnt->packets, cnt->bytes);

    return TC_ACT_OK;
}

#endif /* TC_STAT_H_ */
