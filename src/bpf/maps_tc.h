#ifndef MAPS_TC_H_
#define MAPS_TC_H_

// #################
// #   TC TABLES   #
// #################

#include "bpf_elf.h"

#include "struct_tc.h"

#define MAX_CONFIG_ENTRIES      1024
#define MAX_TUNNEL_ENTRIES      1024    /* service records */
#define MAX_SERVICE_ENTRIES     65535
#define MAX_ENTRIES_FOR_DEBUG   3

////////////////////////////////
// TABLE-NAT        EP -> EP (8B)

struct bpf_elf_map SEC(ELF_SECTION_MAPS) map_nat = {
    .type           = BPF_MAP_TYPE_HASH,
    .size_key       = sizeof(struct endpoint),
    .size_value     = sizeof(struct endpoint),
    .max_elem       = 2*MAX_SERVICE_ENTRIES,    /* DNAT + SNAT */
    .pinning        = PIN_GLOBAL_NS,
};
BPF_ANNOTATE_KV_PAIR(map_nat, struct endpoint, struct endpoint);

////////////////////////////////
// TABLE-DECAP      EP -> REF count (4B)

struct bpf_elf_map SEC(ELF_SECTION_MAPS) map_decap = {
    .type           = BPF_MAP_TYPE_HASH,
    .size_key       = sizeof(struct endpoint),
//    .size_value     = sizeof(struct empty),
    .size_value     = sizeof(__u32),
    .max_elem       = MAX_SERVICE_ENTRIES,
    .pinning        = PIN_GLOBAL_NS,
};
BPF_ANNOTATE_KV_PAIR(map_decap, struct endpoint, __u32);

////////////////////////////////
// 3: TABLE-ENCAP      EP (12B) -> SERVICE (40B)

struct bpf_elf_map SEC(ELF_SECTION_MAPS) map_encap = {
    .type           = BPF_MAP_TYPE_LRU_HASH,
    .size_key       = sizeof(struct encap_key),
    .size_value     = sizeof(struct service),
    .max_elem       = MAX_ENTRIES_FOR_DEBUG, /* MAX_SERVICE_ENTRIES */
    .pinning        = PIN_GLOBAL_NS,
};
BPF_ANNOTATE_KV_PAIR(map_encap, struct encap_key, struct service);

////////////////////////////////
// 4: TABLE-VERIFY     tunnel-id (4B) -> verify (32B)

struct bpf_elf_map SEC(ELF_SECTION_MAPS) map_verify = {
    .type           = BPF_MAP_TYPE_HASH,
    .size_key       = sizeof(struct identity),
    .size_value     = sizeof(struct verify),
    .max_elem       = MAX_SERVICE_ENTRIES,
    .pinning        = PIN_GLOBAL_NS,
};
BPF_ANNOTATE_KV_PAIR(map_verify, struct identity, struct verify);

////////////////////////////////
// TABLE-TUNNEL tunnel-id (4B) -> GUE (18B)

struct bpf_elf_map SEC(ELF_SECTION_MAPS) map_tunnel = {
    .type           = BPF_MAP_TYPE_HASH,
    .size_key       = sizeof(__u32),
    .size_value     = sizeof(struct tunnel),
    .max_elem       = MAX_SERVICE_ENTRIES,
    .pinning        = PIN_GLOBAL_NS,
};
BPF_ANNOTATE_KV_PAIR(map_tunnel, __u32, struct tunnel);

////////////////////////////////
// TABE-PROXY veth-ifindex -> MAC (6B)

struct bpf_elf_map SEC(ELF_SECTION_MAPS) map_proxy = {
    .type           = BPF_MAP_TYPE_HASH,
    .size_key       = sizeof(__u32),
    .size_value     = sizeof(struct mac),
    .max_elem       = MAX_SERVICE_ENTRIES,
    .pinning        = PIN_GLOBAL_NS,
};
BPF_ANNOTATE_KV_PAIR(map_proxy, __u32, struct mac);

////////////////////////////////
// TABLE-CONFIG veth-ifindex -> CFG
struct bpf_elf_map SEC(ELF_SECTION_MAPS) map_config = {
    .type       = BPF_MAP_TYPE_HASH,
    .size_key   = sizeof(__u32),
    .size_value = sizeof(struct cfg_if),
    .pinning    = PIN_GLOBAL_NS,
    .max_elem   = CFG_IDX_MAX,
};
BPF_ANNOTATE_KV_PAIR(map_config, __u32, struct cfg_if);

////////////////////////////////
// TABLE-STATS
struct bpf_elf_map SEC(ELF_SECTION_MAPS) map_stats = {
    .type       = BPF_MAP_TYPE_HASH,
    .size_key   = sizeof(__u32),
    .size_value = sizeof(struct statistics),
    .pinning    = PIN_GLOBAL_NS,
    .max_elem   = MAX_CONFIG_ENTRIES,
};
BPF_ANNOTATE_KV_PAIR(map_stats, __u32, struct statistics);

#endif /* MAPS_TC_H_ */
