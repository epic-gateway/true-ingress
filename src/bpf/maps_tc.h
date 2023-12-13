#ifndef MAPS_TC_H_
#define MAPS_TC_H_

// #################
// #   TC TABLES   #
// #################

#include "bpf_elf.h"

#include "struct_tc.h"

#define MAX_CONFIG_ENTRIES      1024
#define MAX_TUNNEL_ENTRIES      256*1024
#define MAX_SERVICE_ENTRIES     65535
#define MAX_ENCAP_ENTRIES       1024*1024

////////////////////////////////
// TABLE-CONFIG veth-ifindex -> CFG
struct bpf_elf_map SEC(ELF_SECTION_MAPS) map_config = {
    .type       = BPF_MAP_TYPE_HASH,
    .size_key   = sizeof(__u32),
    .size_value = sizeof(struct cfg_if),
    .pinning    = PIN_GLOBAL_NS,
    .max_elem   = MAX_CONFIG_ENTRIES,
};
BPF_ANNOTATE_KV_PAIR(map_config, __u32, struct cfg_if);

////////////////////////////////
// TABLE-ENCAP      EP (12B) -> SERVICE (16B)
struct bpf_elf_map SEC(ELF_SECTION_MAPS) map_encap = {
    .type           = BPF_MAP_TYPE_LRU_HASH,
    .size_key       = sizeof(struct encap_key),
    .size_value     = sizeof(struct service),
    .max_elem       = MAX_ENCAP_ENTRIES,
    .pinning        = PIN_GLOBAL_NS,
};
BPF_ANNOTATE_KV_PAIR(map_encap, struct encap_key, struct service);

////////////////////////////////
// TABLE-TUNNEL tunnel-id (4B) -> GUE (28B)
struct bpf_elf_map SEC(ELF_SECTION_MAPS) map_tunnel = {
    .type           = BPF_MAP_TYPE_LRU_HASH,
    .size_key       = sizeof(__u32),
    .size_value     = sizeof(struct tunnel),
    .max_elem       = MAX_SERVICE_ENTRIES,
    .pinning        = PIN_GLOBAL_NS,
};
BPF_ANNOTATE_KV_PAIR(map_tunnel, __u32, struct tunnel);

////////////////////////////////
// TABLE-PROXY veth-ifindex -> MAC (6B)
struct bpf_elf_map SEC(ELF_SECTION_MAPS) map_proxy = {
    .type           = BPF_MAP_TYPE_HASH,
    .size_key       = sizeof(__u32),
    .size_value     = sizeof(struct mac),
    .max_elem       = MAX_SERVICE_ENTRIES,
    .pinning        = PIN_GLOBAL_NS,
};
BPF_ANNOTATE_KV_PAIR(map_proxy, __u32, struct mac);

#endif /* MAPS_TC_H_ */
