#ifndef MAPS_TC_H_
#define MAPS_TC_H_

// #################
// #   TC TABLES   #
// #################

#include "bpf_elf.h"

#include "stat_tc.h"
#include "struct_tc.h"


#define MAX_TUNNEL_ENTRIES      1024    /* service records */
#define MAX_SERVICE_ENTRIES     65535

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
// TABLE-ENCAP      EP -> SERVICE (56B)

struct bpf_elf_map SEC(ELF_SECTION_MAPS) map_encap = {
    .type           = BPF_MAP_TYPE_HASH,
    .size_key       = sizeof(struct encap_key),
    .size_value     = sizeof(struct service),
    .max_elem       = MAX_SERVICE_ENTRIES,
    .pinning        = PIN_GLOBAL_NS,
};
BPF_ANNOTATE_KV_PAIR(map_encap, struct encap_key, struct service);

////////////////////////////////
// TABLE-VERIFY     SID -> KEY (40B)

struct bpf_elf_map SEC(ELF_SECTION_MAPS) map_verify = {
    .type           = BPF_MAP_TYPE_HASH,
    .size_key       = sizeof(struct identity),
    .size_value     = sizeof(struct verify),
    .max_elem       = MAX_SERVICE_ENTRIES,
    .pinning        = PIN_GLOBAL_NS,
};
BPF_ANNOTATE_KV_PAIR(map_verify, struct identity, struct verify);

////////////////////////////////
// TABLE-TUNNEL tunnel-id -> GUE (18B)

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

#endif /* MAPS_TC_H_ */
