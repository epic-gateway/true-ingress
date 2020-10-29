#ifndef MAPS_TC_H_
#define MAPS_TC_H_

// #################
// #   TC TABLES   #
// #################

#include "bpf_elf.h"

#include "stat_tc.h"
#include "struct_tc.h"


#define MAX_TUNNEL_ENTRIES      1024    /* service records */
#define MAX_SERVICE_ENTRIES     1024

////////////////////////////////
// TABLE-NAT        EP -> EP

struct bpf_elf_map SEC("maps") map_nat = {
    .type           = BPF_MAP_TYPE_HASH,
    .size_key       = sizeof(struct endpoint),
    .size_value     = sizeof(struct endpoint),
    .max_elem       = 2*MAX_SERVICE_ENTRIES,    /* DNAT + SNAT */
    .pinning        = PIN_GLOBAL_NS,
};

////////////////////////////////
// TABLE-DECAP      EP -> REF count

struct bpf_elf_map SEC("maps") map_decap = {
    .type           = BPF_MAP_TYPE_HASH,
    .size_key       = sizeof(struct endpoint),
//    .size_value     = sizeof(struct empty),
    .size_value     = sizeof(__u32),
    .max_elem       = MAX_TUNNEL_ENTRIES,
    .pinning        = PIN_GLOBAL_NS,
};

////////////////////////////////
// TABLE-ENCAP      EP -> SERVICE

struct bpf_elf_map SEC("maps") map_encap = {
    .type           = BPF_MAP_TYPE_HASH,
    .size_key       = sizeof(struct endpoint),
    .size_value     = sizeof(struct service),
    .max_elem       = MAX_TUNNEL_ENTRIES,
    .pinning        = PIN_GLOBAL_NS,
};

struct bpf_elf_map SEC("maps") map_proxy_encap = {
    .type           = BPF_MAP_TYPE_HASH,
    .size_key       = sizeof(struct proxy_encap_key),
    .size_value     = sizeof(struct service),
    .max_elem       = MAX_TUNNEL_ENTRIES,
    .pinning        = PIN_GLOBAL_NS,
};

////////////////////////////////
// TABLE-VERIFY     SID -> KEY

struct bpf_elf_map SEC("maps") map_verify = {
    .type           = BPF_MAP_TYPE_HASH,
    .size_key       = sizeof(struct identity),
    .size_value     = sizeof(struct verify),
    .max_elem       = MAX_SERVICE_ENTRIES,
    .pinning        = PIN_GLOBAL_NS,
};

////////////////////////////////
// TABLE-TUNNEL tunnel-id -> GUE

struct bpf_elf_map SEC("maps") map_tunnel = {
    .type           = BPF_MAP_TYPE_HASH,
    .size_key       = sizeof(__u32),
    .size_value     = sizeof(struct tunnel),
    .max_elem       = MAX_TUNNEL_ENTRIES,
    .pinning        = PIN_GLOBAL_NS,
};

////////////////////////////////
// TABE-PROXY veth-ifindex -> MAC

struct bpf_elf_map SEC("maps") map_proxy = {
    .type           = BPF_MAP_TYPE_HASH,
    .size_key       = sizeof(__u32),
    .size_value     = sizeof(struct mac),
    .max_elem       = MAX_TUNNEL_ENTRIES,
    .pinning        = PIN_GLOBAL_NS,
};

#endif /* MAPS_TC_H_ */
