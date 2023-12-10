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
// TABLE-ENCAP      EP (12B) -> SERVICE (40B)
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, MAX_ENCAP_ENTRIES);
    __type(key, struct encap_key);
    __type(value, struct service);
} map_encap SEC(".maps");

////////////////////////////////
// TABLE-VERIFY     tunnel-id (4B) -> verify (32B)
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_SERVICE_ENTRIES);
    __type(key, struct identity);
    __type(value, struct verify);
} map_verify SEC(".maps");

////////////////////////////////
// TABLE-TUNNEL tunnel-id (4B) -> GUE (18B)
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, MAX_SERVICE_ENTRIES);
    __type(key, __u32);
    __type(value, struct tunnel);
} map_tunnel SEC(".maps");

////////////////////////////////
// TABLE-PROXY veth-ifindex -> MAC (6B)
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_SERVICE_ENTRIES);
    __type(key, __u32);
    __type(value, struct mac);
} map_proxy SEC(".maps");

////////////////////////////////
// TABLE-CONFIG veth-ifindex -> CFG
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_CONFIG_ENTRIES);
    __type(key, __u32);
    __type(value, struct cfg_if);
} map_config SEC(".maps");

#endif /* MAPS_TC_H_ */
