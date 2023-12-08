#ifndef STRUCT_TC_H_
#define STRUCT_TC_H_

#include <bpf/bpf_endian.h>

// #################
// # TC STRUCTURES #
// #################

////////////////////////////////
// MAC
struct mac {
    __u8   value[6];         // MAC address
};

////////////////////////////////
// Endpoint
struct endpoint {
    __u32  ip;                      /* Proxy IP */
    __u16  port;                    /* Proxy port */
    __u16  proto;                   /* IP proto */
};

static inline struct endpoint *
make_endpoint(struct endpoint *ref,
              __u32  ip,
              __u16  port,
              __u16  proto)
{
    ref->ip      = bpf_htonl(ip);
    ref->port    = bpf_htons(port);
    ref->proto   = bpf_htons(proto);
    return ref;
}

////////////////////////////////
// Encap-key (EP + IfIndex)
struct encap_key {
    struct endpoint ep;             /* Destination */
    __u32           ifindex;        /* if-index of proxy container */
};

static inline struct encap_key *
make_encap_key(struct encap_key *ref,
              __u32  ip,
              __u16  port,
              __u16  proto,
              __u32  ifindex)
{
    ref->ep.ip      = bpf_htonl(ip);
    ref->ep.port    = bpf_htons(port);
    ref->ep.proto   = bpf_htons(proto);
    ref->ifindex    = bpf_htonl(ifindex);
    return ref;
}
////////////////////////////////
// Tunnel
struct tunnel {
    __u32  ip_local;              /* outer: sender IP address (configured) */
    __u16  port_local;            /* outer: sender port  (configured)*/
    __u32  ip_remote;             /* outer: target IP address */          // can be NAT, filled from GUE control packet
    __u16  port_remote;           /* outer: target port */                // can be NAT, filled from GUE control packet
    struct mac   mac_remote;         // discovered MAC address
    struct mac   mac_local;         // discovered MAC address
};

static inline struct tunnel *
make_tunnel(struct tunnel *ref,
            __u32  ip_local,
            __u16  port_local,
            __u32  ip_remote,
            __u16  port_remote)
{
    ref->ip_local      = bpf_htonl(ip_local);
    ref->port_local    = bpf_htons(port_local);
    ref->ip_remote     = bpf_htonl(ip_remote);
    ref->port_remote   = bpf_htons(port_remote);
    __builtin_memset(&ref->mac_remote, 0, sizeof(struct mac));
    __builtin_memset(&ref->mac_local, 0, sizeof(struct mac));
    return ref;
}
////////////////////////////////
// Service identity

#define GID_SID_TYPE        __u16

struct identity {
    GID_SID_TYPE  service_id;              /* GUE service ID */
    GID_SID_TYPE  group_id;                /* GUE group ID */
};

static inline struct identity *
make_identity(struct identity *ref,
              GID_SID_TYPE service_id,
              GID_SID_TYPE group_id)
{
    ref->service_id = bpf_htons(service_id);
    ref->group_id = bpf_htons(group_id);
    return ref;
}
////////////////////////////////
// Security key

#define SECURITY_KEY_SIZE   16      /* bytes */

struct verify {
    __u8   value[SECURITY_KEY_SIZE];        /* GUE security KEY */
    __u32  tunnel_id;
    struct encap_key encap;
};

static inline struct verify *
make_verify(struct verify   *ref,
            __u32  tunnel_id,
            struct encap_key *encap)
{
    ref->tunnel_id  = bpf_htonl(tunnel_id);
    __builtin_memcpy(&ref->encap, encap, sizeof(ref->encap));
    return ref;
}

////////////////////////////////
// Service (GUE Header)
struct service {
    struct identity identity;
    struct verify   key;
};

static inline struct service *
make_service(struct service  *ref,
             struct identity *identity,
             struct verify   *key)
{
    ref->identity   = *identity;
    ref->key        = *key;
    return ref;
}

////////////////////////////////
// Configuration

#define CFG_RX_GUE      1       /* unimplemented */
#define CFG_RX_DNAT     2       /* unimplemented */
#define CFG_RX_FWD      4       /* Forward packet after FIB lookup */
#define CFG_RX_DUMP     8       /* Dump intercepted packet */

#define CFG_TX_PROXY    1       /* set in case of EGW (do not set for NODE) */
#define CFG_TX_SNAT     2       /* unimplemented */
#define CFG_TX_FWD      4       /* Forward packet after FIB lookup */
#define CFG_TX_DUMP     8       /* Dump intercepted packet */
#define CFG_TX_FIB     16       /* FIB lookup after encap */

#define CFG_IDX_RX      0
#define CFG_IDX_TX      1
#define CFG_IDX_MAX     2

struct config {
    __u32   flags;
};

struct cfg_if {
    struct config queue[CFG_IDX_MAX];
};

////////////////////////////////
// Statistics

#define STAT_IDX_RX      0
#define STAT_IDX_TX      1
#define STAT_IDX_MAX     2

struct statistics {
    __u64   packets[STAT_IDX_MAX];
    __u64   bytes[STAT_IDX_MAX];
};

#endif /* STRUCT_TC_H_ */
