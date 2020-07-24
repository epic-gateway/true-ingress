#ifndef STRUCT_TC_H_
#define STRUCT_TC_H_

#include <bpf/bpf_endian.h>

// #################
// # TC STRUCTURES #
// #################

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
// Tunnel
struct tunnel {
    __u32  ip_local;              /* outer: sender IP address (configured) */
    __u16  port_local;            /* outer: sender port  (configured)*/
    __u32  ip_remote;             /* outer: target IP address */          // can be NAT, filled from GUE control packet
    __u16  port_remote;           /* outer: target port */                // can be NAT, filled from GUE control packet
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
    struct endpoint dnat;
    struct endpoint snat;
};

static inline struct verify *
make_verify(struct verify   *ref,
            struct endpoint *dnat,
            struct endpoint *snat)
{
    ref->dnat.ip    = dnat->ip;
    ref->dnat.port  = dnat->port;
    ref->dnat.proto = dnat->proto;
    ref->snat.ip    = snat->ip;
    ref->snat.port  = snat->port;
    ref->snat.proto = snat->proto;
    return ref;
}

////////////////////////////////
// Service (GUE Header)
struct service {
    __u32           tunnel_id;
    struct identity identity;
    struct verify   key;
};

static inline struct service *
make_service(struct service  *ref,
             __u32            tunnel_id,
             struct identity *identity,
             struct verify   *key)
{
    ref->tunnel_id  = bpf_htonl(tunnel_id);
    ref->identity   = *identity;
    ref->key        = *key;
    return ref;
}
////////////////////////////////
// "Empty"
//struct empty {
//    __u32    foo;
//};

////////////////////////////////
// Configuration

#define CFG_RX_GUE      1       /* check TABLE_DECAP to match and decapsulate decapsulate GUE */
#define CFG_RX_DNAT     2       /* check TABLE-NAT to match and perform DNAT */
#define CFG_RX_DUMP     8       /* DUMP intercepted packet */

#define CFG_TX_PROXY    1       /* set in case of EGW (do not set for NODE) */
#define CFG_TX_SNAT     2       /* check TABLE-NAT to match and perform DNAT */
#define CFG_TX_DUMP     8       /* DUMP intercepted packet */

#define CFG_NAME_SIZE   16

#define CFG_IDX_RX      0
#define CFG_IDX_TX      1
#define CFG_IDX_MAX     2

struct config {
    __u32   id;
    __u32   flags;
    char    name[CFG_NAME_SIZE];
};

static inline struct config *
make_config(struct config  *ref,
             __u32   id,
             __u32   flags)
{
    ref->id     = id;
    ref->flags  = flags;
    return ref;
}

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
