#ifndef STRUCT_TC_H_
#define STRUCT_TC_H_

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

////////////////////////////////
// Tunnel
struct tunnel {
    __u32  ip_local;              /* outer: sender IP address (configured) */
    __u16  port_local;            /* outer: sender port  (configured)*/
    __u32  ip_remote;             /* outer: target IP address */          // can be NAT, filled from GUE control packet
    __u16  port_remote;           /* outer: target port */                // can be NAT, filled from GUE control packet
};

////////////////////////////////
// Service identity

#define GID_SID_TYPE        __u32

struct identity {
    GID_SID_TYPE  service_id;              /* GUE service ID */
    GID_SID_TYPE  group_id;                /* GUE group ID */
};

////////////////////////////////
// Security key

#define SECURITY_KEY_SIZE   16      /* bytes */

struct key {
    __u8   value[SECURITY_KEY_SIZE];        /* GUE security KEY */
};

////////////////////////////////
// Service (GUE Header)
struct service {
    __u32           tunnel_id;
    struct identity identity;
    struct key      key;
};

////////////////////////////////
// "Empty"
//struct empty {
//    __u32    foo;
//};

////////////////////////////////
// Configuration

#define CFG_RX_GUE      1
#define CFG_RX_DNAT     2

#define CFG_TX_PROXY    1
#define CFG_TX_DSO      2

#define CFG_NAME_SIZE   16

#define CFG_IDX_RX      0
#define CFG_IDX_TX      1
#define CFG_IDX_MAX     2

struct config {
    __u32   id;
    __u32   flags;
    char    name[CFG_NAME_SIZE];
};

////////////////////////////////
// Statistics
struct statistics {
    __u64   packets;
    __u64   bytes;
};

#endif /* STRUCT_TC_H_ */
