#ifndef TC_PFC_H_
#define TC_PFC_H_

#include <linux/in.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>

#include "common_tc.h"

struct guehdr {
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
    __u8    hlen : 5,
            control : 1,
            version : 2;
#else
    __u8    version : 2,
            control : 1,
            hlen : 5;
#endif
    __u8 proto_ctype;
    __u16 flags;
};

struct gueext1hdr {
    __u32   id;
};

struct gueext5hdr {
    __u32   id;
    __u8    key[16];
};

struct tunhdr {
    struct iphdr        ip;
    struct udphdr       udp;
    __u32               gue;
    __u32               gue_id;
    __u64               gue_key[2];
} __attribute__((packed));

struct headers {
    struct ethhdr *eth;
    struct iphdr *iph;
    struct tcphdr *tcph;
    struct udphdr *udph;
    void *payload;
    __u32 off_eth;
    __u32 off_iph;
    __u32 off_tcph;
    __u32 off_udph;
    __u32 off_payload;
};

static inline
int parse_headers(struct __sk_buff *skb, struct headers *hdr)
{
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;
    __u32 nh_off = 0;

    hdr->eth = data;
    hdr->off_eth = nh_off;

    nh_off += sizeof(*hdr->eth);
    if (data + nh_off > data_end)
    {
        bpf_print("ERROR: (ETH) Invalid packet size\n");
        return TC_ACT_SHOT;
    }

    if (hdr->eth->h_proto != bpf_htons(ETH_P_IP))
    {
        return TC_ACT_SHOT;
    }
    
    hdr->iph = data + nh_off;
    hdr->off_iph = nh_off;
    nh_off += sizeof(struct iphdr);
    if (data + nh_off > data_end)
    {
        bpf_print("ERROR: (IPv4) Invalid packet size\n");
        return TC_ACT_SHOT;
    }

    if (hdr->iph->protocol == IPPROTO_TCP)
    {
        hdr->tcph = data + nh_off;
        hdr->off_tcph = nh_off;
        nh_off += sizeof(struct tcphdr);
        if ((void*)&hdr->tcph[1] > data_end)
        {
            bpf_print("ERROR: (UDP) Invalid packet size\n");
            return TC_ACT_SHOT;
        }
        hdr->payload = (void*)&hdr->tcph[1];
        hdr->off_payload = nh_off;
        return TC_ACT_OK;
    }
    else if (hdr->iph->protocol == IPPROTO_UDP)
    {
        hdr->udph = data + nh_off;
        hdr->off_udph = nh_off;
        nh_off += sizeof(struct udphdr);
        if ((void*)&hdr->udph[1] > data_end)
        {
            bpf_print("ERROR: (UDP) Invalid packet size\n");
            return TC_ACT_SHOT;
        }
        hdr->payload = (void*)&hdr->udph[1];
        hdr->off_payload = nh_off;
        return TC_ACT_OK;
    }

    return TC_ACT_SHOT;
}

static inline
int set_mss(struct __sk_buff *skb, __u16 new_mss)
{
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;
    __u32 nh_off = 0;
    struct ethhdr *eth;
    struct iphdr *iph;
    struct tcphdr *tcph;

    eth = data;
    nh_off += sizeof(struct ethhdr);
    if (data + nh_off > data_end)
    {
        bpf_print("ERROR: (ETH) Invalid packet size\n");
        return TC_ACT_SHOT;
    }

    if (eth->h_proto != bpf_htons(ETH_P_IP))
    {
        return TC_ACT_OK;
    }

    iph = data + nh_off;
    nh_off += sizeof(struct iphdr);
    if (data + nh_off > data_end)
    {
        bpf_print("ERROR: (IPv4) Invalid packet size\n");
        return TC_ACT_SHOT;
    }

    if (iph->protocol != IPPROTO_TCP)
    {
        return TC_ACT_OK;
    }

    tcph = data + nh_off;
    nh_off += sizeof(struct tcphdr);
    if ((void*)&tcph[1] > data_end)
    {
        bpf_print("ERROR: (UDP) Invalid packet size\n");
        return TC_ACT_SHOT;
    }

    if (!tcph->syn) {
        return TC_ACT_OK;
    }

    __u32 *optx = (void*)&tcph[1];
    int i = 0;

    #pragma clang loop unroll(full)
    for (i = 0; i < 10; i++) {
        if (i >= (tcph->doff - 5)) {
            break;
        }

        ASSERT((void*)&optx[i+1] <= data_end, TC_ACT_OK, "ERROR: (TCP) no OPT anymore\n");
        if ((bpf_ntohl(optx[i]) >> 16) == 0x0204) {
            __u16 *old_mss = (__u16 *)&optx[i];
            if (bpf_ntohs(old_mss[1]) > new_mss) {
                bpf_print("Replacing mss %u -> %u\n", old_mss, new_mss);
                old_mss[1] = bpf_htons(new_mss);
            }
            break;
        }
    }

    return TC_ACT_OK;
}

static inline
int parse_ep(struct __sk_buff *skb, struct endpoint *sep, struct endpoint *dep)
{
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;
    __u32 nh_off = 0;
    struct ethhdr *eth;
    struct iphdr *iph;
    struct tcphdr *tcph;
    struct udphdr *udph;

    eth = data;
    nh_off += sizeof(struct ethhdr);
    if (data + nh_off > data_end)
    {
        bpf_print("ERROR: (ETH) Invalid packet size\n");
        return TC_ACT_SHOT;
    }

    if (eth->h_proto != bpf_htons(ETH_P_IP))
    {
        return TC_ACT_SHOT;
    }

    iph = data + nh_off;
    nh_off += sizeof(struct iphdr);
    if (data + nh_off > data_end)
    {
        bpf_print("ERROR: (IPv4) Invalid packet size\n");
        return TC_ACT_SHOT;
    }

    sep->ip       = bpf_htonl(iph->saddr);
    sep->proto    = bpf_htons(iph->protocol);
    dep->ip       = bpf_htonl(iph->saddr);
    dep->proto    = bpf_htons(iph->protocol);

    if (iph->protocol == IPPROTO_TCP)
    {
        tcph = data + nh_off;
        nh_off += sizeof(struct tcphdr);
        if ((void*)&tcph[1] > data_end)
        {
            bpf_print("ERROR: (UDP) Invalid packet size\n");
            return TC_ACT_SHOT;
        }
        sep->port = tcph->source;
        dep->port = tcph->dest;
        return TC_ACT_OK;
    }
    else if (iph->protocol == IPPROTO_UDP)
    {
        udph = data + nh_off;
        nh_off += sizeof(struct udphdr);
        if ((void*)&udph[1] > data_end)
        {
            bpf_print("ERROR: (UDP) Invalid packet size\n");
            return TC_ACT_SHOT;
        }
        sep->port = udph->source;
        dep->port = udph->dest;
        return TC_ACT_OK;
    }

    return TC_ACT_SHOT;
}

static inline
void parse_src_ep(struct endpoint *ep, struct headers *hdr)
{
    ep->ip       = bpf_htonl(hdr->iph->saddr);
    ep->proto    = bpf_htons(hdr->iph->protocol);
    if (hdr->tcph)
        ep->port = hdr->tcph->source;
    else if (hdr->udph)
        ep->port = hdr->udph->source;
    else
        ep->port = 0;

//    bpf_print("Parsed Source EP: ip %x, port %u, proto %u\n", ep->ip, bpf_ntohs(ep->port), bpf_ntohs(ep->proto));
//    bpf_print("Parsed Source EP: %lx\n", *(__u64*)ep);
}

static inline
void parse_dest_ep(struct endpoint *ep, struct headers *hdr)
{
    ep->ip       = bpf_htonl(hdr->iph->daddr);
    ep->proto    = bpf_htons(hdr->iph->protocol);
    if (hdr->tcph)
        ep->port = hdr->tcph->dest;
    else if (hdr->udph)
        ep->port = hdr->udph->dest;

//    bpf_print("Parsed Destination EP: ip %x, port %u, proto %u\n", ep->ip, bpf_ntohs(ep->port), bpf_ntohs(ep->proto));
//    bpf_print("Parsed Destination EP: %lx\n", *(__u64*)ep);
}

#define IP_CSUM_OFF offsetof(struct iphdr, check)
#define IP_DST_OFF offsetof(struct iphdr, daddr)
#define IP_SRC_OFF offsetof(struct iphdr, saddr)

#define TCP_CSUM_OFF offsetof(struct tcphdr, check)
#define TCP_SPORT_OFF offsetof(struct tcphdr, source)
#define TCP_DPORT_OFF offsetof(struct tcphdr, dest)

#define UDP_CSUM_OFF offsetof(struct udphdr, check)
#define UDP_SPORT_OFF offsetof(struct udphdr, source)
#define UDP_DPORT_OFF offsetof(struct udphdr, dest)

#define IS_PSEUDO 0x10

static inline
int dnat4(struct __sk_buff *skb, struct headers *hdr, __u32 new_ip, __u16 new_port)
{
    int ret, off_l4_csum = 0, off_port = 0, flags = IS_PSEUDO;
    __u32 old_ip = hdr->iph->daddr;
    __u16 old_port = 0;

    switch (hdr->iph->protocol) {
    case IPPROTO_TCP:
        off_l4_csum = hdr->off_tcph + TCP_CSUM_OFF;
        off_port = hdr->off_tcph + TCP_DPORT_OFF;
        break;

    case IPPROTO_UDP:
        off_l4_csum = hdr->off_udph + UDP_CSUM_OFF;
        off_port = hdr->off_udph + UDP_DPORT_OFF;
        flags |= BPF_F_MARK_MANGLED_0;
        break;
    }

    ASSERT(off_port, TC_ACT_OK, "Couldn\'t determine port offset\n");
    ASSERT(off_l4_csum, TC_ACT_OK, "Couldn\'t determine csum offset\n");

    if (bpf_skb_load_bytes(skb, off_port, &old_port, sizeof(old_port)) < 0) {
        return TC_ACT_OK;
    }

    // checksum
    ret = bpf_l4_csum_replace(skb, off_l4_csum, old_ip, new_ip, flags | sizeof(new_ip));
    ASSERT(ret >= 0, TC_ACT_UNSPEC, "bpf_l4_csum_replace failed: %d\n", ret);

    ret = bpf_l4_csum_replace(skb, off_l4_csum, old_port, new_port, flags | sizeof(new_port));
    ASSERT(ret >= 0, TC_ACT_UNSPEC, "bpf_l4_csum_replace failed: %d\n", ret);

    ret = bpf_l3_csum_replace(skb, hdr->off_iph + IP_CSUM_OFF, old_ip, new_ip, sizeof(new_ip));
    ASSERT(ret >= 0, TC_ACT_UNSPEC, "bpf_l3_csum_replace failed: %d\n", ret);

    // values
    ret = bpf_skb_store_bytes(skb, hdr->off_iph + IP_DST_OFF, &new_ip, sizeof(new_ip), 0);
    ASSERT(ret >= 0, TC_ACT_UNSPEC, "bpf_skb_store_bytes() failed: %d\n", ret);

    ret = bpf_skb_store_bytes(skb, off_port, &new_port, sizeof(new_port), 0);
    ASSERT(ret >= 0, TC_ACT_UNSPEC, "bpf_skb_store_bytes() failed: %d\n", ret);

    return TC_ACT_OK;
}

static inline
int snat4(struct __sk_buff *skb, struct headers *hdr, __u32 new_ip, __u16 new_port)
{
    int ret, off_l4_csum = 0, off_port = 0, flags = IS_PSEUDO;
    __u32 old_ip = hdr->iph->saddr;
    __u16 old_port = 0;

    switch (hdr->iph->protocol) {
    case IPPROTO_TCP:
        off_l4_csum = hdr->off_tcph + TCP_CSUM_OFF;
        off_port = hdr->off_tcph + TCP_SPORT_OFF;
        break;

    case IPPROTO_UDP:
        off_l4_csum = hdr->off_udph + UDP_CSUM_OFF;
        off_port = hdr->off_udph + UDP_SPORT_OFF;
        flags |= BPF_F_MARK_MANGLED_0;
        break;
    }

    ASSERT(off_port, TC_ACT_OK, "Couldn\'t determine port offset\n");
    ASSERT(off_l4_csum, TC_ACT_OK, "Couldn\'t determine csum offset\n");

    if (bpf_skb_load_bytes(skb, off_port, &old_port, sizeof(old_port)) < 0) {
        return TC_ACT_OK;
    }

    // checksum
    ret = bpf_l4_csum_replace(skb, off_l4_csum, old_ip, new_ip, flags | sizeof(new_ip));
    ASSERT(ret >= 0, TC_ACT_UNSPEC, "bpf_l4_csum_replace failed: %d\n", ret);

    ret = bpf_l4_csum_replace(skb, off_l4_csum, old_port, new_port, flags | sizeof(new_port));
    ASSERT(ret >= 0, TC_ACT_UNSPEC, "bpf_l4_csum_replace failed: %d\n", ret);

    ret = bpf_l3_csum_replace(skb, hdr->off_iph + IP_CSUM_OFF, old_ip, new_ip, sizeof(new_ip));
    ASSERT(ret >= 0, TC_ACT_UNSPEC, "bpf_l3_csum_replace failed: %d\n", ret);

    // values
    ret = bpf_skb_store_bytes(skb, hdr->off_iph + IP_SRC_OFF, &new_ip, sizeof(new_ip), 0);
    ASSERT(ret >= 0, TC_ACT_UNSPEC, "bpf_skb_store_bytes() failed: %d\n", ret);

    ret = bpf_skb_store_bytes(skb, off_port, &new_port, sizeof(new_port), 0);
    ASSERT(ret >= 0, TC_ACT_UNSPEC, "bpf_skb_store_bytes() failed: %d\n", ret);

    return TC_ACT_OK;
}

//////////////////////////////
// GUE
static inline
int update_tunnel_from_guec(__u32 tunnel_id, struct headers *hdr)
{
    // update map
    struct tunnel *tun = bpf_map_lookup_elem(&map_tunnel, &tunnel_id);
    ASSERT(tun, TC_ACT_SHOT, "ERROR: Failed to update tunnel-id %u\n", tunnel_id);

    struct endpoint ep = { 0 };
    parse_src_ep(&ep, hdr);
    bpf_print("GUE Control: Updating tunnel-id %u remote to %x:%u\n", tunnel_id, ep.ip, bpf_ntohs(ep.port));
    tun->ip_remote = ep.ip;
    tun->port_remote = ep.port;
    tun->mac_remote[0] = hdr->eth->h_source[0];
    tun->mac_remote[1] = hdr->eth->h_source[1];
    tun->mac_remote[2] = hdr->eth->h_source[2];
    tun->mac_remote[3] = hdr->eth->h_source[3];
    tun->mac_remote[4] = hdr->eth->h_source[4];
    tun->mac_remote[5] = hdr->eth->h_source[5];

    return TC_ACT_SHOT;
}

static inline
int service_verify(struct gueext5hdr *gueext)
{
    struct identity id = *(struct identity *)&gueext->id;
    struct verify *vrf = bpf_map_lookup_elem(&map_verify, (struct identity *)&gueext->id);
    ASSERT(vrf != 0, dump_action(TC_ACT_UNSPEC), "ERROR: Service (group-id %u, service-id %u) not found!\n", bpf_ntohs(id.service_id), bpf_ntohs(id.group_id));

    __u64 *ref_key = (__u64 *)vrf->value;
    __u64 *pkt_key = (__u64 *)gueext->key;

    if ((pkt_key[0] != ref_key[0]) || (pkt_key[1] != ref_key[1])) {
        bpf_print("ERROR: Service (group-id %u, service-id %u) key mismatch!\n", bpf_ntohs(id.service_id), bpf_ntohs(id.group_id));
        bpf_print("    Expected : %lx%lx\n", bpf_ntohll(ref_key[0]), bpf_ntohll(ref_key[1]));
        bpf_print("    Received : %lx%lx\n", bpf_ntohll(pkt_key[0]), bpf_ntohll(pkt_key[1]));
        return 1;
    }

    bpf_print("Service (group-id %u, service-id %u) key verified\n", bpf_ntohs(id.service_id), bpf_ntohs(id.group_id));
    return 0;
}


static __always_inline
void set_ipv4_csum(struct iphdr *iph)
{
    __u16 *iph16 = (__u16 *)iph;
    __u32 csum = 0;
    int i;

    iph->check = 0;

#pragma clang loop unroll(full)
    for (i = 0, csum = 0; i < sizeof(*iph) >> 1; i++)
        csum += *iph16++;

    iph->check = ~((csum & 0xffff) + (csum >> 16));
}

static __always_inline
int gue_encap_v4(struct __sk_buff *skb, struct tunnel *tun, struct service *svc)
{
    struct iphdr iph_inner = { 0 };
    struct tunhdr h_outer = {{0}, {0}, 0, 0, {0, 0}};
    int olen = sizeof(h_outer);
    __u64 flags = 0;
    __u64 *from = (__u64 *)svc->key.value;
    int ret;

    if (bpf_skb_load_bytes(skb, ETH_HLEN, &iph_inner, sizeof(iph_inner)) < 0)
        return TC_ACT_OK;

    // prepare new outer network header
    // fill GUE
    h_outer.gue = 0xa00405;   //GUE data header: 0x0504a000
    h_outer.gue_id = svc->identity.service_id + (svc->identity.group_id << 16);
    h_outer.gue_key[0] = from[0];
    h_outer.gue_key[1] = from[1];

    // fill IP
    h_outer.ip = iph_inner;
    h_outer.ip.daddr = bpf_htonl(tun->ip_remote);
    h_outer.ip.saddr = bpf_htonl(tun->ip_local);
    h_outer.ip.tot_len = bpf_htons(olen + bpf_ntohs(h_outer.ip.tot_len));
    h_outer.ip.protocol = IPPROTO_UDP;
    h_outer.ip.tos = 0;     // SET EXPLICIT TRAFFIC CLASS

    set_ipv4_csum((void *)&h_outer.ip);

    // fill UDP
    int len = bpf_ntohs(iph_inner.tot_len) + sizeof(h_outer.udp) + sizeof(h_outer.gue) + 20 /*sizeof(h_outer.gueext*/;
    h_outer.udp.dest    = tun->port_remote;
    h_outer.udp.source  = tun->port_local;
    h_outer.udp.len     = bpf_htons(len);
    h_outer.udp.check   = 0;

    // add room between mac and network header
    flags = BPF_F_ADJ_ROOM_FIXED_GSO | BPF_F_ADJ_ROOM_ENCAP_L3_IPV4 | BPF_F_ADJ_ROOM_ENCAP_L4_UDP;
    ret = bpf_skb_adjust_room(skb, olen, BPF_ADJ_ROOM_MAC, flags); 
    if (ret) {
        bpf_print("bpf_skb_adjust_room: %d\n", ret);
        return TC_ACT_SHOT;
    }

    // store new outer network header
    ret = bpf_skb_store_bytes(skb, ETH_HLEN, &h_outer, olen, BPF_F_INVALIDATE_HASH);
    if (ret < 0) {
        bpf_print("bpf_skb_store_bytes: %d\n", ret);
        return TC_ACT_SHOT;
    }

    // Resolve destination MAC
    __u32 *ptr = (__u32 *)&tun->mac_remote[2];
    if (*ptr == 0) {
        bpf_print("Performing MAC lookup\n");
        struct bpf_fib_lookup fib_params = { 0 };

        fib_params.family       = AF_INET;
        fib_params.tos          = h_outer.ip.tos;
        fib_params.l4_protocol  = IPPROTO_UDP;
        fib_params.sport        = 0;
        fib_params.dport        = 0;
        fib_params.tot_len      = bpf_ntohs(h_outer.ip.tot_len);
        fib_params.ipv4_src     = bpf_htonl(tun->ip_local);
        fib_params.ipv4_dst     = bpf_htonl(tun->ip_remote);
        fib_params.ifindex      = skb->ifindex;

        // flags: 0, BPF_FIB_LOOKUP_DIRECT 1, BPF_FIB_LOOKUP_OUTPUT 2
        #define MY_BPF_FIB_LOOKUP_DIRECT  1
        #define MY_BPF_FIB_LOOKUP_OUTPUT  2
        int rc = bpf_fib_lookup(skb, &fib_params, sizeof(fib_params), MY_BPF_FIB_LOOKUP_DIRECT | MY_BPF_FIB_LOOKUP_OUTPUT);
        switch (rc) {
        case BPF_FIB_LKUP_RET_SUCCESS:
            break;
        case BPF_FIB_LKUP_RET_NO_NEIGH:
            bpf_print("ERROR: FIB lookup failed: ARP entry missing\n", rc);
            return TC_ACT_UNSPEC;
        case BPF_FIB_LKUP_RET_FWD_DISABLED :
            bpf_print("ERROR: FIB lookup failed: Forwaring disabled\n", rc);
            return TC_ACT_UNSPEC;
        default :
            bpf_print("ERROR: FIB lookup failed: %d\n", rc);
            return TC_ACT_UNSPEC;
        }

        __u32 *dst = (__u32 *)&fib_params.dmac[2];
        bpf_print("  Updating MAC to %x\n", bpf_ntohl(*dst));
        __builtin_memcpy(tun->mac_remote, fib_params.dmac, ETH_ALEN);
    }

    // Update destination MAC
    //bpf_print("Setting D-MAC %x\n", bpf_ntohl(*ptr));
    ret = bpf_skb_store_bytes(skb, 0, tun->mac_remote, 6, BPF_F_INVALIDATE_HASH);
    if (ret < 0) {
        bpf_print("bpf_skb_store_bytes: %d\n", ret);
        return TC_ACT_SHOT;
    }

    return TC_ACT_OK;
}

static __always_inline
int gue_decap_v4(struct __sk_buff *skb)
{
    int olen = sizeof(struct tunhdr);
    __u64 flags = 0; //BPF_F_ADJ_ROOM_FIXED_GSO | BPF_F_ADJ_ROOM_ENCAP_L3_IPV4 | BPF_F_ADJ_ROOM_ENCAP_L4_UDP;

    /* shrink room between mac and network header */
    if (bpf_skb_adjust_room(skb, -olen, BPF_ADJ_ROOM_MAC, flags))
        return TC_ACT_SHOT;

    return TC_ACT_OK;
}

#endif /* TC_PFC_H_ */
