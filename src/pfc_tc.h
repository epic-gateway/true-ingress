#ifndef TC_PFC_H_
#define TC_PFC_H_

#include <linux/in.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/icmp.h>

#include "common_tc.h"

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
    ASSERT(i < (tcph->doff - 5), TC_ACT_OK, "(TCP) has no OPT anymore\n");
    ASSERT((void*)&optx[i+1] <= data_end, TC_ACT_OK, "(TCP) has no OPT anymore\n");
    if ((bpf_ntohl(optx[i]) >> 16) == 0x0204) {
        __u16 *old_mss = (__u16 *)&optx[i];
        if (bpf_ntohs(old_mss[1]) > new_mss) {
            bpf_print("Replacing mss %u -> %u\n", old_mss, new_mss);
            old_mss[1] = bpf_htons(new_mss);

            // checksum
            int ret = bpf_l4_csum_replace(skb, nh_off + TCP_CSUM_OFF, *old_mss, new_mss, IS_PSEUDO | sizeof(new_mss));
            ASSERT(ret >= 0, TC_ACT_UNSPEC, "bpf_l4_csum_replace failed: %d\n", ret);
        }
        return TC_ACT_OK;
    }

    i = 1;
    ASSERT(i < (tcph->doff - 5), TC_ACT_OK, "(TCP) has no OPT anymore\n");
    ASSERT((void*)&optx[i+1] <= data_end, TC_ACT_OK, "(TCP) has no OPT anymore\n");
    if ((bpf_ntohl(optx[i]) >> 16) == 0x0204) {
        __u16 *old_mss = (__u16 *)&optx[i];
        if (bpf_ntohs(old_mss[1]) > new_mss) {
            bpf_print("Replacing mss %u -> %u\n", old_mss, new_mss);
            old_mss[1] = bpf_htons(new_mss);

            // checksum
            int ret = bpf_l4_csum_replace(skb, nh_off + TCP_CSUM_OFF, *old_mss, new_mss, IS_PSEUDO | sizeof(new_mss));
            ASSERT(ret >= 0, TC_ACT_UNSPEC, "bpf_l4_csum_replace failed: %d\n", ret);
        }
        return TC_ACT_OK;
    }

    i = 2;
    ASSERT(i < (tcph->doff - 5), TC_ACT_OK, "(TCP) has no OPT anymore\n");
    ASSERT((void*)&optx[i+1] <= data_end, TC_ACT_OK, "(TCP) has no OPT anymore\n");
    if ((bpf_ntohl(optx[i]) >> 16) == 0x0204) {
        __u16 *old_mss = (__u16 *)&optx[i];
        if (bpf_ntohs(old_mss[1]) > new_mss) {
            bpf_print("Replacing mss %u -> %u\n", old_mss, new_mss);
            old_mss[1] = bpf_htons(new_mss);

            // checksum
            int ret = bpf_l4_csum_replace(skb, nh_off + TCP_CSUM_OFF, *old_mss, new_mss, IS_PSEUDO | sizeof(new_mss));
            ASSERT(ret >= 0, TC_ACT_UNSPEC, "bpf_l4_csum_replace failed: %d\n", ret);
        }
        return TC_ACT_OK;
    }

    i = 3;
    ASSERT(i < (tcph->doff - 5), TC_ACT_OK, "(TCP) has no OPT anymore\n");
    ASSERT((void*)&optx[i+1] <= data_end, TC_ACT_OK, "(TCP) has no OPT anymore\n");
    if ((bpf_ntohl(optx[i]) >> 16) == 0x0204) {
        __u16 *old_mss = (__u16 *)&optx[i];
        if (bpf_ntohs(old_mss[1]) > new_mss) {
            bpf_print("Replacing mss %u -> %u\n", old_mss, new_mss);
            old_mss[1] = bpf_htons(new_mss);

            // checksum
            int ret = bpf_l4_csum_replace(skb, nh_off + TCP_CSUM_OFF, *old_mss, new_mss, IS_PSEUDO | sizeof(new_mss));
            ASSERT(ret >= 0, TC_ACT_UNSPEC, "bpf_l4_csum_replace failed: %d\n", ret);
        }
        return TC_ACT_OK;
    }

    i = 4;
    ASSERT(i < (tcph->doff - 5), TC_ACT_OK, "(TCP) has no OPT anymore\n");
    ASSERT((void*)&optx[i+1] <= data_end, TC_ACT_OK, "(TCP) has no OPT anymore\n");
    if ((bpf_ntohl(optx[i]) >> 16) == 0x0204) {
        __u16 *old_mss = (__u16 *)&optx[i];
        if (bpf_ntohs(old_mss[1]) > new_mss) {
            bpf_print("Replacing mss %u -> %u\n", old_mss, new_mss);
            old_mss[1] = bpf_htons(new_mss);

            // checksum
            int ret = bpf_l4_csum_replace(skb, nh_off + TCP_CSUM_OFF, *old_mss, new_mss, IS_PSEUDO | sizeof(new_mss));
            ASSERT(ret >= 0, TC_ACT_UNSPEC, "bpf_l4_csum_replace failed: %d\n", ret);
        }
        return TC_ACT_OK;
    }

    i = 5;
    ASSERT(i < (tcph->doff - 5), TC_ACT_OK, "(TCP) has no OPT anymore\n");
    ASSERT((void*)&optx[i+1] <= data_end, TC_ACT_OK, "(TCP) has no OPT anymore\n");
    if ((bpf_ntohl(optx[i]) >> 16) == 0x0204) {
        __u16 *old_mss = (__u16 *)&optx[i];
        if (bpf_ntohs(old_mss[1]) > new_mss) {
            bpf_print("Replacing mss %u -> %u\n", old_mss, new_mss);
            old_mss[1] = bpf_htons(new_mss);

            // checksum
            int ret = bpf_l4_csum_replace(skb, nh_off + TCP_CSUM_OFF, *old_mss, new_mss, IS_PSEUDO | sizeof(new_mss));
            ASSERT(ret >= 0, TC_ACT_UNSPEC, "bpf_l4_csum_replace failed: %d\n", ret);
        }
        return TC_ACT_OK;
    }

    i = 6;
    ASSERT(i < (tcph->doff - 5), TC_ACT_OK, "(TCP) has no OPT anymore\n");
    ASSERT((void*)&optx[i+1] <= data_end, TC_ACT_OK, "(TCP) has no OPT anymore\n");
    if ((bpf_ntohl(optx[i]) >> 16) == 0x0204) {
        __u16 *old_mss = (__u16 *)&optx[i];
        if (bpf_ntohs(old_mss[1]) > new_mss) {
            bpf_print("Replacing mss %u -> %u\n", old_mss, new_mss);
            old_mss[1] = bpf_htons(new_mss);

            // checksum
            int ret = bpf_l4_csum_replace(skb, nh_off + TCP_CSUM_OFF, *old_mss, new_mss, IS_PSEUDO | sizeof(new_mss));
            ASSERT(ret >= 0, TC_ACT_UNSPEC, "bpf_l4_csum_replace failed: %d\n", ret);
        }
        return TC_ACT_OK;
    }

    i = 7;
    ASSERT(i < (tcph->doff - 5), TC_ACT_OK, "(TCP) has no OPT anymore\n");
    ASSERT((void*)&optx[i+1] <= data_end, TC_ACT_OK, "(TCP) has no OPT anymore\n");
    if ((bpf_ntohl(optx[i]) >> 16) == 0x0204) {
        __u16 *old_mss = (__u16 *)&optx[i];
        if (bpf_ntohs(old_mss[1]) > new_mss) {
            bpf_print("Replacing mss %u -> %u\n", old_mss, new_mss);
            old_mss[1] = bpf_htons(new_mss);

            // checksum
            int ret = bpf_l4_csum_replace(skb, nh_off + TCP_CSUM_OFF, *old_mss, new_mss, IS_PSEUDO | sizeof(new_mss));
            ASSERT(ret >= 0, TC_ACT_UNSPEC, "bpf_l4_csum_replace failed: %d\n", ret);
        }
        return TC_ACT_OK;
    }

    i = 8;
    ASSERT(i < (tcph->doff - 5), TC_ACT_OK, "(TCP) has no OPT anymore\n");
    ASSERT((void*)&optx[i+1] <= data_end, TC_ACT_OK, "(TCP) has no OPT anymore\n");
    if ((bpf_ntohl(optx[i]) >> 16) == 0x0204) {
        __u16 *old_mss = (__u16 *)&optx[i];
        if (bpf_ntohs(old_mss[1]) > new_mss) {
            bpf_print("Replacing mss %u -> %u\n", old_mss, new_mss);
            old_mss[1] = bpf_htons(new_mss);

            // checksum
            int ret = bpf_l4_csum_replace(skb, nh_off + TCP_CSUM_OFF, *old_mss, new_mss, IS_PSEUDO | sizeof(new_mss));
            ASSERT(ret >= 0, TC_ACT_UNSPEC, "bpf_l4_csum_replace failed: %d\n", ret);
        }
        return TC_ACT_OK;
    }

    i = 9;
    ASSERT(i < (tcph->doff - 5), TC_ACT_OK, "(TCP) has no OPT anymore\n");
    ASSERT((void*)&optx[i+1] <= data_end, TC_ACT_OK, "(TCP) has no OPT anymore\n");
    if ((bpf_ntohl(optx[i]) >> 16) == 0x0204) {
        __u16 *old_mss = (__u16 *)&optx[i];
        if (bpf_ntohs(old_mss[1]) > new_mss) {
            bpf_print("Replacing mss %u -> %u\n", old_mss, new_mss);
            old_mss[1] = bpf_htons(new_mss);

            // checksum
            int ret = bpf_l4_csum_replace(skb, nh_off + TCP_CSUM_OFF, *old_mss, new_mss, IS_PSEUDO | sizeof(new_mss));
            ASSERT(ret >= 0, TC_ACT_UNSPEC, "bpf_l4_csum_replace failed: %d\n", ret);
        }
        return TC_ACT_OK;
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
    //__builtin_memcpy(&tun->mac_remote, hdr->eth->h_source, ETH_ALEN);
    //__builtin_memcpy(&tun->mac_local, hdr->eth->h_dest, ETH_ALEN);

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

#define MY_BPF_FIB_LOOKUP_DIRECT  1
#define MY_BPF_FIB_LOOKUP_OUTPUT  2

static __always_inline
int fib_lookup(struct __sk_buff *skb, struct bpf_fib_lookup *fib_params, int ifindex, int flags)
{
    struct headers hdr = { 0 };
    ASSERT(parse_headers(skb, &hdr) != TC_ACT_SHOT, dump_action(TC_ACT_UNSPEC), "Uninteresting packet type, IGNORING\n", dump_pkt(skb));

    fib_params->family       = AF_INET;
    fib_params->tos          = hdr.iph->tos;
    fib_params->l4_protocol  = hdr.iph->protocol;
    fib_params->sport        = 0;
    fib_params->dport        = 0;
    fib_params->tot_len      = bpf_ntohs(hdr.iph->tot_len);
    fib_params->ipv4_src     = bpf_htonl(hdr.iph->saddr);
    fib_params->ipv4_dst     = bpf_htonl(hdr.iph->daddr);
    fib_params->ifindex      = ifindex;

    int rc = bpf_fib_lookup(skb, fib_params, sizeof(*fib_params), flags);
    switch (rc) {
    case BPF_FIB_LKUP_RET_SUCCESS:
        break;
    case BPF_FIB_LKUP_RET_NO_NEIGH:
        bpf_print("ERROR: FIB lookup failed: ARP entry missing\n", rc);
        return TC_ACT_UNSPEC;
    case BPF_FIB_LKUP_RET_FWD_DISABLED :
        bpf_print("ERROR: FIB lookup failed: Forwarding disabled\n", rc);
        return TC_ACT_UNSPEC;
    default :
        bpf_print("ERROR: FIB lookup failed: %d\n", rc);
        return TC_ACT_UNSPEC;
    }

    bpf_print("FIB lookup input: S-IP %x D-IP %x ifindex %u\n",
              bpf_ntohl(hdr.iph->saddr), bpf_ntohl(hdr.iph->daddr), ifindex);
    bpf_print("FIB lookup output: S-MAC %x D-MAC %x via ifindex %u\n",
              bpf_ntohl(*(__u32*)&(fib_params->smac[2])), bpf_ntohl(*(__u32*)&(fib_params->dmac[2])), fib_params->ifindex);

    return TC_ACT_OK;
}

static __always_inline
int gue_encap_v4(struct __sk_buff *skb, struct tunnel *tun, struct service *svc, __u32 *via_ifindex)
{
    struct iphdr iph_inner = { 0 };
    struct tunhdr h_outer = {{0}, {0}, 0, 0, {0, 0}};
    int olen = sizeof(h_outer);
    __u64 flags = 0;
    __u64 *from = (__u64 *)svc->key.value;
    int ret;

    if (bpf_skb_load_bytes(skb, ETH_HLEN, &iph_inner, sizeof(iph_inner)) < 0)
        return TC_ACT_OK;

    // add room between mac and network header
//    flags = BPF_F_ADJ_ROOM_FIXED_GSO | BPF_F_ADJ_ROOM_ENCAP_L3_IPV4 | BPF_F_ADJ_ROOM_ENCAP_L4_UDP;
    flags = BPF_F_ADJ_ROOM_FIXED_GSO | BPF_F_ADJ_ROOM_ENCAP_L3_IPV4 | BPF_F_ADJ_ROOM_ENCAP_L4_UDP;
    ret = bpf_skb_adjust_room(skb, olen, BPF_ADJ_ROOM_MAC, flags);
    if (ret == -524) {   // -ENOTSUPP (caused by near MTU sized packet)
        bpf_print("bpf_skb_adjust_room FAILED, sending ICMP response back\n", ret);

        // get original L4 header
        __u64 buff;
        ret = bpf_skb_load_bytes(skb, ETH_HLEN + sizeof(iph_inner), &buff, sizeof(buff));
        ASSERT(ret >= 0, TC_ACT_UNSPEC, "bpf_skb_load_bytes()1 failed: %d\n", ret);

        // adjust buffer size
        olen = (ETH_HLEN + 2 * sizeof(struct iphdr) + sizeof(struct icmphdr) + sizeof(buff)) - skb->len;
        ret = bpf_skb_adjust_room(skb, olen, BPF_ADJ_ROOM_NET, 0);
        if (ret) {
            bpf_print("bpf_skb_adjust_room: %d\n", ret);
            return TC_ACT_SHOT;
        }

        // store original L4 as ICMP payload
        ret = bpf_skb_store_bytes(skb, ETH_HLEN + 2 * sizeof(struct iphdr) + sizeof(struct icmphdr), &buff, sizeof(buff), 0);
        ASSERT(ret >= 0, TC_ACT_UNSPEC, "bpf_skb_store_bytes()1 failed: %d\n", ret);

        // store original IPv4 as ICMP payload
        ret = bpf_skb_store_bytes(skb, ETH_HLEN + sizeof(struct iphdr) + sizeof(struct icmphdr), &iph_inner, sizeof(iph_inner), 0);
        ASSERT(ret >= 0, TC_ACT_UNSPEC, "bpf_skb_store_bytes()2 failed: %d\n", ret);

        struct icmphdr icmph = { 0 };

        ret = bpf_skb_load_bytes(skb, ETH_HLEN + sizeof(struct iphdr), &icmph, sizeof(struct icmphdr));
        ASSERT(ret >= 0, TC_ACT_UNSPEC, "bpf_skb_load_bytes()2 failed: %d\n", ret);

        icmph.type = 3;
        icmph.code = 4;
        icmph.checksum = 0;
        icmph.un.frag.mtu = bpf_htons(1400);

        // calculate ICMP cecksum
        __u16 *ptr16 = (__u16 *)&buff;
        __u32 csum = ptr16[0] + ptr16[1] + ptr16[2] + ptr16[3];
        ptr16 = (__u16 *)&iph_inner;
        csum += ptr16[0] + ptr16[1] + ptr16[2] + ptr16[3] + ptr16[4] + ptr16[5] + ptr16[6] + ptr16[7] + ptr16[8] + ptr16[9];
        ptr16 = (__u16 *)&icmph;
        csum += ptr16[0] + ptr16[1] + ptr16[2] + ptr16[3];

        icmph.checksum = ~((csum & 0xffff) + (csum >> 16));

        // store ICMP header
        ret = bpf_skb_store_bytes(skb, ETH_HLEN + sizeof(struct iphdr), &icmph, sizeof(struct icmphdr), 0);
        ASSERT(ret >= 0, TC_ACT_UNSPEC, "bpf_skb_store_bytes()3 failed: %d\n", ret);

        // update IPv4 header (size & proto)
        __u32 old_len = iph_inner.tot_len;
        __u16 old_proto = iph_inner.protocol;

        iph_inner.tot_len = bpf_htons(2 * sizeof(struct iphdr) + sizeof(struct icmphdr) + sizeof(buff));
        iph_inner.protocol = IPPROTO_ICMP;

        // IPv4 swap addesses
        __u32 tmp = iph_inner.saddr;
        iph_inner.saddr = iph_inner.daddr;
        iph_inner.daddr = tmp;

        // store IPv4
        ret = bpf_skb_store_bytes(skb, ETH_HLEN, &iph_inner, sizeof(iph_inner), 0);
        ASSERT(ret >= 0, TC_ACT_UNSPEC, "bpf_skb_store_bytes()3 failed: %d\n", ret);

        // update IPv4 checksum
        ret = bpf_l3_csum_replace(skb, ETH_HLEN + IP_CSUM_OFF, old_len + bpf_htons(old_proto), iph_inner.tot_len + bpf_ntohs(iph_inner.protocol), sizeof(old_proto));
        ASSERT(ret >= 0, TC_ACT_UNSPEC, "bpf_l3_csum_replace()2 failed: %d\n", ret);

        // swap MACs
        __u8 src[6], dst[6];
        ret = bpf_skb_load_bytes(skb, 0, src, 6);
        ASSERT(ret >= 0, TC_ACT_UNSPEC, "bpf_skb_load_bytes()3 failed: %d\n", ret);
        ret = bpf_skb_load_bytes(skb, 6, dst, 6);
        ASSERT(ret >= 0, TC_ACT_UNSPEC, "bpf_skb_load_bytes()4 failed: %d\n", ret);

        ret = bpf_skb_store_bytes(skb, 0, dst, 6, 0);
        ASSERT(ret >= 0, TC_ACT_UNSPEC, "bpf_skb_load_bytes()5 failed: %d\n", ret);
        ret = bpf_skb_store_bytes(skb, 6, src, 6, 0);
        ASSERT(ret >= 0, TC_ACT_UNSPEC, "bpf_skb_load_bytes()6 failed: %d\n", ret);

        // done
        return bpf_redirect(skb->ifindex, BPF_F_INGRESS);
    }
    if (ret) {
        bpf_print("bpf_skb_adjust_room: %d\n", ret);
        return TC_ACT_SHOT;
    }

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
    h_outer.ip.ttl = 64;

    set_ipv4_csum((void *)&h_outer.ip);

    // fill UDP
    int len = bpf_ntohs(iph_inner.tot_len) + sizeof(h_outer.udp) + sizeof(h_outer.gue) + 20 /*sizeof(h_outer.gueext*/;
    h_outer.udp.dest    = tun->port_remote;
    h_outer.udp.source  = tun->port_local;
    h_outer.udp.len     = bpf_htons(len);
    h_outer.udp.check   = 0;

    // store new outer network header
    ret = bpf_skb_store_bytes(skb, ETH_HLEN, &h_outer, olen, BPF_F_INVALIDATE_HASH);
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
