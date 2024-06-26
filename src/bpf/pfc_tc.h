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

struct gueexthdr {
    __u32   tunnelid;
};

struct tunhdr {
    struct iphdr        ip;
    struct udphdr       udp;
    __u32               gue;
    struct gueexthdr    gue_id;
} __attribute__((packed));

// In order to safely parse a GUE packet we need to ensure that there
// are at least this many bytes in the packet's skb data. Not all
// packets have that at first. In some cases we need to
// bpf_skb_pull_data() this many bytes before we can parse.
#define TOTAL_GUE_HEADER_SIZE sizeof(struct ethhdr) + sizeof(struct tunhdr)

// In order to safely call parse_ep() on a packet we need to ensure
// that there are at least this many linear bytes in the packet's skb
// data. Not all packets have that at first. In some cases we need to
// bpf_skb_pull_data() this many bytes before we can parse.
#define TOTAL_EP_HEADER_SIZE sizeof(struct ethhdr) \
    + sizeof(struct iphdr) \
    + (sizeof(struct tcphdr) > sizeof(struct udphdr) ? sizeof(struct tcphdr) : sizeof(struct udphdr))

struct headers {
    struct ethhdr *eth;
    struct iphdr *iph;
    struct tcphdr *tcph;
    struct udphdr *udph;
    struct guehdr *gueh;
    __u32 off_eth;
    __u32 off_iph;
    __u32 off_tcph;
    __u32 off_udph;
    __u32 off_gueh;
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
        if (data + nh_off > data_end)
        {
            bpf_print("ERROR: (TCP) Invalid packet size\n");
            return TC_ACT_SHOT;
        }
        hdr->gueh = data + nh_off;
        hdr->off_gueh = nh_off;
        return TC_ACT_OK;
    }
    else if (hdr->iph->protocol == IPPROTO_UDP)
    {
        hdr->udph = data + nh_off;
        hdr->off_udph = nh_off;
        nh_off += sizeof(struct udphdr);
        if (data + nh_off > data_end)
        {
            bpf_print("ERROR: (UDP) Invalid packet size\n");
            return TC_ACT_SHOT;
        }

        // GUE Header
        hdr->gueh = data + nh_off;
        hdr->off_gueh = nh_off;
        nh_off += sizeof(struct guehdr);
        if ((void *)(long)hdr->gueh + sizeof(struct guehdr) > (void *)(long)data_end)
        {
            bpf_print("ERROR: (GUE) Invalid packet size (gueh + sizeof(struct guehdr) > data_end): \n");
            bpf_print("                  data: %u\n", data);
            bpf_print("                  gueh: %u\n", hdr->gueh);
            bpf_print(" sizeof(struct guehdr): %u\n", sizeof(struct guehdr));
            bpf_print("              data_end: %u\n", data_end);
            return TC_ACT_SHOT;
        }

        return TC_ACT_OK;
    }

    return TC_ACT_SHOT;
}

static inline
int dump_headers(int debug, struct headers *headers) {
    debug_print(debug, "HEADERS: ==================\n");
    debug_print(debug, "    eth: %u\n", headers->eth);
    debug_print(debug, "     ip: %u\n", headers->iph);
    debug_print(debug, "   udph: %u\n", headers->udph);
    debug_print(debug, "udph[1]: %u\n", &headers->udph[1]);
    debug_print(debug, "HEADERS: ==================\n");
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
            bpf_print("ERROR: (TCP) Invalid packet size\n");
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

    return TC_ACT_SHOT;
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
    fib_params->ipv4_src     = hdr.iph->saddr;
    fib_params->ipv4_dst     = hdr.iph->daddr;
    fib_params->ifindex      = ifindex;

    int rc = bpf_fib_lookup(skb, fib_params, sizeof(*fib_params), flags);
    switch (rc) {
    case BPF_FIB_LKUP_RET_SUCCESS:
        break;
    case BPF_FIB_LKUP_RET_NO_NEIGH:
        bpf_print("ERROR: FIB lookup failed: Route found but ARP entry missing\n", rc);
        return TC_ACT_UNSPEC;
    case BPF_FIB_LKUP_RET_FWD_DISABLED :
        bpf_print("ERROR: FIB lookup failed: '/proc/sys/net/ipv4/ip_forward' disabled\n", rc);
        return TC_ACT_UNSPEC;
    default :
        bpf_print("ERROR: FIB lookup failed: %d\n", rc);
        return TC_ACT_UNSPEC;
    }

    return TC_ACT_OK;
}

static __always_inline
int gue_encap_v4(struct __sk_buff *skb, struct tunnel *tun, struct service *svc)
{
    struct iphdr iph_inner = { 0 };
    struct tunhdr h_outer = {{0}, {0}, 0, {0}};
    int olen = sizeof(h_outer);
    __u64 flags = 0;
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

        // we've put our grubby paws all over the packet
        // so we need to recalc the checksum or linux will
        // drop it like it's hot
        bpf_set_hash_invalid(skb);

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
    h_outer.gue_id.tunnelid = svc->tunnel_id;

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
    int len = bpf_ntohs(iph_inner.tot_len) + sizeof(h_outer.udp) + sizeof(h_outer.gue) + sizeof(h_outer.gue_id);
    h_outer.udp.dest    = tun->port_remote;
    h_outer.udp.source  = tun->port_local;
    h_outer.udp.len     = bpf_htons(len);
    h_outer.udp.check   = 0;

    // store new outer network header
    ret = bpf_skb_store_bytes(skb, ETH_HLEN, &h_outer, olen, 0);
    if (ret < 0) {
        bpf_print("bpf_skb_store_bytes: %d\n", ret);
        return TC_ACT_SHOT;
    }

    // we've put our grubby paws all over the packet
    // so we need to recalc the checksum or linux will
    // drop it like it's hot
    bpf_set_hash_invalid(skb);

    return TC_ACT_OK;
}

static __always_inline
int gue_decap_v4(struct __sk_buff *skb)
{
    int olen = sizeof(struct tunhdr);
    __u64 flags = 0; //BPF_F_ADJ_ROOM_FIXED_GSO | BPF_F_ADJ_ROOM_ENCAP_L3_IPV4 | BPF_F_ADJ_ROOM_ENCAP_L4_UDP;

    /* shrink room between mac and network header */
    int ret = bpf_skb_adjust_room(skb, -olen, BPF_ADJ_ROOM_MAC, flags);
    if (ret) {
        bpf_print("bpf_skb_adjust_room: %d\n", ret);
        return TC_ACT_SHOT;
    }

    // we've put our grubby paws all over the packet
    // so we need to recalc the checksum or linux will
    // drop it like it's hot
    bpf_set_hash_invalid(skb);

    return TC_ACT_OK;
}

#endif /* TC_PFC_H_ */
