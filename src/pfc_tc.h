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
void parse_src_ep(struct endpoint *ep, struct headers *hdr)
{
    ep->ip       = bpf_htonl(hdr->iph->saddr);
    ep->proto    = bpf_htons(hdr->iph->protocol);
    if (hdr->tcph)
        ep->port = hdr->tcph->source;
    else if (hdr->udph)
        ep->port = hdr->udph->source;

    bpf_print("Parsed Source EP: ip %x, port %u, proto %u\n", ep->ip, bpf_ntohs(ep->port), bpf_ntohs(ep->proto));
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

    bpf_print("Parsed Destination EP: ip %x, port %u, proto %u\n", ep->ip, bpf_ntohs(ep->port), bpf_ntohs(ep->proto));
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
    int ret, off_csum = 0, off_port = 0, flags = IS_PSEUDO;
    __u32 old_ip = hdr->iph->daddr;
    __u16 old_port = 0;

    switch (hdr->iph->protocol) {
    case IPPROTO_TCP:
        off_csum = hdr->off_tcph + TCP_CSUM_OFF;
        off_port = hdr->off_tcph + TCP_DPORT_OFF;
        break;

    case IPPROTO_UDP:
        off_csum = hdr->off_udph + UDP_CSUM_OFF;
        off_port = hdr->off_udph + UDP_DPORT_OFF;
        flags |= BPF_F_MARK_MANGLED_0;
        break;
    }

    ASSERT(off_port, TC_ACT_OK, "Couldn\'t determine port offset\n");
    ASSERT(off_csum, TC_ACT_OK, "Couldn\'t determine csum offset\n");

    if (bpf_skb_load_bytes(skb, off_port, &old_port, sizeof(old_port)) < 0) {
        return TC_ACT_OK;
    }

    // checksum
    ret = bpf_l4_csum_replace(skb, off_csum, old_ip, new_ip, flags | sizeof(new_ip));
    ASSERT(ret >= 0, TC_ACT_UNSPEC, "bpf_l4_csum_replace failed: %d\n", ret);

    ret = bpf_l4_csum_replace(skb, off_csum, old_port, new_port, flags | sizeof(new_port));
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
    int ret, off_csum = 0, off_port = 0, flags = IS_PSEUDO;
    __u32 old_ip = hdr->iph->saddr;
    __u16 old_port = 0;

    switch (hdr->iph->protocol) {
    case IPPROTO_TCP:
        off_csum = hdr->off_tcph + TCP_CSUM_OFF;
        off_port = hdr->off_tcph + TCP_SPORT_OFF;
        break;

    case IPPROTO_UDP:
        off_csum = hdr->off_udph + UDP_CSUM_OFF;
        off_port = hdr->off_udph + UDP_SPORT_OFF;
        flags |= BPF_F_MARK_MANGLED_0;
        break;
    }

    ASSERT(off_port, TC_ACT_OK, "Couldn\'t determine port offset\n");
    ASSERT(off_csum, TC_ACT_OK, "Couldn\'t determine csum offset\n");

    if (bpf_skb_load_bytes(skb, off_port, &old_port, sizeof(old_port)) < 0) {
        return TC_ACT_OK;
    }

    // checksum
    ret = bpf_l4_csum_replace(skb, off_csum, old_ip, new_ip, flags | sizeof(new_ip));
    ASSERT(ret >= 0, TC_ACT_UNSPEC, "bpf_l4_csum_replace failed: %d\n", ret);

    ret = bpf_l4_csum_replace(skb, off_csum, old_port, new_port, flags | sizeof(new_port));
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
    struct verify *vrf = bpf_map_lookup_elem(&map_verify, (struct identity *)&gueext->id);
    ASSERT(vrf != 0, dump_action(TC_ACT_UNSPEC), "ERROR: Service id %x not found!\n", bpf_ntohl(gueext->id));

    __u64 *ref_key = (__u64 *)vrf->value;
    __u64 *pkt_key = (__u64 *)gueext->key;

    if ((pkt_key[0] != ref_key[0]) || (pkt_key[1] != ref_key[1])) {
        bpf_print("ERROR: Service id %x key mismatch!\n", bpf_ntohl(gueext->id));
        bpf_print("    Expected : %lx%lx\n", bpf_ntohll(ref_key[0]), bpf_ntohll(ref_key[1]));
        bpf_print("    Received : %lx%lx\n", bpf_ntohll(pkt_key[0]), bpf_ntohll(pkt_key[1]));
        return 1;
    }

    bpf_print("Service id %x key verified\n", bpf_ntohl(gueext->id));
    return 0;
}

static __always_inline
int gue_encap_v4(struct __sk_buff *skb, struct tunnel *tun, struct service *svc)
{
    return TC_ACT_OK;
}

static __always_inline
int gue_decap_v4(struct __sk_buff *skb)
{
    return TC_ACT_OK;
}

#endif /* TC_PFC_H_ */