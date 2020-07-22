#ifndef TC_COMMON_H_
#define TC_COMMON_H_

#include <linux/in.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>

#define bpf_print(fmt, ...)                                         \
({                                                                  \
        char ____fmt[] = fmt;                                       \
        bpf_trace_printk(____fmt, sizeof(____fmt), ##__VA_ARGS__);  \
})

#define ASSERT(_expr, _retval, _fmt, ...)   \
({                                          \
    if (!(_expr)) {                         \
        bpf_print(_fmt, ##__VA_ARGS__);     \
        return _retval;                     \
    }                                       \
})

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

    if (!off_port || !off_csum) {
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

    if (!off_port || !off_csum) {
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

#endif /* TC_COMMON_H_ */
