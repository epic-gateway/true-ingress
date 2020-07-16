#ifndef TC_COMMON_H_
#define TC_COMMON_H_

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
};

static inline
int parse_headers(struct __sk_buff *skb, struct headers *hdr)
{
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;
    
    hdr->eth = data;

    __u64 nh_off = sizeof(*hdr->eth);
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
    nh_off += sizeof(struct iphdr);
    if (data + nh_off > data_end)
    {
        bpf_print("ERROR: (IPv4) Invalid packet size\n");
        return TC_ACT_SHOT;
    }

    if (hdr->iph->protocol == IPPROTO_TCP)
    {
        hdr->tcph = data + nh_off;
        if ((void*)&hdr->tcph[1] > data_end)
        {
            bpf_print("ERROR: (UDP) Invalid packet size\n");
            return TC_ACT_SHOT;
        }
        hdr->payload = (void*)&hdr->tcph[1];
        return TC_ACT_OK;
    }
    else if (hdr->iph->protocol == IPPROTO_UDP)
    {
        hdr->udph = data + nh_off;
        if ((void*)&hdr->udph[1] > data_end)
        {
            bpf_print("ERROR: (UDP) Invalid packet size\n");
            return TC_ACT_SHOT;
        }
        hdr->payload = (void*)&hdr->udph[1];
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

#endif /* TC_COMMON_H_ */
