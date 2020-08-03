#ifndef TC_DUMP_H_
#define TC_DUMP_H_

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/pkt_cls.h>

//#include <linux/pkt_cls.h>
//#include <stdint.h>
//#include <iproute2/bpf_elf.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/if_vlan.h>
#include <linux/if_packet.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/icmp.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/if_arp.h>

#ifndef __section
# define __section(x)  __attribute__((section(x), used))
#endif

#ifndef VLAN_HDR_SZ     /* VLAN header length */
#define VLAN_HDR_SZ	4	/* bytes */
#endif

#ifndef ETH_ALEN        /* Ethernet MAC address length */
#define ETH_ALEN	6	/* bytes */
#endif

struct arpexthdr {
    unsigned char  ar_sha[ETH_ALEN];   /* sender hardware address	*/
    unsigned char  ar_sip[4];          /* sender IP address		*/
    unsigned char  ar_tha[ETH_ALEN];   /* target hardware address	*/
    unsigned char  ar_tip[4];          /* target IP address		*/
};

// redeclaration, because if_vlan.h doesn't contain it
struct vlan_hdr {
    __be16  h_vlan_TCI;
    __be16  h_vlan_encapsulated_proto;
};


static inline
int dump_icmp(void *data, __u64 nh_off, void *data_end)
{
    struct icmphdr *icmph = data + nh_off;
    if ((void*)&icmph[1] > data_end)
    {
        char msg1[] = "ERROR: (ICMP) Invalid packet size\n";
        bpf_trace_printk(msg1, sizeof(msg1));
        return TC_ACT_SHOT;
    }

    if (icmph->type == ICMP_ECHO)
    {
        char msg2[] = "  ICMP ECHO REQUEST: id %u, seq %u\n";
        bpf_trace_printk(msg2, sizeof(msg2), bpf_ntohs(icmph->un.echo.id), bpf_ntohs(icmph->un.echo.sequence));
    }
    else if (icmph->type == ICMP_ECHOREPLY)
    {
        char msg3[] = "  ICMP ECHO REPLY: id %u, seq %u\n";
        bpf_trace_printk(msg3, sizeof(msg3), bpf_ntohs(icmph->un.echo.id), bpf_ntohs(icmph->un.echo.sequence));
    }
    else if (icmph->type == ICMP_TIME_EXCEEDED)
    {
        char msg4[] = "  ICMP TIME EXCEEDED...\n";
        bpf_trace_printk(msg4, sizeof(msg4));
    }
    else if (icmph->type == ICMP_DEST_UNREACH)
    {
        char msg5[] = "  ICMP DEST UNREACHABLE...\n";
        bpf_trace_printk(msg5, sizeof(msg5));
    }
    else
    {
        char msg6[] = "  ICMP : type %x, code %x\n";
        bpf_trace_printk(msg6, sizeof(msg6), icmph->type, icmph->code);
    }

    return TC_ACT_OK;
}

static inline
int dump_tcp(void *data, __u64 nh_off, void *data_end)
{
    struct tcphdr *tcph = data + nh_off;
    if ((void*)&tcph[1] > data_end)
    {
        char msg1[] = "ERROR: (TCP) Invalid packet size\n";
        bpf_trace_printk(msg1, sizeof(msg1));
        return TC_ACT_SHOT;
    }

    char msg2[] = "  TCP  : %d -> %d\n";
    bpf_trace_printk(msg2, sizeof(msg2), bpf_ntohs(tcph->source), bpf_ntohs(tcph->dest));
    /*char msg4[] = "       (";
    bpf_trace_printk(msg4, sizeof(msg4));
    if (tcph->rst)
    {
        char msg[] = " RST";
        bpf_trace_printk(msg, sizeof(msg));
    }
    if (tcph->syn)
    {
        char msg[] = " SYN";
        bpf_trace_printk(msg, sizeof(msg));
    }
    if (tcph->fin)
    {
        char msg[] = " FIN";
        bpf_trace_printk(msg, sizeof(msg));
    }
    if (tcph->ack)
    {
        char msg[] = " ACK";
        bpf_trace_printk(msg, sizeof(msg));
    }
    char msg3[] = " )\n";
    bpf_trace_printk(msg3, sizeof(msg3));*/

    return TC_ACT_OK;
}

static inline
int dump_udp(void *data, __u64 nh_off, void *data_end)
{
    struct udphdr *udph = data + nh_off;
    if ((void*)&udph[1] > data_end)
    {
        char msg1[] = "ERROR: (UDP) Invalid packet size\n";
        bpf_trace_printk(msg1, sizeof(msg1));
        return TC_ACT_SHOT;
    }

    char msg2[] = "  UDP  : %d -> %d\n";
    bpf_trace_printk(msg2, sizeof(msg2), bpf_ntohs(udph->source), bpf_ntohs(udph->dest));

    return TC_ACT_OK;
}

static inline
int dump_ipv4(void *data, __u64 nh_off, void *data_end)
{
    struct iphdr *iph = data + nh_off;

    nh_off += sizeof(struct iphdr);
    if (data + nh_off > data_end)
    {
        char msg1[] = "ERROR: (IPv4) Invalid packet size\n";
        bpf_trace_printk(msg1, sizeof(msg1));
        return TC_ACT_SHOT;
    }

//    char msg2[] = "  IPv4 : %x -> %x, proto %u\n";
//    bpf_trace_printk(msg2, sizeof(msg2), bpf_ntohl(iph->saddr), bpf_ntohl(iph->daddr), iph->protocol);

    char msg2[] = "  IPv4 : %x -> %x, id %u\n";
    bpf_trace_printk(msg2, sizeof(msg2), bpf_ntohl(iph->saddr), bpf_ntohl(iph->daddr), bpf_ntohs(iph->id));
//    bpf_trace_printk(msg2, sizeof(msg2), iph->saddr, iph->daddr, iph->protocol);

    if (iph->protocol == IPPROTO_ICMP)
        dump_icmp(data, nh_off, data_end);
    else if (iph->protocol == IPPROTO_TCP)
        dump_tcp(data, nh_off, data_end);
    else if (iph->protocol == IPPROTO_UDP)
        dump_udp(data, nh_off, data_end);
    else {
        char msg3[] = "    proto %u\n";
        bpf_trace_printk(msg3, sizeof(msg3), iph->protocol);
    }

    return TC_ACT_OK;
}

static inline
int dump_ipv6(void *data, __u64 nh_off, void *data_end)
{
    char msg[] = "  IPv6  : NOT SUPPORTED\n";
    bpf_trace_printk(msg, sizeof(msg));

    return TC_ACT_OK;
}

static inline
int dump_vlan(void *data, __u64 nh_off, void *data_end)
{
    struct vlan_hdr *vhdr = data + nh_off;

    nh_off += sizeof(struct vlan_hdr);
    if (data + nh_off > data_end)
    {
        char msg1[] = "ERROR: (VLAN) Invalid packet size\n";
        bpf_trace_printk(msg1, sizeof(msg1));
        return TC_ACT_SHOT;
    }

    __u16 h_proto = vhdr->h_vlan_encapsulated_proto;

    char msg2[] = "  VLAN : id %u, proto %x\n";
    bpf_trace_printk(msg2, sizeof(msg2), bpf_ntohs(vhdr->h_vlan_TCI), bpf_ntohs(h_proto));

    if (h_proto == bpf_htons(ETH_P_IP))
        dump_ipv4(data, nh_off, data_end);
    else if (h_proto == bpf_htons(ETH_P_IPV6))
        dump_ipv6(data, nh_off, data_end);
//    else if (h_proto == bpf_htons(ETH_P_8021Q) || h_proto == bpf_htons(ETH_P_8021AD))
//        dump_vlan(data, nh_off, data_end);

    return TC_ACT_OK;
}

static inline
int dump_arp(void *data, __u64 nh_off, void *data_end)
{
    struct arphdr *arph = data + nh_off;
    char msg1[] = "ERROR: (ARP) Invalid packet size\n";

    nh_off += sizeof(struct arphdr);
    if (data + nh_off > data_end)
    {
        bpf_trace_printk(msg1, sizeof(msg1));
        return TC_ACT_SHOT;
    }

    if (arph->ar_op == bpf_htons(ARPOP_REQUEST))
    {
        struct arpexthdr *arpexth = (struct arpexthdr *)&arph[1];

        nh_off += sizeof(struct arpexthdr);
        if (data + nh_off > data_end)
        {
            bpf_trace_printk(msg1, sizeof(msg1));
            return TC_ACT_SHOT;
        }

        __u32 *src = (__u32 *)arpexth->ar_sip;
        __u32 *dst = (__u32 *)arpexth->ar_tip;
        char msg4[] = "  ARP WHO HAS: %x, tell %x\n";
        bpf_trace_printk(msg4, sizeof(msg4), bpf_ntohl(*dst), bpf_ntohl(*src));
    }
    else if (arph->ar_op == bpf_htons(ARPOP_REPLY))
    {
        struct arpexthdr *arpexth = (struct arpexthdr *)&arph[1];

        nh_off += sizeof(struct arpexthdr);
        if (data + nh_off > data_end)
        {
            bpf_trace_printk(msg1, sizeof(msg1));
            return TC_ACT_SHOT;
        }

        __u32 *src = (__u32*)arpexth->ar_sip;
        __u32 *mac = (__u32*)&arpexth->ar_sha[2];
        char msg5[] = "  ARP REPLY: %x -> %x\n";
        bpf_trace_printk(msg5, sizeof(msg5), bpf_ntohl(*src), bpf_ntohl(*mac));
    }
    else
    {
        char msg6[] = "  ARP  : op %u\n";
        bpf_trace_printk(msg6, sizeof(msg6), bpf_ntohs(arph->ar_op));
    }

    return TC_ACT_OK;
}

static inline
int dump_eth(void *data, void *data_end)
{
    struct ethhdr *eth = data;
    char msg1[] = "ERROR: (ETH) Invalid packet size\n";
    char msg2[] = "  ETH  : %x -> %x, proto %x\n";

    __u64 nh_off = sizeof(*eth);
    if (data + nh_off > data_end)
    {
        bpf_trace_printk(msg1, sizeof(msg1));
        return TC_ACT_SHOT;
    }

    __u16 h_proto = eth->h_proto;

    __u32 *src = (__u32*)&eth->h_source[2];
    __u32 *dst = (__u32*)&eth->h_dest[2];

    bpf_trace_printk(msg2, sizeof(msg2), bpf_ntohl(*src), bpf_ntohl(*dst), bpf_ntohs(h_proto));
//    bpf_trace_printk(msg2, sizeof(msg2), *src, *dst, bpf_ntohs(h_proto));

    if (h_proto == bpf_htons(ETH_P_IP))
        dump_ipv4(data, nh_off, data_end);
    else if (h_proto == bpf_htons(ETH_P_IPV6))
        dump_ipv6(data, nh_off, data_end);
    else if (h_proto == bpf_htons(ETH_P_8021Q) || h_proto == bpf_htons(ETH_P_8021AD))
        dump_vlan(data, nh_off, data_end);
    else if (h_proto == bpf_htons(ETH_P_ARP))
        dump_arp(data, nh_off, data_end);

    return TC_ACT_OK;
}

static inline
int dump_pkt(struct __sk_buff *skb)
{
    char msg[] = "DUMP: =====================\n";
    bpf_trace_printk(msg, sizeof(msg));
    char msg1[] = "  Size : %u B\n";
    bpf_trace_printk(msg1, sizeof(msg1), skb->len);

    //dump_eth((void *)(long)skb->data, (void *)(long)skb->data_end);
    void *data = (void *)(long)skb->data;
	void *data_end = (void *)(long)skb->data_end;
    dump_eth(data, data_end);

    bpf_trace_printk(msg, sizeof(msg));

    return TC_ACT_OK;
}

////////////////// ACTION DUMP SECTION //////////////////
static inline
int dump_action(int action) {
    switch (action)
    {
        case TC_ACT_PIPE:
        {  
            char msg1[] = "Action: TC_ACT_PIPE\n\n";
            bpf_trace_printk(msg1, sizeof(msg1));
            break;
        }
        case TC_ACT_RECLASSIFY:
        {
            char msg2[] = "Action: TC_ACT_RECLASSIFY\n\n";
            bpf_trace_printk(msg2, sizeof(msg2));
            break;
        }
        case TC_ACT_OK:
        {
            char msg3[] = "Action: TC_ACT_OK\n\n";
            bpf_trace_printk(msg3, sizeof(msg3));
            break;
        }
        case TC_ACT_REDIRECT:
        {
            char msg4[] = "Action: TC_ACT_REDIRECT\n\n";
            bpf_trace_printk(msg4, sizeof(msg4));
            break;
        }
        case TC_ACT_SHOT:
        {
            char msg5[] = "Action: TC_ACT_SHOT\n\n";
            bpf_trace_printk(msg5, sizeof(msg5));
            break;
        }
        case TC_ACT_UNSPEC:
        {
            char msg5[] = "Action: TC_ACT_UNSPEC\n\n";
            bpf_trace_printk(msg5, sizeof(msg5));
            break;
        }
        default:
        {
            char msg6[] = "Action: UNKNOWN (%d)\n\n";
            bpf_trace_printk(msg6, sizeof(msg6));
            break;
        }
    }

    return action;
}

#endif /* TC_DUMP_H_ */
