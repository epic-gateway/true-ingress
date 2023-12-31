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

#include "common_tc.h"

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
int dump_icmp(void *data, void *data_end)
{
    struct icmphdr *icmph = data;
    ASSERT((void*)&icmph[1] <= data_end, TC_ACT_SHOT, "ERROR: (ICMP) Invalid packet size\n");

    if (icmph->type == ICMP_ECHO)
    {
        bpf_print("  ICMP ECHO REQUEST: id %u, seq %u\n", bpf_ntohs(icmph->un.echo.id), bpf_ntohs(icmph->un.echo.sequence));
    }
    else if (icmph->type == ICMP_ECHOREPLY)
    {
        bpf_print("  ICMP ECHO REPLY: id %u, seq %u\n", bpf_ntohs(icmph->un.echo.id), bpf_ntohs(icmph->un.echo.sequence));
    }
    else if (icmph->type == ICMP_TIME_EXCEEDED)
    {
        bpf_print("  ICMP TIME EXCEEDED...\n");
    }
    else if (icmph->type == ICMP_DEST_UNREACH)
    {
        bpf_print("  ICMP DEST UNREACHABLE: %u\n", icmph->code);
    }
    else
    {
        bpf_print("  ICMP : type %x, code %x\n", icmph->type, icmph->code);
    }
    bpf_print("    csum 0x%x\n", bpf_ntohs(icmph->checksum));

    return TC_ACT_OK;
}

static inline
int dump_tcp(void *data, void *data_end)
{
    struct tcphdr *tcph = data;
    ASSERT((void*)&tcph[1] <= data_end, TC_ACT_SHOT, "ERROR: (TCP) Invalid packet size\n");

    char flags[5], *p = flags;
    if (tcph->syn)
        *(p++) = 'S';
    if (tcph->fin)
        *(p++) = 'F';
    if (tcph->rst)
        *(p++) = 'R';
    if (tcph->ack)
        *(p++) = 'A';
    *(p) = 0;

    bpf_print("  TCP  : %d -> %d, Flags [%s]\n", bpf_ntohs(tcph->source), bpf_ntohs(tcph->dest), flags);
    bpf_print("    csum 0x%x\n", bpf_ntohs(tcph->check));

    if (tcph->syn) {
        __u32 *optx = (void*)&tcph[1];

        int i = 0;
        ASSERT(i < (tcph->doff - 5), TC_ACT_OK, "(TCP) has no OPT anymore\n");
        ASSERT((void*)&optx[i+1] <= data_end, TC_ACT_OK, "(TCP) has no OPT anymore\n");

        if ((bpf_ntohl(optx[i]) >> 16) == 0x0204) {
            __u16 *mss = (__u16 *)&optx[i];
            bpf_print("    mss %uB\n", bpf_ntohs(mss[1]));
            return TC_ACT_OK;
        }

        i = 1;
        ASSERT(i < (tcph->doff - 5), TC_ACT_OK, "(TCP) has no OPT anymore\n");
        ASSERT((void*)&optx[i+1] <= data_end, TC_ACT_OK, "(TCP) has no OPT anymore\n");

        if ((bpf_ntohl(optx[i]) >> 16) == 0x0204) {
            __u16 *mss = (__u16 *)&optx[i];
            bpf_print("    mss %uB\n", bpf_ntohs(mss[1]));
            return TC_ACT_OK;
        }

        i = 2;
        ASSERT(i < (tcph->doff - 5), TC_ACT_OK, "(TCP) has no OPT anymore\n");
        ASSERT((void*)&optx[i+1] <= data_end, TC_ACT_OK, "(TCP) has no OPT anymore\n");

        if ((bpf_ntohl(optx[i]) >> 16) == 0x0204) {
            __u16 *mss = (__u16 *)&optx[i];
            bpf_print("    mss %uB\n", bpf_ntohs(mss[1]));
            return TC_ACT_OK;
        }

        i = 3;
        ASSERT(i < (tcph->doff - 5), TC_ACT_OK, "(TCP) has no OPT anymore\n");
        ASSERT((void*)&optx[i+1] <= data_end, TC_ACT_OK, "(TCP) has no OPT anymore\n");

        if ((bpf_ntohl(optx[i]) >> 16) == 0x0204) {
            __u16 *mss = (__u16 *)&optx[i];
            bpf_print("    mss %uB\n", bpf_ntohs(mss[1]));
            return TC_ACT_OK;
        }

        i = 4;
        ASSERT(i < (tcph->doff - 5), TC_ACT_OK, "(TCP) has no OPT anymore\n");
        ASSERT((void*)&optx[i+1] <= data_end, TC_ACT_OK, "(TCP) has no OPT anymore\n");

        if ((bpf_ntohl(optx[i]) >> 16) == 0x0204) {
            __u16 *mss = (__u16 *)&optx[i];
            bpf_print("    mss %uB\n", bpf_ntohs(mss[1]));
            return TC_ACT_OK;
        }

        i = 5;
        ASSERT(i < (tcph->doff - 5), TC_ACT_OK, "(TCP) has no OPT anymore\n");
        ASSERT((void*)&optx[i+1] <= data_end, TC_ACT_OK, "(TCP) has no OPT anymore\n");

        if ((bpf_ntohl(optx[i]) >> 16) == 0x0204) {
            __u16 *mss = (__u16 *)&optx[i];
            bpf_print("    mss %uB\n", bpf_ntohs(mss[1]));
            return TC_ACT_OK;
        }

        i = 6;
        ASSERT(i < (tcph->doff - 5), TC_ACT_OK, "(TCP) has no OPT anymore\n");
        ASSERT((void*)&optx[i+1] <= data_end, TC_ACT_OK, "(TCP) has no OPT anymore\n");

        if ((bpf_ntohl(optx[i]) >> 16) == 0x0204) {
            __u16 *mss = (__u16 *)&optx[i];
            bpf_print("    mss %uB\n", bpf_ntohs(mss[1]));
            return TC_ACT_OK;
        }

        i = 7;
        ASSERT(i < (tcph->doff - 5), TC_ACT_OK, "(TCP) has no OPT anymore\n");
        ASSERT((void*)&optx[i+1] <= data_end, TC_ACT_OK, "(TCP) has no OPT anymore\n");

        if ((bpf_ntohl(optx[i]) >> 16) == 0x0204) {
            __u16 *mss = (__u16 *)&optx[i];
            bpf_print("    mss %uB\n", bpf_ntohs(mss[1]));
            return TC_ACT_OK;
        }

        i = 8;
        ASSERT(i < (tcph->doff - 5), TC_ACT_OK, "(TCP) has no OPT anymore\n");
        ASSERT((void*)&optx[i+1] <= data_end, TC_ACT_OK, "(TCP) has no OPT anymore\n");

        if ((bpf_ntohl(optx[i]) >> 16) == 0x0204) {
            __u16 *mss = (__u16 *)&optx[i];
            bpf_print("    mss %uB\n", bpf_ntohs(mss[1]));
            return TC_ACT_OK;
        }

        i = 9;
        ASSERT(i < (tcph->doff - 5), TC_ACT_OK, "(TCP) has no OPT anymore\n");
        ASSERT((void*)&optx[i+1] <= data_end, TC_ACT_OK, "(TCP) has no OPT anymore\n");

        if ((bpf_ntohl(optx[i]) >> 16) == 0x0204) {
            __u16 *mss = (__u16 *)&optx[i];
            bpf_print("    mss %uB\n", bpf_ntohs(mss[1]));
            return TC_ACT_OK;
        }
    }

    return TC_ACT_OK;
}

static inline
int dump_udp(void *data, void *data_end)
{
    struct udphdr *udph = data;
    ASSERT((void*)&udph[1] <= data_end, TC_ACT_SHOT, "ERROR: (UDP) Invalid packet size\n");

    bpf_print("  UDP  : %d -> %d\n", bpf_ntohs(udph->source), bpf_ntohs(udph->dest));
    bpf_print("    len %u, csum 0x%x\n", bpf_ntohs(udph->len), bpf_ntohs(udph->check));

    return TC_ACT_OK;
}

static inline
int dump_ipv4(void *data, void *data_end)
{
    struct iphdr *iph = data;
    ASSERT((void*)&iph[1] <= data_end, TC_ACT_SHOT, "ERROR: (IPv4) Invalid packet size\n");

    bpf_print("  IPv4 : %x -> %x\n", bpf_ntohl(iph->saddr), bpf_ntohl(iph->daddr));
    bpf_print("    len %u, id %u, csum 0x%x\n", bpf_ntohs(iph->tot_len), bpf_ntohs(iph->id), bpf_ntohs(iph->check));
    bpf_print("    ttl %u, flags %x, frag_off %u\n", iph->ttl, bpf_ntohs(iph->frag_off) >> 13, bpf_ntohs(iph->frag_off) & 0x1FFF);

    if (iph->protocol == IPPROTO_ICMP)
        dump_icmp(&iph[1], data_end);
    else if (iph->protocol == IPPROTO_TCP)
        dump_tcp(&iph[1], data_end);
    else if (iph->protocol == IPPROTO_UDP)
        dump_udp(&iph[1], data_end);
    else {
        bpf_print("    proto %u\n", iph->protocol);
    }

    return TC_ACT_OK;
}

static inline
int dump_ipv6(void *data, void *data_end)
{
    bpf_print("  IPv6  : NOT SUPPORTED\n");

    return TC_ACT_OK;
}

static inline
int dump_vlan(void *data, void *data_end)
{
    struct vlan_hdr *vhdr = data;
    ASSERT((void*)&vhdr[1] <= data_end, TC_ACT_SHOT, "ERROR: (VLAN) Invalid packet size\n");

    __u16 h_proto = vhdr->h_vlan_encapsulated_proto;

    bpf_print("  VLAN : id %u, proto %x\n", bpf_ntohs(vhdr->h_vlan_TCI), bpf_ntohs(h_proto));

    if (h_proto == bpf_htons(ETH_P_IP))
        dump_ipv4(&vhdr[1], data_end);
    else if (h_proto == bpf_htons(ETH_P_IPV6))
        dump_ipv6(&vhdr[1], data_end);
//    else if (h_proto == bpf_htons(ETH_P_8021Q) || h_proto == bpf_htons(ETH_P_8021AD))
//        dump_vlan2(&vhdr[1], data_end);

    return TC_ACT_OK;
}

static inline
int dump_arp(void *data, void *data_end)
{
    struct arphdr *arph = data;
    ASSERT((void*)&arph[1] <= data_end, TC_ACT_SHOT, "ERROR: (ARP) Invalid packet size\n");

    if (arph->ar_op == bpf_htons(ARPOP_REQUEST))
    {
        struct arpexthdr *arpexth = (struct arpexthdr *)&arph[1];
        ASSERT((void *)&arpexth[1] <= data_end, TC_ACT_SHOT, "ERROR: (ARP) Invalid packet size\n");

        __u32 *src = (__u32 *)arpexth->ar_sip;
        __u32 *dst = (__u32 *)arpexth->ar_tip;
        bpf_print("  ARP WHO HAS: %x, tell %x\n", bpf_ntohl(*dst), bpf_ntohl(*src));
    }
    else if (arph->ar_op == bpf_htons(ARPOP_REPLY))
    {
        struct arpexthdr *arpexth = (struct arpexthdr *)&arph[1];
        ASSERT((void *)&arpexth[1] <= data_end, TC_ACT_SHOT, "ERROR: (ARP) Invalid packet size\n");

        __u32 *src = (__u32*)arpexth->ar_sip;
        __u32 *mac = (__u32*)&arpexth->ar_sha[2];
        bpf_print("  ARP REPLY: %x -> %x\n", bpf_ntohl(*src), bpf_ntohl(*mac));
    }
    else
    {
        bpf_print("  ARP  : op %u\n", bpf_ntohs(arph->ar_op));
    }

    return TC_ACT_OK;
}

static inline
int dump_eth(void *data, void *data_end)
{
    struct ethhdr *eth = data;
    ASSERT((void*)&eth[1] <= data_end, TC_ACT_SHOT, "ERROR: (ETH) Invalid packet size\n");

    __u16 h_proto = eth->h_proto;
    __u32 *src = (__u32*)&eth->h_source[2];
    __u32 *dst = (__u32*)&eth->h_dest[2];

    bpf_print("  ETH  : %x -> %x, proto %x\n", bpf_ntohl(*src), bpf_ntohl(*dst), bpf_ntohs(h_proto));
    bpf_print("         data: %u\n", data);
    bpf_print("     data_end: %u\n", data_end);

    if (h_proto == bpf_htons(ETH_P_IP))
        dump_ipv4(&eth[1], data_end);
    else if (h_proto == bpf_htons(ETH_P_IPV6))
        dump_ipv6(&eth[1], data_end);
    else if (h_proto == bpf_htons(ETH_P_8021Q) || h_proto == bpf_htons(ETH_P_8021AD))
        dump_vlan(&eth[1], data_end);
    else if (h_proto == bpf_htons(ETH_P_ARP))
        dump_arp(&eth[1], data_end);

    return TC_ACT_OK;
}

static inline
int dump_pkt(struct __sk_buff *skb)
{
    bpf_print("DUMP: =====================\n");
    bpf_print("  mark %u,  len %u\n", skb->mark, skb->len);

    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;
    dump_eth(data, data_end);

    bpf_print("DUMP: =====================\n");

    return TC_ACT_OK;
}

////////////////// ACTION DUMP SECTION //////////////////
static inline
int dump_action(int action) {
    switch (action)
    {
        case TC_ACT_PIPE:
        {  
            bpf_print("Action: TC_ACT_PIPE\n\n");
            break;
        }
        case TC_ACT_RECLASSIFY:
        {
            bpf_print("Action: TC_ACT_RECLASSIFY\n\n");
            break;
        }
        case TC_ACT_OK:
        {
            bpf_print("Action: TC_ACT_OK\n\n");
            break;
        }
        case TC_ACT_REDIRECT:
        {
            bpf_print("Action: TC_ACT_REDIRECT\n\n");
            break;
        }
        case TC_ACT_SHOT:
        {
            bpf_print("Action: TC_ACT_SHOT\n\n");
            break;
        }
        case TC_ACT_UNSPEC:
        {
            bpf_print("Action: TC_ACT_UNSPEC\n\n");
            break;
        }
        default:
        {
            bpf_print("Action: UNKNOWN (%d)\n\n");
            break;
        }
    }

    return action;
}

static inline
int debug_action(int action, int debug) {
    if (debug) {
        return dump_action(action);
    }

    return action;
}

#endif /* TC_DUMP_H_ */
