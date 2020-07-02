#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/pkt_cls.h>

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

#include "dump_tc.h"

/* A minimal, stand-alone unit, which matches on all traffic
 * with the default classid (return code of -1) looks like: */

//__section("ingress")
int egw_rx(struct __sk_buff *skb)
{
    char msg[] = "EGW RX << ifindex %u, len %u\n";
    bpf_trace_printk(msg, sizeof(msg), skb->ifindex, skb->len);
    dump_pkt(skb);
    return dump_action(TC_ACT_UNSPEC);
}

char _license[] SEC("license") = "GPL";
