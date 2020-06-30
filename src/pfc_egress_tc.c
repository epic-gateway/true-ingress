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

/* A minimal, stand-alone unit, which matches on all traffic
 * with the default classid (return code of -1) looks like: */

//__section("egress")
int pfc_tx(struct __sk_buff *skb)
{
    char msg[] = "PFC TX >> ifindex %u, len %u\n";
    bpf_trace_printk(msg, sizeof(msg), skb->ifindex, skb->len);

    return TC_ACT_UNSPEC;
}

char _license[] SEC("license") = "GPL";
