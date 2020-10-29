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

//__section("egress")
int tag_tx(struct __sk_buff *skb)
{
    bpf_print("TAG TX <<<< ifindex %u, len %u\n", skb->ifindex, skb->len);
    bpf_print("  ingress_ifindex %u\n", skb->ingress_ifindex);
    bpf_print("  mark %u\n", skb->mark);

    dump_pkt(skb);

    return dump_action(TC_ACT_UNSPEC);
}

char _license[] SEC("license") = "GPL";
