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
#include "maps_tc.h"

//__section("egress")
int tag_tx(struct __sk_buff *skb)
{
    if (skb->ifindex == skb->ingress_ifindex) {
        bpf_print("PFC-Tag (iif %u RX) >>>> PKT len %u\n", skb->ifindex, skb->len);
    } else {
        bpf_print("PFC-Tag (iif %u TX) >>>> PKT len %u\n", skb->ifindex, skb->len);
    }

    skb->mark = skb->ifindex;
    bpf_print("  Tagged %u\n", skb->mark);

    __u32 key = skb->ifindex;
    struct mac mac_remote = { 0 };
    // Update destination MAC
    int ret = bpf_skb_load_bytes(skb, 6, mac_remote.value, 6);
    if (ret < 0) {
        bpf_print("bpf_skb_load_bytes: %d\n", ret);
        return dump_action(TC_ACT_UNSPEC);
    }

    bpf_print("  Update proxy MAC: ifindex %u -> MAC %x\n", key, bpf_ntohl(*(__u32*)&(mac_remote.value[2])));

    // update TABLE-PROXY
    bpf_map_update_elem(&map_proxy, &key, &mac_remote, BPF_ANY);


    return dump_action(TC_ACT_UNSPEC);
}

char _license[] SEC("license") = "GPL";
