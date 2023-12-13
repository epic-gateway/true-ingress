#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

#include "dump_tc.h"

int tag(struct __sk_buff *skb)
{
    __u32 key = skb->ifindex;

    if (key == skb->ingress_ifindex) {
        bpf_print("Tag (iif %u RX) >>>> PKT len %u\n", key, skb->len);
    } else {
        bpf_print("Tag (iif %u TX) >>>> PKT len %u\n", key, skb->len);
    }

    // Mark the packet with the Envoy pod's ifindex
    skb->mark = key;
    bpf_print("  Tagged %u\n", skb->mark);

    return dump_action(TC_ACT_UNSPEC);
}

char _license[] SEC("license") = "GPL";
