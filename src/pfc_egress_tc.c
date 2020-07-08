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
#include "cfg_tc.h"
#include "stat_tc.h"
#include "maps_tc.h"

//__section("egress")
int pfc_tx(struct __sk_buff *skb)
{
    char msg1[] = "PFC TX << ifindex %u, len %u\n";
    bpf_trace_printk(msg1, sizeof(msg1), skb->ifindex, skb->len);

    // get config
    __u32 cfg_key = CFG_IDX_TX;
    struct config *cfg = bpf_map_lookup_elem(&map_config, &cfg_key);
    if (!cfg) {
        char msg[] = "ERR: Config not found!\n";
        bpf_trace_printk(msg, sizeof(msg));
        return TC_ACT_UNSPEC;
    }

    char msg2[] = "CFG: id %u, flags %x, name %s\n";
    bpf_trace_printk(msg2, sizeof(msg2), cfg->id, cfg->flags, cfg->name);

    // start processing
    stats_update(skb->ifindex, skb);
    stats_print(skb->ifindex);
    dump_pkt(skb);
    
    struct endpoint ep = { 0 };

    // check ROLE
    if (cfg->flags & CFG_TX_PROXY) {
        char msg3[] = "Is PROXY\n";
        bpf_trace_printk(msg3, sizeof(msg3));

        // get DEP
        // ...
        char msg4[] = "Parsed DEP: ip %x, port %u, proto %u\n";
        bpf_trace_printk(msg4, sizeof(msg4), ep.ip, ep.port, ep.proto);
        
        // is Service endpoint?
        struct service *svc = bpf_map_lookup_elem(&map_encap, &ep);
        if (svc) {
            char msg5[] = "GUE Encap\n";
            bpf_trace_printk(msg5, sizeof(msg5));

            return dump_action(TC_ACT_OK);
        }
    } else {
        char msg3[] = "Is NODE\n";
        bpf_trace_printk(msg3, sizeof(msg3));

        // get SEP
        // ...
        char msg4[] = "Parsed SEP: ip %x, port %u, proto %u\n";
        bpf_trace_printk(msg4, sizeof(msg4), ep.ip, ep.port, ep.proto);

        // chack output mode
        if (cfg->flags & CFG_TX_DSO) {
            char msg6[] = "Output mode: DSO\n";
            bpf_trace_printk(msg6, sizeof(msg6));
        } else {
            char msg6[] = "Output mode: Regular\n";
            bpf_trace_printk(msg6, sizeof(msg6));
        }
    }

    return dump_action(TC_ACT_UNSPEC);
}

char _license[] SEC("license") = "GPL";
