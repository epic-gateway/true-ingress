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

//__section("ingress")
int pfc_rx(struct __sk_buff *skb)
{
    char msg1[] = "PFC RX << ifindex %u, len %u\n";
    bpf_trace_printk(msg1, sizeof(msg1), skb->ifindex, skb->len);

    // get config
    __u32 cfg_key = CFG_IDX_RX;
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

    // get DEP
    struct endpoint ep = { 0 };
    // ...
    char msg4[] = "Parsed DEP: ip %x, port %u, proto %u\n";
    bpf_trace_printk(msg4, sizeof(msg4), ep.ip, ep.port, ep.proto);
    
    // check packet for DECAP
    if (cfg->flags & CFG_RX_GUE) {
        char msg3[] = "Checking GUE\n";
        bpf_trace_printk(msg3, sizeof(msg3));
        
        // is GUE endpoint?
        __u32 *found = bpf_map_lookup_elem(&map_decap, &ep);
        if (found) {
            char msg5[] = "Processing GUE\n";
            bpf_trace_printk(msg5, sizeof(msg5));
            // control or data
            // verify GUE header
            // decap
            return dump_action(TC_ACT_OK);
        }
    }

    // check packet for DNAT
    if (cfg->flags & CFG_RX_DNAT) {
        char msg3[] = "Checking DNAT\n";
        bpf_trace_printk(msg3, sizeof(msg3));
        
        // is PROXY endpoint?
        struct endpoint *dnat = bpf_map_lookup_elem(&map_nat, &ep);
        if (dnat) {
            char msg5[] = "Processing DNAT\n";
            bpf_trace_printk(msg5, sizeof(msg5));
            return dump_action(TC_ACT_OK);
        }
    }

    return dump_action(TC_ACT_UNSPEC);
}

char _license[] SEC("license") = "GPL";
