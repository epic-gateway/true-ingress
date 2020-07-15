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

#include "common_tc.h"

//__section("ingress")
int pfc_rx(struct __sk_buff *skb)
{
    // get config
    __u32 cfg_key = CFG_IDX_RX;
    struct config *cfg = bpf_map_lookup_elem(&map_config, &cfg_key);
    if (!cfg) {
        bpf_print("ERR: Config not found!\n");
        return dump_action(TC_ACT_UNSPEC);
    }

    // log hello
    bpf_print("%s(%u) RX <<<< (cfg flags %x)\n", cfg->name, cfg->id, cfg->flags);
//    bpf_print("FLAGS CFG_RX_GUE(%u) : %u\n", CFG_RX_GUE, cfg->flags & CFG_RX_GUE);
//    bpf_print("FLAGS CFG_RX_DNAT(%u): %u\n", CFG_RX_DNAT, cfg->flags & CFG_RX_DNAT);
//    bpf_print("FLAGS CFG_RX_DUMP(%u): %u\n", CFG_RX_DUMP, cfg->flags & CFG_RX_DUMP);
    bpf_print("PKT #%u, ifindex %u, len %u\n", stats_update(skb->ifindex, STAT_IDX_RX, skb), skb->ifindex, skb->len);

    // parse packet
    struct headers hdr = { 0 };
    if (parse_headers(skb, &hdr) == TC_ACT_SHOT) {
        bpf_print("Uninteresting packet type, IGNORING\n");
        return dump_action(TC_ACT_OK);
    }

    // dump packet
    if (cfg->flags & CFG_RX_DUMP) {
//      stats_update(skb->ifindex, skb);
//      stats_print(skb->ifindex);

        dump_pkt(skb);
    }

    // start processing
    // get Destination EP
    struct endpoint ep = { 0 };
    parse_dest_ep(&ep, &hdr);

    // check packet for DECAP
    if (cfg->flags & CFG_RX_GUE) {
        // is GUE endpoint?
        if (bpf_map_lookup_elem(&map_decap, &ep)) {
            bpf_print("Parsing GUE header\n");
            // control or data
            if (0) {
                bpf_print("GUE Control: tunnel-id %u from %x:%u\n", 0, 0, 0);
            } else {
                bpf_print("GUE Data: service-id %u, group-id %u\n", 0, 0);
                if (0) {
                    bpf_print("GUE service verification failed\n");
                    return dump_action(TC_ACT_SHOT);
                }

                bpf_print("GUE Decap\n");
                // decap
            }
            return dump_action(TC_ACT_OK);
        }
    }

    // check packet for DNAT
    if (cfg->flags & CFG_RX_DNAT) {
        // is PROXY endpoint?
        struct endpoint *dnat = bpf_map_lookup_elem(&map_nat, &ep);
        if (dnat) {
            bpf_print("DNAT to %x:%u\n", dnat->ip, bpf_ntohs(dnat->port));
            return dump_action(TC_ACT_OK);
        }
    }

    return dump_action(TC_ACT_UNSPEC);
}

char _license[] SEC("license") = "GPL";
