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
    bpf_print("PFC RX <<<< # %u, ifindex %u, len %u\n", stats_update(skb->ifindex, STAT_IDX_RX, skb), skb->ifindex, skb->len);

    // get config
    __u32 key = skb->ifindex;
    struct cfg_if *iface = bpf_map_lookup_elem(&map_config, &key);
    ASSERT(iface != 0, dump_action(TC_ACT_UNSPEC), "ERROR: Config not found!\n", dump_pkt(skb));
    struct config *cfg = &iface->queue[CFG_IDX_RX];

    // log hello
    bpf_print("ID %s(%u) Flags %x\n", cfg->name, cfg->id, cfg->flags);

    // parse packet
    struct headers hdr = { 0 };
    ASSERT(parse_headers(skb, &hdr) != TC_ACT_SHOT, dump_action(TC_ACT_OK), "Uninteresting packet type, IGNORING\n", dump_pkt(skb));

    // dump packet
    if (cfg->flags & CFG_RX_DUMP) {
        dump_pkt(skb);
    }

    // start processing
    struct endpoint ep = { 0 };
    // get Destination EP
    parse_dest_ep(&ep, &hdr);

    // check packet for DECAP
    if (cfg->flags & CFG_RX_GUE) {
        // is GUE endpoint?
        if (bpf_map_lookup_elem(&map_decap, &ep)) {
            bpf_print("Parsing GUE header\n");
            void *data_end = (void *)(long)skb->data_end;
            // control or data
            struct guehdr *gue = hdr.payload;

            ASSERT((void*)&gue[1] <= data_end, dump_action(TC_ACT_SHOT), "ERROR: (GUE) Invalid packet size\n");

            ASSERT1(gue->version == 0, dump_action(TC_ACT_SHOT), bpf_print("ERROR: Unsupported GUE version %u\n", gue->version));

            if (gue->control) {
                if (gue->hlen == 1) {
                    bpf_print("GUE Control: ID\n");
                    struct gueext1hdr *gueext = (struct gueext1hdr *)&gue[1];
                    ASSERT((void*)&gueext[1] <= data_end, dump_action(TC_ACT_SHOT), "ERROR: (GUEext) Invalid packet size\n");

                    return dump_action(update_tunnel_from_guec(bpf_ntohl(gueext->id), &hdr));
                } else if (gue->hlen == 5) {
                    bpf_print("GUE Control: ID + KEY\n");
                    struct gueext5hdr *gueext = (struct gueext5hdr *)&gue[1];
                    ASSERT1((void*)&gueext[1] <= data_end, dump_action(TC_ACT_SHOT), bpf_print("ERROR: (GUEext) Invalid packet size\n"));

                    ASSERT1(service_verify(gueext) == 0, dump_action(TC_ACT_SHOT), );

                    return dump_action(update_tunnel_from_guec(bpf_ntohl(gueext->id), &hdr));
                } else {
                    ASSERT(0, dump_action(TC_ACT_SHOT), "ERROR: Unexpected GUE control HLEN %u\n", gue->hlen);
                }

                return dump_action(TC_ACT_SHOT);
            } else {
                ASSERT(gue->hlen != 0, dump_action(TC_ACT_UNSPEC), "Linux GUE (no ext fields)\n");              // FIXME: remove when linux infra not used anymore
                ASSERT(gue->hlen == 5, dump_action(TC_ACT_SHOT), "Unexpected GUE data HLEN %u\n", gue->hlen);

                bpf_print("GUE Data: ID + KEY\n");
                struct gueext5hdr *gueext = (struct gueext5hdr *)&gue[1];
                ASSERT((void*)&gueext[1] <= data_end, dump_action(TC_ACT_SHOT), "ERROR: (GUEext) Invalid packet size\n");

                __u32 id = bpf_ntohl(gueext->id);
                bpf_print("GUE Data: id %x (service-id %u, group-id %u)\n", id, id & 0xFFFF, (id >> 16) & 0xFFFF);

                ASSERT1(service_verify(gueext) == 0, dump_action(TC_ACT_SHOT), );

                bpf_print("GUE Decap\n");
                // decap

                return dump_action(TC_ACT_OK);
            }
        }
    }

    // check packet for DNAT
    if (cfg->flags & CFG_RX_DNAT) {
        // is PROXY endpoint?
        struct endpoint *dnat = bpf_map_lookup_elem(&map_nat, &ep);
        if (dnat) {
            bpf_print("DNAT to %x:%u\n", dnat->ip, bpf_ntohs(dnat->port));

            dnat4(skb, &hdr, dnat->ip, dnat->port);
            if (cfg->flags & CFG_RX_DUMP) {
                dump_pkt(skb);
            }

            return dump_action(TC_ACT_OK);
        }
    }

    return dump_action(TC_ACT_UNSPEC);
}

char _license[] SEC("license") = "GPL";
