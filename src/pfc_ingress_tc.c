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

//////////////////////////////
struct guehdr {
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
    __u8    hlen : 5,
            control : 1,
            version : 2;
#else
    __u8    version : 2,
            control : 1,
            hlen : 5;
#endif
    __u8 proto_ctype;
    __u16 flags;
};
//////////////////////////////
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
    bpf_print("PKT #%u, ifindex %u, len %u\n", stats_update(skb->ifindex, STAT_IDX_RX, skb), skb->ifindex, skb->len);

    // parse packet
    struct headers hdr = { 0 };
    if (parse_headers(skb, &hdr) == TC_ACT_SHOT) {
        bpf_print("Uninteresting packet type, IGNORING\n");
        return dump_action(TC_ACT_OK);
    }

    // dump packet
    if (cfg->flags & CFG_RX_DUMP) {
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
            void *data_end = (void *)(long)skb->data_end;
            // control or data
            struct guehdr *gue = hdr.payload;

            if ((void*)&gue[1] > data_end)
            {
                bpf_print("ERROR: (GUE) Invalid packet size\n");
                return dump_action(TC_ACT_SHOT);
            }

            bpf_print("  gue->version = %u\n", gue->version);
            if (gue->version != 0) {
                bpf_print("ERROR: Unsupported GUE version %u\n", gue->version);
                return dump_action(TC_ACT_SHOT);
            }

            bpf_print("  gue->control = %u\n", gue->control);
            if (gue->control) {
                bpf_print("  gue->hlen = %u\n", gue->hlen);
                if (gue->hlen != 1) {
                    bpf_print("ERROR: Unexpected GUE control HLEN %u\n", gue->hlen);
                    return dump_action(TC_ACT_SHOT);
                }

                __u32 *tunnel_id_ptr = (__u32 *)&gue[1];
                if ((void*)&tunnel_id_ptr[1] > data_end)
                {
                    bpf_print("ERROR: (GUE) Invalid packet size\n");
                    return dump_action(TC_ACT_SHOT);
                }
                __u32 tunnel_id = bpf_ntohl(*tunnel_id_ptr);
                bpf_print("  tunnel_id = %u\n", tunnel_id);

                // update map
                struct tunnel *tun = bpf_map_lookup_elem(&map_tunnel, &tunnel_id);
                if (!tun) {
                    bpf_print("ERROR: Failed to update tunnel-id %u\n", tunnel_id);
                    return dump_action(TC_ACT_SHOT);
                }

                parse_src_ep(&ep, &hdr);
                bpf_print("GUE Control: Updating tunnel-id %u remote to %x:%u\n", tunnel_id, ep.ip, bpf_ntohs(ep.port));
                tun->ip_remote = ep.ip;
                tun->port_remote = ep.port;

                return dump_action(TC_ACT_SHOT);
            } else {
                if (gue->hlen != 5) {
                    bpf_print("Unexpected GUE data HLEN %u\n", gue->hlen);
                    return dump_action(TC_ACT_UNSPEC);
                }

                bpf_print("GUE Data: service-id %u, group-id %u\n", 0, 0);
                if (0) {
                    bpf_print("ERROR: GUE service verification failed\n");
                    return dump_action(TC_ACT_SHOT);
                }

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
            return dump_action(TC_ACT_OK);
        }
    }

    return dump_action(TC_ACT_UNSPEC);
}

char _license[] SEC("license") = "GPL";
