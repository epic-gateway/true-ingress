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

//__section("egress")
int pfc_tx(struct __sk_buff *skb)
{
    bpf_print("PFC TX <<<< # %u, ifindex %u, len %u\n", stats_update(skb->ifindex, STAT_IDX_TX, skb), skb->ifindex, skb->len);

    // get config
    __u32 key = skb->ifindex;
    struct cfg_if *iface = bpf_map_lookup_elem(&map_config, &key);
    ASSERT(iface != 0, dump_action(TC_ACT_UNSPEC), "ERROR: Config not found!\n", dump_pkt(skb));
    struct config *cfg = &iface->queue[CFG_IDX_TX];

    // log hello
    bpf_print("ID %s(%u) Flags %x\n", cfg->name, cfg->id, cfg->flags);

    // parse packet
    struct headers hdr = { 0 };
    ASSERT(parse_headers(skb, &hdr) != TC_ACT_SHOT, dump_action(TC_ACT_OK), "Uninteresting packet type, IGNORING\n", dump_pkt(skb));

    // dump packet
    if (cfg->flags & CFG_TX_DUMP) {
        dump_pkt(skb);
    }

    // start processing
    struct endpoint ep = { 0 };

    // check ROLE
    if (cfg->flags & CFG_TX_PROXY) {
        bpf_print("Is PROXY\n");

        // get Destination EP
        parse_dest_ep(&ep, &hdr);

        // is Service endpoint?
        struct service *svc = bpf_map_lookup_elem(&map_encap, &ep);
        if (svc) {
            bpf_print("GUE Encap: service-id %x, group-id %x, tunnel-id %x\n", bpf_ntohs(svc->identity.service_id), bpf_ntohs(svc->identity.group_id), bpf_ntohl(svc->tunnel_id));
            __u64 *ptr = (__u64 *)svc->key.value;
            bpf_print("    key %lx%lx\n", ptr[0], ptr[1]);
            __u32 key = bpf_ntohl(svc->tunnel_id);
            struct tunnel *tun = bpf_map_lookup_elem(&map_tunnel, &key);
            ASSERT(tun, dump_action(TC_ACT_UNSPEC), "ERROR: tunnel-id %x not found\n", key);

            bpf_print("GUE Encap: tunnel-id %x\n", key);
            bpf_print("    FROM %x:%u\n", tun->ip_local, bpf_ntohs(tun->port_local));
            bpf_print("    TO   %x:%u\n", tun->ip_remote, bpf_ntohs(tun->port_remote));

            ASSERT (TC_ACT_OK == gue_encap_v4(skb, tun, svc), dump_action(TC_ACT_SHOT), "GUE Encap Failed!\n");
            if (cfg->flags & CFG_TX_DUMP) {
                dump_pkt(skb);
            }

            return dump_action(TC_ACT_OK);
        }

        // check output mode
        if (cfg->flags & CFG_TX_SNAT) {
            bpf_print("Checking SNAT\n");

            // get Source EP
            parse_src_ep(&ep, &hdr);

            struct endpoint *snat = bpf_map_lookup_elem(&map_nat, &ep);
            if (snat) {
                bpf_print("SNAT to %x:%u\n", snat->ip, bpf_ntohs(snat->port));

                snat4(skb, &hdr, snat->ip, snat->port);
                if (cfg->flags & CFG_TX_DUMP) {
                    dump_pkt(skb);
                }

                return dump_action(TC_ACT_OK);
            }
        }
    } else {
        bpf_print("Is NODE\n");

        // get SEP
        parse_src_ep(&ep, &hdr);

        // check output mode
        if (cfg->flags & CFG_TX_SNAT) {
            bpf_print("Output mode: DSR (SNAT)\n");

            struct endpoint *snat = bpf_map_lookup_elem(&map_nat, &ep);
            if (snat) {
                bpf_print("SNAT to %x:%u\n", snat->ip, bpf_ntohs(snat->port));

                snat4(skb, &hdr, snat->ip, snat->port);
                if (cfg->flags & CFG_TX_DUMP) {
                    dump_pkt(skb);
                }

                return dump_action(TC_ACT_OK);
            }
        } else {
            bpf_print("Output mode: Regular (GUE Encap)\n");

            struct service *svc = bpf_map_lookup_elem(&map_encap, &ep);
            if (svc) {
                bpf_print("GUE Encap: service-id %x, group-id %x, tunnel-id %x\n", bpf_ntohs(svc->identity.service_id), bpf_ntohs(svc->identity.group_id), bpf_ntohl(svc->tunnel_id));
                __u64 *ptr = (__u64 *)svc->key.value;
                bpf_print("    key %lx%lx\n", ptr[0], ptr[1]);
                __u32 key = bpf_ntohl(svc->tunnel_id);
                struct tunnel *tun = bpf_map_lookup_elem(&map_tunnel, &key);
                ASSERT(tun, dump_action(TC_ACT_UNSPEC), "ERROR: tunnel-id %x not found\n", key);

                bpf_print("GUE Encap: tunnel-id %x\n", key);
                bpf_print("    FROM %x:%u\n", tun->ip_local, bpf_ntohs(tun->port_local));
                bpf_print("    TO   %x:%u\n", tun->ip_remote, bpf_ntohs(tun->port_remote));

                ASSERT (TC_ACT_OK == gue_encap_v4(skb, tun, svc), dump_action(TC_ACT_SHOT), "GUE Encap Failed!\n");
                if (cfg->flags & CFG_TX_DUMP) {
                    dump_pkt(skb);
                }

                return dump_action(TC_ACT_OK);
            }
        }
    }

    return dump_action(TC_ACT_UNSPEC);
}

char _license[] SEC("license") = "GPL";
