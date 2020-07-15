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
    // get config
    __u32 cfg_key = CFG_IDX_TX;
    struct config *cfg = bpf_map_lookup_elem(&map_config, &cfg_key);
    if (!cfg) {
        bpf_print("ERR: Config not found!\n");
        return dump_action(TC_ACT_UNSPEC);
    }

    // log hello
    bpf_print("%s(%u) TX <<<< (cfg flags %x)\n", cfg->name, cfg->id, cfg->flags);
    bpf_print("PKT #%u, ifindex %u, len %u\n", stats_update(skb->ifindex, STAT_IDX_TX, skb), skb->ifindex, skb->len);

    // parse packet
    struct headers hdr = { 0 };
    if (parse_headers(skb, &hdr) == TC_ACT_SHOT) {
        bpf_print("Uninteresting packet type, IGNORING\n");
        return dump_action(TC_ACT_OK);
    }

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
            bpf_print("GUE Encap: service-id %u, group-id %u, key %s\n", svc->identity.service_id, svc->identity.group_id, svc->key.value);
            bpf_print("GUE Encap: tunnel-id %u ", svc->tunnel_id);
            struct tunnel *tun = bpf_map_lookup_elem(&map_tunnel, &svc->tunnel_id);
            if (!tun) {
                bpf_print("NOT FOUND\n");
                return dump_action(TC_ACT_UNSPEC);
            }

            bpf_print("(%x:%u -> ", tun->ip_local, tun->port_local);
            bpf_print("%x:%u)\n", tun->ip_remote, tun->port_remote);

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
                return dump_action(TC_ACT_OK);
            }
        }
    } else {
        bpf_print("Is NODE\n");

        // get SEP
        parse_src_ep(&ep, &hdr);

        // check output mode
        if (cfg->flags & CFG_TX_SNAT) {
            bpf_print("Output mode: DSO (SNAT)\n");

            struct endpoint *snat = bpf_map_lookup_elem(&map_nat, &ep);
            if (snat) {
                bpf_print("SNAT to %x:%u\n", snat->ip, bpf_ntohs(snat->port));
                return dump_action(TC_ACT_OK);
            }
        } else {
            bpf_print("Output mode: Regular (GUE Encap)\n");

            struct service *svc = bpf_map_lookup_elem(&map_encap, &ep);
            if (svc) {
                bpf_print("GUE Encap: service-id %u, group-id %u, key %s\n", svc->identity.service_id, svc->identity.group_id, svc->key.value);
                bpf_print("GUE Encap: tunnel-id %u ", svc->tunnel_id);
                struct tunnel *tun = bpf_map_lookup_elem(&map_tunnel, &svc->tunnel_id);
                if (!tun) {
                    bpf_print("NOT FOUND\n");
                    return dump_action(TC_ACT_UNSPEC);
                }

                bpf_print("(%x:%u -> ", tun->ip_local, tun->port_local);
                bpf_print("%x:%u)\n", tun->ip_remote, tun->port_remote);

                return dump_action(TC_ACT_OK);
            }
        }
    }

    return dump_action(TC_ACT_UNSPEC);
}

char _license[] SEC("license") = "GPL";
