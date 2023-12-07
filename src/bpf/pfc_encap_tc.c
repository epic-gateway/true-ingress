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
#include "stat_tc.h"
#include "maps_tc.h"

#include "pfc_tc.h"

int pfc_encap(struct __sk_buff *skb)
{
    // get config
    __u32 key = skb->ifindex;
    struct cfg_if *iface = bpf_map_lookup_elem(&map_config, &key);
    ASSERT(iface != 0, dump_action(TC_ACT_UNSPEC), "Encap ERROR: Config %u not found!\n", key);
    struct config *cfg = &iface->queue[(skb->ifindex == skb->ingress_ifindex) ? CFG_IDX_RX : CFG_IDX_TX];
    int debug = cfg->flags & CFG_TX_DUMP;

    if (cfg->prog == CFG_PROG_NONE) {
        bpf_print("cfg[%u]->prog = CFG_PROG_ENCAP\n", (skb->ifindex == skb->ingress_ifindex) ? CFG_IDX_RX : CFG_IDX_TX);
        cfg->prog = CFG_PROG_ENCAP;
        bpf_map_update_elem(&map_config, &key, iface, BPF_ANY);
    }

    // dump packet
    if (debug) {
        if (skb->ifindex == skb->ingress_ifindex) {
            bpf_print("Encap (iif %u RX) >>>> PKT # %u, len %u\n", skb->ifindex, stats_update(skb->ifindex, STAT_IDX_TX, skb), skb->len);
        } else {
            bpf_print("Encap (iif %u TX) >>>> PKT # %u, len %u\n", skb->ifindex, stats_update(skb->ifindex, STAT_IDX_TX, skb), skb->len);
        }

        // log identification info
        bpf_print("ID: \'%s\'    Flags: %u\n", cfg->name, cfg->flags);

        // dump packet
        if (debug) {
            dump_pkt(skb);
        }
    }

    // parse packet
    struct headers hdr = { 0 };
    if (parse_headers(skb, &hdr) == TC_ACT_SHOT) {
        return debug_action(TC_ACT_UNSPEC, debug);
    }

    // start processing
    int ret;
    struct endpoint dep = { 0 };
    // get Destination EP
    parse_dest_ep(&dep, &hdr);

    // check ROLE
    if (cfg->flags & CFG_TX_PROXY) {

        // is Service endpoint?
        struct encap_key ekey = { dep, bpf_ntohl(skb->mark) };
        struct service *svc = bpf_map_lookup_elem(&map_encap, &ekey);
        if (!svc) {
            debug_print(debug, "Encap map lookup failed\n");
        } else {
            debug_print(debug, "GUE Encap Service: group-id %u, service-id %u, tunnel-id %u\n",
                      bpf_ntohs(svc->identity.service_id), bpf_ntohs(svc->identity.group_id), bpf_ntohl(svc->key.tunnel_id));
            __u32 key = bpf_ntohl(svc->key.tunnel_id);
            struct tunnel *tun = bpf_map_lookup_elem(&map_tunnel, &key);
            ASSERT(tun, debug_action(TC_ACT_UNSPEC, debug), "ERROR: tunnel-id %u not found\n", key);
            ASSERT(tun->ip_remote, debug_action(TC_ACT_UNSPEC, debug), "ERROR: tunnel-id %u remote endpoint not resolved\n", key);

            debug_print(debug, "GUE Encap Tunnel: id %u\n", key);
            debug_print(debug, "    FROM %x:%u\n", tun->ip_local, bpf_ntohs(tun->port_local));
            debug_print(debug, "    TO   %x:%u\n", tun->ip_remote, bpf_ntohs(tun->port_remote));

            __u32 via_ifindex = 0;
            ret = gue_encap_v4(skb, tun, svc);
            ASSERT (ret != TC_ACT_SHOT, debug_action(TC_ACT_SHOT, debug), "GUE Encap Failed!\n");

            if (cfg->flags & CFG_TX_FIB) {
                // Resolve MAC addresses if not known yet
                struct bpf_fib_lookup fib_params = { 0 };

                // flags: 0, BPF_FIB_LOOKUP_DIRECT 1, BPF_FIB_LOOKUP_OUTPUT 2
                ret = fib_lookup(skb, &fib_params, skb->ifindex, 0);
                if (ret == TC_ACT_OK) {
                    __builtin_memcpy(&via_ifindex, &fib_params.ifindex, sizeof(via_ifindex));

                    debug_print(debug, "Adjusting MACs\n");
                    // Update destination MAC
                    ret = bpf_skb_store_bytes(skb, 0, &fib_params.dmac, 6, BPF_F_INVALIDATE_HASH);
                    if (ret < 0) {
                        bpf_print("bpf_skb_store_bytes(D-MAC): %d\n", ret);
                        return TC_ACT_SHOT;
                    }

                    // Update source MAC
                    ret = bpf_skb_store_bytes(skb, 6, &fib_params.smac, 6, BPF_F_INVALIDATE_HASH);
                    if (ret < 0) {
                        bpf_print("bpf_skb_store_bytes(S-MAC): %d\n", ret);
                        return TC_ACT_SHOT;
                    }
                }
            }

            if (debug) {
                dump_pkt(skb);
            }

            if (cfg->flags & CFG_TX_FWD && via_ifindex && via_ifindex != skb->ifindex) {
                debug_print(debug, "Redirecting to %u TX\n", via_ifindex);
                return debug_action(bpf_redirect(via_ifindex, 0), debug);
            }

            return debug_action(TC_ACT_UNSPEC, debug);
        }
    } else {
        struct encap_key ekey = { dep, 0 };
        debug_print(debug, "querying encap table key: %x:%x:%x", ekey.ep.ip, ekey.ep.port, ekey.ep.proto);
        struct service *svc = bpf_map_lookup_elem(&map_encap, &ekey);
        if (!svc) {
            debug_print(debug, "Lookup failed: GUE Encap Service: %x:%x:%x\n", ekey.ep.ip, ekey.ep.port, ekey.ep.proto);
        } else {
            // Regular mode
            debug_print(debug, "Regular: GUE Encap Service: group-id %u, service-id %u, tunnel-id %u",
                      bpf_ntohs(svc->identity.service_id), bpf_ntohs(svc->identity.group_id), bpf_ntohl(svc->key.tunnel_id));

            __u32 key = bpf_ntohl(svc->key.tunnel_id);
            struct tunnel *tun = bpf_map_lookup_elem(&map_tunnel, &key);
            ASSERT(tun, debug_action(TC_ACT_UNSPEC, debug), "ERROR: tunnel-id %u not found\n", key);
            ASSERT(tun->ip_remote, debug_action(TC_ACT_UNSPEC, debug), "ERROR: tunnel-id %u remote endpoint not resolved\n", key);

            debug_print(debug, "Regular: GUE Encap Tunnel: id %u\n", key);
            debug_print(debug, "    FROM %x:%u\n", tun->ip_local, bpf_ntohs(tun->port_local));
            debug_print(debug, "    TO   %x:%u\n", tun->ip_remote, bpf_ntohs(tun->port_remote));

            ret = gue_encap_v4(skb, tun, svc);
            ASSERT (ret != TC_ACT_SHOT, debug_action(TC_ACT_SHOT, debug), "GUE Encap Failed!\n");

            __u32 via_ifindex = 0;
            if (cfg->flags & CFG_TX_FIB) {
                // Resolve MAC addresses if not known yet
                struct bpf_fib_lookup fib_params = { 0 };

                // flags: 0, BPF_FIB_LOOKUP_DIRECT 1, BPF_FIB_LOOKUP_OUTPUT 2
                ret = fib_lookup(skb, &fib_params, skb->ifindex, 0);
                if (ret == TC_ACT_OK) {
                    __builtin_memcpy(&via_ifindex, &fib_params.ifindex, sizeof(via_ifindex));

                    debug_print(debug, "Adjusting MACs\n");
                    // Update destination MAC
                    ret = bpf_skb_store_bytes(skb, 0, &fib_params.dmac, 6, BPF_F_INVALIDATE_HASH);
                    if (ret < 0) {
                        debug_print(debug, "bpf_skb_store_bytes(D-MAC): %d\n", ret);
                        return TC_ACT_SHOT;
                    }

                    // Update source MAC
                    ret = bpf_skb_store_bytes(skb, 6, &fib_params.smac, 6, BPF_F_INVALIDATE_HASH);
                    if (ret < 0) {
                        debug_print(debug, "bpf_skb_store_bytes(S-MAC): %d\n", ret);
                        return TC_ACT_SHOT;
                    }
                }
            }

            if (debug) {
                dump_pkt(skb);
            }

            if ((cfg->flags & CFG_TX_FWD) && via_ifindex && via_ifindex != skb->ifindex) {
                debug_print(debug, "Redirecting to %u TX\n", via_ifindex);
                return debug_action(bpf_redirect(via_ifindex, 0), debug);
            }

            return debug_action(TC_ACT_UNSPEC, debug);
        }
    }

    return debug_action(TC_ACT_UNSPEC, debug);
}

char _license[] SEC("license") = "GPL";
