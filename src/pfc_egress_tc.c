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

#include "pfc_tc.h"

//__section("egress")
int pfc_tx(struct __sk_buff *skb)
{
    bpf_print("PFC TX <<<< # %u, ifindex %u, len %u\n", stats_update(skb->ifindex, STAT_IDX_TX, skb), skb->ifindex, skb->len);
//    bpf_print("  gso_segs %u\n", skb->gso_segs);
//    bpf_print("  gso_size %u\n", skb->gso_size);
    bpf_print("  tag %u\n", skb->mark);

    // get config
    __u32 key = skb->ifindex;
    struct cfg_if *iface = bpf_map_lookup_elem(&map_config, &key);
    ASSERT(iface != 0, dump_action(TC_ACT_UNSPEC), "ERROR: Config not found!\n", dump_pkt(skb));
    struct config *cfg = &iface->queue[CFG_IDX_TX];

    // log hello
    bpf_print("ID %s(%u) Flags %x\n", cfg->name, cfg->id, cfg->flags);

    // dump packet
    if (cfg->flags & CFG_TX_DUMP) {
        dump_pkt(skb);
    }

    // parse packet
    struct headers hdr = { 0 };
//    ASSERT(parse_headers(skb, &hdr) != TC_ACT_SHOT, dump_action(TC_ACT_OK), "Uninteresting packet type, IGNORING\n", dump_pkt(skb));
    if (parse_headers(skb, &hdr) == TC_ACT_SHOT) {
        return dump_action(TC_ACT_UNSPEC);
    }

    // start processing
    int ret;
    struct endpoint dep = { 0 }, sep = { 0 };
    // get Destination EP
    parse_dest_ep(&dep, &hdr);
    //bpf_print("Parsed Dest EP: ip %x, port %u, proto %u\n", dep.ip, bpf_ntohs(dep.port), bpf_ntohs(dep.proto));

    // check ROLE
    if (cfg->flags & CFG_TX_PROXY) {
        bpf_print("Is PROXY\n");

        // is Service endpoint?
        struct encap_key ekey = { dep, bpf_ntohl(skb->mark) };
        //__u32 *ptr = (__u32*)&ekey;
        //bpf_print("encap KEY: %x%x%x\n", ptr[0], ptr[1], ptr[2]);
        struct service *svc = bpf_map_lookup_elem(&map_encap, &ekey);
        if (svc) {
            if (cfg->id) {
                __u32 key = skb->mark;
                struct mac mac_remote = { 0 };
                // Update destination MAC
                int ret = bpf_skb_load_bytes(skb, 6, mac_remote.value, 6);
                if (ret < 0) {
                    bpf_print("bpf_skb_load_bytes: %d\n", ret);
                    return dump_action(TC_ACT_SHOT);
                }

                //__u32 ptr = *(__u32*)&(mac_remote.value[2]);
                //bpf_print("Update proxy MAC: ifindex %u -> MAC %x\n", key, bpf_ntohl(ptr));

                // update TABLE-PROXY
                bpf_map_update_elem(&map_proxy, &key, &mac_remote, BPF_ANY);
            }

            bpf_print("GUE Encap Service: group-id %u, service-id %u, tunnel-id %u\n",
                      bpf_ntohs(svc->identity.service_id), bpf_ntohs(svc->identity.group_id), bpf_ntohl(svc->key.tunnel_id));
            //__u64 *ptr = (__u64 *)svc->key.value;
            //bpf_print("    tunnel KEY %lx%lx\n", ptr[0], ptr[1]);
            __u32 key = bpf_ntohl(svc->key.tunnel_id);
            struct tunnel *tun = bpf_map_lookup_elem(&map_tunnel, &key);
            ASSERT(tun, dump_action(TC_ACT_UNSPEC), "ERROR: tunnel-id %u not found\n", key);
            ASSERT(tun->ip_remote, dump_action(TC_ACT_SHOT), "ERROR: tunnel remote endpoint not resolved\n");

            __u32 *mac = (__u32 *)&tun->mac_remote.value[2];
            bpf_print("GUE Encap Tunnel: id %u\n", key);
            bpf_print("    FROM %x:%u\n", tun->ip_local, bpf_ntohs(tun->port_local));
            bpf_print("    TO   %x:%u\t(%x)\n", tun->ip_remote, bpf_ntohs(tun->port_remote), bpf_ntohl(*mac));

            // fix MSS
            //set_mss(skb, 1400);

            ret = gue_encap_v4(skb, tun, svc);
            ASSERT (ret != TC_ACT_SHOT, dump_action(TC_ACT_SHOT), "GUE Encap Failed!\n");
            if (cfg->flags & CFG_TX_DUMP) {
                dump_pkt(skb);
            }

            if (cfg->id) {
                bpf_print("Redirecting to %u TX\n", cfg->id);
                return dump_action(bpf_redirect(cfg->id, 0));
            }

            return dump_action(TC_ACT_UNSPEC);
        }

        // check output mode
        if (cfg->flags & CFG_TX_SNAT) {
            //bpf_print("Checking SNAT\n");

            // get Source EP
            parse_src_ep(&sep, &hdr);

            struct endpoint *snat = bpf_map_lookup_elem(&map_nat, &sep);
            if (snat) {
                bpf_print("SNAT to %x:%u\n", snat->ip, bpf_ntohs(snat->port));

                snat4(skb, &hdr, bpf_htonl(snat->ip), snat->port);
                if (cfg->flags & CFG_TX_DUMP) {
                    dump_pkt(skb);
                }

                return dump_action(TC_ACT_OK);
            }
        }
    } else {
        bpf_print("Is NODE\n");

        // FIXME: client tracking ...
        // check output mode
        if (cfg->flags & CFG_TX_SNAT) {
            //bpf_print("Output mode: DSR (SNAT)\n");

            //bpf_print("snat KEY: %lx\n", *(__u64*)&dep);
            struct endpoint *snat = bpf_map_lookup_elem(&map_nat, &dep);
            if (snat) {
                bpf_print("SNAT to %x:%u\n", snat->ip, bpf_ntohs(snat->port));

                snat4(skb, &hdr, bpf_htonl(snat->ip), snat->port);
                if (cfg->flags & CFG_TX_DUMP) {
                    dump_pkt(skb);
                }

                return dump_action(TC_ACT_UNSPEC);
            }
        } else {
            //bpf_print("Output mode: Regular (GUE Encap)\n");

            struct encap_key ekey = { dep, 0 };
            struct service *svc = bpf_map_lookup_elem(&map_encap, &ekey);
            if (svc) {
//                __u32 *tmp = (__u32 *)svc;
//                bpf_print("%x %x %x\n", tmp[0], tmp[1], tmp[2]);
//                bpf_print("%x %x %x\n", tmp[3], tmp[4], tmp[5]);
                bpf_print("GUE Encap Service: group-id %u, service-id %u, tunnel-id %u\n",
                          bpf_ntohs(svc->identity.service_id), bpf_ntohs(svc->identity.group_id), bpf_ntohl(svc->key.tunnel_id));
//                bpf_print("GUE Encap Service: service-id %x, group-id %x, tunnel-id %x\n",
//                          svc->identity.service_id, svc->identity.group_id, svc->key.tunnel_id);
                //__u64 *ptr = (__u64 *)svc->key.value;
                //bpf_print("    tunnel KEY %lx%lx\n", ptr[0], ptr[1]);
                __u32 key = bpf_ntohl(svc->key.tunnel_id);
                struct tunnel *tun = bpf_map_lookup_elem(&map_tunnel, &key);
                ASSERT(tun, dump_action(TC_ACT_UNSPEC), "ERROR: tunnel-id %u not found\n", key);
                ASSERT(tun->ip_remote, dump_action(TC_ACT_SHOT), "ERROR: tunnel remote endpoint not resolved\n");

                __u32 *mac = (__u32 *)&tun->mac_remote.value[2];
                bpf_print("GUE Encap Tunnel: id %u\n", key);
                bpf_print("    FROM %x:%u\n", tun->ip_local, bpf_ntohs(tun->port_local));
                bpf_print("    TO   %x:%u\t(%x)\n", tun->ip_remote, bpf_ntohs(tun->port_remote), bpf_ntohl(*mac));

                // fix MSS
                //set_mss(skb, 1400);

                ret = gue_encap_v4(skb, tun, svc);
                ASSERT (ret != TC_ACT_SHOT, dump_action(TC_ACT_SHOT), "GUE Encap Failed!\n");
                if (cfg->flags & CFG_TX_DUMP) {
                    dump_pkt(skb);
                }

                return dump_action(TC_ACT_UNSPEC);
            }
        }
    }

    return dump_action(TC_ACT_UNSPEC);
}

char _license[] SEC("license") = "GPL";
