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

int pfc_decap(struct __sk_buff *skb)
{
    __u32 pktnum = stats_update(skb->ifindex, STAT_IDX_RX, skb);
    if (skb->ifindex == skb->ingress_ifindex) {
        bpf_print("PFC-Decap (iif %u RX) >>>> PKT # %u, len %u\n", skb->ifindex, pktnum, skb->len);
    } else {
        bpf_print("PFC-Decap (iif %u TX) >>>> PKT # %u, len %u\n", skb->ifindex, pktnum, skb->len);
    }

    // get config
    __u32 key = skb->ifindex;
    struct cfg_if *iface = bpf_map_lookup_elem(&map_config, &key);
    ASSERT(iface != 0, dump_action(TC_ACT_UNSPEC), "ERROR: Config not found!\n", dump_pkt(skb));
    struct config *cfg = &iface->queue[(skb->ifindex == skb->ingress_ifindex) ? CFG_IDX_RX : CFG_IDX_TX];

    if (cfg->prog == CFG_PROG_NONE) {
        bpf_print("cfg[%u]->prog = CFG_PROG_DECAP\n", (skb->ifindex == skb->ingress_ifindex) ? CFG_IDX_RX : CFG_IDX_TX);
        cfg->prog = CFG_PROG_DECAP;
        bpf_map_update_elem(&map_config, &key, iface, BPF_ANY);
    }

    // log hello
    bpf_print("ID %s Flags %u\n", cfg->name, cfg->flags);

    // dump packet
    if (cfg->flags & CFG_RX_DUMP) {
        dump_pkt(skb);
    }

    // parse packet
    struct headers hdr = { 0 };
    if (parse_headers(skb, &hdr) == TC_ACT_SHOT) {
        return dump_action(TC_ACT_UNSPEC);
    }

    // start processing
    struct endpoint ep = { 0 };
    // get Destination EP
    parse_dest_ep(&ep, &hdr);

    // check packet for DECAP
    if (cfg->flags & CFG_RX_GUE) {
        int ret = 0;
        // is GUE endpoint?
        if (bpf_map_lookup_elem(&map_decap, &ep)) {
            void *data_end = (void *)(long)skb->data_end;
            // control or data
            struct guehdr *gue = hdr.payload;

            bpf_print("        &gue[1]: %u\n", (void*)&gue[1]);
            bpf_print("       data_end: %u\n", data_end);
            if ((void*)&gue[1] > data_end) {
                bpf_print("ERROR: (GUE) Invalid packet size\n");
                return dump_action(TC_ACT_SHOT);
            }

            ASSERT1(gue->version == 0, dump_action(TC_ACT_SHOT), bpf_print("ERROR: Unsupported GUE version %u\n", gue->version));

            if (gue->control) {
                if (gue->hlen == 6) {
                    bpf_print("GUE Control: IDs + KEY\n");
                    struct guepinghdr *gueext = (struct guepinghdr *)&gue[1];
                    ASSERT1((void*)&gueext[1] <= data_end, dump_action(TC_ACT_SHOT), bpf_print("ERROR: (GUEext) Invalid packet size\n"));

                    ASSERT1(service_verify(&gueext->ext) == 0, dump_action(TC_ACT_SHOT), bpf_print("ERROR: (GUEext) Service verify failure\n"));

                    return dump_action(update_tunnel_from_guec(bpf_ntohl(gueext->tunnelid), &hdr));
                } else {
                    ASSERT(0, dump_action(TC_ACT_SHOT), "ERROR: Unexpected GUE control HLEN %u\n", gue->hlen);
                }

                return dump_action(TC_ACT_SHOT);
            } else {
                bpf_print("GUE Data: Decap\n");

                ASSERT(gue->hlen != 0, dump_action(TC_ACT_UNSPEC), "Linux GUE (no ext fields)\n");              // FIXME: remove when linux infra not used anymore
                ASSERT(gue->hlen == 5, dump_action(TC_ACT_SHOT), "Unexpected GUE data HLEN %u\n", gue->hlen);

                struct gueexthdr *gueext = (struct gueexthdr *)&gue[1];
                bpf_print("     &gueext[1]: %u\n", (void*)&gueext[1]);
                bpf_print("       data_end: %u\n", data_end);
                if ((void*)&gueext[1] > data_end) {
                    bpf_print("ERROR: (GUEext) Invalid packet size\n");
                    return dump_action(TC_ACT_SHOT);
                }

                // check service identity
                ASSERT1(service_verify(gueext) == 0, dump_action(TC_ACT_SHOT), );

                // get verify structure
                struct verify *verify = bpf_map_lookup_elem(&map_verify, (struct identity *)&gueext->gidsid);
                ASSERT(verify != 0, dump_action(TC_ACT_UNSPEC), "ERROR: Service id %u not found!\n", bpf_ntohl(gueext->gidsid));

                struct service svc = {{ 0 }, {{ 0 }, 0, {{ 0 }, 0 }}, 0 };
                __builtin_memcpy(&svc.key, verify, sizeof(*verify));
                svc.identity = *(struct identity *)&gueext->gidsid;
                svc.hash = pktnum;

                ASSERT (TC_ACT_OK == gue_decap_v4(skb), dump_action(TC_ACT_SHOT), "GUE Decap Failed!\n");

                if (verify->encap.ifindex) {  // EPIC
                    if (cfg->flags & CFG_RX_FWD) {
                        __u32 ifindex = bpf_ntohl(verify->encap.ifindex);

                        // update TABLE-PROXY
                        struct mac *mac_remote = bpf_map_lookup_elem(&map_proxy, &ifindex);
                        ASSERT(mac_remote != 0, dump_action(TC_ACT_UNSPEC), "ERROR: Proxy MAC for ifindex %u not found!\n", ifindex);

                        bpf_print("Set D-MAC: ifindex %u -> MAC %x\n", ifindex, bpf_ntohl(*(__u32*)&(mac_remote->value[2])));
                        ret = bpf_skb_store_bytes(skb, 0, mac_remote->value, 6, BPF_F_INVALIDATE_HASH);
                        if (ret < 0) {
                            bpf_print("bpf_skb_store_bytes: %d\n", ret);
                        }

                        if (cfg->flags & CFG_TX_DUMP) {
                            dump_pkt(skb);
                        }

                        bpf_print("Redirecting to container ifindex %u TX\n", ifindex);
                        return dump_action(bpf_redirect(ifindex, 0));
                    }

                    if (cfg->flags & CFG_TX_DUMP) {
                        dump_pkt(skb);
                    }
                } else {                      // PureLB
                    struct encap_key skey = { { 0 } , 0 };
                    struct endpoint dep = { 0 };
                    ASSERT(parse_ep(skb, &skey.ep, &dep) != TC_ACT_SHOT, dump_action(TC_ACT_UNSPEC), "ERROR: SRC EP parsing failed!\n");

                    // update TABLE-ENCAP
                    bpf_print("updating encap table: %x:%x:%x\n", skey.ep.ip, skey.ep.port, skey.ep.proto);
                    ASSERT(bpf_map_update_elem(&map_encap, &skey, &svc, BPF_ANY) == 0, dump_action(TC_ACT_UNSPEC), "ERROR: map_encap update failed\n");

                    if (cfg->flags & CFG_RX_FWD) {
                        // flags: 0, BPF_FIB_LOOKUP_DIRECT 1, BPF_FIB_LOOKUP_OUTPUT 2
                        struct bpf_fib_lookup fib_params = { 0 };
                        ret = fib_lookup(skb, &fib_params, skb->ifindex, 0);
                        if (ret == TC_ACT_OK) {
                            // Update destination MAC
                            ret = bpf_skb_store_bytes(skb, 0, &fib_params.dmac, 6, BPF_F_INVALIDATE_HASH);
                            if (ret < 0) {
                                bpf_print("bpf_skb_store_bytes(D-MAC): %d\n", ret);
                            }

                            // Update source MAC
                            ret = bpf_skb_store_bytes(skb, 6, &fib_params.smac, 6, BPF_F_INVALIDATE_HASH);
                            if (ret < 0) {
                                bpf_print("bpf_skb_store_bytes(S-MAC): %d\n", ret);
                            }

                            if (cfg->flags & CFG_TX_DUMP) {
                                dump_pkt(skb);
                            }

                            bpf_print("Redirecting to interface ifindex %u TX\n", fib_params.ifindex);
                            return dump_action(bpf_redirect(fib_params.ifindex, 0));
                        }
                    }

                    if (cfg->flags & CFG_TX_DUMP) {
                        dump_pkt(skb);
                    }
                }

                return dump_action(TC_ACT_UNSPEC);
            }
        }
    }

    // check packet for DNAT
    if (cfg->flags & CFG_RX_DNAT) {
        // is PROXY endpoint?
        struct endpoint *dnat = bpf_map_lookup_elem(&map_nat, &ep);
        if (dnat) {
            bpf_print("DNAT to %x:%u\n", dnat->ip, bpf_ntohs(dnat->port));

            dnat4(skb, &hdr, bpf_htonl(dnat->ip), dnat->port);
            if (cfg->flags & CFG_RX_DUMP) {
                dump_pkt(skb);
            }

            return dump_action(TC_ACT_OK);
        }
    }

    return dump_action(TC_ACT_UNSPEC);
}

char _license[] SEC("license") = "GPL";
