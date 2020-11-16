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

//__section("ingress")
int pfc_rx(struct __sk_buff *skb)
{
    __u32 pktnum = stats_update(skb->ifindex, STAT_IDX_RX, skb);
    bpf_print("PFC RX <<<< # %u, ifindex %u, len %u\n", pktnum, skb->ifindex, skb->len);
//    bpf_print("  gso_segs %u\n", skb->gso_segs);
//    bpf_print("  gso_size %u\n", skb->gso_size);

    // get config
    __u32 key = skb->ifindex;
    struct cfg_if *iface = bpf_map_lookup_elem(&map_config, &key);
    ASSERT(iface != 0, dump_action(TC_ACT_UNSPEC), "ERROR: Config not found!\n", dump_pkt(skb));
    struct config *cfg = &iface->queue[CFG_IDX_RX];

    // log hello
    bpf_print("ID %s(%u) Flags %x\n", cfg->name, cfg->id, cfg->flags);

    // dump packet
    if (cfg->flags & CFG_RX_DUMP) {
        dump_pkt(skb);
    }

    // parse packet
    struct headers hdr = { 0 };
//    ASSERT(parse_headers(skb, &hdr) != TC_ACT_SHOT, dump_action(TC_ACT_OK), "Uninteresting packet type, IGNORING\n", dump_pkt(skb));
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
        //bpf_print("Decap key %lx\n", *(__u64*)&ep);

        if (bpf_map_lookup_elem(&map_decap, &ep)) {
            //bpf_print("Parsing GUE header\n");
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
                bpf_print("GUE Data: Decap\n");

                ASSERT(gue->hlen != 0, dump_action(TC_ACT_UNSPEC), "Linux GUE (no ext fields)\n");              // FIXME: remove when linux infra not used anymore
                ASSERT(gue->hlen == 5, dump_action(TC_ACT_SHOT), "Unexpected GUE data HLEN %u\n", gue->hlen);

                struct gueext5hdr *gueext = (struct gueext5hdr *)&gue[1];
                ASSERT((void*)&gueext[1] <= data_end, dump_action(TC_ACT_SHOT), "ERROR: (GUEext) Invalid packet size\n");

                //__u32 id = bpf_ntohl(gueext->id);
                //bpf_print("GUE Data: id %x (service-id %u, group-id %u)\n", id, id & 0xFFFF, (id >> 16) & 0xFFFF);
                // check service identity
                ASSERT1(service_verify(gueext) == 0, dump_action(TC_ACT_SHOT), );

                // get verify structure
                struct verify *verify = bpf_map_lookup_elem(&map_verify, (struct identity *)&gueext->id);
                ASSERT(verify != 0, dump_action(TC_ACT_UNSPEC), "ERROR: Service id %u not found!\n", bpf_ntohl(gueext->id));

                struct service svc;
                __builtin_memcpy(&svc.key, verify, sizeof(*verify));  //FIXME?
                svc.identity = *(struct identity *)&gueext->id;
//                __builtin_memcpy(&svc.identity, &gueext->id, 4);
                svc.hash = pktnum;

                ASSERT (TC_ACT_OK == gue_decap_v4(skb), dump_action(TC_ACT_SHOT), "GUE Decap Failed!\n");

                if (verify->encap.ifindex) {  // usually EGW
                    __u32 ifindex = bpf_ntohl(verify->encap.ifindex);

                    // update TABLE-PROXY
                    struct mac *mac_remote = bpf_map_lookup_elem(&map_proxy, &ifindex);
                    ASSERT(mac_remote != 0, dump_action(TC_ACT_UNSPEC), "ERROR: Proxy MAC for ifindex %u not found!\n", ifindex);

                    struct mac tmp = { 0 };
                    ret = bpf_skb_load_bytes(skb, 0, tmp.value, 6);
                    if (ret < 0) {
                        bpf_print("bpf_skb_load_bytes D-MAC: %d\n", ret);
                        return dump_action(TC_ACT_SHOT);
                    }
                    ret = bpf_skb_store_bytes(skb, 6, tmp.value, 6, BPF_F_INVALIDATE_HASH);
                    if (ret < 0) {
                        bpf_print("bpf_skb_store_bytes(S-MAC): %d\n", ret);
                        return TC_ACT_SHOT;
                    }

                    // Update destination MAC
                    ret = bpf_skb_store_bytes(skb, 0, mac_remote->value, 6, BPF_F_INVALIDATE_HASH);
                    if (ret < 0) {
                        bpf_print("bpf_skb_store_bytes: %d\n", ret);
                        return TC_ACT_SHOT;
                    }

                    if (cfg->flags & CFG_TX_DUMP) {
                        dump_pkt(skb);
                    }

                    bpf_print("Redirecting to container ifindex %u TX\n", ifindex);
                    return dump_action(bpf_redirect(ifindex, 0));
                } else {                // usually NODE
                    //bpf_print("Create/refresh tracking record\n");
                    struct encap_key skey = { { 0 } , 0 };
                    struct endpoint dep = { 0 };
                    ASSERT(parse_ep(skb, &skey.ep, &dep) != TC_ACT_SHOT, dump_action(TC_ACT_UNSPEC), "ERROR: SRC EP parsing failed!\n");
                    //bpf_print("  Parsed Source EP: ip %x, port %u, proto %u\n", skey.ep.ip, bpf_ntohs(skey.ep.port), bpf_ntohs(skey.ep.proto));
                    //bpf_print("  KEY: %lx\n", *(__u64*)&skey.ep);
                    //__u32 *ptr = (__u32*)&ekey;
                    //bpf_print("encap KEY: %x%x%x\n", ptr[0], ptr[1], ptr[2]);

                    //bpf_print("  VALUE: group-id %u, service-id %u, tunnel-id %u\n",
                    //        bpf_ntohs(svc.identity.service_id), bpf_ntohs(svc.identity.group_id), bpf_ntohl(svc.key.tunnel_id));
                    //bpf_print("         hash %x\n", svc.hash);
                    //__u64 *ptr = (__u64 *)svc.key.value;
                    //bpf_print("    key %lx%lx\n", ptr[0], ptr[1]);

                    // update TABLE-ENCAP
                    bpf_map_update_elem(&map_encap, &skey, &svc, BPF_ANY);

                    __u32 via_ifindex = 0;
#if 0
                    // flags: 0, BPF_FIB_LOOKUP_DIRECT 1, BPF_FIB_LOOKUP_OUTPUT 2
                    int flags_fib = 0;
                    struct bpf_fib_lookup fib_params = { 0 };
                    ret = fib_lookup(skb, &fib_params, skb->ifindex, flags_fib);
                    if (ret == TC_ACT_OK) {
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

                        __builtin_memcpy(&via_ifindex, &fib_params.ifindex, sizeof(via_ifindex));
                    }
#else
                    // Update source MAC
                    struct mac tmp = { 0 };
                    // Update destination MAC
                    ret = bpf_skb_load_bytes(skb, 0, tmp.value, 6);
                    if (ret < 0) {
                        bpf_print("bpf_skb_load_bytes D-MAC: %d\n", ret);
                        return dump_action(TC_ACT_SHOT);
                    }
                    ret = bpf_skb_store_bytes(skb, 6, tmp.value, 6, BPF_F_INVALIDATE_HASH);
                    if (ret < 0) {
                        bpf_print("bpf_skb_store_bytes(S-MAC): %d\n", ret);
                        return TC_ACT_SHOT;
                    }
#endif
                    if (cfg->flags & CFG_TX_DUMP) {
                        dump_pkt(skb);
                    }

                    if ((cfg->flags & CFG_RX_FWD) && via_ifindex && via_ifindex != skb->ifindex) {
                        bpf_print("Redirecting to interface ifindex %u TX\n", via_ifindex);
                        return dump_action(bpf_redirect(via_ifindex, 0));
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
