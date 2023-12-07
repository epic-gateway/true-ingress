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
    // get config
    __u32 key = skb->ifindex;
    struct cfg_if *iface = bpf_map_lookup_elem(&map_config, &key);
    ASSERT(iface != 0, dump_action(TC_ACT_UNSPEC), "Decap ERROR: Config %u not found!\n", key);
    struct config *cfg = &iface->queue[(skb->ifindex == skb->ingress_ifindex) ? CFG_IDX_RX : CFG_IDX_TX];
    int debug = cfg->flags & CFG_RX_DUMP;

    if (cfg->prog == CFG_PROG_NONE) {
        bpf_print("cfg[%u]->prog = CFG_PROG_DECAP\n", (skb->ifindex == skb->ingress_ifindex) ? CFG_IDX_RX : CFG_IDX_TX);
        cfg->prog = CFG_PROG_DECAP;
        bpf_map_update_elem(&map_config, &key, iface, BPF_ANY);
    }

    __u32 pktnum = stats_update(skb->ifindex, STAT_IDX_RX, skb);

    // Pull (i.e. "linearize") the packet if needed.
    // https://github.com/torvalds/linux/blob/master/include/uapi/linux/bpf.h#L2301
    // If len is greater than the distance between data and data_end.
    long pull_amount = (skb->len > TOTAL_GUE_HEADER_SIZE) ? TOTAL_GUE_HEADER_SIZE : skb->len;
    if ((void *)(long)skb->data + pull_amount > (void *)(long)skb->data_end) {
        if (debug) {
            bpf_print("*** Pulling packet headers\n");
            bpf_print("      skb len: %u\n", skb->len);
            bpf_print("  pull amount: %u\n", pull_amount);
            bpf_print("         data: %u\n", skb->data);
            bpf_print("     data_end: %u\n", skb->data_end);
        }
        if (bpf_skb_pull_data(skb, pull_amount) < 0) {
            bpf_print("failure to pull data\n");
            return debug_action(TC_ACT_SHOT, debug);
        }
    }

    // dump packet
    if (debug) {
        if (skb->ifindex == skb->ingress_ifindex) {
            bpf_print("Decap (iif %u RX) >>>> PKT # %u, len %u\n", skb->ifindex, pktnum, skb->len);
        } else {
            bpf_print("Decap (iif %u TX) >>>> PKT # %u, len %u\n", skb->ifindex, pktnum, skb->len);
        }

        // log identification info
        bpf_print("ID: \'%s\'    Flags: %u\n", cfg->name, cfg->flags);

        dump_pkt(skb);
    }

    // parse packet
    struct headers hdr = { 0 };
    if (parse_headers(skb, &hdr) == TC_ACT_SHOT) {
        return debug_action(TC_ACT_UNSPEC, debug);
    }
    dump_headers(debug, &hdr);

    // start processing

    int ret = 0;
    struct endpoint src_ep = { 0 };
    // get source EP
    parse_src_ep(&src_ep, &hdr);
    // Is this a GUE packet? There are two ways that we can
    // tell. First, if there's an entry in map_decap for the
    // source IP and port then it's probably a GUE packet. If that
    // lookup fails then we check the dest port, i.e., is the
    // packet being sent to port 6080? If it is then it's probably
    // a GUE packet. In both cases we verify the packet to make
    // sure that it's legit.
    if (!bpf_map_lookup_elem(&map_decap, &src_ep)) {
        debug_print(debug, "decap map lookup failed\n");
        struct endpoint dest_ep = { 0 };
        parse_dest_ep(&dest_ep, &hdr);

        // We already failed the decap map lookup so if the port
        // check fails, too, then it's definitely not a GUE packet
        // and we don't want to try to decap it.
        ASSERT1(bpf_ntohs(dest_ep.port) == 6080, debug_action(TC_ACT_UNSPEC, debug), debug_print(debug, "Decap map lookup failed and dest port not 6080: %u\n", bpf_ntohs(dest_ep.port)));
        debug_print(debug, "Packet probably GUE based on dest port\n");
    }

    // The packet is probably GUE but we need to verify.

    void *data_end = (void *)(long)skb->data_end;
    // control or data
    debug_print(debug, "            gueh: %u\n", hdr.gueh);
    debug_print(debug, "        &gueh[1]: %u\n", (void*)&hdr.gueh[1]);

    // This check is redundant with the one in parse_headers()
    // but the verifier fails if I don't have it here, also.
    if ((void *)(long)hdr.gueh + sizeof(struct guehdr) > (void *)(long)data_end) {
        bpf_print("ERROR: (GUE) Invalid packet size\n");
        return debug_action(TC_ACT_SHOT, debug);
    }

    ASSERT1(hdr.gueh->version == 0, debug_action(TC_ACT_SHOT, debug), bpf_print("ERROR: Unsupported GUE version %u\n", hdr.gueh->version));

    if (hdr.gueh->control) {
        if (hdr.gueh->hlen == 6) {
            debug_print(debug, "GUE Control: IDs + KEY\n");
            struct guepinghdr *gueext = (struct guepinghdr *)&hdr.gueh[1];
            ASSERT1((void*)&gueext[1] <= data_end, debug_action(TC_ACT_SHOT, debug), bpf_print("ERROR: (GUEext) Invalid packet size\n"));

            ASSERT1(service_verify(&gueext->ext) == 0, debug_action(TC_ACT_SHOT, debug), bpf_print("ERROR: (GUEext) Service verify failure\n"));

            return debug_action(update_tunnel_from_guec(bpf_ntohl(gueext->tunnelid), &hdr), debug);
        } else {
            ASSERT(0, debug_action(TC_ACT_SHOT, debug), "ERROR: Unexpected GUE control HLEN %u\n", hdr.gueh->hlen);
        }

        return debug_action(TC_ACT_SHOT, debug);
    } else {
        debug_print(debug, "GUE Data: Decap\n");

        ASSERT(hdr.gueh->hlen != 0, debug_action(TC_ACT_UNSPEC, debug), "Linux GUE (no ext fields)\n");              // FIXME: remove when linux infra not used anymore
        ASSERT(hdr.gueh->hlen == 5, debug_action(TC_ACT_SHOT, debug), "Unexpected GUE data HLEN %u\n", hdr.gueh->hlen);

        struct gueexthdr *gueext = (struct gueexthdr *)&hdr.gueh[1];
        if ((void*)&gueext[1] > data_end) {
            bpf_print("ERROR: (GUEext) Invalid packet size\n");
            return debug_action(TC_ACT_SHOT, debug);
        }

        // check service identity
        ASSERT1(service_verify(gueext) == 0, debug_action(TC_ACT_SHOT, debug), bpf_print("service_verify failed"));

        // get verify structure
        struct verify *verify = bpf_map_lookup_elem(&map_verify, (struct identity *)&gueext->gidsid);
        ASSERT(verify != 0, debug_action(TC_ACT_UNSPEC, debug), "ERROR: Service id %u not found!\n", bpf_ntohl(gueext->gidsid));

        struct service svc = {{ 0 }, {{ 0 }, 0, {{ 0 }, 0 }}, 0 };
        __builtin_memcpy(&svc.key, verify, sizeof(*verify));
        svc.identity = *(struct identity *)&gueext->gidsid;
        svc.hash = pktnum;

        // Decap the packet
        ASSERT(TC_ACT_OK == gue_decap_v4(skb), debug_action(TC_ACT_SHOT, debug), "GUE Decap Failed!\n");

        // Pull (i.e. "linearize") the packet if needed. We
        // did this above with the encapsulated packet, but
        // when we decap the packet we evidently get a new skb
        // that might not have enough linear bytes to parse
        // the header so we need to do this again.
        pull_amount = (skb->len > TOTAL_EP_HEADER_SIZE) ? TOTAL_EP_HEADER_SIZE : skb->len;
        if ((void *)(long)skb->data + pull_amount > (void *)(long)skb->data_end) {
            if (debug) {
                bpf_print("*** AFTER DECAP Pulling packet headers\n");
                bpf_print("      skb len: %u\n", skb->len);
                bpf_print("  pull amount: %u\n", pull_amount);
                bpf_print("         data: %u\n", skb->data);
                bpf_print("     data_end: %u\n", skb->data_end);
            }
            if (bpf_skb_pull_data(skb, pull_amount) < 0) {
                bpf_print("failure to pull data\n");
                return debug_action(TC_ACT_SHOT, debug);
            }
        }

        if (verify->encap.ifindex) {  // EPIC
            if (cfg->flags & CFG_RX_FWD) {
                __u32 ifindex = bpf_ntohl(verify->encap.ifindex);

                // Lookup dest mac struct from TABLE-PROXY
                struct mac *mac_remote = bpf_map_lookup_elem(&map_proxy, &ifindex);
                ASSERT(mac_remote != 0, debug_action(TC_ACT_UNSPEC, debug), "ERROR: Proxy MAC for ifindex %u not found!\n", ifindex);

                debug_print(debug, "Set D-MAC: ifindex %u -> MAC %x\n", ifindex, bpf_ntohl(*(__u32*)&(mac_remote->value[2])));
                ret = bpf_skb_store_bytes(skb, 0, mac_remote->value, 6, BPF_F_INVALIDATE_HASH);
                if (ret < 0) {
                    bpf_print("bpf_skb_store_bytes: %d\n", ret);
                }

                if (debug) {
                    dump_pkt(skb);
                    bpf_print("Redirecting to container ifindex %u TX\n", ifindex);
                }

                return debug_action(bpf_redirect(ifindex, 0), debug);
            }

            if (debug) {
                dump_pkt(skb);
            }
        } else {                      // PureLB
            struct encap_key skey = { { 0 } , 0 };
            struct endpoint dep = { 0 };
            ASSERT(parse_ep(skb, &skey.ep, &dep) != TC_ACT_SHOT, debug_action(TC_ACT_UNSPEC, debug), "ERROR: SRC EP parsing failed!\n");

            // update TABLE-ENCAP
            debug_print(debug, "updating encap table key: %x:%x:%x", skey.ep.ip, skey.ep.port, skey.ep.proto);
            debug_print(debug, "updating encap table val: %u:%u:%u", bpf_ntohs(svc.identity.service_id), bpf_ntohs(svc.identity.group_id), bpf_ntohl(svc.key.tunnel_id));
            ASSERT(bpf_map_update_elem(&map_encap, &skey, &svc, BPF_ANY) == 0, debug_action(TC_ACT_UNSPEC, debug), "ERROR: map_encap update failed\n");

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

                    if (debug) {
                        dump_pkt(skb);
                        bpf_print("Redirecting to interface ifindex %u TX\n", fib_params.ifindex);
                    }

                    return debug_action(bpf_redirect(fib_params.ifindex, 0), debug);
                }
            }

            if (debug) {
                dump_pkt(skb);
            }
        }

        return debug_action(TC_ACT_UNSPEC, debug);
    }

    return debug_action(TC_ACT_UNSPEC, debug);
}

char _license[] SEC("license") = "GPL";
