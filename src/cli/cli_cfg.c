#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>
#include <linux/types.h>
#include <getopt.h>
#include <net/if.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <bpf_util.h>

#include "struct_tc.h"
#include "cli_util.h"

void usage(char *prog) {
    fprintf(stderr,"ERR: Too little arguments\n");
    fprintf(stderr,"Usage:\n");
    fprintf(stderr,"    %s get <interface|all>\n", prog);
    fprintf(stderr,"    %s set <interface> <direction> <flags> <name>\n", prog);
    fprintf(stderr,"    %s del <interface|all>\n\n", prog);
    fprintf(stderr,"    <interface>     - Interface where PFC is attached\n");
    fprintf(stderr,"    <direction>     - 0 for ingress, 1 for egress\n");
    fprintf(stderr,"    <flags>         - PFC operational mode:\n");
    fprintf(stderr,"                       Ingress : 1 GUE-DECAP, 4 FWD, 8 DUMP\n");
    fprintf(stderr,"                       Egress  : 1 IS-PROXY, 2 DSR, 4 FWD, 8 DUMP, 16 FIB\n");
    fprintf(stderr,"    <name>          - Instance identifier (string)\n");
}

void map_cfg_print_header() {
    printf("TABLE-CFG:\n     Interface          Ifindex  Direction  Binary        Name                 Flags\n");
    printf("-------------------------------------------------------------------------------------------------------------\n");
}

void map_cfg_print_footer() {
    printf("-------------------------------------------------------------------------------------------------------------\n");
    printf("\n");
}

void map_cfg_print_count(__u32 count) {
    printf("-------------------------------------------------------------------------------------------------------------\n");
    printf("Entries:  %u\n\n", count);
}

void print_none(__u8 direction, unsigned int key, struct config *value) {
    char ifname[32];

    printf("CFG  %-16s   %-5u    %s    None          %-16s     %u\n",
            if_indextoname(key, ifname), key,
            (direction == CFG_IDX_RX) ? "Ingress" : "Egress ",
            value->name, value->flags);
}

void print_decap(__u8 direction, unsigned int key, struct config *value) {
    char ifname[32];

    printf("CFG  %-16s   %-5u    %s    PFC-Decap     %-16s    %s%s%s%s\n",
            if_indextoname(key, ifname), key,
            (direction == CFG_IDX_RX) ? "Ingress" : "Egress ", value->name,
            (value->flags & CFG_RX_GUE) ? " GUE-DECAP(1)" : "",
            (value->flags & CFG_RX_FWD) ? " FWD(4)" : "",
            (value->flags & CFG_RX_DUMP) ? " DUMP(8)" : "");
}

void print_encap(__u8 direction, unsigned int key, struct config *value) {
    char ifname[32];

    printf("CFG  %-16s   %-5u    %s    PFC-Encap     %-16s    %s%s%s%s%s\n",
            if_indextoname(key, ifname), key,
            (direction == CFG_IDX_RX) ? "Ingress" : "Egress ", value->name,
            (value->flags & CFG_TX_PROXY) ? " PROXY(1)" : "",
            (value->flags & CFG_TX_FWD) ? " FWD(4)" : "",
            (value->flags & CFG_TX_DUMP) ? " DUMP(8)" : "",
            (value->flags & CFG_TX_FIB) ? " FIB(16)" : "");
}

void print_tag(__u8 direction, unsigned int key, struct config *value) {
    char ifname[32];

    printf("CFG  %-16s   %-5u    %s    PFC-Tag       %-16s     %u\n",
            if_indextoname(key, ifname), key,
            (direction == CFG_IDX_RX) ? "Ingress" : "Egress ", 
            value->name, value->flags);
}

void print_unknown(__u8 direction, unsigned int key, struct config *value) {
    char ifname[32];

    printf("CFG  %-16s   %-5u    %s    Unknown       %-16s     %u\n",
            if_indextoname(key, ifname), key,
            (direction == CFG_IDX_RX) ? "Ingress" : "Egress ",
            value->name, value->flags);
}

void map_cfg_print_record(unsigned int key, struct cfg_if *value) {
    switch (value->queue[CFG_IDX_RX].prog) {
        case CFG_PROG_NONE:
            print_none(CFG_IDX_RX, key, &value->queue[CFG_IDX_RX]);
            break;
        case CFG_PROG_DECAP:
            print_decap(CFG_IDX_RX, key, &value->queue[CFG_IDX_RX]);
            break;
        case CFG_PROG_ENCAP:
            print_encap(CFG_IDX_RX, key, &value->queue[CFG_IDX_RX]);
            break;
        case CFG_PROG_TAG:
            print_tag(CFG_IDX_RX, key, &value->queue[CFG_IDX_RX]);
            break;
        default:
            print_unknown(CFG_IDX_RX, key, &value->queue[CFG_IDX_RX]);
    }

    switch (value->queue[CFG_IDX_TX].prog) {
        case CFG_PROG_NONE:
            print_none(CFG_IDX_TX, key, &value->queue[CFG_IDX_TX]);
            break;
        case CFG_PROG_DECAP:
            print_decap(CFG_IDX_TX, key, &value->queue[CFG_IDX_TX]);
            break;
        case CFG_PROG_ENCAP:
            print_encap(CFG_IDX_TX, key, &value->queue[CFG_IDX_TX]);
            break;
        case CFG_PROG_TAG:
            print_tag(CFG_IDX_TX, key, &value->queue[CFG_IDX_TX]);
            break;
        default:
            print_unknown(CFG_IDX_TX, key, &value->queue[CFG_IDX_TX]);
    }
}

void map_cfg_print_err(unsigned int key, const char *name, int err) {
    char ifname[32];

    fprintf(stderr, "CFG.%s (%d) (%s) -> ERR (%d) \'%s\'\n", name,
            key, if_indextoname(key, ifname), errno, strerror(errno));
}

bool map_cfg_get(int map_fd, unsigned int ifindex, struct cfg_if *value) {

    if (bpf_map_lookup_elem(map_fd, &ifindex, value)) {
        return errno;
    }

    return 0;
}

bool map_cfg_getall(int map_fd) {
    __u32 prev_key, key;
    struct cfg_if value;
    __u32 count = 0;
    int ret;

    map_cfg_print_header();
    while(bpf_map_get_next_key(map_fd, &prev_key, &key) == 0) {
        ret = map_cfg_get(map_fd, key, &value);
        if (!ret) {
            map_cfg_print_record(key, &value);
            ++count;
        } else {
            map_cfg_print_err(key, "GET", ret);
            break;
        }
        prev_key=key;
    }
    map_cfg_print_count(count);

    return true;
}

bool map_cfg_set(int map_fd, unsigned int ifindex, unsigned int qid, uint flags, char *name) {
    struct cfg_if value = { 0 };
    char ifname[32];

    // read the existing struct (if any)
    bpf_map_lookup_elem(map_fd, &ifindex, &value);

    // update the struct
    struct config *cfg = &value.queue[qid];
    cfg->flags = flags;
    strncpy(cfg->name, name, 16);

    // write it back
    if (bpf_map_update_elem(map_fd, &ifindex, &value, 0)) {
        fprintf(stderr, "CFG.SET {%u[%u]} (%s[%s]) -> ERR (%d) \'%s\'\n",
                ifindex, qid, if_indextoname(ifindex, ifname),
                (qid) ? "TX" : "RX", errno, strerror(errno));
        return false;
    }
    printf("CFG.SET {%u[%u]} (%s[%s])\t\tCREATED\n", ifindex, qid,
           if_indextoname(ifindex, ifname), (qid) ? "TX" : "RX");

    return true;
}

bool map_cfg_del(int map_fd, unsigned int ifindex) {
    char ifname[32];

    if (bpf_map_delete_elem(map_fd, &ifindex)) {
        fprintf(stderr, "CFG.DEL {%u} (%s)\t\tERR (%d) \'%s\'\n", ifindex, if_indextoname(ifindex, ifname), errno, strerror(errno));

        return false;
    } else {
        printf("CFG.DEL {%u} (%s)\t\tOK\n", ifindex, if_indextoname(ifindex, ifname));
    }

    return true;
}

bool map_cfg_delall(int map_fd) {
    __u32 prev_key, key;

    while(bpf_map_get_next_key(map_fd, &prev_key, &key) == 0) {
        map_cfg_del(map_fd, key);
        //prev_key=key;
    }

    return true;
}

// cli cfg [get|set] [key] ...
// cli cfg set <key> <id> <flags> <name>
// cli cfg get all|<key>

int main(int argc, char **argv)
{
    if (argc < 3) {
        usage(argv[0]);
        return 1;
    }

    int map_fd = open_bpf_map_file("/sys/fs/bpf/tc/globals/map_config");
    if (map_fd < 0) {
        return 1;
    }

    // process operation
    if (!strncmp(argv[1], "set", 4)) {
        if (argc < 6) {
            usage(argv[0]);
            return 1;
        }

        // convert interface name
        unsigned int ifindex = if_nametoindex(argv[2]);
        if (ifindex == 0) {
            fprintf(stderr, "ERR: Interface \'%s\' err(%d):%s\n", argv[2], errno, strerror(errno));
            return 1;
        }

        unsigned int qid = atoi(argv[3]);
        if (qid >= CFG_IDX_MAX) {
            fprintf(stderr, "ERR: Queue index out of range \'%u\'\n", qid);
            return 1;
        }

        map_cfg_set(map_fd, ifindex, qid, atoi(argv[4]), argv[5]);
    } else if (!strncmp(argv[1], "get", 4)) {
        if (!strncmp(argv[2], "all", 4)) {
            map_cfg_getall(map_fd);
        } else {
            // convert interface name
            unsigned int ifindex = if_nametoindex(argv[2]);
            if (ifindex == 0) {
                fprintf(stderr, "ERR: Interface \'%s\' err(%d):%s\n", argv[2], errno, strerror(errno));
                return 1;
            }
            struct cfg_if value;
            int ret = map_cfg_get(map_fd, ifindex, &value);
            if (!ret) {
                map_cfg_print_record(ifindex, &value);
            } else {
                map_cfg_print_err(ifindex, "GET", ret);
            }
        }
    } else if (!strncmp(argv[1], "del", 4)) {
        if (!strncmp(argv[2], "all", 4)) {
            map_cfg_delall(map_fd);
        } else {
            // convert interface name
            unsigned int ifindex = if_nametoindex(argv[2]);
            if (ifindex == 0) {
                fprintf(stderr, "ERR: Interface \'%s\' err(%d):%s\n", argv[2], errno, strerror(errno));
                return 1;
            }
            map_cfg_del(map_fd, ifindex);
        }
    } else {
        fprintf(stderr, "ERR: Unknown operation:%s\n", argv[1]);
        return 1;
    }

    return 0;
}
