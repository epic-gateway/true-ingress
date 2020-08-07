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

int open_bpf_map_file(const char *file) {
    int fd;

    fd = bpf_obj_get(file);
    if (fd < 0) {
        fprintf(stderr,
            "WARN: Failed to open bpf map file:%s err(%d):%s\n",
            file, errno, strerror(errno));
        return fd;
    }
    return fd;
}

bool map_cfg_get(int map_fd, unsigned int ifindex, struct cfg_if *value) {
    char ifname[32];

    if (bpf_map_lookup_elem(map_fd, &ifindex, value)) {
        fprintf(stderr, "CFG.GET (%d) (%s) -> ERR (%d) \'%s\'\n", ifindex, if_indextoname(ifindex, ifname), errno, strerror(errno));
        return false;
    } else {
        printf("CFG.GET (%u) (%s):\n", ifindex, if_indextoname(ifindex, ifname));
        printf("    Ingress -> id %u, name \'%s\', flags (%x) :%s%s%s\n",
               value->queue[CFG_IDX_RX].id, value->queue[CFG_IDX_RX].name, value->queue[CFG_IDX_RX].flags,
               (value->queue[CFG_IDX_RX].flags & CFG_RX_GUE) ? " GUE-DECAP" : "",
               (value->queue[CFG_IDX_RX].flags & CFG_RX_DNAT) ? " DNAT" : "",
               (value->queue[CFG_IDX_RX].flags & CFG_RX_DUMP) ? " DUMP" : "");
        printf("    Egress  -> id %u, name \'%s\', flags (%x) :%s%s%s\n",
               value->queue[CFG_IDX_TX].id, value->queue[CFG_IDX_TX].name, value->queue[CFG_IDX_TX].flags,
               (value->queue[CFG_IDX_TX].flags & CFG_TX_PROXY) ? " PROXY" : "",
               (value->queue[CFG_IDX_TX].flags & CFG_TX_SNAT) ? " SNAT" : "",
               (value->queue[CFG_IDX_TX].flags & CFG_TX_DUMP) ? " DUMP" : "");
    }

    return true;
}

bool map_cfg_getall(int map_fd) {
    __u32 prev_key, key;
    struct cfg_if value;

    //map_cfg_print_header();
    while(bpf_map_get_next_key(map_fd, &prev_key, &key) == 0) {
        map_cfg_get(map_fd, key, &value);
        prev_key=key;
    }
    //map_cfg_print_footer();

    return true;
}

bool map_cfg_set(int map_fd, unsigned int ifindex, unsigned int qid, uint id, uint flags, char *name) {
    struct cfg_if value = { 0 };
    char ifname[32];

    if (bpf_map_lookup_elem(map_fd, &ifindex, &value)) {  // create new
        struct config *cfg = &value.queue[qid];

        cfg->id = id;
        cfg->flags = flags;
        strncpy(cfg->name, name, 16);

        if (bpf_map_update_elem(map_fd, &ifindex, &value, 0)) {
            fprintf(stderr, "CFG.SET {%u[%u]} (%s[%s]) -> ERR (%d) \'%s\'\n",
                    ifindex, qid, if_indextoname(ifindex, ifname),
                    (qid) ? "TX" : "RX", errno, strerror(errno));
            return false;
        }
        printf("CFG.SET {%u[%u]} (%s[%s])\t\tCREATED\n", ifindex, qid,
                    if_indextoname(ifindex, ifname), (qid) ? "TX" : "RX");
    } else {    // update existing
        struct config *cfg = &value.queue[qid];

        cfg->id = id;
        cfg->flags = flags;
        strncpy(cfg->name, name, 16);

        if (bpf_map_update_elem(map_fd, &ifindex, &value, 0)) {
            fprintf(stderr, "CFG.SET {%u[%u]} (%s[%s]) -> ERR (%d) \'%s\'\n",
                    ifindex, qid, if_indextoname(ifindex, ifname),
                    (qid) ? "TX" : "RX", errno, strerror(errno));
            return false;
        }
        printf("CFG.SET {%u[%u]} (%s[%s])\t\tUPDATED\n", ifindex, qid,
                    if_indextoname(ifindex, ifname), (qid) ? "TX" : "RX");
    }

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

void usage(char *prog) {
    fprintf(stderr,"ERR: Too little arguments\n");
    fprintf(stderr,"Usage:\n");
    fprintf(stderr,"    %s get <interface|all>\n", prog);
    fprintf(stderr,"    %s set <interface> <qid> <id> <flags> <name>\n", prog);
    fprintf(stderr,"    %s del <interface|all>\n", prog);
    fprintf(stderr,"    <qid> - 0 for ingress, 1 for egress\n");
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
        if (argc < 7) {
            usage(argv[0]);
            return 1;
        }

        // convert interface name
        unsigned int ifindex = if_nametoindex(argv[2]);
        if (ifindex == 0) {
            fprintf(stderr, "ERR: Interface \'%s\' err(%d):%s\n", argv[2], errno, strerror(errno));
            return 1;
        }
        /*if (ifindex >= MAX_IFINDEX) {
            fprintf(stderr, "ERR: Fix MAX_IFINDEX err(%d):%s\n", errno, strerror(errno));
            return 1;
        }*/

        unsigned int qid = atoi(argv[3]);
        if (qid >= CFG_IDX_MAX) {
            fprintf(stderr, "ERR: Queue index out of range \'%u\'\n", qid);
            return 1;
        }
            
        map_cfg_set(map_fd, ifindex, qid, atoi(argv[4]), atoi(argv[5]), argv[6]);
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
            /*if (ifindex >= MAX_IFINDEX) {
                fprintf(stderr, "ERR: Fix MAX_IFINDEX err(%d):%s\n", errno, strerror(errno));
                return 1;
            }*/
            struct cfg_if value;
            map_cfg_get(map_fd, ifindex, &value);
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
            /*if (ifindex >= MAX_IFINDEX) {
                fprintf(stderr, "ERR: Fix MAX_IFINDEX err(%d):%s\n", errno, strerror(errno));
                return 1;
            }*/
            map_cfg_del(map_fd, ifindex);
        }
    } else {
        fprintf(stderr, "ERR: Unknown operation:%s\n", argv[1]);
        return 1;
    }

    return 0;
}
