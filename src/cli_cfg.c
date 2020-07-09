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

bool map_get(int map_fd, int idx) {
    struct config cfg;
    int err;

    err = bpf_map_lookup_elem(map_fd, &idx, &cfg);
    if (err) {
        fprintf(stderr, "GET (%d) -> ERR (%d) \'%s\'\n", idx, errno, strerror(errno));
        return false;
    } else {
        printf("GET (%d) -> id %u, flags %x, name \'%s\'\n", idx, cfg.id, cfg.flags, cfg.name);
    }

    return true;
}

bool map_get_all(int map_fd) {
    map_get(map_fd, CFG_IDX_RX);
    map_get(map_fd, CFG_IDX_TX);

    return true;
}

bool map_set(int map_fd, int idx, uint id, uint flags, char *name) {
    struct config cfg;
    int err;

    cfg.id = id;
    cfg.flags = flags;
    strncpy(cfg.name, name, 16);

    err = bpf_map_update_elem(map_fd, &idx, &cfg, 0);
    if (err) {
        fprintf(stderr, "SET(%d) -> ERR (%d) \'%s\'\n", idx, errno, strerror(errno));
        return false;
    }

    printf("OK\n");
    return true;
}

bool map_set_all(int map_fd) {
    map_set(map_fd, CFG_IDX_RX, 10, CFG_RX_GUE | CFG_RX_DNAT, "RX");
    map_set(map_fd, CFG_IDX_TX, 10, CFG_TX_PROXY, "TX");

    return true;
}

void usage(char *prog) {
    fprintf(stderr,"ERR: Too little arguments\n");
    fprintf(stderr,"Usage:\n");
    fprintf(stderr,"    %s get <idx|all>\n", prog);
    fprintf(stderr,"    %s set <idx> <id> <flags> <name>\n", prog);
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

    if (!strncmp(argv[1], "set", 4)) {
        if (argc < 6) {
            usage(argv[0]);
            return 1;
        }
            
        map_set(map_fd, atoi(argv[2]), atoi(argv[3]), atoi(argv[4]), argv[5]);
    } else if (!strncmp(argv[1], "get", 4)) {
        if (!strncmp(argv[2], "all", 4)) {
            map_get_all(map_fd);
        } else {
            map_get(map_fd, atoi(argv[2]));
        }
    } else {
        fprintf(stderr,"ERR: Unknown operation:%s\n", argv[1]);
        return 1;
    }

    return 0;
}
