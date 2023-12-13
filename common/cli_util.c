#include <errno.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <bpf/bpf.h>
#include "cli_util.h"

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

__u16 get_proto_number(const char *proto) {
    if (!strncmp(proto, "tcp", 4)) {
        return IPPROTO_TCP;
    } else if (!strncmp(proto, "udp", 4)) {
        return IPPROTO_UDP;
    }

    return 0;
}

const char *get_proto_name(__u16 proto) {
    switch (proto) {
        case IPPROTO_TCP:
            return "tcp";
        case IPPROTO_UDP:
            return "udp";
    }

    return "proto-unknown";
}
