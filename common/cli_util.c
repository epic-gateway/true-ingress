#include <errno.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <bpf/bpf.h>
#include "struct_tc.h"
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

bool map_encap_del(int map_fd, struct encap_key *key) {
    struct in_addr from;
    from.s_addr = ntohl(key->ep.ip);

    if (bpf_map_delete_elem(map_fd, key)) {
        fprintf(stderr, "ENCAP.DEL (%s %s:%u) %u\t\tERR (%d) \'%s\'\n",
                get_proto_name(ntohs(key->ep.proto)), inet_ntoa(from), ntohs(key->ep.port), ntohl(key->ifindex), errno, strerror(errno));

        return false;
    } else {
        printf("ENCAP.DEL (%s %s:%u) %u\t\tOK\n", get_proto_name(ntohs(key->ep.proto)), inet_ntoa(from), ntohs(key->ep.port), ntohl(key->ifindex));
    }

    return true;
}

bool map_encap_del_all(int map_fd) {
    struct encap_key prev_key, key;

    while (bpf_map_get_next_key(map_fd, &prev_key, &key) == 0) {
        if (!map_encap_del(map_fd, &key)) {
            break;
        }
        prev_key=key;
    }

    return true;
}
