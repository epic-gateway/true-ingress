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

#include <arpa/inet.h>

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

void usage(char *prog) {
    fprintf(stderr,"ERR: Too little arguments\n");
    fprintf(stderr,"Usage:\n");
    fprintf(stderr,"    %s get all|<proto> <ip-proxy> <port-proxy>\n", prog);
    fprintf(stderr,"    %s del all|<proto> <ip-proxy> <port-proxy>\n", prog);
}

////////////////////
// TABLE-ENCAP
// struct endpoint -> struct service
//struct service {
//    __u32           tunnel_id;
//    struct identity identity;
//    struct verify      key;
//};
////////////////////
void map_encap_print_header() {
    printf("TABLE-ENCAP:\n\tdestination\tifindex -> hash\n");
    printf("--------------------------------------------------------------------------\n");
}

void map_encap_print_footer() {
    //printf("--------------------------------------------------------------------------\n");
    printf("\n");
}

bool map_encap_get(int map_fd, struct encap_key *key, struct service *value) {
    struct in_addr from;
    from.s_addr = ntohl(key->ep.ip);

    if (bpf_map_lookup_elem(map_fd, key, value)) {
        fprintf(stderr, "ENCAP.GET {%s, %s, %u, %u}\t\tERR (%d) \'%s\'\n",
                get_proto_name(ntohs(key->ep.proto)), inet_ntoa(from), ntohs(key->ep.port), ntohl(key->ifindex), errno, strerror(errno));

        return false;
    } else {
        printf("ENCAP (%s, %s, %u)  %u -> %u\n", get_proto_name(ntohs(key->ep.proto)), inet_ntoa(from), ntohs(key->ep.port), ntohl(key->ifindex), value->hash);
    }
    return true;
}

bool map_encap_getall(int map_fd) {
    struct encap_key prev_key, key;
    struct service value;

    map_encap_print_header();
    while (bpf_map_get_next_key(map_fd, &prev_key, &key) == 0) {
        if (!map_encap_get(map_fd, &key, &value)) {
            break;
        }

        prev_key=key;
    }
    map_encap_print_footer();

    return true;
}

bool map_encap_del(int map_fd, struct encap_key *key) {
    struct in_addr from;
    from.s_addr = ntohl(key->ep.ip);

    if (bpf_map_delete_elem(map_fd, key)) {
        fprintf(stderr, "ENCAP.DEL {%s, %s, %u, %u}\t\tERR (%d) \'%s\'\n",
                get_proto_name(ntohs(key->ep.proto)), inet_ntoa(from), ntohs(key->ep.port), ntohl(key->ifindex), errno, strerror(errno));

        return false;
    } else {
        printf("ENCAP.DEL {%s, %s, %u, %u}\t\tOK\n", get_proto_name(ntohs(key->ep.proto)), inet_ntoa(from), ntohs(key->ep.port), ntohl(key->ifindex));
    }

    return true;
}

bool map_encap_delall(int map_fd) {
    struct encap_key prev_key, key;

    while (bpf_map_get_next_key(map_fd, &prev_key, &key) == 0) {
        if (!map_encap_del(map_fd, &key)) {
            break;
        }
        //prev_key=key;
    }

    return true;
}

////////////////////
// MAIN
////////////////////
int main(int argc, char **argv)
{
    struct in_addr from;

    if (argc < 3) {
        usage(argv[0]);
        return 1;
    }

    int map_encap_fd = open_bpf_map_file("/sys/fs/bpf/tc/globals/map_encap");
    if (map_encap_fd < 0) {
        return 1;
    }

    if (!strncmp(argv[1], "get", 4)) {
        if (!strncmp(argv[2], "all", 4)) {
            map_encap_getall(map_encap_fd);
        } else {
            if (argc < 5) {
                usage(argv[0]);
                return 1;
            }

            struct encap_key key;
            struct service svc;

            if (inet_aton(argv[3], &from) == 0) {
                fprintf(stderr, "Invalid address %s\n", argv[3]);
                return 1;
            }

            make_encap_key(&key, from.s_addr, atoi(argv[4]), get_proto_number(argv[2]), 0);

            map_encap_get(map_encap_fd, &key, &svc);
        }
    } else if (!strncmp(argv[1], "del", 4)) {
        if (!strncmp(argv[2], "all", 4)) {
            map_encap_delall(map_encap_fd);
        } else {
            if (argc < 5) {
                usage(argv[0]);
                return 1;
            }

            struct encap_key key;

            if (inet_aton(argv[3], &from) == 0) {
                fprintf(stderr, "Invalid address %s\n", argv[3]);
                return 1;
            }

            make_encap_key(&key, from.s_addr, atoi(argv[4]), get_proto_number(argv[2]), 0);

            map_encap_del(map_encap_fd, &key);
        }
    } else {
        fprintf(stderr,"ERR: Unknown operation \'%s\'\n", argv[1]);
        return 1;
    }

    return 0;
}
