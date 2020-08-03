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

// MAP_TUNNEL:	u32 -> struct tunnel
// MAP_DECAP:	struct endpoint -> u32

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
    fprintf(stderr,"    %s get <id>|all\n", prog);
    fprintf(stderr,"    %s set <id> <ip-local> <port-local> <ip-remote> <port-remote>\n", prog);
    fprintf(stderr,"    %s del <id>|all\n", prog);
}

////////////////////
// TABLE-TUNNEL
////////////////////
void map_tunnel_print_header() {
    printf("TABLE-TUNNEL:\ntunnel-id\t\tlocal-ip:port -> remote-ip:port\n");
    printf("--------------------------------------------------------------------------\n");
}

void map_tunnel_print_footer() {
    //printf("--------------------------------------------------------------------------\n");
    printf("\n");
}

bool map_tunnel_get(int map_fd, __u32 id, struct tunnel *value) {
    if (bpf_map_lookup_elem(map_fd, &id, value)) {
        fprintf(stderr, "TUNNEL.GET\t%8u\t\tERR (%d) \'%s\'\n", id, errno, strerror(errno));

        return false;
    } else {
        struct in_addr local, remote;
        local.s_addr = ntohl(value->ip_local);
        remote.s_addr = ntohl(value->ip_remote);
        printf("%8u\t%16s:%-5u -> ", id,
               inet_ntoa(local), ntohs(value->port_local));
        printf("%16s:%-5u", inet_ntoa(remote), ntohs(value->port_remote));
        printf("\t\t%02x:%02x:%02x:%02x:%02x:%02x", value->mac_remote[0], value->mac_remote[1], value->mac_remote[2], value->mac_remote[3], value->mac_remote[4], value->mac_remote[5]);
        printf("\t\t(%08x:%04x -> %08x:%04x)\n",
               value->ip_local, ntohs(value->port_local),
               value->ip_remote, ntohs(value->port_remote));
    }

    return true;
}

bool map_tunnel_getall(int map_fd) {
    __u32 prev_key, key;
    struct tunnel value;

    map_tunnel_print_header();
    while(bpf_map_get_next_key(map_fd, &prev_key, &key) == 0) {
        map_tunnel_get(map_fd, key, &value);
        prev_key=key;
    }
    map_tunnel_print_footer();

    return true;
}

bool map_tunnel_set(int map_fd, __u32 id, struct tunnel *value) {
    if (bpf_map_update_elem(map_fd, &id, value, 0)) {
        fprintf(stderr, "TUNNEL.SET {%u}\t\tERR (%d) \'%s\'\n", id, errno, strerror(errno));

        return false;
    } else {
        printf("TUNNEL.SET {%u}\t\tOK\n", id);
    }

    return true;
}

bool map_tunnel_del(int map_fd, __u32 id) {
    if (bpf_map_delete_elem(map_fd, &id)) {
        fprintf(stderr, "TUNNEL.DEL {%u}\t\tERR (%d) \'%s\'\n", id, errno, strerror(errno));

        return false;
    } else {
        printf("TUNNEL.DEL {%u}\t\tOK\n", id);
    }

    return true;
}

bool map_tunnel_delall(int map_fd) {
    __u32 prev_key, key;

    while(bpf_map_get_next_key(map_fd, &prev_key, &key) == 0) {
        map_tunnel_del(map_fd, key);
        //prev_key=key;
    }

    return true;
}

////////////////////
// TABLE-DECAP
////////////////////
void map_decap_print_header() {
    printf("TABLE-DECAP:\n     proto\t\tip\t\t port\n");
    printf("--------------------------------------------------------------------------\n");
}

void map_decap_print_footer() {
    //printf("--------------------------------------------------------------------------\n");
    printf("\n");
}

bool map_decap_get(int map_fd, struct endpoint *key) {
    __u32 value;
    struct in_addr from;
    from.s_addr = ntohl(key->ip);

    if (bpf_map_lookup_elem(map_fd, key, &value)) {
        fprintf(stderr, "DECAP.GET {%s, %s, %u}\t\tERR (%d) \'%s\'\n",
                get_proto_name(ntohs(key->proto)), inet_ntoa(from), ntohs(key->port), errno, strerror(errno));

        return false;
    } else {
        printf(" %8s\t%16s\t%6u", get_proto_name(ntohs(key->proto)), inet_ntoa(from), ntohs(key->port));
        printf("\t\t(%04x  %08x  %04x)\n", key->proto, key->ip, key->port);
    }

    return true;
}

bool map_decap_getall(int map_fd) {
    struct endpoint prev_key, key;

    map_decap_print_header();
    while (bpf_map_get_next_key(map_fd, &prev_key, &key) == 0) {
        if (!map_decap_get(map_fd, &key)) {
            break;
        }

        prev_key=key;
    }
    map_decap_print_footer();

    return true;
}

bool map_decap_set(int map_fd, struct endpoint *key) {
    __u32 value = 0;
    struct in_addr from;
    from.s_addr = ntohl(key->ip);

    if (bpf_map_update_elem(map_fd, key, &value, 0)) {
        fprintf(stderr, "DECAP.SET {%s, %s, %u}\t\tERR (%d) \'%s\'\n",
                get_proto_name(ntohs(key->proto)), inet_ntoa(from), ntohs(key->port), errno, strerror(errno));

        return false;
    } else {
        printf("DECAP.SET {%s, %s, %u}\t\tOK\n", get_proto_name(ntohs(key->proto)), inet_ntoa(from), ntohs(key->port));
    }

    return true;
}

bool map_decap_del(int map_fd, struct endpoint *key) {
    struct in_addr from;
    from.s_addr = ntohl(key->ip);

    if (bpf_map_delete_elem(map_fd, key)) {
        fprintf(stderr, "DECAP.DEL {%s, %s, %u}\t\tERR (%d) \'%s\'\n",
                get_proto_name(ntohs(key->proto)), inet_ntoa(from), ntohs(key->port), errno, strerror(errno));

        return false;
    } else {
        printf("DECAP.DEL {%s, %s, %u}\t\tOK\n", get_proto_name(ntohs(key->proto)), inet_ntoa(from), ntohs(key->port));
    }

    return true;
}

bool map_decap_delall(int map_fd) {
    struct endpoint prev_key, key;

    while (bpf_map_get_next_key(map_fd, &prev_key, &key) == 0) {
        if (!map_decap_del(map_fd, &key)) {
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
    struct in_addr local, remote;

    if (argc < 2) {
        usage(argv[0]);
        return 1;
    }

    int map_tunnel_fd = open_bpf_map_file("/sys/fs/bpf/tc/globals/map_tunnel");
    if (map_tunnel_fd < 0) {
        return 1;
    }

    int map_decap_fd = open_bpf_map_file("/sys/fs/bpf/tc/globals/map_decap");
    if (map_decap_fd < 0) {
        return 1;
    }

    if (!strncmp(argv[1], "set", 4)) {
        if (argc < 6) {
            usage(argv[0]);
            return 1;
        }

        if (inet_aton(argv[3], &local) == 0) {
            fprintf(stderr, "Invalid address %s\n", argv[3]);
            return 1;
        }

        if (inet_aton(argv[5], &remote) == 0) {
            fprintf(stderr, "Invalid address %s\n", argv[5]);
            return 1;
        }

        struct tunnel tun;
        struct endpoint ep;

        if (!map_tunnel_set(map_tunnel_fd, atoi(argv[2]), make_tunnel(&tun, local.s_addr, atoi(argv[4]), remote.s_addr, atoi(argv[6])))) {
            return 1;
        }
        map_decap_set(map_decap_fd, make_endpoint(&ep, local.s_addr, atoi(argv[4]), get_proto_number("udp")));
    } else if (!strncmp(argv[1], "get", 4)) {
        if (argc < 3) {
            usage(argv[0]);
            return 1;
        }

        if (!strncmp(argv[2], "all", 4)) {
            map_tunnel_getall(map_tunnel_fd);
            map_decap_getall(map_decap_fd);
        } else {
            struct tunnel value;
            if (!map_tunnel_get(map_tunnel_fd, atoi(argv[2]), &value)) {
                return 1;
            }
            struct endpoint ep;
            map_decap_get(map_decap_fd, make_endpoint(&ep, ntohl(value.ip_local), ntohs(value.port_local), get_proto_number("udp")));
        }
    } else if (!strncmp(argv[1], "list", 5)) {
        map_tunnel_getall(map_tunnel_fd);
        map_decap_getall(map_decap_fd);
    } else if (!strncmp(argv[1], "del", 4)) {
        if (argc < 3) {
            usage(argv[0]);
            return 1;
        }

        if (!strncmp(argv[2], "all", 4)) {
            map_tunnel_delall(map_tunnel_fd);
            map_decap_delall(map_decap_fd);
        } else {
            struct tunnel value;
            if (!map_tunnel_get(map_tunnel_fd, atoi(argv[2]), &value)) {
                return 1;
            }
            struct endpoint ep;
            map_decap_del(map_decap_fd, make_endpoint(&ep, ntohl(value.ip_local), ntohs(value.port_local), get_proto_number("udp")));
            map_tunnel_del(map_tunnel_fd, atoi(argv[2]));
        }
    } else {
        fprintf(stderr,"ERR: Unknown operation \'%s\'\n", argv[1]);
        return 1;
    }

    return 0;
}
