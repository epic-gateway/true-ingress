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
    fprintf(stderr,"    %s get all|<proto> <ip-from> <port-from>\n", prog);
    fprintf(stderr,"    %s set all|<proto> <ip-from> <port-from> <ip-to> <port-to>\n", prog);
    fprintf(stderr,"    %s del all|<proto> <ip-from> <port-from>\n\n", prog);
    fprintf(stderr,"    <proto>         - original ip.proto (supported tcp|udp)\n");
    fprintf(stderr,"    <ip-from>       - original ipv4 address\n");
    fprintf(stderr,"    <port-from>     - original port\n");
    fprintf(stderr,"    <ip-to>         - replacement ipv4 address\n");
    fprintf(stderr,"    <port-to>       - replacement port\n");
}

////////////////////
// TABLE-NAT
// struct endpoint -> struct endpoint
////////////////////
void map_nat_print_header() {
    printf("TABLE-NAT:\n\t    original ip:port -> new ip:port\n");
    printf("--------------------------------------------------------------------------\n");
}

void map_nat_print_footer() {
    //printf("--------------------------------------------------------------------------\n");
    printf("\n");
}

bool map_nat_get(int map_fd, struct endpoint *key, struct endpoint *value) {
    struct in_addr from, to;
    from.s_addr = ntohl(key->ip);

    if (bpf_map_lookup_elem(map_fd, key, value)) {
        fprintf(stderr, "NAT.GET {%s, %s, %u}\t\tERR (%d) \'%s\'\n",
                get_proto_name(ntohs(key->proto)), inet_ntoa(from), ntohs(key->port), errno, strerror(errno));

        return false;
    } else {
        to.s_addr = ntohl(value->ip);
        printf("NAT {%s, %s, %u} -> ", get_proto_name(ntohs(key->proto)), inet_ntoa(from), ntohs(key->port));
        printf("{%s, %s, %u}", get_proto_name(ntohs(value->proto)), inet_ntoa(to), ntohs(value->port));
        printf("\t\t{%04x, %08x, %04x} -> ", key->proto, key->ip, key->port);
        printf("{%04x, %08x, %04x}\n", value->proto, value->ip, value->port);
    }

    return true;
}

bool map_nat_getall(int map_fd) {
    struct endpoint prev_key, key, value;

    map_nat_print_header();
    while (bpf_map_get_next_key(map_fd, &prev_key, &key) == 0) {
        if (!map_nat_get(map_fd, &key, &value)) {
            break;
        }

        prev_key=key;
    }
    map_nat_print_footer();

    return true;
}

bool map_nat_set(int map_fd, struct endpoint *key, struct endpoint *value) {
    struct in_addr from;
    from.s_addr = ntohl(key->ip);

    if (bpf_map_update_elem(map_fd, key, value, 0)) {
        fprintf(stderr, "NAT.SET {%s, %s, %u}\t\tERR (%d) \'%s\'\n",
                get_proto_name(ntohs(key->proto)), inet_ntoa(from), ntohs(key->port), errno, strerror(errno));

        return false;
    } else {
        printf("NAT.SET {%s, %s, %u}\t\tOK\n", get_proto_name(ntohs(key->proto)), inet_ntoa(from), ntohs(key->port));
    }

    return true;
}

bool map_nat_del(int map_fd, struct endpoint *key) {
    struct in_addr from;
    from.s_addr = ntohl(key->ip);

    if (bpf_map_delete_elem(map_fd, key)) {
        fprintf(stderr, "NAT.DEL {%s, %s, %u}\t\tERR (%d) \'%s\'\n",
                get_proto_name(ntohs(key->proto)), inet_ntoa(from), ntohs(key->port), errno, strerror(errno));

        return false;
    } else {
        printf("NAT.DEL {%s, %s, %u}\t\tOK\n", get_proto_name(ntohs(key->proto)), inet_ntoa(from), ntohs(key->port));
    }

    return true;
}

bool map_nat_delall(int map_fd) {
    struct endpoint prev_key, key;

    while (bpf_map_get_next_key(map_fd, &prev_key, &key) == 0) {
        if (!map_nat_del(map_fd, &key)) {
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
    __u16 proto;
    struct in_addr from, to;

    if (argc < 3) {
        usage(argv[0]);
        return 1;
    }

    int map_nat_fd = open_bpf_map_file("/sys/fs/bpf/tc/globals/map_nat");
    if (map_nat_fd < 0) {
        return 1;
    }

    if (!strncmp(argv[1], "set", 4)) { // %s set <proto>2 <ip-from>3 <port-from>4 <ip-to>5 <port-to>6
        if (argc < 6) {
            usage(argv[0]);
            return 1;
        }
        
        proto = get_proto_number(argv[2]);
        if( proto == 0) {
            fprintf(stderr, "Unsupported IP proto \'%s\'\n", argv[2]);
            return 1;
        }

        if (inet_aton(argv[3], &from) == 0) {
            fprintf(stderr, "Invalid address %s\n", argv[3]);
            return 1;
        }

        if (inet_aton(argv[5], &to) == 0) {
            fprintf(stderr, "Invalid address %s\n", argv[5]);
            return 1;
        }

        struct endpoint ep_from = { 0 }, ep_to = { 0 };

        make_endpoint(&ep_from, from.s_addr, atoi(argv[4]), proto);
        make_endpoint(&ep_to, to.s_addr, atoi(argv[6]), proto);

        map_nat_set(map_nat_fd, &ep_from, &ep_to);
    } else if (!strncmp(argv[1], "get", 4)) {   // %s get <proto>2 <ip-from>3 <port-from>4
        if (!strncmp(argv[2], "all", 4)) {
            map_nat_getall(map_nat_fd);
        } else {
            if (argc < 4) {
                usage(argv[0]);
                return 1;
            }
        
            proto = get_proto_number(argv[2]);
            if( proto == 0) {
                fprintf(stderr, "Unsupported IP proto \'%s\'\n", argv[2]);
                return 1;
            }

            if (inet_aton(argv[3], &from) == 0) {
                fprintf(stderr, "Invalid address %s\n", argv[3]);
                return 1;
            }

            struct endpoint ep_from = { 0 }, value = { 0 };

            make_endpoint(&ep_from, from.s_addr, atoi(argv[4]), proto);

            map_nat_get(map_nat_fd, &ep_from, &value);
        }
    } else if (!strncmp(argv[1], "del", 4)) {   // %s del <proto> <ip-from> <port-from>
        if (!strncmp(argv[2], "all", 4)) {
            map_nat_delall(map_nat_fd);
        } else {
            if (argc < 4) {
                usage(argv[0]);
                return 1;
            }
        
            proto = get_proto_number(argv[2]);
            if( proto == 0) {
                fprintf(stderr, "Unsupported IP proto \'%s\'\n", argv[2]);
                return 1;
            }

            if (inet_aton(argv[3], &from) == 0) {
                fprintf(stderr, "Invalid address %s\n", argv[3]);
                return 1;
            }

            struct endpoint ep_from = { 0 };

            make_endpoint(&ep_from, from.s_addr, atoi(argv[4]), proto);

            map_nat_del(map_nat_fd, &ep_from);
        }
    } else {
        fprintf(stderr,"ERR: Unknown operation \'%s\'\n", argv[1]);
        return 1;
    }

    return 0;
}
