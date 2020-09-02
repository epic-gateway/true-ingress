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
// TABLE-NAT
// struct endpoint -> struct endpoint
////////////////////
void map_nat_print_header() {
    printf("TABLE-NAT:\n\t    proxy-ip:port -> backend-ip:port\n");
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
        fprintf(stderr, "GC.NAT.GET {%s, %s, %u}\t\tERR (%d) \'%s\'\n",
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
// TABLE-ENCAP
// struct endpoint -> struct service
//struct service {
//    __u32           tunnel_id;
//    struct identity identity;
//    struct verify      key;
//};
////////////////////
void map_encap_print_header() {
    printf("TABLE-ENCAP:\n\t\tdestination -> tunnel-id\tgid+sid\t\tkey\thash\n");
    printf("--------------------------------------------------------------------------\n");
}

void map_encap_print_footer() {
    //printf("--------------------------------------------------------------------------\n");
    printf("\n");
}

bool map_encap_get(int map_fd, struct endpoint *key, struct service *value) {
    struct in_addr from;
    from.s_addr = ntohl(key->ip);

    if (bpf_map_lookup_elem(map_fd, key, value)) {
        fprintf(stderr, "GC.ENCAP.GET {%s, %s, %u}\t\tERR (%d) \'%s\'\n",
                get_proto_name(ntohs(key->proto)), inet_ntoa(from), ntohs(key->port), errno, strerror(errno));

        return false;
    } else if (value->hash != 0) {
        printf("ENCAP (%s, %s, %u) -> ", get_proto_name(ntohs(key->proto)), inet_ntoa(from), ntohs(key->port));
        printf("%u\t\t(%u, %u)\t\'%16.16s\'\t%u", ntohl(value->tunnel_id), ntohs(value->identity.service_id), ntohs(value->identity.group_id), (char*)value->key.value, value->hash);
        printf("\t\t(%04x, %08x, %04x) -> ", key->proto, key->ip, key->port);
        __u64 *ptr = (__u64 *)value->key.value;
        printf("(%08x\t(%04x, %04x)\t\'%llx%llx\'\n", value->tunnel_id, value->identity.service_id, value->identity.group_id, ptr[0], ptr[1]);
    }
    return true;
}

bool map_encap_getall(int map_encap_fd, int map_nat_fd) {
    struct endpoint prev_key, key, nat;
    struct service svc;

    map_encap_print_header();
    while (bpf_map_get_next_key(map_encap_fd, &prev_key, &key) == 0) {
        if (!map_encap_get(map_encap_fd, &key, &svc)) {
            break;
        }
        if (svc.hash != 0) {
            map_nat_get(map_nat_fd, &key, &nat);
        }

        prev_key=key;
    }
    map_encap_print_footer();

    return true;
}

bool map_encap_del(int map_encap_fd, int map_nat_fd, struct endpoint *key) {
    struct in_addr from;
    from.s_addr = ntohl(key->ip);
    struct service value;
    bool ret = true;

    // check
    if (!map_encap_get(map_encap_fd, key, &value)) {
        fprintf(stderr, "GC.ENCAP.DEL: Item not found\n");
        return false;
    }

    if (value.hash == 0) {
        fprintf(stderr, "GC.ENCAP.DEL: Cannot delete static entry\n");
        return false;
    }

    // delete encap entry
    if (bpf_map_delete_elem(map_encap_fd, key)) {
        fprintf(stderr, "GC.ENCAP.DEL {%s, %s, %u}\t\tERR (%d) \'%s\'\n",
                get_proto_name(ntohs(key->proto)), inet_ntoa(from), ntohs(key->port), errno, strerror(errno));

        ret = false;
    } else {
        printf("GC.ENCAP.DEL {%s, %s, %u}\t\tOK\n", get_proto_name(ntohs(key->proto)), inet_ntoa(from), ntohs(key->port));
    }

    // delete nat entry
    if (bpf_map_delete_elem(map_nat_fd, key)) {
        fprintf(stderr, "GC.NAT.DEL {%s, %s, %u}\t\tERR (%d) \'%s\'\n",
                get_proto_name(ntohs(key->proto)), inet_ntoa(from), ntohs(key->port), errno, strerror(errno));

        ret = false;
    } else {
        printf("GC.NAT.DEL {%s, %s, %u}\t\tOK\n", get_proto_name(ntohs(key->proto)), inet_ntoa(from), ntohs(key->port));
    }

    return ret;
}

bool map_encap_delall(int map_encap_fd, int map_nat_fd) {
    struct endpoint prev_key, key;

    while (bpf_map_get_next_key(map_encap_fd, &prev_key, &key) == 0) {
        if (!map_encap_del(map_encap_fd, map_nat_fd, &key)) {
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

    int map_nat_fd = open_bpf_map_file("/sys/fs/bpf/tc/globals/map_nat");
    if (map_nat_fd < 0) {
        return 1;
    }

    int map_encap_fd = open_bpf_map_file("/sys/fs/bpf/tc/globals/map_encap");
    if (map_encap_fd < 0) {
        return 1;
    }

    if (!strncmp(argv[1], "get", 4)) {
        if (!strncmp(argv[2], "all", 4)) {
            map_encap_getall(map_encap_fd, map_nat_fd);
        } else {
            if (argc < 5) {
                usage(argv[0]);
                return 1;
            }

            struct endpoint key, nat;
            struct service svc;

            if (inet_aton(argv[3], &from) == 0) {
                fprintf(stderr, "Invalid address %s\n", argv[3]);
                return 1;
            }

            make_endpoint(&key, from.s_addr, atoi(argv[4]), get_proto_number(argv[2]));

            map_encap_get(map_encap_fd, &key, &svc);
            map_nat_get(map_nat_fd, &key, &nat);
        }
    } else if (!strncmp(argv[1], "del", 4)) {
        if (!strncmp(argv[2], "all", 4)) {
            map_encap_delall(map_encap_fd, map_nat_fd);
        } else {
            if (argc < 5) {
                usage(argv[0]);
                return 1;
            }

            struct endpoint key;

            if (inet_aton(argv[3], &from) == 0) {
                fprintf(stderr, "Invalid address %s\n", argv[3]);
                return 1;
            }

            map_encap_del(map_encap_fd, map_nat_fd, make_endpoint(&key, from.s_addr, atoi(argv[4]), get_proto_number(argv[2])));
        }
    } else {
        fprintf(stderr,"ERR: Unknown operation \'%s\'\n", argv[1]);
        return 1;
    }

    return 0;
}
