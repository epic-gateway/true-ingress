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
    fprintf(stderr,"    %s get <service-id> <group-id>\n", prog);
    fprintf(stderr,"    %s set <service-id> <group-id> <proto> <ip-proxy> <port-proxy> <ip-ep> <port-ep> <tunnel-id> <key>\n", prog);
    fprintf(stderr,"    %s del <service-id> <group-id>\n", prog);
}

////////////////////
// TABLE-NAT
// struct endpoint -> struct endpoint
////////////////////
void map_nat_print_header() {
    printf("TABLE-NAT:\ntunnel-id\t\tlocal-ip:port -> remote-ip:port\n");
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
// TABLE-VERIFY
// struct identity -> struct verify
//struct identity {
//    GID_SID_TYPE  service_id;              /* GUE service ID */
//    GID_SID_TYPE  group_id;                /* GUE group ID */
//};
//struct verify {
//    __u8   value[SECURITY_KEY_SIZE];        /* GUE security KEY */
//};
////////////////////
void map_verify_print_header() {
    printf("TABLE-VERIFY:\ntunnel-id\t\tlocal-ip:port -> remote-ip:port\n");
    printf("--------------------------------------------------------------------------\n");
}

void map_verify_print_footer() {
    //printf("--------------------------------------------------------------------------\n");
    printf("\n");
}

bool map_verify_get(int map_fd, struct identity *key, struct verify *value) {
    if (bpf_map_lookup_elem(map_fd, key, value)) {
        fprintf(stderr, "VERIFY.GET {%u, %u}\t\tERR (%d) \'%s\'\n",
                ntohs(key->service_id), ntohs(key->group_id), errno, strerror(errno));

        return false;
    } else {
        struct in_addr dnat_ip, snat_ip;
        dnat_ip.s_addr = ntohl(value->dnat.ip);
        snat_ip.s_addr = ntohl(value->snat.ip);

        printf("VERIFY {%u, %u} -> ", ntohs(key->service_id), ntohs(key->group_id));
        printf("{\'%16.16s\'", value->value);
        printf(" {%s, %s, %u}}",
                get_proto_name(ntohs(value->dnat.proto)), inet_ntoa(dnat_ip), ntohs(value->dnat.port));
        printf(" {%s, %s, %u}}",
                get_proto_name(ntohs(value->snat.proto)), inet_ntoa(snat_ip), ntohs(value->snat.port));
        printf("\t\t{%08x (%04x, %04x)} -> ", ntohl(*(__u32*)key), ntohs(key->service_id), ntohs(key->group_id));
        __u64 *ptr = (__u64 *)value->value;
        printf("{\'%llx%llx\' {%04x, %08x, %04x} {%04x, %08x, %04x}}\n", ptr[0], ptr[1],
                value->dnat.proto, value->dnat.ip, value->dnat.port,
                value->snat.proto, value->snat.ip, value->snat.port);
    }

    return true;
}

bool map_verify_getall(int map_fd) {
    struct identity prev_key, key;
    struct verify value;

    map_verify_print_header();
    while (bpf_map_get_next_key(map_fd, &prev_key, &key) == 0) {
        if (!map_verify_get(map_fd, &key, &value)) {
            break;
        }

        prev_key=key;
    }
    map_verify_print_footer();

    return true;
}

bool map_verify_set(int map_fd, struct identity *key, struct verify *value) {
    if (bpf_map_update_elem(map_fd, key, value, 0)) {
        fprintf(stderr, "VERIFY.SET {%u, %u}\t\tERR (%d) \'%s\'\n",
                ntohs(key->service_id), ntohs(key->group_id), errno, strerror(errno));

        return false;
    } else {
        printf("VERIFY.SET {%u, %u}\t\tOK\n", ntohs(key->service_id), ntohs(key->group_id));
    }

    return true;
}

bool map_verify_del(int map_fd, struct identity *key) {
    if (bpf_map_delete_elem(map_fd, key)) {
        fprintf(stderr, "VERIFY.DEL {%u, %u}\t\tERR (%d) \'%s\'\n",
                ntohs(key->service_id), ntohs(key->group_id), errno, strerror(errno));

        return false;
    } else {
        printf("VERIFY.DEL {%u, %u}\t\tOK\n", ntohs(key->service_id), ntohs(key->group_id));
    }

    return true;
}

bool map_verify_delall(int map_fd) {
    struct identity prev_key, key;

    while (bpf_map_get_next_key(map_fd, &prev_key, &key) == 0) {
        if (!map_verify_del(map_fd, &key)) {
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
    printf("TABLE-ENCAP:\ntunnel-id\t\tlocal-ip:port -> remote-ip:port\n");
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
        fprintf(stderr, "ENCAP.GET {%s, %s, %u}\t\tERR (%d) \'%s\'\n",
                get_proto_name(ntohs(key->proto)), inet_ntoa(from), ntohs(key->port), errno, strerror(errno));

        return false;
    } else {
        printf("ENCAP {%s, %s, %u} -> ", get_proto_name(ntohs(key->proto)), inet_ntoa(from), ntohs(key->port));
        printf("{%u, {%u, %u}, \'%16.16s\'}", ntohl(value->tunnel_id), ntohs(value->identity.service_id), ntohs(value->identity.group_id), (char*)value->key.value);
        printf("\t\t{%04x, %08x, %04x} -> ", key->proto, key->ip, key->port);
        __u64 *ptr = (__u64 *)value->key.value;
        printf("{%08x, {%04x, %04x}, \'%llx%llx\'}\n", value->tunnel_id, value->identity.service_id, value->identity.group_id, ptr[0], ptr[1]);
    }
    return true;
}

bool map_encap_getall(int map_fd) {
    struct endpoint prev_key, key;
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

bool map_encap_set(int map_fd, struct endpoint *key, struct service *value) {
    struct in_addr from;
    from.s_addr = ntohl(key->ip);

    if (bpf_map_update_elem(map_fd, key, value, 0)) {
        fprintf(stderr, "ENCAP.SET {%s, %s, %u}\t\tERR (%d) \'%s\'\n",
                get_proto_name(ntohs(key->proto)), inet_ntoa(from), ntohs(key->port), errno, strerror(errno));

        return false;
    } else {
        printf("ENCAP.SET {%s, %s, %u}\t\tOK\n", get_proto_name(ntohs(key->proto)), inet_ntoa(from), ntohs(key->port));
    }

    return true;
}

bool map_encap_del(int map_fd, struct endpoint *key) {
    struct in_addr from;
    from.s_addr = ntohl(key->ip);

    if (bpf_map_delete_elem(map_fd, key)) {
        fprintf(stderr, "ENCAP.DEL {%s, %s, %u}\t\tERR (%d) \'%s\'\n",
                get_proto_name(ntohs(key->proto)), inet_ntoa(from), ntohs(key->port), errno, strerror(errno));

        return false;
    } else {
        printf("ENCAP.DEL {%s, %s, %u}\t\tOK\n", get_proto_name(ntohs(key->proto)), inet_ntoa(from), ntohs(key->port));
    }

    return true;
}

bool map_encap_delall(int map_fd) {
    struct endpoint prev_key, key;

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

    int map_verify_fd = open_bpf_map_file("/sys/fs/bpf/tc/globals/map_verify");
    if (map_verify_fd < 0) {
        return 1;
    }

    int map_encap_fd = open_bpf_map_file("/sys/fs/bpf/tc/globals/map_encap");
    if (map_encap_fd < 0) {
        return 1;
    }

    if (!strncmp(argv[1], "set", 4)) { // %s set <service-id> <group-id> <proto> <ip-proxy> <port-proxy> <ip-ep> <port-ep> <tunnel-id> <key>
        if (argc < 11) {
            usage(argv[0]);
            return 1;
        }
        
        proto = get_proto_number(argv[4]);
        if( proto == 0) {
            fprintf(stderr, "Unsupported IP proto \'%s\'\n", argv[4]);
            return 1;
        }

        if (inet_aton(argv[5], &from) == 0) {
            fprintf(stderr, "Invalid address %s\n", argv[5]);
            return 1;
        }

        if (inet_aton(argv[7], &to) == 0) {
            fprintf(stderr, "Invalid address %s\n", argv[7]);
            return 1;
        }

        struct endpoint ep_from, ep_to;
        // dnat
        map_nat_set(map_nat_fd, make_endpoint(&ep_from, from.s_addr, atoi(argv[6]), proto), make_endpoint(&ep_to, to.s_addr, atoi(argv[8]), proto));
        // snat
        map_nat_set(map_nat_fd, &ep_to, &ep_from);

        struct service svc;
        struct identity id;
        struct verify pwd;
        
        strncpy((char*)pwd.value, argv[10], SECURITY_KEY_SIZE);
        map_encap_set(map_encap_fd, &ep_to, make_service(&svc, atoi(argv[9]), make_identity(&id, atoi(argv[2]), atoi(argv[3])), make_verify(&pwd, &ep_from, &ep_to)));

        map_verify_set(map_verify_fd, &id, &pwd);
    } else if (!strncmp(argv[1], "get", 4)) {
        if (!strncmp(argv[2], "all", 4)) {
            map_encap_getall(map_encap_fd);
            map_nat_getall(map_nat_fd);
            map_verify_getall(map_verify_fd);
        } else {
            if (argc < 4) {
                usage(argv[0]);
                return 1;
            }

            struct identity id;
            struct verify pwd;

            map_verify_get(map_verify_fd, make_identity(&id, atoi(argv[2]), atoi(argv[3])), &pwd);

            struct endpoint value;
            // dnat
            map_nat_get(map_nat_fd, &pwd.dnat, &value);
            // snat
            map_nat_get(map_nat_fd, &pwd.snat, &value);

            struct service svc;

            map_encap_get(map_encap_fd, &pwd.snat, &svc);
        }
    } else if (!strncmp(argv[1], "del", 4)) {
        if (!strncmp(argv[2], "all", 4)) {
            map_verify_delall(map_verify_fd);
            map_nat_delall(map_nat_fd);
            map_encap_delall(map_encap_fd);
        } else {
            if (argc < 4) {
                usage(argv[0]);
                return 1;
            }

            struct identity id;
            struct verify pwd;

            if (!map_verify_get(map_verify_fd, make_identity(&id, atoi(argv[2]), atoi(argv[3])), &pwd)) {
                return 1;
            }

            // dnat
            map_nat_del(map_nat_fd, &pwd.dnat);
            // snat
            map_nat_del(map_nat_fd, &pwd.snat);

            map_encap_del(map_encap_fd, &pwd.snat);
            map_verify_del(map_verify_fd, &id);
        }
    } else {
        fprintf(stderr,"ERR: Unknown operation \'%s\'\n", argv[1]);
        return 1;
    }

    return 0;
}
