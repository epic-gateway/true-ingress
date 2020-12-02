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
        case 0:
            return "NONE";
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
    fprintf(stderr,"    %s get all|<group-id> <service-id>\n", prog);
    fprintf(stderr,"    %s set-gw all|<group-id> <service-id> <key> <tunnel-id> <proto> <ip-ep> <port-ep> <ifindex>\n", prog);
    fprintf(stderr,"    %s set-node all|<group-id> <service-id> <key> <tunnel-id>\n", prog);
    fprintf(stderr,"    %s del all|<group-id> <service-id>\n\n", prog);
    fprintf(stderr,"    <group-id>      - GUE header group id\n");
    fprintf(stderr,"    <service-id>    - GUE header service id\n");
    fprintf(stderr,"    <key>           - GUE header 128b key\n");
    fprintf(stderr,"    <tunnel-id>     - Transport GUE tunnel identifier\n");
    fprintf(stderr,"    <proto>         - Flow identifier: Ip.proto (supported tcp|udp)\n");
    fprintf(stderr,"    <ip-ep>         - Flow identifier: Backend ipv4 address\n");
    fprintf(stderr,"    <port-ep>       - Flow identifier: Backend port\n");
    fprintf(stderr,"    <ifindex>       - Flow identifier: Ifindex of proxy container veth\n");
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
    printf("TABLE-VERIFY:\n\tgid+sid -> security key\t\ttunnel-id\tendpoint\t\tifindex\n");
    printf("--------------------------------------------------------------------------\n");
}

void map_verify_print_footer() {
    printf("--------------------------------------------------------------------------\n");
    printf("\n");
}

void map_verify_print_count(__u32 count) {
    printf("--------------------------------------------------------------------------\n");
    printf("Entries:  %u\n\n", count);
}

void map_verify_print_record(struct identity *key, struct verify *value) {
    struct in_addr from;
    from.s_addr = ntohl(value->encap.ep.ip);

    printf("VERIFY (%u, %u) -> ", ntohs(key->service_id), ntohs(key->group_id));
    printf("\'%16.16s\'", value->value);
    printf("\t%u", ntohl(value->tunnel_id));
    printf("\t\t(%s %s:%u)\t%u", get_proto_name(ntohs(value->encap.ep.proto)), inet_ntoa(from), ntohs(value->encap.ep.port), ntohl(value->encap.ifindex));
//        printf(" -> \t\t{%08x (%04x, %04x)} -> ", ntohl(*(__u32*)key), ntohs(key->service_id), ntohs(key->group_id));
//        __u64 *ptr = (__u64 *)value->value;
//        printf("{\'%llx%llx\' %08x}", ptr[0], ptr[1], value->tunnel_id);
    printf("\n");
}

int map_verify_get(int map_fd, struct identity *key, struct verify *value) {
    if (bpf_map_lookup_elem(map_fd, key, value)) {
        fprintf(stderr, "VERIFY.GET (%u, %u)\t\tERR (%d) \'%s\'\n",
                ntohs(key->service_id), ntohs(key->group_id), errno, strerror(errno));

        return errno;
    }

    return 0;
}

bool map_verify_getall(int map_fd) {
    struct identity prev_key, key;
    struct verify value;
    __u32 count = 0;

    map_verify_print_header();
    while (bpf_map_get_next_key(map_fd, &prev_key, &key) == 0) {
        if (map_verify_get(map_fd, &key, &value)) {
            break;
        }
        map_verify_print_record(&key, &value);
        ++count;
        prev_key=key;
    }
    map_verify_print_count(count);
    //map_verify_print_footer();

    return true;
}

bool map_verify_set(int map_fd, struct identity *key, struct verify *value) {
    if (bpf_map_update_elem(map_fd, key, value, 0)) {
        fprintf(stderr, "VERIFY.SET (%u, %u)\t\tERR (%d) \'%s\'\n",
                ntohs(key->service_id), ntohs(key->group_id), errno, strerror(errno));

        return false;
    } else {
        printf("VERIFY.SET (%u, %u)\t\tOK\n", ntohs(key->service_id), ntohs(key->group_id));
    }

    return true;
}

bool map_verify_del(int map_fd, struct identity *key) {
    if (bpf_map_delete_elem(map_fd, key)) {
        fprintf(stderr, "VERIFY.DEL (%u, %u)\t\tERR (%d) \'%s\'\n",
                ntohs(key->service_id), ntohs(key->group_id), errno, strerror(errno));

        return false;
    } else {
        printf("VERIFY.DEL (%u, %u)\t\tOK\n", ntohs(key->service_id), ntohs(key->group_id));
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
    printf("TABLE-ENCAP:\n\tdestination\tifindex -> tunnel-id\tgid+sid\t\tkey\t\t\thash\n");
    printf("--------------------------------------------------------------------------\n");
}

void map_encap_print_footer() {
    printf("--------------------------------------------------------------------------\n");
    printf("\n");
}

void map_encap_print_count(__u32 count) {
    printf("--------------------------------------------------------------------------\n");
    printf("Entries:  %u\n\n", count);
}

bool map_encap_get(int map_fd, struct encap_key *key, struct service *value) {
    struct in_addr from;
    from.s_addr = ntohl(key->ep.ip);

    if (bpf_map_lookup_elem(map_fd, key, value)) {
        fprintf(stderr, "ENCAP.GET (%s %s:%u) %u\t\tERR (%d) \'%s\'\n",
                get_proto_name(ntohs(key->ep.proto)), inet_ntoa(from), ntohs(key->ep.port), ntohl(key->ifindex), errno, strerror(errno));

        return false;
    } else {
        printf("ENCAP (%s %s:%u)  %u -> ", get_proto_name(ntohs(key->ep.proto)), inet_ntoa(from), ntohs(key->ep.port), ntohl(key->ifindex));
        printf("%u\t\t(%u, %u)\t\'%16.16s\'\t%u", ntohl(value->key.tunnel_id), ntohs(value->identity.service_id), ntohs(value->identity.group_id), (char*)value->key.value, value->hash);
//        __u32 *ptrk = (__u32 *)key;
//        printf("\t\t(%x%x%x) -> ", ptrk[0], ptrk[1], ptrk[2]);
//        __u64 *ptr = (__u64 *)value->key.value;
//        printf("(%08x\t(%04x, %04x)\t\'%llx%llx\'", value->key.tunnel_id, value->identity.service_id, value->identity.group_id, ptr[0], ptr[1]);
        printf("\n");
    }
    return true;
}

bool map_encap_getall(int map_fd) {
    struct encap_key prev_key, key;
    struct service value;
    __u32 count = 0;

    map_encap_print_header();
    while (bpf_map_get_next_key(map_fd, &prev_key, &key) == 0) {
        if (!map_encap_get(map_fd, &key, &value)) {
            break;
        }
        ++count;
        prev_key=key;
    }
    map_encap_print_count(count);
    //map_encap_print_footer();

    return true;
}

bool map_encap_set(int map_fd, struct encap_key *key, struct service *value) {
    struct in_addr from;
    from.s_addr = ntohl(key->ep.ip);

    if (bpf_map_update_elem(map_fd, key, value, 0)) {
        fprintf(stderr, "ENCAP.SET (%s %s:%u) %u\t\tERR (%d) \'%s\'\n",
                get_proto_name(ntohs(key->ep.proto)), inet_ntoa(from), ntohs(key->ep.port), ntohl(key->ifindex), errno, strerror(errno));

        return false;
    } else {
        printf("ENCAP.SET (%s %s:%u) %u\t\tOK\n", get_proto_name(ntohs(key->ep.proto)), inet_ntoa(from), ntohs(key->ep.port), ntohl(key->ifindex));
    }

    return true;
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
    __u16 proto;
    struct in_addr to;

    if (argc < 3) {
        usage(argv[0]);
        return 1;
    }

//    int map_nat_fd = open_bpf_map_file("/sys/fs/bpf/tc/globals/map_nat");
//    if (map_nat_fd < 0) {
//        return 1;
//    }

    int map_verify_fd = open_bpf_map_file("/sys/fs/bpf/tc/globals/map_verify");
    if (map_verify_fd < 0) {
        return 1;
    }

    int map_encap_fd = open_bpf_map_file("/sys/fs/bpf/tc/globals/map_encap");
    if (map_encap_fd < 0) {
        return 1;
    }

    if (!strncmp(argv[1], "set-gw", 7)) { // set-gw <group-id>2 <service-id>3 <key>4 <tunnel-id>5 <proto>6 <ip-ep>7 <port-ep>8 <ifindex>9
        if (argc < 9) {
            usage(argv[0]);
            return 1;
        }
        
        proto = get_proto_number(argv[6]);
        if( proto == 0) {
            fprintf(stderr, "Unsupported IP proto \'%s\'\n", argv[6]);
            return 1;
        }

        if (inet_aton(argv[7], &to) == 0) {
            fprintf(stderr, "Invalid address %s\n", argv[7]);
            return 1;
        }

        struct endpoint ep_to = { 0 };

        struct service svc = { 0 };
        struct identity id = { 0 };
        struct verify pwd = { 0 };
        struct encap_key ekey = { 0 };
        __u32 tid = atoi(argv[5]);
        
        strncpy((char*)pwd.value, argv[4], SECURITY_KEY_SIZE);

        make_endpoint(&ep_to, to.s_addr, atoi(argv[8]), proto);
        make_encap_key(&ekey, to.s_addr, atoi(argv[8]), proto, atoi(argv[9]));
        make_identity(&id, atoi(argv[2]), atoi(argv[3]));
        make_verify(&pwd, tid, &ekey);
        make_service(&svc, &id, &pwd);

        // update encap entry
        {
            struct verify current;

            if (!map_verify_get(map_verify_fd, &id, &current)) {
                map_encap_del(map_encap_fd, &current.encap);
            }
        }

        map_encap_set(map_encap_fd, &ekey, &svc);
        map_verify_set(map_verify_fd, &id, &pwd);
    } else if (!strncmp(argv[1], "set-node", 9)) {  // set-node <group-id>2 <service-id>3 <key>4 <tunnel-id>5
        if (argc < 5) {
            usage(argv[0]);
            return 1;
        }

//        struct service svc = { 0 };
        struct identity id = { 0 };
        struct verify pwd = { 0 };
        __u32 tid = atoi(argv[5]);
        struct encap_key ekey = { 0 };

        if (argc == 9) {
            proto = get_proto_number(argv[6]);
            if( proto == 0) {
                fprintf(stderr, "Unsupported IP proto \'%s\'\n", argv[6]);
                return 1;
            }

            if (inet_aton(argv[7], &to) == 0) {
                fprintf(stderr, "Invalid address %s\n", argv[7]);
                return 1;
            }
            make_encap_key(&ekey, to.s_addr, atoi(argv[8]), proto, 0);
        }
        
        strncpy((char*)pwd.value, argv[4], SECURITY_KEY_SIZE);

        make_identity(&id, atoi(argv[2]), atoi(argv[3]));
        make_verify(&pwd, tid, &ekey);
//        make_service(&svc, &id, &pwd);

//        map_encap_set(map_encap_fd, &ekey, &svc);
        map_verify_set(map_verify_fd, &id, &pwd);
    } else if (!strncmp(argv[1], "get", 4)) {
        if (!strncmp(argv[2], "all", 4)) {
            map_encap_getall(map_encap_fd);
            map_verify_getall(map_verify_fd);
        } else {
            if (argc < 4) {
                usage(argv[0]);
                return 1;
            }

            struct identity id;
            struct verify pwd;

            map_verify_get(map_verify_fd, make_identity(&id, atoi(argv[2]), atoi(argv[3])), &pwd);
            map_verify_print_record(&id, &pwd);

            struct service svc;

            map_encap_get(map_encap_fd, &pwd.encap, &svc);
        }
    } else if (!strncmp(argv[1], "del", 4)) {
        if (!strncmp(argv[2], "all", 4)) {
            map_verify_delall(map_verify_fd);
            map_encap_delall(map_encap_fd);
        } else {
            if (argc < 4) {
                usage(argv[0]);
                return 1;
            }

            struct identity id;
            struct verify pwd;

            if (!map_verify_get(map_verify_fd, make_identity(&id, atoi(argv[2]), atoi(argv[3])), &pwd)) {
                map_encap_del(map_encap_fd, &pwd.encap);
                map_verify_del(map_verify_fd, &id);
            }
        }
    } else {
        fprintf(stderr,"ERR: Unknown operation \'%s\'\n", argv[1]);
        return 1;
    }

    return 0;
}
