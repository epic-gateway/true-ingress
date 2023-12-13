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
#include "cli_util.h"

void usage(char *prog) {
    fprintf(stderr,"ERR: Too little arguments\n");
    fprintf(stderr,"Usage:\n");
    fprintf(stderr,"    %s get all|<tunnel-id>\n", prog);
    fprintf(stderr,"    %s set-gw <tunnel-id> <proto> <ip-ep> <port-ep> <ifindex>\n", prog);
    fprintf(stderr,"    %s set-node <tunnel-id>\n", prog);
    fprintf(stderr,"    %s del all|<tunnel-id>\n\n", prog);
    fprintf(stderr,"    <tunnel-id>     - Transport GUE tunnel identifier\n");
    fprintf(stderr,"    <proto>         - Flow identifier: Ip.proto (supported tcp|udp)\n");
    fprintf(stderr,"    <ip-ep>         - Flow identifier: Backend ipv4 address\n");
    fprintf(stderr,"    <port-ep>       - Flow identifier: Backend port\n");
    fprintf(stderr,"    <ifindex>       - Flow identifier: Ifindex of proxy container veth\n");
}

////////////////////
// TABLE-ENCAP
// struct encap_key -> struct service
void map_encap_print_header() {
    printf("TABLE-ENCAP:\n\tdestination\tifindex -> tunnel-id\t\n");
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

/*
 * Print one encap structure.
 */
void map_encap_print(struct encap_key *key, struct service *value) {
    struct in_addr from;
    from.s_addr = ntohl(key->ep.ip);

    printf("ENCAP (%s %s:%u)  %u -> ", get_proto_name(ntohs(key->ep.proto)), inet_ntoa(from), ntohs(key->ep.port), ntohl(key->ifindex));
    printf("%u\n", ntohl(value->tunnel_id));
}

bool map_encap_get(int map_fd, struct encap_key *key, struct service *value) {
    struct in_addr from;
    from.s_addr = ntohl(key->ep.ip);

    if (bpf_map_lookup_elem(map_fd, key, value)) {
        fprintf(stderr, "ENCAP.GET (%s %s:%u) %u\t\tERR (%d) \'%s\'\n",
                get_proto_name(ntohs(key->ep.proto)), inet_ntoa(from), ntohs(key->ep.port), ntohl(key->ifindex), errno, strerror(errno));

        return false;
    }
    return true;
}

bool map_encap_getall(int map_fd) {
    struct encap_key prev_key, key;
    struct service value;
    __u32 count = 0;

    map_encap_print_header();
    while (bpf_map_get_next_key(map_fd, &prev_key, &key) == 0) {
        if (map_encap_get(map_fd, &key, &value)) {
            map_encap_print(&key, &value);
        }
        ++count;
        prev_key=key;
    }
    map_encap_print_count(count);

    return true;
}

/*
 * Print the encaps that belong to the tunnel with the provided
 * identity.
 */
void map_encap_print_tunnel(int map_fd, __u32 tid) {
    struct encap_key prev_key, key;
    struct service encap;

    while (bpf_map_get_next_key(map_fd, &prev_key, &key) == 0) {
        if (map_encap_get(map_fd, &key, &encap)
            && encap.tunnel_id == tid) {
            map_encap_print(&key, &encap);
            prev_key=key;
        }
    }
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

/*
 * Delete the encaps that belong to the tunnel with the provided
 * identity.
 */
void map_encap_del(int map_fd, __u32 tid) {
    struct encap_key prev_key, key;
    struct service encap;

    while (bpf_map_get_next_key(map_fd, &prev_key, &key) == 0) {
        if (map_encap_get(map_fd, &key, &encap)
            && encap.tunnel_id == tid) {
						bpf_map_delete_elem(map_fd, &key);
        }
        prev_key=key;
    }
}

bool map_encap_del_all(int map_fd) {
    struct encap_key prev_key, key;

    while (bpf_map_get_next_key(map_fd, &prev_key, &key) == 0) {
				bpf_map_delete_elem(map_fd, &key);
        prev_key=key;
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

    int map_encap_fd = open_bpf_map_file("/sys/fs/bpf/tc/globals/map_encap");
    if (map_encap_fd < 0) {
        return 1;
    }

    if (!strncmp(argv[1], "set-gw", 7)) { // set-gw <tunnel-id>2 <proto>3 <ip-ep>4 <port-ep>5 <ifindex>6
        if (argc < 6) {
            usage(argv[0]);
            return 1;
        }

        proto = get_proto_number(argv[3]);
        if( proto == 0) {
            fprintf(stderr, "Unsupported IP proto \'%s\'\n", argv[3]);
            return 1;
        }

        if (inet_aton(argv[4], &to) == 0) {
            fprintf(stderr, "Invalid address %s\n", argv[4]);
            return 1;
        }

        struct endpoint ep_to = { 0 };

        __u32 tid = bpf_htonl(atoi(argv[2]));
        struct service svc = { 0 };
        struct encap_key ekey = { 0 };

        make_endpoint(&ep_to, to.s_addr, atoi(argv[5]), proto);
        make_encap_key(&ekey, to.s_addr, atoi(argv[5]), proto, atoi(argv[6]));
        make_service(&svc, &tid, &ekey);
        map_encap_set(map_encap_fd, &ekey, &svc);
    } else if (!strncmp(argv[1], "get", 4)) {
        if (!strncmp(argv[2], "all", 4)) {
            map_encap_getall(map_encap_fd);
        } else {
            if (argc < 3) {
                usage(argv[0]);
                return 1;
            }

            __u32 tid = bpf_htonl(atoi(argv[2]));
						map_encap_print_tunnel(map_encap_fd, tid);
        }
    } else if (!strncmp(argv[1], "del", 4)) {
        if (!strncmp(argv[2], "all", 4)) {
            map_encap_del_all(map_encap_fd);
        } else {
            if (argc < 3) {
                usage(argv[0]);
                return 1;
            }

            __u32 tid = bpf_htonl(atoi(argv[2]));
            map_encap_del(map_encap_fd, tid);
        }
    } else {
        fprintf(stderr,"ERR: Unknown operation \'%s\'\n", argv[1]);
        return 1;
    }

    return 0;
}
