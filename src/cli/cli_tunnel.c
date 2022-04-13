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

// MAP_TUNNEL:	u32 -> struct tunnel
// MAP_DECAP:	struct endpoint -> u32

void usage(char *prog) {
    fprintf(stderr,"ERR: Too little arguments\n");
    fprintf(stderr,"Usage:\n");
    fprintf(stderr,"    %s get <id>|all\n", prog);
    fprintf(stderr,"    %s set <id> <ip-local> <port-local> <ip-remote> <port-remote>\n", prog);
    fprintf(stderr,"    %s del <id>|all\n\n", prog);
    fprintf(stderr,"    <id>            - GUE tunnel identifier\n");
    fprintf(stderr,"    <ip-local>      - GUE tunnel local ip address\n");
    fprintf(stderr,"    <port-local>    - GUE tunnel local UDP port\n");
    fprintf(stderr,"    <ip-remote>     - GUE tunnel remote ip address\n");
    fprintf(stderr,"    <port-remote>   - GUE tunnel remote UDP port\n");
}

////////////////////
// TABLE-TUNNEL
////////////////////
void map_tunnel_print_header() {
    printf("TABLE-TUNNEL:\n   \ttunnel-id\t\tlocal-ip:port -> remote-ip:port\n");
    printf("--------------------------------------------------------------------------\n");
}

void map_tunnel_print_footer() {
    printf("--------------------------------------------------------------------------\n");
    printf("\n");
}

void map_tunnel_print_count(__u32 count) {
    printf("--------------------------------------------------------------------------\n");
    printf("Entries:  %u\n\n", count);
}

void map_tunnel_print_record(__u32 id, struct tunnel *value) {
    struct in_addr local, remote;

    local.s_addr = ntohl(value->ip_local);
    remote.s_addr = ntohl(value->ip_remote);

    printf("TUN\t%8u\t%16s:%u -> ", id,
            inet_ntoa(local), ntohs(value->port_local));
    printf("%s:%u", inet_ntoa(remote), ntohs(value->port_remote));
    printf("\n");
}

void map_tunnel_print_ok(__u32 id, const char *name) {
    printf("TUNNEL.%s (%u)\t\tOK\n", name, id);
}

void map_tunnel_print_err(__u32 id, const char *name, int err) {
    fprintf(stderr, "TUNNEL.%s (%u)\t\tERR (%d) \'%s\'\n", name, id, err, strerror(err));
}

int map_tunnel_get(int map_fd, __u32 id, struct tunnel *value) {
    if (bpf_map_lookup_elem(map_fd, &id, value)) {
        return errno;
    }

    return 0;
}

bool map_tunnel_getall(int map_fd) {
    __u32 prev_key, key;
    struct tunnel value;
    int ret;
    __u32 count = 0;

    map_tunnel_print_header();
    while(bpf_map_get_next_key(map_fd, &prev_key, &key) == 0) {
        ret = map_tunnel_get(map_fd, key, &value);
        if (!ret) {
            map_tunnel_print_record(key, &value);
            ++count;
        } else {
            map_tunnel_print_err(key, "GET", ret);
            break;
        }

        prev_key=key;
    }

    map_tunnel_print_count(count);
    return true;
}

bool map_tunnel_set(int map_fd, __u32 id, struct tunnel *value) {
    int ret = bpf_map_update_elem(map_fd, &id, value, 0);
    if (ret) {
        map_tunnel_print_err(id, "SET", ret);

        return false;
    } else {
        map_tunnel_print_ok(id, "SET");
    }

    return true;
}

bool map_tunnel_del(int map_fd, __u32 id) {
    int ret = bpf_map_delete_elem(map_fd, &id);
    if (ret) {
        map_tunnel_print_err(id, "SET", ret);

        return false;
    } else {
        map_tunnel_print_ok(id, "DEL");
    }

    return true;
}

bool map_tunnel_delall(int map_fd) {
    __u32 prev_key, key;

    while(bpf_map_get_next_key(map_fd, &prev_key, &key) == 0) {
        map_tunnel_del(map_fd, key);
    }

    return true;
}

////////////////////
// TABLE-DECAP
////////////////////
void map_decap_print_header() {
    printf("TABLE-DECAP:\n           proto\tip:port\t\t\tref-count\n");
    printf("--------------------------------------------------------------------------\n");
}

void map_decap_print_footer() {
    printf("--------------------------------------------------------------------------\n");
    printf("\n");
}

void map_decap_print_count(__u32 count) {
    printf("--------------------------------------------------------------------------\n");
    printf("Entries:  %u\n\n", count);
}

void map_decap_print_record(struct endpoint *key, __u32 *value) {
    struct in_addr from;
    from.s_addr = ntohl(key->ip);

    printf("DECAP\t%8s    %s:%u\t\t%u", get_proto_name(ntohs(key->proto)), inet_ntoa(from), ntohs(key->port), *value);
    printf("\n");
}

void map_decap_print_ok(struct endpoint *key, const char *name) {
    struct in_addr from;
    from.s_addr = ntohl(key->ip);

    printf("DECAP.%s (%s, %s, %u)\t%llx\tOK\n", name, get_proto_name(ntohs(key->proto)), inet_ntoa(from), ntohs(key->port), *(__u64 *)key);
}

void map_decap_print_err(struct endpoint *key, const char *name, int err) {
    struct in_addr from;
    from.s_addr = ntohl(key->ip);

    fprintf(stderr, "DECAP.%s (%s, %s, %u)\t\tERR (%d) \'%s\'\n", name,
            get_proto_name(ntohs(key->proto)), inet_ntoa(from), ntohs(key->port), err, strerror(err));
}

int map_decap_get(int map_fd, struct endpoint *key, __u32 *value) {
    if (bpf_map_lookup_elem(map_fd, key, value)) {
        return errno;
    }
    return 0;
}

bool map_decap_getall(int map_fd) {
    struct endpoint prev_key, key;
    __u32 value, count = 0;
    int ret;

    map_decap_print_header();
    while (bpf_map_get_next_key(map_fd, &prev_key, &key) == 0) {
        ret = map_decap_get(map_fd, &key, &value);
        if (!ret) {
            map_decap_print_record(&key, &value);
            ++count;
        } else {
            map_decap_print_err(&key, "GET", ret);
            break;
        }

        prev_key=key;
    }
    map_decap_print_count(count);
    return true;
}

bool map_decap_inc(int map_fd, struct endpoint *key) {
    __u32 value = 1;

    int ret = map_decap_get(map_fd, key, &value);
    if (!ret) {
        ++value;
    }

    if (bpf_map_update_elem(map_fd, key, &value, 0)) {
        map_decap_print_err(key, "INC", errno);
        return false;
    } else {
        if (ret) {    // create
            map_decap_print_ok(key, "SET");
        } else { // increase ref count
            map_decap_print_ok(key, "INC");
        }
    }

    return true;
}

bool map_decap_del(int map_fd, struct endpoint *key) {
    if (bpf_map_delete_elem(map_fd, key)) {
        map_decap_print_err(key, "DEL", errno);
        return false;
    } else {
        map_decap_print_ok(key, "DEL");
    }

    return true;
}

bool map_decap_dec(int map_fd, struct endpoint *key) {
    __u32 value = 1;

    if (map_decap_get(map_fd, key, &value)) {    // create
        return true;
    }

    if (value > 1) { // decrease ref count
        --value;

        if (bpf_map_update_elem(map_fd, key, &value, 0)) {
            map_decap_print_err(key, "DEC", errno);
            return false;
        } else {
            map_decap_print_ok(key, "DEC");
        }
    } else {    // remove
        return map_decap_del(map_fd, key);
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
        __u32 id = atoi(argv[2]);

        // update decap entry
        {
            if (!map_tunnel_get(map_tunnel_fd, id, &tun)) {
                map_decap_dec(map_decap_fd, make_endpoint(&ep, ntohl(tun.ip_local), ntohs(tun.port_local), get_proto_number("udp")));
            }
        }

        make_endpoint(&ep, local.s_addr, atoi(argv[4]), get_proto_number("udp"));

        map_tunnel_set(map_tunnel_fd, atoi(argv[2]), make_tunnel(&tun, local.s_addr, atoi(argv[4]), remote.s_addr, atoi(argv[6])));
        map_decap_inc(map_decap_fd, &ep);
    } else if (!strncmp(argv[1], "get", 4)) {
        if (argc < 3) {
            usage(argv[0]);
            return 1;
        }

        if (!strncmp(argv[2], "all", 4)) {
            map_tunnel_getall(map_tunnel_fd);
            map_decap_getall(map_decap_fd);
        } else {
            __u32 id = atoi(argv[2]);
            struct tunnel tun;
            int ret;

            ret = map_tunnel_get(map_tunnel_fd, id, &tun);
            if (ret) {
                return 1;
            }

            map_tunnel_print_header();
            map_tunnel_print_record(id, &tun);
            map_tunnel_print_footer();

            struct endpoint ep;
            __u32 refcnt;

            make_endpoint(&ep, ntohl(tun.ip_local), ntohs(tun.port_local), get_proto_number("udp"));
            ret = map_decap_get(map_decap_fd, &ep, &refcnt);
            if (!ret) {
                map_decap_print_header();
                map_decap_print_record(&ep, &refcnt);
                map_decap_print_footer();
            } else {
                map_decap_print_err(&ep, "GET", ret);
            }
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
            if (map_tunnel_get(map_tunnel_fd, atoi(argv[2]), &value)) {
                return 1;
            }
            struct endpoint ep;
            map_decap_dec(map_decap_fd, make_endpoint(&ep, ntohl(value.ip_local), ntohs(value.port_local), get_proto_number("udp")));
            map_tunnel_del(map_tunnel_fd, atoi(argv[2]));
        }
    } else {
        fprintf(stderr,"ERR: Unknown operation \'%s\'\n", argv[1]);
        return 1;
    }

    return 0;
}
