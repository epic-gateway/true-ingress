#ifndef CLI_UTIL_H
#define CLI_UTIL_H

#include <stdlib.h>
#include <string.h>
#include <linux/types.h>
#include "struct_tc.h"

int open_bpf_map_file(const char *file);
__u16 get_proto_number(const char *proto);
const char *get_proto_name(__u16 proto);
bool map_encap_del(int map_fd, struct encap_key *key);
bool map_encap_del_all(int map_fd);
char *base64encode (const void *encode_this, int encode_this_many_bytes);
char *base64decode (const void *decode_this, int decode_this_many_bytes);

#endif /* CLI_UTIL_H */
