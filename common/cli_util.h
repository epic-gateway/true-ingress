#ifndef CLI_UTIL_H
#define CLI_UTIL_H

#include <stdlib.h>
#include <linux/types.h>

int open_bpf_map_file(const char *file);
__u16 get_proto_number(const char *proto);
const char *get_proto_name(__u16 proto);

#endif /* CLI_UTIL_H */
