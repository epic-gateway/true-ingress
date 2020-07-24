#ifndef CFG_TC_H_
#define CFG_TC_H_

#include "bpf_elf.h"

#include "struct_tc.h"

struct bpf_elf_map SEC("maps") map_config = {
    .type       = BPF_MAP_TYPE_HASH,
    .size_key   = sizeof(__u32),
    .size_value = sizeof(struct cfg_if),
    .pinning    = PIN_GLOBAL_NS,
    .max_elem   = CFG_IDX_MAX,
};

#endif /* CFG_TC_H_ */
