#ifndef ELF_MAP_H_
#define ELF_MAP_H_

/* Object pinning settings
 * A setting of PIN_GLOBAL_NS would place it into a global namespace,
 * so that it can be shared among different object files. A setting
 * of PIN_NONE (= 0) means no sharing, so each tc invocation a new map
 * instance is being created.
 */
#define PIN_NONE            0
#define PIN_OBJECT_NS       1
#define PIN_GLOBAL_NS       2

/* ELF map definition */
struct bpf_elf_map {
    __u32 type;
    __u32 size_key;
    __u32 size_value;
    __u32 max_elem;
    __u32 flags;
    __u32 id;
    __u32 pinning;
    __u32 inner_id;
    __u32 inner_idx;
};

#endif /* ELF_MAP_H_ */
