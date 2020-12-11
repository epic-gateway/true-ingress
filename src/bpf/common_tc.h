#ifndef TC_COMMON_H_
#define TC_COMMON_H_

#include <linux/in.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>

#define bpf_print(fmt, ...)                                         \
({                                                                  \
        char ____fmt[] = fmt;                                       \
        bpf_trace_printk(____fmt, sizeof(____fmt), ##__VA_ARGS__);  \
})

#define ASSERT(_expr, _retval, _fmt, ...)   \
({                                          \
    if (!(_expr)) {                         \
        bpf_print(_fmt, ##__VA_ARGS__);     \
        return _retval;                     \
    }                                       \
})

#define ASSERT1(_expr, _retval, _cmd)       \
({                                          \
    if (!(_expr)) {                         \
        _cmd;                               \
        return _retval;                     \
    }                                       \
})

static inline
__u64 bpf_htonll(__u64 value)
{
    __u32 upper = value >> 32;
    __u32 lower = value & 0xFFFFFFFF;
    __u64 tmp = bpf_htonl(lower);
    tmp <<= 32;

    return tmp + bpf_htonl(upper);
}

static inline
__u64 bpf_ntohll(__u64 value)
{
    __u32 upper = value >> 32;
    __u32 lower = value & 0xFFFFFFFF;
    __u64 tmp = bpf_ntohl(lower);
    tmp <<= 32;

    return tmp + bpf_ntohl(upper);
}

#endif /* TC_COMMON_H_ */
