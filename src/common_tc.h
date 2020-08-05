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

#endif /* TC_COMMON_H_ */
