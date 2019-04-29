#ifndef __EBPFFIREWALL_H
#define __EBPFFIREWALL_H

#include <linux/types.h>

struct portforward_rule {
    __u16 oriport;
    __u16 redirport;
};

struct portforward_table_cinfo {
    __u32 ip;
    __u16 port;
};

struct portforward_table_sinfo {
    __u16 oriport;
    __u16 redirport;
    __u32 timeout;

};

struct mac {
    __u8 addr[6];
};


#endif
