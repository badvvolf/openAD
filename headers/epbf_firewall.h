#ifndef __EBPFFIREWALL_H
#define __EBPFFIREWALL_H

#include <linux/types.h>

struct portforward_rule {
    __u16 inport;
    __u16 outport;
};

struct portforward_table_cinfo {
    __u32 ip;
    __u16 port;
};

struct portforward_table_sinfo {
    
    __u16 inport;
    __u16 outport;
    __u32 timeout;

};

#endif
