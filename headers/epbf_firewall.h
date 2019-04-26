#ifndef __EBPFFIREWALL_H
#define __EBPFFIREWALL_H

#include <linux/types.h>

struct portforward_rule {
    __u16 outport;
    __u16 inport;
};

struct portforward_table_cinfo {
    __u32 ip;
    __u16 port;
};

struct portforward_table_sinfo {
    __u16 outport;
    __u16 inport;
    __u32 timeout;

};

struct mac {
    __u8 addr[6];
};

struct test {
    // __u16 outport;
    // __u16 inport;
    __u8 addr_dest[50];
    //__u32 dip;
   // __u32 sip;
    
};


#endif
