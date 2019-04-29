/* Copyright(c) 2019 kjkjk1178.
 * Copyright (c) 2016 Facebook
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of version 2 of the GNU General Public
 * License as published by the Free Software Foundation.
 */


#include "epbf_firewall.h"

#include <linux/pkt_cls.h>
#include <iproute2/bpf_elf.h>
#include <linux/bpf.h>
#include <stddef.h>
#include "bpf_helpers.h" //for ebpf wrapper functinos 

#include <linux/if_ether.h>  
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/in.h>

#define bpf_htons(x) ((__be16)___constant_swab16((x)))
#define SEC(NAME) __attribute__((section(NAME), used))

// #ifndef BPF_FUNC
// # define BPF_FUNC(NAME, ...)              \
//    (*NAME)(__VA_ARGS__) = (void *)BPF_FUNC_##NAME
// #endif

// static void *BPF_FUNC(map_lookup_elem, void *map, const void *key);

struct bpf_elf_map SEC("maps") port_forward_table = {
    .type        = BPF_MAP_TYPE_HASH,
    .size_key    = sizeof(struct portforward_table_cinfo), //outport
    .size_value  = sizeof(struct portforward_table_sinfo), 
    .pinning = PIN_GLOBAL_NS,
    .max_elem   = 0x10000, //temp... did't decide the size,
};



static __always_inline int redirect_tcp(struct iphdr *ip, struct tcphdr *tcp)
{
    struct portforward_table_cinfo cinfo = {};
    struct portforward_table_sinfo *sinfo = NULL;

    if(ip == NULL || tcp == NULL)
        return TC_ACT_OK;
        
    cinfo.ip = ip->daddr;
    cinfo.port = tcp->dest;

    //find rule
    sinfo = bpf_map_lookup_elem(&port_forward_table, &cinfo);

    if(sinfo != NULL) {
        //change port
        tcp->source = sinfo->oriport;
        
        //sinfo->timeout = TIMEOUT;
    }
    
    return TC_ACT_OK;
}


SEC("egress")
int tc_egress(struct __sk_buff *skb)
{
    void *data = (void *)(long)skb->data;
	struct ethhdr *eth = data;
	void *data_end = (void *)(long)skb->data_end;

	if(eth + 1 > data_end)
		return TC_ACT_OK;

	if(eth->h_proto == bpf_htons(ETH_P_IP)) {
		struct iphdr *ip = data + sizeof(*eth);
        
		if(ip + 1 > data_end)
			return TC_ACT_OK;
        
        switch(ip->protocol)
        {
        case IPPROTO_TCP : {

            __u32 iplen = (__u32)(ip->ihl) * 4;
            struct tcphdr * tcp = (struct tcphdr *)((__u8 *)ip + iplen);

            if(tcp + 1 > data_end)
                return TC_ACT_OK;

            return redirect_tcp(ip, tcp);
            
            break;
            }
            
        default:
            return TC_ACT_OK;
        }
	} 
}

char _license[] SEC("license") = "GPL";