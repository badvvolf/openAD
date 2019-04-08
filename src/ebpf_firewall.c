
#include "epbf_firewall.h"

#include <linux/bpf.h>
#include "bpf_helpers.h" //for ebpf wrapper functinos 
#include <stddef.h>
#include <stdbool.h> 
#include <linux/if_ether.h> 
#include <linux/ip.h>
//#include <netinet/ip.h>
//#include <arpa/inet.h>
#include <linux/tcp.h>
#include <linux/in.h>

#define SEC(NAME) __attribute__((section(NAME), used))

#define htons(x) ((__be16)___constant_swab16((x)))
#define htonl(x) ((__be32)___constant_swab32((x)))



//////temp
#define TIMEOUT 0
//////


enum direction{ 
      INBOUND = 0x00000001,
      OUTBOUND = 0x00000002
};

//2^n
enum filter_reult{
      PASS = 0x00000000,
      BLACKLIST = 0x00000001,
      PORTFORWARD = 0x00000002
};

/*
    To do
    - search other helper function, like BPF_FUNC_sk_redirect_map

*/


//first, ban the blacklist by IP (not consider the port)
struct bpf_map_def SEC("maps") blacklist = {
      .type        = BPF_MAP_TYPE_HASH,
      .key_size    = sizeof(__u32), //IP
      .value_size  = sizeof(__u32), 
      .max_entries = 0x1000000, //temp... did't decide the size
      .map_flags   = BPF_F_NO_PREALLOC,
};

//
struct bpf_map_def SEC("maps") port_forward_rule = {
      .type        = BPF_MAP_TYPE_HASH,
      .key_size    = sizeof(__u16), //outport
      .value_size  = sizeof(sizeof(struct portforward_rule)), 
      .max_entries = 0x1000000, //temp... did't decide the size
      .map_flags   = BPF_F_NO_PREALLOC,
};

struct bpf_map_def SEC("maps") port_forward_table = {
      .type        = BPF_MAP_TYPE_HASH,
      .key_size    = sizeof(sizeof(struct portforward_table_cinfo)), //outport
      .value_size  = sizeof(sizeof(struct portforward_table_sinfo)), 
      .max_entries = 0x1000000, //temp... did't decide the size
      .map_flags   = BPF_F_NO_PREALLOC,
};


struct bpf_map_def SEC("maps") mymac = {
      .type        = BPF_MAP_TYPE_HASH,
      .key_size    = sizeof(__u8),
      .value_size  = sizeof(__u8[6]), 
      .max_entries = 0x1,
      .map_flags   = BPF_F_NO_PREALLOC,
};

static __always_inline int process_blacklist(__u32 saddr)
{
      __u32 *value = bpf_map_lookup_elem(&blacklist, &saddr);
      
      if(value != NULL)
            return BLACKLIST;
      else
            return PASS;   
}

static __always_inline int redirect_tcp(struct iphdr *ip, __u32 direction)
{
      //get tcp header
      __u32 iplen = (__u32)(ip->ihl) * 4;
      struct tcphdr * tcp_hdr;
      tcp_hdr = (struct tcphdr *)((__u8 *)ip + iplen);
      
      struct portforward_rule * rule;
      __u16 rule_key;
      struct portforward_table_cinfo cinfo;
      struct portforward_table_sinfo *sinfo = NULL;
      struct portforward_table_sinfo sinfo_reg;

      //out -> in 
      if(direction == INBOUND) {

            rule_key = tcp_hdr->dest;
            rule = bpf_map_lookup_elem(&port_forward_rule, &rule_key);
            
            if(rule == NULL)
                  return PASS;

            cinfo.ip = ip->saddr;
            cinfo.port = tcp_hdr->source;

            sinfo = bpf_map_lookup_elem(&port_forward_table, &cinfo);

            //if it was not connected already
            if(sinfo == NULL) {
                  //add it to portfoward table
                  sinfo_reg.outport = rule->outport;
                  sinfo_reg.inport = rule->inport;

                  sinfo = &sinfo_reg;
            }

            //change packet
            tcp_hdr->dest = rule->inport;
            
            //update timeout
            sinfo->timeout = TIMEOUT;
 
      }
      //in -> out
      else if (direction == OUTBOUND) {
            
         

      }

      ///////temp
      if(sinfo!=NULL)
            bpf_map_update_elem(&port_forward_table, &cinfo, sinfo, BPF_ANY);

      return PORTFORWARD;
}


static __always_inline int process_redirect(struct iphdr *ip, __u32 direction)
{
      switch(ip->protocol)
      {
      
      case IPPROTO_TCP : 
            return redirect_tcp(ip, direction); 
            break;

      default:
            break;

      } //switch(ip->protocol)
      
      
      /////temp
      return 0;
}

static __always_inline int filter_ipv4(struct iphdr *ip, __u32 direction)
{
      int filter_flag = 0;
      int rule = XDP_PASS;

      filter_flag |= process_blacklist(ip->saddr);

      //drop first
      if(filter_flag & BLACKLIST)
      {
            rule = XDP_DROP;
            goto filter_ipv4_end;
      }

      filter_flag |= process_redirect(ip, direction);
      if(filter_flag & PORTFORWARD)
      {
            rule = XDP_PASS; //????
            goto filter_ipv4_end;
      }
      
filter_ipv4_end :

      return rule;
}


static __always_inline int get_direction(struct ethhdr *eth)
{
      __u8 key = 0;
      __u8 *my_macaddr = bpf_map_lookup_elem(&mymac, &key);
      
      //if they are same?

      if(__builtin_memcmp(eth->h_dest, my_macaddr, 6))
            return INBOUND;
      else if (__builtin_memcmp(eth->h_source, my_macaddr, 6))
            return OUTBOUND;
}

static __always_inline int get_filter_result(void *data, void *data_end )
{
      struct ethhdr *eth = data;
      __u16 eth_proto = eth->h_proto;
      __u32 direction = get_direction(eth);

      //process filtering
	if (eth_proto == htons(ETH_P_IP)){

            struct iphdr *ip = data + sizeof(struct ethhdr);
            if (ip + 1 > data_end)
		      return XDP_DROP;

            return filter_ipv4(ip, direction);
      }
	else
		return XDP_PASS;
}


//main
SEC("xdp")
int xdp_filter(struct xdp_md *xdp)
{	
      void *data_end = (void *)(long)xdp->data_end;
	void *data = (void *)(long)xdp->data;
	struct ethhdr *eth = data;

	if (eth + 1 > data_end)
	      return XDP_DROP;
      else
            return get_filter_result(data, data_end);      
}




char _license[] SEC("license") = "GPL";
 
