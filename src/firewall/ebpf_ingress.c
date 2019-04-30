
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

#define bpf_htons(x) ((__be16)___constant_swab16((x)))
//#define htonl(x) ((__be32)___constant_swab32((x)))



//////temp
#define TIMEOUT 0
//////



////////////
enum direction{ 
      INBOUND = 0x00000001,
      OUTBOUND = 0x00000002,
      DIRCTIONERR = 0x00000004
};

//2^n
enum filter_reult{
      PASS = 0x00000000,
      BLACKLIST = 0x00000001,
};



//first, ban the blacklist by IP (not consider the port)
struct bpf_map_def SEC("maps") blacklist = {
      .type        = BPF_MAP_TYPE_HASH,
      .key_size    = sizeof(__u32), //IP
      .value_size  = sizeof(__u32), 
      .max_entries = 0x1000000, //temp... did't decide the size
      .map_flags   = BPF_F_NO_PREALLOC,
};

struct bpf_map_def SEC("maps") port_forward_rule = {
      .type        = BPF_MAP_TYPE_HASH,
      .key_size    = sizeof(__u16), //oriport
      .value_size  = sizeof(struct portforward_rule), 
      .max_entries = 0x10000, //temp... did't decide the size
      .map_flags   = BPF_F_NO_PREALLOC,
};

// use pinned map -> share with egress
struct bpf_map_def SEC("maps") port_forward_table = {
      .type        = BPF_MAP_TYPE_HASH,
      .key_size    = sizeof(struct portforward_table_cinfo), //oriport
      .value_size  = sizeof(struct portforward_table_sinfo), 
      .max_entries = 0x10000, //temp... did't decide the size
      .map_flags   = BPF_F_NO_PREALLOC,
};


struct bpf_map_def SEC("maps") mymac = {
      .type        = BPF_MAP_TYPE_HASH,
      .key_size    = sizeof(__u8),
      .value_size  = sizeof(struct mac), 
      .max_entries = 0x1,
      .map_flags   = BPF_F_NO_PREALLOC,
};


static __always_inline int check_blacklist(__u32 saddr)
{
      __u32 *value = bpf_map_lookup_elem(&blacklist, &saddr);
      
      if(value != NULL)
            return BLACKLIST;
      else
            return PASS;   
}

static __always_inline void redirect_tcp(struct iphdr *ip, struct tcphdr * tcp, void *data_end )
{
      struct portforward_rule * rule = NULL;
      __u16 rule_key;
      struct portforward_table_cinfo cinfo = {};
      struct portforward_table_sinfo *sinfo = NULL;
      struct portforward_table_sinfo sinfo_reg = {};
     
      // out -> in
      // update table
      rule_key = tcp->dest;
      rule = bpf_map_lookup_elem(&port_forward_rule, &rule_key);
      
      if(rule == NULL)
            return;

      cinfo.ip = ip->saddr;
      cinfo.port = tcp->source;

      sinfo = bpf_map_lookup_elem(&port_forward_table, &cinfo);

      //if it was not connected already
      //add it to portfoward table
      if(sinfo == NULL) {
            
            sinfo_reg.oriport = rule->oriport;
            sinfo_reg.redirport = rule->redirport;
            sinfo = &sinfo_reg;
      }

      //change packet
      tcp->dest = sinfo->redirport;
      
      // //update timeout
      // sinfo->timeout = TIMEOUT;
      
      bpf_map_update_elem(&port_forward_table, &cinfo, sinfo, BPF_ANY);
}


static __always_inline void process_redirect(struct iphdr *ip, void *data_end)
{
      
      if(ip == NULL)
            return;
            
      switch(ip->protocol)
      {
      
      case IPPROTO_TCP : {

            __u32 iplen = (__u32)(ip->ihl) * 4;
            struct tcphdr * tcp = (struct tcphdr *)((__u8 *)ip + iplen);
      
            if (tcp + 1 > data_end)
	            return;
            
            redirect_tcp(ip, tcp, data_end); 
            break;
            }

      default:
            
            break;
      } //switch(ip->protocol)
           
}

static __always_inline int filter_ipv4(struct iphdr *ip, void *data_end )
{
      int flag = 0;


      flag = check_blacklist(ip->saddr);

      //drop first
      if(flag == BLACKLIST)
            return XDP_DROP;
           
      process_redirect(ip, data_end);
      return XDP_PASS;

}

static __always_inline int bpf_memcmp(void * s1, void * s2, __s32 n)
{
      for(__s32 i = 0; i< n; i++) {

            if(((__u8 *)s1)[i] != ((__u8 *)s2)[i])
                  return 1;
      }

      return 0;
}

static __always_inline int get_direction(struct ethhdr *eth, void *data_end)
{
      __u8 key = 0;
      struct mac *macaddr = bpf_map_lookup_elem(&mymac, &key);

      if(macaddr==NULL)
            return DIRCTIONERR;

      if(!bpf_memcmp(eth->h_dest, macaddr, 6))
            return INBOUND;
      else
           return DIRCTIONERR;

}

static __always_inline int get_filter_result(void *data, void *data_end)
{
      struct ethhdr *eth = data;
      __u16 eth_proto = eth->h_proto;
      
      __u32 direction = get_direction(eth, data_end);
      
      // if it's not server's or broadcast, just pass
      if(direction == DIRCTIONERR)
            return XDP_PASS;
      
      //process filtering
	if (eth_proto == bpf_htons(ETH_P_IP)){

            struct iphdr *ip = data + sizeof(struct ethhdr);
            if (ip + 1 > data_end)
		      return XDP_PASS;

            return filter_ipv4(ip, data_end);
      }

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
 
