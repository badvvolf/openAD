
#include <linux/bpf.h>
#include "bpf_helpers.h" //for ebpf wrapper functinos 
#include <stddef.h>
#include <stdbool.h> 
#include <linux/if_ether.h> 
#include <linux/ip.h>
//#include <arpa/inet.h>

#define SEC(NAME) __attribute__((section(NAME), used))

#define htons(x) ((__be16)___constant_swab16((x)))
#define htonl(x) ((__be32)___constant_swab32((x)))

#define BLACKLIST 0x00000001



//first, ban the blacklist by IP (not consider the port)
struct bpf_map_def SEC("maps") blacklist = {
      .type        = BPF_MAP_TYPE_HASH,
      .key_size    = sizeof(__u32), //IP
      .value_size  = sizeof(__u32), 
      .max_entries = 0x1000000, //temp... did't decide the size
      .map_flags   = BPF_F_NO_PREALLOC,
};

static __always_inline int process_blacklist(__u32 saddr)
{
      __u32 *value = bpf_map_lookup_elem(&blacklist, &saddr);
      
      if(value != NULL)
            return BLACKLIST;
      else
            return 0;   
}


static __always_inline int filter_ipv4(struct iphdr *ip)
{
      int filter_flag = 0;
      int rule = XDP_PASS;

      filter_flag |= process_blacklist(ip->saddr);

      if(filter_flag == BLACKLIST)
            rule = XDP_DROP;
      
      return rule;
}

static __always_inline int get_filter_result(void *data, void *data_end )
{
      struct ethhdr *eth = data;
      __u16 eth_proto = eth->h_proto;

      //process filtering
	if (eth_proto == htons(ETH_P_IP)){

            struct iphdr *ip = data + sizeof(struct ethhdr);
            if (ip + 1 > data_end)
		      return XDP_DROP;
            return filter_ipv4(ip);
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
 
