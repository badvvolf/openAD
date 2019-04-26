#include "netrulemanager.h"
#include "bpf.h"
#include "libbpf.h"
#include <errno.h>
#include <string.h>
#include <iostream>
#include <arpa/inet.h>


#include <unistd.h>

using namespace std;


bool NetRuleManager::addBlacklist(uint32_t ban_ip)
{
    int32_t fd;
    uint32_t values = XDP_DROP;
	uint32_t key = ban_ip;

	int32_t res;
    if(fd_map_exported["blacklist"] <= 0)
        openExportedMap(map_path["blacklist"],"blacklist");
    
    fd = fd_map_exported["blacklist"];

    res = bpf_map_update_elem(fd, &key, &values, BPF_NOEXIST);

	if (res != 0) { /* 0 == success */
		fprintf(stderr,
			    "%s()  key:0x%X errno(%d/%s)",
			    __func__, key, errno, strerror(errno));

		if (errno == 17) {
			fprintf(stderr, ": Already in blacklist\n");
			return false;
		}
		fprintf(stderr, "\n");
		return true;
	}

	return true;
}

bool NetRuleManager::addPortForward(uint16_t outport, uint16_t inport)
{
    int32_t fd;
    struct portforward_rule rule = {htons(outport), htons(inport)};
	uint16_t key = htons(outport);

	int32_t res;
    if(fd_map_exported["port_forward_rule"] <= 0)
        openExportedMap(map_path["port_forward_rule"],"port_forward_rule");
    
    fd = fd_map_exported["port_forward_rule"];

    res = bpf_map_update_elem(fd, &key, &rule, BPF_NOEXIST);

	if (res != 0) { /* 0 == success */
		fprintf(stderr,
			    "%s()  key:0x%X errno(%d/%s)",
			    __func__, key, errno, strerror(errno));

		if (errno == 17) {
			fprintf(stderr, ": Already in port_forward_rule\n");
			return false;
		}
		fprintf(stderr, "\n");
		return true;
	}

	return true;
}


bool NetRuleManager::initiate_counter()
{
	int32_t fd = fd_map_exported["counter"];
	uint32_t key = 0;
	uint32_t counter = 0;
	bpf_map_update_elem(fd, &key, &counter, BPF_NOEXIST);

}

bool NetRuleManager::findTest()
{
    
	uint32_t key = 0;
	int32_t fd = fd_map_exported["counter"];
	uint32_t logkey;
	uint32_t oldkey;

	bpf_map_lookup_elem(fd, &key, &logkey);
	oldkey = logkey;
	while(1)
	{
		sleep(2);
		logkey = 0;
		bpf_map_lookup_elem(fd, &key, &logkey);
		printf("wake.. %d\n", logkey);
		if(logkey == oldkey)
			continue;
		else
		{
			oldkey = logkey;
		}
		
		printf("the log key is %d\n", logkey);

		fd = fd_map_exported["result"];

		for(uint32_t j =0; j<logkey; j++)
		{
			struct test t = {};
			bpf_map_lookup_elem(fd, &j, &t);
			
			printf("key %d\t:", j);
			//printf("result : dport : %d sport : %d\n", t.outport, t.inport);
			for (int i = 0; i < 50; ++i){
				printf("%x ",  t.addr_dest[i] );
			}
			printf("\n");
		}
	}
	return true;
}