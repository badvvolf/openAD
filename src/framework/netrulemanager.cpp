#include "netrulemanager.h"
#include "bpf.h"
#include "libbpf.h"
#include <errno.h>
#include <string.h>
#include <iostream>
#include <arpa/inet.h>

#include <unistd.h>

#include <sys/ioctl.h>
#include <linux/if.h>
#include <stdio.h>


using namespace std;

bool NetRuleManager::isMacSet = false;

NetRuleManager::NetRuleManager(string interface) : EBPFSuper(interface)
{
	if(fd_map_exported["blacklist"] <= 0)
    	openExportedMap(map_path["blacklist"],"blacklist");

	if(fd_map_exported["port_forward_rule"] <= 0)
        openExportedMap(map_path["port_forward_rule"],"port_forward_rule");
    
	if(fd_map_exported["mymac"] <= 0)
        openExportedMap(map_path["mymac"],"mymac");
	
	setMacAddrInfo();
	
	cout << "initial"<<endl;
}


bool NetRuleManager::setMacAddrInfo()
{
	int32_t fd = fd_map_exported["mymac"];
	uint8_t key = 0;
	int32_t res;
	
	if(isMacSet)
		return true;

	cout << "setting MAC" << endl;

	struct mac macaddr = getMacAddr();
    
    res = bpf_map_update_elem(fd, &key, &macaddr, BPF_NOEXIST);

	if (res != 0) { /* 0 == success */
		fprintf(stderr,
			    "%s()  key:0x%X errno(%d/%s)",
			    __func__, key, errno, strerror(errno));

		if (errno == 17) {
			fprintf(stderr, ": Already in macaddr\n");
			isMacSet = true;
			return false;
		}
		fprintf(stderr, "\n");
	}

	isMacSet = true;
	return true;

}

struct mac NetRuleManager::getMacAddr()
{
	//get mac address
	struct ifreq s;
	struct mac macaddr = {};
  	int32_t fd = socket(PF_INET, SOCK_DGRAM, IPPROTO_IP);

  	strcpy(s.ifr_name, net_interface.c_str());
    if (0 == ioctl(fd, SIOCGIFHWADDR, &s)) {
        for (int i = 0; i < 6; ++i){
            macaddr.addr[i] = s.ifr_addr.sa_data[i];
			cout << macaddr.addr[i];
        }
    }
	close(fd);
	return macaddr;
}

bool NetRuleManager::addBlacklist(uint32_t ban_ip)
{
    int32_t fd = fd_map_exported["blacklist"];
    uint32_t values = XDP_DROP;
	uint32_t key = ban_ip;
	int32_t res;
   
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
	}

	return true;
}


bool NetRuleManager::subBlacklist(uint32_t ban_ip)
{
    int32_t fd = fd_map_exported["blacklist"];
	uint32_t key = ban_ip;
	int32_t res;

	res = bpf_map_delete_elem(fd, &key);

	if (res != 0) { /* 0 == success */
		fprintf(stderr,
			    "%s()  key:0x%X errno(%d/%s)",
			    __func__, key, errno, strerror(errno));

		// exception handling -> no blacklist before
		// if (errno == 17) {
		// 	fprintf(stderr, ": Already in blacklist\n");
		// 	return false;
		// }
		fprintf(stderr, "\n");
	}

	return true;

}




bool NetRuleManager::addPortForward(uint16_t outport, uint16_t inport)
{
    int32_t fd = fd_map_exported["port_forward_rule"];
    struct portforward_rule rule = {htons(outport), htons(inport)};
	uint16_t key = htons(outport);
	int32_t res;
  
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
	}

	return true;
}

bool NetRuleManager::subPortForward(uint16_t outport, uint16_t inport)
{
	int32_t fd = fd_map_exported["port_forward_rule"];
    struct portforward_rule rule = {htons(outport), htons(inport)};
	uint16_t key = htons(outport);
	int32_t res;

	res = bpf_map_delete_elem(fd, &key);

	if (res != 0) { /* 0 == success */
		fprintf(stderr,
			    "%s()  key:0x%X errno(%d/%s)",
			    __func__, key, errno, strerror(errno));

		// exception handling -> no portforward rule before
		// if (errno == 17) {
		// 	fprintf(stderr, ": \n");
		// 	return false;
		// }
		fprintf(stderr, "\n");
	}

	return true;

}