#include "netrulemanager.h"
#include "bpf.h"
#include "libbpf.h"
#include <errno.h>
#include <string.h>
#include <iostream>

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



