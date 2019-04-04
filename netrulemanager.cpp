#include "netrulemanager.h"
#include "bpf.h"
#include "libbpf.h"
#include <errno.h>
#include <string.h>

using namespace std;

//if you already opened map, then just process
// if you didn't opened, open first.
// user don't mind if it's opened. it just automated


bool NetRuleManager::addBlacklist(int fd, char *ip, int32_t ban_ip)
{
    if(notopened)
        OpenMap("", (int32_t)MAPNUM::BLACKLIST);
    

    __u32 values = XDP_DROP;
	__u32 key;
	int res;
	res = inet_pton(AF_INET, ip, &key);

	if (res <= 0) {
		if (res == 0)
			fprintf(stderr,
				"ERR: IPv4 \"%s\" not in presentation format\n",
				ip);
		else
			perror("inet_pton");
		return 1;
	}

    res = bpf_map_update_elem(fd, &key, &values, BPF_NOEXIST);

	if (res != 0) { /* 0 == success */
		fprintf(stderr,
			"%s() IP:%s key:0x%X errno(%d/%s)",
			__func__, ip, key, errno, strerror(errno));

		if (errno == 17) {
			fprintf(stderr, ": Already in blacklist\n");
			return 0;
		}
		fprintf(stderr, "\n");
		return 1;
	}

	return 0;
}

