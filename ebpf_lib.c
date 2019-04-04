#include "libbpf.h"
#include <errno.h>
#include <arpa/inet.h>


int open_bpf_map(const char *file)
{
	int fd;

	fd = bpf_obj_get(file);
	if (fd < 0) {
		printf("ERR: Failed to open bpf map file:%s err(%d):%s\n",
		       file, errno, strerror(errno));
		exit(1);
	}
	return fd;
}

int add_blacklist(int fd, char *ip)
{
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



load_bpf_file_fixup_map

