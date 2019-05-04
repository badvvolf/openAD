
#include <linux/bpf.h>
#include <linux/if_link.h>
#include <assert.h>
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <arpa/inet.h>
#include <netinet/ether.h>
#include <unistd.h>
#include <time.h>
#include "bpf.h"
#include "bpf_load.h"
#include "libbpf.h"
#include "bpf_util.h"
#include "xlb_common.h"
#include <stdbool.h>


#include <net/if.h>
#include <sys/statfs.h>
#include <libgen.h>

static const char *file_pinned_map[6]   = {
  "/sys/fs/bpf/blacklist", 
  "/sys/fs/bpf/port_forward_rule", 
  "/sys/fs/bpf/tc/globals/port_forward_table",
  "/sys/fs/bpf/tc/globals/rptest",
  "/sys/fs/bpf/mymac", 
};


static char ifname_buf[IF_NAMESIZE];
static char *ifname = NULL;

static int ifindex = -1;
static __u32 xdp_flags = 0;

#define NR_MAPS 4


int maps_marked_for_export[MAX_MAPS] = { 0 };

static const char* map_idx_to_export_filename(int idx)
{
  const char *file = NULL;

 
  /* Mapping map_fd[idx] to export filenames */
  /*switch (idx) {
  case 0: 
    file = file_pinned_map;
    break;
	case 1 : 
		break;
  default:
    break;
  }*/
  file = file_pinned_map[idx];

 printf("file : %d %s\n", idx, file);
  if (DEBUG) printf("FileNAME: %s \n", file);

  return file;
}

static void remove_xdp_program(int ifindex, const char *ifname, __u32 xdp_flags)
{
  int i;
  fprintf(stderr, "Removing XDP program on ifindex:%d device:%s\n",
	  ifindex, ifname);
  if (ifindex > -1)
    set_link_xdp_fd(ifindex, -1, xdp_flags);


  for (i = 0; i < NR_MAPS; i++) {
	  
    const char *file = map_idx_to_export_filename(i);

    if (unlink(file) < 0) {
      printf("WARN: cannot rm map(%s) file:%s err(%d):%s\n",
	     map_data[i].name, file, errno, strerror(errno));
    }
  }
}

static void usage(const char *cmd)
{
  printf("Start a XDP prog which encapsulates incoming packets\n");
  printf("Usage: %s [...]\n", cmd);
  printf("    -i <ifindex> Interface Index\n");
  printf("    -S use skb-mode\n");
  printf("    -N enforce native mode\n");
  printf("    -v verbose\n");
  printf("    -h Display this help\n");
}

#ifndef BPF_FS_MAGIC
# define BPF_FS_MAGIC   0xcafe4a11
#endif

static int bpf_fs_check_path(const char *path)
{
  struct statfs st_fs;
  char *dname, *dir;
  int err = 0;

  if (path == NULL)
    return -EINVAL;

  dname = strdup(path);
  if (dname == NULL)
    return -ENOMEM;

  dir = dirname(dname);
  if (statfs(dir, &st_fs)) {
    fprintf(stderr, "ERR: failed to statfs %s: (%d)%s\n",
	    dir, errno, strerror(errno));
    err = -errno;
  }
  free(dname);

  if (!err && st_fs.f_type != BPF_FS_MAGIC) {
    fprintf(stderr,
	                            "ERR: specified path %s is not on BPF FS\n\n"
	                            " You need to mount the BPF filesystem type like:\n"
	    "  mount -t bpf bpf /sys/fs/bpf/\n\n",
	    path);
    err = -EINVAL;
  }

  return err;
}

int load_map_file(const char *file, struct bpf_map_data *map_data)
{
  int fd;

  if (bpf_fs_check_path(file) < 0) {
    exit(EXIT_FAIL_MAP_FS);
  }

  fd = bpf_obj_get(file);
 
  if (fd > 0) { /* Great: map file already existed use it */
    if (verbose)
      printf(" - Loaded bpf-map:%-30s from file:%s\n",
	     map_data->name, file);
    return fd;
  }
  return -1;
}


//this is callback func
//this will be called for every map which is load (loop, index ++)
void pre_load_maps_via_fs(struct bpf_map_data *map_data, int idx)
{
  const char *file;
  int fd;
	
	//save the map fd to use it...
  file = map_idx_to_export_filename(idx);

  printf("%d\n", idx); 
  fd = load_map_file(file, map_data);
  //this is get map file

  if (fd > 0) {
    map_data->fd = fd;
	
  } else {
    printf("map fd 1 : %d %d\n", fd, idx);
    maps_marked_for_export[idx] = 1;
  }
}

int export_map_idx(int map_idx)
{
  const char *file;

  file = map_idx_to_export_filename(map_idx);

  //map_fd is from bpf_load
  printf("map fd 2 : %d %d\n", map_fd[map_idx], map_idx);


  if (bpf_obj_pin(map_fd[map_idx], file) != 0) {
    fprintf(stderr, "ERR: Cannot pin map(%s) file:%s err(%d):%s\n",
	    map_data[map_idx].name, file, errno, strerror(errno));
    return EXIT_FAIL_MAP;
  }
  if (verbose)
    printf(" - Export bpf-map:%-30s to   file:%s\n",
	   map_data[map_idx].name, file);
  return 0;
}

void export_maps(void)
{
  int i;
  for (i = 0; i < NR_MAPS; i++) {
	   
    if (maps_marked_for_export[i] == 1)
      export_map_idx(i);
  }
}

void chown_maps(uid_t owner, gid_t group)
{
  const char *file;
  int i;


  for (i = 0; i < NR_MAPS; i++) {
    file = map_idx_to_export_filename(i);

    if (chown(file, owner, group) < 0)
      fprintf(stderr,
	      "WARN: Cannot chown file:%s err(%d):%s\n",
	      file, errno, strerror(errno));
  }
}

static void poll_stats(int map_fd, int interval)
{
	__u32 key = inet_addr("52.79.102.173");
	__u32 values = XDP_DROP;

	printf("key : %x %d\n", key, map_fd);
	bpf_map_update_elem(map_fd, &key, &values, 0);
	
  values = 0;
	assert(bpf_map_lookup_elem(map_fd, &key, &values) == 0);
	printf("read : %x\n", values);
	
	sleep(interval);
}

int main(int argc, char **argv)
{
	const char *optstr = "i:Shvr";
	struct rlimit r = {RLIM_INFINITY, RLIM_INFINITY};
	char filename[256] = "./build/firewall_ingress.o";
	int opt;

	uid_t owner = -1; /* -1 result in no-change of owner */
	gid_t group = -1;
	
	bool rm_xdp_prog = false;

	while ((opt = getopt(argc, argv, optstr)) != -1) {
		switch (opt) {
		case 'v':
		  verbose = 1;
		  break;
		case 'r':
		  rm_xdp_prog = true;
		  break;
		case 'i':
		  if (strlen(optarg) >= IF_NAMESIZE) {
		    fprintf(stderr, "ERR: Intereface name too long\n");
		    goto error;
		  }
		  ifname = (char *)&ifname_buf;
		  strncpy(ifname, optarg, IF_NAMESIZE);
		  ifindex = if_nametoindex(ifname);
		  if (ifindex == 0) {
		    fprintf(stderr,
			    "ERR: Interface name unknown err(%d):%s\n",
			    errno, strerror(errno));
		    goto error;
		  }
		  break;
		case 'S':
			xdp_flags |= XDP_FLAGS_SKB_MODE;
			break;
		error:
		default:
			usage(argv[0]);
			return 1;
		}
	}

        if (ifindex == -1) {
	  printf("ERR: required option -i missing");
	  usage(argv[0]);
	  return EXIT_FAIL_OPTION;
	}
		
	if (rm_xdp_prog) {
	  remove_xdp_program(ifindex, ifname, xdp_flags);
	  return 0;
	}
	
	if (setrlimit(RLIMIT_MEMLOCK, &r)) {
		perror("setrlimit(RLIMIT_MEMLOCK, RLIM_INFINITY)");
		return 1;
	}

  //load ebpf program with opening (exported)map file
  // if there is no exported map, then open inner file -> after that, 
  // export it yourself
	if (load_bpf_file_fixup_map(filename, pre_load_maps_via_fs)) {
	  fprintf(stderr, "Error in load_bpf_file_fixup_map(): %s", bpf_log_buf);
		return 1;
	}

	printf("---------%d\n", prog_fd[0]);
	if (!prog_fd[0]) {
		printf("load_bpf_file: %s\n", strerror(errno));
		return 1;
	}

	export_maps();

	if (owner >= 0)
	  chown_maps(owner, group);

	if (set_link_xdp_fd(ifindex, prog_fd[0], xdp_flags) < 0) {
		printf("link set xdp fd failed\n");
		return 1;
	}


//  poll_stats(map_fd[0], 1000);

	return 0;
}