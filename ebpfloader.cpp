
#include "ebpfloader.h"
#include <sys/resource.h>
#include <errno.h>
#include <unistd.h>
#include <string.h>
#include "bpf_load.h"
#include <net/if.h>


#include <sys/socket.h>
#include <sys/ioctl.h>
#include <linux/if.h>
#include <netdb.h>
#include <stdio.h>
#include <string.h>


using namespace std;

std::string EBPFLoader::filepath_ebpf;
std::string EBPFLoader::net_interface;
std::map<std::string, bool> EBPFLoader::map_exported;
std::map<std::string, int32_t> EBPFLoader::map_index; 


EBPFLoader::EBPFLoader(string filepath, string interface)
{
    filepath_ebpf = filepath;
    net_interface = interface;
}

EBPFLoader::~EBPFLoader()
{
    map_exported.clear();
    map_index.clear();
}


bool EBPFLoader::setMacAddrMap()
{
	int32_t fd;
    struct mac macaddr = {};
	uint8_t key = 0;

	struct ifreq s;
  	fd = socket(PF_INET, SOCK_DGRAM, IPPROTO_IP);

  	strcpy(s.ifr_name, net_interface.c_str());
    if (0 == ioctl(fd, SIOCGIFHWADDR, &s)) {
        
        for (int i = 0; i < 6; ++i)
            macaddr.addr[i] = s.ifr_addr.sa_data[i];
    }

    close(fd);




	int32_t res;
    if(fd_map_exported["mymac"] <= 0)
        openExportedMap(map_path["mymac"],"mymac");
    
    fd = fd_map_exported["mymac"];

    res = bpf_map_update_elem(fd, &key, &macaddr, BPF_NOEXIST);

	if (res != 0) { /* 0 == success */
		fprintf(stderr,
			    "%s()  key:0x%X errno(%d/%s)",
			    __func__, key, errno, strerror(errno));

		if (errno == 17) {
			fprintf(stderr, ": Already in macaddr\n");
			return false;
		}
		fprintf(stderr, "\n");
		return true;
	}

	return true;

}





void EBPFLoader::preloadMapsViaFs(struct bpf_map_data *map_data, int32_t mapnum)
{
    string file;
    map_index[map_data->name] =  mapnum;

    file = map_path[map_data->name];

    //if already exoirted    
    if (openExportedMap(file, map_data->name)) {

        map_data->fd = fd_map_exported[map_data->name];
        map_exported[map_data->name] = true;

    } 
    else 
        map_exported[map_data->name] = false;
    
}


void EBPFLoader::chownExportedMaps(uid_t owner, gid_t group)
{
    map<string, bool>::iterator iter;
    for(iter = map_exported.begin(); iter!=map_exported.end(); iter ++) {   
        if(iter->second)
            continue;
     
        int32_t index = map_index[iter->first];
        string path = map_path[iter->first];

        if (chown(path.c_str(), owner, group) < 0)
            fprintf(stderr,"WARN: Cannot chown file:%s err(%d):%s\n",
	                path.c_str(), errno, strerror(errno));
    }
}


int32_t EBPFLoader::load()
{
	struct rlimit r = {RLIM_INFINITY, RLIM_INFINITY};
	uid_t owner = -1; /* -1 result in no-change of owner */
	gid_t group = -1;

    //get network interface number
    uint32_t ifindex = if_nametoindex(net_interface.c_str());

    if (ifindex == 0) {
        return -1;
    }

    if (ifindex == -1) {
	   return -1;
	}
    	
	if (setrlimit(RLIMIT_MEMLOCK, &r)) {
		perror("setrlimit(RLIMIT_MEMLOCK, RLIM_INFINITY)");
		return 1;
	}

	if (load_bpf_file_fixup_map(filepath_ebpf.c_str(), EBPFLoader::preloadMapsViaFs)) {
	  fprintf(stderr, "Error in load_bpf_file_fixup_map(): %s", bpf_log_buf);
		return 1;
	}

	if (!prog_fd[0]) {
		printf("load_bpf_file: %s\n", strerror(errno));
		return 1;
	}

	exportMaps();

	if (owner >= 0)
	  chownExportedMaps(owner, group);

	if (bpf_set_link_xdp_fd(ifindex, prog_fd[0], 0) < 0) {
		printf("link set xdp fd failed\n");
		return 1;
	}

    setMacAddrMap();
    return 0;

}


void EBPFLoader::exportMaps(void)
{
    map<string, bool>::iterator iter;

    for(iter = map_exported.begin(); iter!=map_exported.end(); iter ++)
    {   
        if(iter->second)
            continue;
     
        int32_t index = map_index[iter->first];
        string path = map_path[iter->first];
        
        //map_fd[] is in bpf_load.h, it has map fd that not exported
        if (bpf_obj_pin(map_fd[index], path.c_str()) != 0) {
            fprintf(stderr, "ERR: Cannot pin map(%s) file:%s err(%d):%s\n",
            map_data[index].name, path.c_str(), errno, strerror(errno));
        }
    }    
}

