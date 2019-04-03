#include "ebpf_lib.h"

static const char *file_blacklist = "/sys/fs/bpf/blacklist";

class ebpf{

private:


public:

int fd_blacklist;


 int Open_bpf_map(const char *file){
        int fd_blacklist = open_bpf_map(file_blacklist);
    }

    
};


class EBPFSuper{



};


class EBPFLoader : EBPFSuper{



};

class NetRuleManager : EBPFSuper{



};



int main()
{
    ebpf e;
    e.Open_bpf_map(file_blacklist);
    

    char * ip_string = "52.79.102.173";
   
	int res = blacklist_modify(e.fd_blacklist, ip_string);
//	close(fd_blacklist);

}

