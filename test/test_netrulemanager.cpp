#include "ebpfloader.h"
#include "netrulemanager.h"
#include <cstdint>
#include <arpa/inet.h>

int main()
{
   
    EBPFLoader e("./build/firewall.o", "ens33");
    e.load();
    
    char * ip_string = "192.168.42.128";
    uint32_t ip = inet_addr(ip_string);

    NetRuleManager n;
    //n.addBlacklist(ip);
    n.addPortForward(2222, 12345);



}
