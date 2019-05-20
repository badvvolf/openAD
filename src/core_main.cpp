#include "ebpfloader.h"
#include "netrulemanager.h"
#include <cstdint>
#include <arpa/inet.h>

int main()
{
    //load firewall (egress)
    system("tc qdisc add dev ens33 clsact");
    system("tc filter add dev ens33 egress bpf da obj ./firewall_egress.o sec egress");

    //load firewall (ingress)
    EBPFLoader e("./firewall_ingress.o", "ens33");
    e.load();
    
    //get setting from UI


    //start modules with some settings
    //exec()

}
