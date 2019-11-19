#include "ebpfloader.h"
#include "netrulemanager.h"
#include <cstdint>
#include <arpa/inet.h>
#include <logger.h>
#include <iostream>
#include <string>

using namespace std;

int main()
{

    string interface;
    cout << "Enter your network interface" << endl;
    cin >> interface;

    //load firewall (egress)
    string cmd = "tc qdisc add dev " + interface + " clsact";
    system(cmd.c_str());
    cmd = "tc filter add dev " + interface + " egress bpf da obj ./firewall_egress.o sec egress";
    system(cmd.c_str());

    //load firewall (ingress)
    EBPFLoader e("./firewall_ingress.o", "ens33");
    e.load();
    

    //get setting from UI

    

    //start modules with some settings
    //exec()

}

