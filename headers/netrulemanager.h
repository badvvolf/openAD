#ifndef __NETRULEMANAGER_H
#define __NETRULEMANAGER_H

#include "ebpfsuper.h"
#include "epbf_firewall.h"

class NetRuleManager : public EBPFSuper{
//add blacklist

private: 

public:

    bool addBlacklist(uint32_t);
    bool subBlacklist(uint32_t);      
    bool addPortForward(uint16_t, uint16_t);
    bool initiate_counter();

bool findTest();
};

#endif