#ifndef __NETRULEMANAGER_H
#define __NETRULEMANAGER_H

#include "ebpfsuper.h"
#include "epbf_firewall.h"

class NetRuleManager : public EBPFSuper{

private: 

public:

    NetRuleManager();
    bool addBlacklist(uint32_t);
    bool subBlacklist(uint32_t);

    bool addPortForward(uint16_t, uint16_t);
    bool subPortForward(uint16_t, uint16_t);

};

#endif