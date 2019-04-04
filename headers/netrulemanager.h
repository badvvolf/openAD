#ifndef __NETRULEMANAGER_H
#define __NETRULEMANAGER_H

#include "ebpfsuper.h"


class NetRuleManager : public EBPFSuper{
//add blacklist

private: 

public:

    bool addBlacklist(uint32_t);
    bool subBlacklist(uint32_t);      


};

#endif