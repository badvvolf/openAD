#ifndef __BLACKLIST_H
#define __BLACKLIST_H

#include "netrulemanager.h"

class Blacklist {

private: 
    NetRuleManager net_rule_manager;
public:

    bool addBlacklist(uint32_t);
    bool subBlacklist(uint32_t);      
};

#endif