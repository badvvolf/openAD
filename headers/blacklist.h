#ifndef __BLACKLIST_H
#define __BLACKLIST_H

#include "netrulemanager.h"

class Blacklist {

private: 
    NetRuleManager net_rule_manager;
public:

    bool addRule(uint32_t);
    bool subRule(uint32_t);      
};

#endif