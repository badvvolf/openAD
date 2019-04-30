#ifndef __PORTFORWARD_H
#define __PORTFORWARD_H

#include "netrulemanager.h"

class Portforward{

private: 
    NetRuleManager net_rule_manager;
public:
    
    bool addRule(uint16_t, uint16_t);
    bool subRule(uint16_t, uint16_t);   
    
};


#endif