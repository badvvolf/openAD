#ifndef __BLACKLIST_H
#define __BLACKLIST_H

#include "netrulemanager.h"
#include "configuration.h"
#include "logger.h"

class Blacklist {

private: 
    NetRuleManager net_rule_manager;
    uint32_t savepoint;
    Logger & logger;


    void saveBackup(uint32_t);
    void removeBackup(uint32_t);

public:

    Blacklist(Logger&);
    bool addRule(uint32_t);
    bool subRule(uint32_t);
    void setConf(uint32_t);  
 

};

#endif